/**
 * FreeSignal Protocol
 * 
 * Copyright (C) 2025  Christian Braghette
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>
 */

import { Crypto, Database, KeyExchangeData, KeyExchangeDataBundle, KeyExchangeSynMessage, LocalStorage } from "@freesignal/interfaces";
import crypto from "@freesignal/crypto";
import { ExportedKeySession, KeySession } from "./double-ratchet";
import { KeyExchange } from "./x3dh";
import { decodeBase64, encodeBase64 } from "@freesignal/utils";
import { Datagram, IdentityKey, EncryptedData, UserId, XFreeSignal, DataEncoder } from "./types";

type DatagramId = string;

export class FreeSignalAPI {
    protected readonly signKey: Crypto.KeyPair;
    protected readonly boxKey: Crypto.KeyPair;
    protected readonly sessions: LocalStorage<UserId, ExportedKeySession>;
    protected readonly keyExchange: KeyExchange;
    protected readonly users: LocalStorage<UserId, IdentityKey>;

    public readonly userId: UserId;

    public constructor(
        secretSignKey: Uint8Array,
        secretBoxKey: Uint8Array,
        storage: Database<{
            sessions: LocalStorage<UserId, ExportedKeySession>,
            keyExchange: LocalStorage<string, Crypto.KeyPair>,
            users: LocalStorage<UserId, IdentityKey>
        }>) {
        this.signKey = crypto.EdDSA.keyPair(secretSignKey);
        this.boxKey = crypto.ECDH.keyPair(secretBoxKey);
        this.sessions = storage.sessions;
        this.keyExchange = new KeyExchange({ keys: storage.keyExchange, sessions: storage.sessions });
        this.users = storage.users;
        this.userId = UserId.getUserId(this.signKey.publicKey).toString();
    }

    public get identityKeys(): IdentityKey {
        return IdentityKey.from(this.signKey.publicKey, this.boxKey.publicKey);
    }

    public async encryptData(data: Uint8Array, userId: string): Promise<EncryptedData> {
        const sessionJson = await this.sessions.get(userId);
        if (!sessionJson) throw new Error('Session not found for user: ' + userId);
        const session = KeySession.from(sessionJson, this.sessions);
        const encrypted = session.encrypt(data);
        this.sessions.set(userId, session.toJSON()); // Ensure session is updated
        return encrypted;
    }

    public async decryptData(data: Uint8Array, userId: string): Promise<Uint8Array> {
        const sessionJson = await this.sessions.get(userId);
        if (!sessionJson) throw new Error('Session not found for user: ' + userId);
        const session = KeySession.from(sessionJson, this.sessions);
        const decrypted = session.decrypt(data);
        if (!decrypted) throw new Error('Decryption failed for user: ' + userId);
        this.sessions.set(userId, session.toJSON()); // Ensure session is updated
        return decrypted;
    }

    public async getHandshake(url: string, userId?: UserId): Promise<KeyExchangeData> {
        const res = await fetch(`${url}/${userId ?? ''}`, {
            method: 'GET'
        })
        const body = XFreeSignal.decodeBody(new Uint8Array(await res.arrayBuffer()))
        if (body.type === 'error')
            throw new Error(body.data);
        return body.data;
    }

    public async postHandshake(url: string, message: KeyExchangeSynMessage): Promise<boolean> {
        const res = await fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': XFreeSignal.MIME
            },
            body: XFreeSignal.encodeBody('data', message)
        })
        return res.status === 200;
    }

    public async putHandshake(url: string, publicKey: string | Uint8Array, bundle: KeyExchangeDataBundle): Promise<boolean> {
        const res = await fetch(url, {
            method: 'PUT',
            headers: {
                'Content-Type': XFreeSignal.MIME,
                authorization: this.createToken(publicKey instanceof Uint8Array ? publicKey : encodeBase64(publicKey))
            },
            body: XFreeSignal.encodeBody('data', bundle)
        })
        return res.status === 201;
    }

    public async deleteHandshake(url: string, publicKey: string | Uint8Array): Promise<boolean> {
        const res = await fetch(url, {
            method: 'DELETE',
            headers: {
                authorization: this.createToken(publicKey instanceof Uint8Array ? publicKey : encodeBase64(publicKey))
            }
        })
        return res.status === 200;
    }

    public async getDatagrams(publicKey: string | Uint8Array, url: string): Promise<Datagram[]> {
        const res = await fetch(url, {
            method: 'GET',
            headers: {
                authorization: this.createToken(publicKey instanceof Uint8Array ? publicKey : encodeBase64(publicKey))
            }
        });
        const body = XFreeSignal.decodeBody(new Uint8Array(await res.arrayBuffer()));
        if (body.type === 'error')
            throw new Error(body.data);
        return DataEncoder.from<Uint8Array[]>(
            await this.decryptData(body.data, UserId.getUserId(publicKey).toString())
        ).data.map(array => Datagram.from(array));
    }

    public async postDatagrams(datagrams: Datagram[], publicKey: string | Uint8Array, url: string): Promise<number> {
        const data = await this.encryptData(new DataEncoder(datagrams.map(datagram => Datagram.from(datagram).encode())).encode(), UserId.getUserId(publicKey).toString());
        const res = await fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': XFreeSignal.MIME,
                authorization: this.createToken(publicKey instanceof Uint8Array ? publicKey : encodeBase64(publicKey))
            },
            body: XFreeSignal.encodeBody('data', data.encode())
        });
        const body = XFreeSignal.decodeBody(new Uint8Array(await res.arrayBuffer()));
        if (body.type === 'error')
            throw new Error(body.data);
        return DataEncoder.from<number>(await this.decryptData(body.data, UserId.getUserId(publicKey).toString())).data;
    }

    public async deleteDatagrams(datagramIds: DatagramId[], publicKey: string | Uint8Array, url: string): Promise<number> {
        const data = await this.encryptData(new DataEncoder(datagramIds.map(datagramId => crypto.UUID.parse(datagramId))).encode(), UserId.getUserId(publicKey).toString());
        const res = await fetch(url, {
            method: 'DELETE',
            headers: {
                'Content-Type': XFreeSignal.MIME,
                authorization: this.createToken(publicKey instanceof Uint8Array ? publicKey : encodeBase64(publicKey))
            },
            body: XFreeSignal.encodeBody('data', data.encode())
        });
        const body = XFreeSignal.decodeBody(new Uint8Array(await res.arrayBuffer()));
        if (body.type === 'error')
            throw new Error(body.data);
        return DataEncoder.from<number>(await this.decryptData(body.data, UserId.getUserId(publicKey).toString())).data;
    }

    public createToken(publicKey: Uint8Array): string {
        const signature = crypto.EdDSA.sign(crypto.hash(crypto.ECDH.scalarMult(publicKey, this.boxKey.secretKey)), this.signKey.secretKey);
        return `Bearer ${this.userId}:${decodeBase64(signature)}`;
    };

    protected async digestToken(auth?: string): Promise<{ identityKeys: IdentityKey, userId: UserId }> {
        if (auth && auth.startsWith("Bearer ")) {
            const [userId, signature] = auth.substring(7).split(":");
            const identityKeys = await this.users.get(userId);
            if (!identityKeys)
                throw new Error('User not found or invalid auth token');
            if (crypto.EdDSA.verify(crypto.hash(crypto.ECDH.scalarMult(identityKeys.exchangeKey, this.boxKey.secretKey)), encodeBase64(signature), identityKeys.signatureKey))
                return { identityKeys, userId: auth };
            else
                throw new Error('Authorization token not valid');
        }
        throw new Error('Authorization header is required');
    }
}