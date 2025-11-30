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

import crypto from "@freesignal/crypto";
import { KeyExchangeData, KeyExchangeDataBundle, KeyExchangeSynMessage, LocalStorage, Crypto } from "@freesignal/interfaces";
import { ExportedKeySession, KeySession } from "./double-ratchet";
import { concatArrays, decodeBase64, encodeBase64, verifyArrays } from "@freesignal/utils";
import { IdentityKey, PrivateIdentityKey } from "./types";
import { createIdentity } from ".";

export interface ExportedKeyExchange {
    privateIdentityKey: PrivateIdentityKey;
    storage: Array<[string, Crypto.KeyPair]>;
}

export class KeyExchange {
    public static readonly version = 1;
    private static readonly hkdfInfo = "freesignal/x3dh/" + KeyExchange.version;
    private static readonly maxOPK = 10;

    private readonly privateIdentityKey: PrivateIdentityKey;
    private readonly storage: LocalStorage<string, Crypto.KeyPair>;
    private readonly sessions: LocalStorage<string, ExportedKeySession>;

    public constructor(storage: { keys: LocalStorage<string, Crypto.KeyPair>, sessions: LocalStorage<string, ExportedKeySession> }, privateIdentityKey?: PrivateIdentityKey) {
        this.storage = storage.keys;
        this.sessions = storage.sessions;
        this.privateIdentityKey = privateIdentityKey ?? createIdentity();
    }

    public get identityKey(): IdentityKey {
        return this.privateIdentityKey.identityKey;
    }

    private generateSPK(): { signedPreKey: Crypto.KeyPair, signedPreKeyHash: Uint8Array } {
        const signedPreKey = crypto.ECDH.keyPair();
        const signedPreKeyHash = crypto.hash(signedPreKey.publicKey);
        this.storage.set(decodeBase64(signedPreKeyHash), signedPreKey);
        return { signedPreKey, signedPreKeyHash };
    }

    private generateOPK(spkHash: Uint8Array): { onetimePreKey: Crypto.KeyPair, onetimePreKeyHash: Uint8Array } {
        const onetimePreKey = crypto.ECDH.keyPair();
        const onetimePreKeyHash = crypto.hash(onetimePreKey.publicKey);
        this.storage.set(decodeBase64(spkHash).concat(decodeBase64(onetimePreKeyHash)), onetimePreKey);
        return { onetimePreKey, onetimePreKeyHash };
    }

    public async generateBundle(length?: number): Promise<KeyExchangeDataBundle> {
        const { signedPreKey, signedPreKeyHash } = this.generateSPK();
        const onetimePreKey = new Array(length ?? KeyExchange.maxOPK).fill(0).map(() => this.generateOPK(signedPreKeyHash).onetimePreKey);
        return {
            version: KeyExchange.version,
            identityKey: this.identityKey.toString(),
            signedPreKey: decodeBase64(signedPreKey.publicKey),
            signature: decodeBase64(crypto.EdDSA.sign(signedPreKeyHash, this.privateIdentityKey.signatureKey)),
            onetimePreKey: onetimePreKey.map(opk => decodeBase64(opk.publicKey))
        }
    }

    public async generateData(): Promise<KeyExchangeData> {
        const { signedPreKey, signedPreKeyHash } = this.generateSPK();
        const { onetimePreKey } = this.generateOPK(signedPreKeyHash);
        return {
            version: KeyExchange.version,
            identityKey: this.identityKey.toString(),
            signedPreKey: decodeBase64(signedPreKey.publicKey),
            signature: decodeBase64(crypto.EdDSA.sign(signedPreKeyHash, this.privateIdentityKey.signatureKey)),
            onetimePreKey: decodeBase64(onetimePreKey.publicKey)
        }
    }

    public async digestData(message: KeyExchangeData): Promise<{ session: KeySession; message: KeyExchangeSynMessage; identityKey: IdentityKey; }> {
        const ephemeralKey = crypto.ECDH.keyPair();
        const signedPreKey = encodeBase64(message.signedPreKey);
        const identityKey = IdentityKey.from(message.identityKey);
        if (!crypto.EdDSA.verify(crypto.hash(signedPreKey), encodeBase64(message.signature), identityKey.signatureKey))
            throw new Error("Signature verification failed");
        const onetimePreKey = message.onetimePreKey ? encodeBase64(message.onetimePreKey) : undefined;
        const signedPreKeyHash = crypto.hash(signedPreKey);
        const onetimePreKeyHash = onetimePreKey ? crypto.hash(onetimePreKey) : new Uint8Array();
        const rootKey = crypto.hkdf(new Uint8Array([
            ...crypto.ECDH.scalarMult(this.privateIdentityKey.exchangeKey, signedPreKey),
            ...crypto.ECDH.scalarMult(ephemeralKey.secretKey, identityKey.exchangeKey),
            ...crypto.ECDH.scalarMult(ephemeralKey.secretKey, signedPreKey),
            ...onetimePreKey ? crypto.ECDH.scalarMult(ephemeralKey.secretKey, onetimePreKey) : new Uint8Array()
        ]), new Uint8Array(KeySession.keyLength).fill(0), KeyExchange.hkdfInfo, KeySession.keyLength);
        const session = new KeySession(this.sessions, { remoteKey: identityKey.exchangeKey, rootKey });
        const cyphertext = await session.encrypt(concatArrays(crypto.hash(this.identityKey.toBytes()), crypto.hash(identityKey.toBytes())));
        if (!cyphertext) throw new Error("Decryption error");

        return {
            session,
            message: {
                version: KeyExchange.version,
                identityKey: this.identityKey.toString(),
                ephemeralKey: decodeBase64(ephemeralKey.publicKey),
                signedPreKeyHash: decodeBase64(signedPreKeyHash),
                onetimePreKeyHash: decodeBase64(onetimePreKeyHash),
                associatedData: decodeBase64(cyphertext.toBytes())
            },
            identityKey
        }
    }

    public async digestMessage(message: KeyExchangeSynMessage): Promise<{ session: KeySession, identityKey: IdentityKey }> {
        const signedPreKey = await this.storage.get(message.signedPreKeyHash);
        const hash = message.signedPreKeyHash.concat(message.onetimePreKeyHash);
        const onetimePreKey = await this.storage.get(hash);
        const identityKey = IdentityKey.from(message.identityKey);
        if (!signedPreKey || !onetimePreKey || !message.identityKey || !message.ephemeralKey) throw new Error("ACK message malformed");
        if (!this.storage.delete(hash)) throw new Error("Bundle store deleting error");
        const ephemeralKey = encodeBase64(message.ephemeralKey);
        const rootKey = crypto.hkdf(new Uint8Array([
            ...crypto.ECDH.scalarMult(signedPreKey.secretKey, identityKey.exchangeKey),
            ...crypto.ECDH.scalarMult(this.privateIdentityKey.exchangeKey, ephemeralKey),
            ...crypto.ECDH.scalarMult(signedPreKey.secretKey, ephemeralKey),
            ...onetimePreKey ? crypto.ECDH.scalarMult(onetimePreKey.secretKey, ephemeralKey) : new Uint8Array()
        ]), new Uint8Array(KeySession.keyLength).fill(0), KeyExchange.hkdfInfo, KeySession.keyLength);
        const session = new KeySession(this.sessions, { secretKey: this.privateIdentityKey.exchangeKey, rootKey })
        const cleartext = await session.decrypt(encodeBase64(message.associatedData));
        if (!cleartext) throw new Error("Error decrypting ACK message");
        if (!verifyArrays(cleartext, concatArrays(crypto.hash(identityKey.toBytes()), crypto.hash(this.identityKey.toBytes()))))
            throw new Error("Error verifing Associated Data");
        return {
            session,
            identityKey
        };
    }
}