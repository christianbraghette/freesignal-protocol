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

import crypto from "./crypto";
import { KeyExchangeData, KeyExchangeDataBundle, KeyExchangeSynMessage, LocalStorage } from "./types";
import { KeySession } from "./double-ratchet";
import { concatUint8Array, decodeBase64, decodeUTF8, encodeBase64, verifyUint8Array } from "./utils";

export class KeyExchange {
    public static readonly version = 1;
    private static readonly hkdfInfo = decodeUTF8("freesignal/x3dh/" + KeyExchange.version);
    private static readonly maxOPK = 10;

    private readonly _signatureKey: crypto.KeyPair;
    private readonly _identityKey: crypto.KeyPair;
    private readonly bundleStore: LocalStorage<string, crypto.KeyPair>;

    public constructor(signSecretKey: Uint8Array, boxSecretKey: Uint8Array, bundleStore?: LocalStorage<string, crypto.KeyPair>) {
        this._signatureKey = crypto.EdDSA.keyPair(signSecretKey);
        this._identityKey = crypto.ECDH.keyPair(boxSecretKey);
        this.bundleStore = bundleStore ?? new AsyncMap<string, crypto.KeyPair>();
    }

    public get signatureKey() { return this._signatureKey.publicKey; }

    public get identityKey() { return this._identityKey.publicKey; }

    private generateSPK(): { signedPreKey: crypto.KeyPair, signedPreKeyHash: Uint8Array } {
        const signedPreKey = crypto.ECDH.keyPair();
        const signedPreKeyHash = crypto.hash(signedPreKey.publicKey);
        this.bundleStore.set(encodeBase64(signedPreKeyHash), signedPreKey);
        return { signedPreKey, signedPreKeyHash };
    }

    private generateOPK(spkHash: Uint8Array): { onetimePreKey: crypto.KeyPair, onetimePreKeyHash: Uint8Array } {
        const onetimePreKey = crypto.ECDH.keyPair();
        const onetimePreKeyHash = crypto.hash(onetimePreKey.publicKey);
        this.bundleStore.set(encodeBase64(spkHash).concat(encodeBase64(onetimePreKeyHash)), onetimePreKey);
        return { onetimePreKey, onetimePreKeyHash };
    }

    public generateBundle(length?: number): KeyExchangeDataBundle {
        const { signedPreKey, signedPreKeyHash } = this.generateSPK();
        const onetimePreKey = new Array(length ?? KeyExchange.maxOPK).fill(0).map(() => this.generateOPK(signedPreKeyHash).onetimePreKey);
        return {
            version: KeyExchange.version,
            publicKey: encodeBase64(this._signatureKey.publicKey),
            identityKey: encodeBase64(this._identityKey.publicKey),
            signedPreKey: encodeBase64(signedPreKey.publicKey),
            signature: encodeBase64(crypto.EdDSA.sign(signedPreKeyHash, this._signatureKey.secretKey)),
            onetimePreKey: onetimePreKey.map(opk => encodeBase64(opk.publicKey))
        }
    }

    public generateData(): KeyExchangeData {
        const { signedPreKey, signedPreKeyHash } = this.generateSPK();
        const { onetimePreKey } = this.generateOPK(signedPreKeyHash);
        return {
            version: KeyExchange.version,
            publicKey: encodeBase64(this._signatureKey.publicKey),
            identityKey: encodeBase64(this._identityKey.publicKey),
            signedPreKey: encodeBase64(signedPreKey.publicKey),
            signature: encodeBase64(crypto.EdDSA.sign(signedPreKeyHash, this._signatureKey.secretKey)),
            onetimePreKey: encodeBase64(onetimePreKey.publicKey)
        }
    }

    public digestData(message: KeyExchangeData): { session: KeySession, message: KeyExchangeSynMessage } {
        const ephemeralKey = crypto.ECDH.keyPair();
        const signedPreKey = decodeBase64(message.signedPreKey);
        if (!crypto.EdDSA.verify(crypto.hash(signedPreKey), decodeBase64(message.signature), decodeBase64(message.publicKey)))
            throw new Error("Signature verification failed");
        const identityKey = decodeBase64(message.identityKey);
        const onetimePreKey = message.onetimePreKey ? decodeBase64(message.onetimePreKey) : undefined;
        const signedPreKeyHash = crypto.hash(signedPreKey);
        const onetimePreKeyHash = onetimePreKey ? crypto.hash(onetimePreKey) : new Uint8Array();
        const rootKey = crypto.hkdf(new Uint8Array([
            ...crypto.scalarMult(this._identityKey.secretKey, signedPreKey),
            ...crypto.scalarMult(ephemeralKey.secretKey, identityKey),
            ...crypto.scalarMult(ephemeralKey.secretKey, signedPreKey),
            ...onetimePreKey ? crypto.scalarMult(ephemeralKey.secretKey, onetimePreKey) : new Uint8Array()
        ]), new Uint8Array(KeySession.rootKeyLength).fill(0), KeyExchange.hkdfInfo, KeySession.rootKeyLength);
        const session = new KeySession({ remoteKey: identityKey, rootKey });
        const cyphertext = session.encrypt(concatUint8Array(crypto.hash(this._identityKey.publicKey), crypto.hash(identityKey)));
        if (!cyphertext) throw new Error();
        return {
            session,
            message: {
                version: KeyExchange.version,
                publicKey: encodeBase64(this._signatureKey.publicKey),
                identityKey: encodeBase64(this._identityKey.publicKey),
                ephemeralKey: encodeBase64(ephemeralKey.publicKey),
                signedPreKeyHash: encodeBase64(signedPreKeyHash),
                onetimePreKeyHash: encodeBase64(onetimePreKeyHash),
                associatedData: encodeBase64(cyphertext.encode())
            }
        }
    }

    public async digestMessage(message: KeyExchangeSynMessage): Promise<{ session: KeySession; cleartext: Uint8Array; }> {
        const signedPreKey = await this.bundleStore.get(message.signedPreKeyHash);
        const hash = message.signedPreKeyHash.concat(message.onetimePreKeyHash);
        const onetimePreKey = await this.bundleStore.get(hash);
        if (!signedPreKey || !onetimePreKey || !message.identityKey || !message.ephemeralKey) throw new Error("ACK message malformed");
        if (!this.bundleStore.delete(hash)) throw new Error("Bundle store deleting error");
        const identityKey = decodeBase64(message.identityKey);
        const ephemeralKey = decodeBase64(message.ephemeralKey);
        const rootKey = crypto.hkdf(new Uint8Array([
            ...crypto.scalarMult(signedPreKey.secretKey, identityKey),
            ...crypto.scalarMult(this._identityKey.secretKey, ephemeralKey),
            ...crypto.scalarMult(signedPreKey.secretKey, ephemeralKey),
            ...onetimePreKey ? crypto.scalarMult(onetimePreKey.secretKey, ephemeralKey) : new Uint8Array()
        ]), new Uint8Array(KeySession.rootKeyLength).fill(0), KeyExchange.hkdfInfo, KeySession.rootKeyLength);
        const session = new KeySession({ secretKey: this._identityKey.secretKey, rootKey })
        const cleartext = session.decrypt(decodeBase64(message.associatedData));
        if (!cleartext) throw new Error("Error decrypting ACK message");
        if (!verifyUint8Array(cleartext, concatUint8Array(crypto.hash(identityKey), crypto.hash(this._identityKey.publicKey))))
            throw new Error("Error verifing Associated Data");
        return { session, cleartext };
    }
}

class AsyncMap<K, V> implements LocalStorage<K, V> {
    private map: Map<K, V>;

    constructor() {
        this.map = new Map<K, V>();
    }

    async set(key: K, value: V): Promise<this> {
        this.map.set(key, value);
        return this;
    }

    async get(key: K): Promise<V | undefined> {
        return this.map.get(key);
    }

    async has(key: K): Promise<boolean> {
        return this.map.has(key);
    }

    async delete(key: K): Promise<boolean> {
        return this.map.delete(key);
    }

    async entries(): Promise<MapIterator<[K, V]>> {
        return this.map.entries();
    }
}