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
import { KeySession } from "./double-ratchet";
import { concatArrays, decodeBase64, encodeBase64, encodeUTF8, verifyArrays } from "@freesignal/utils";
import { IdentityKeys } from "./types";

export interface ExportedKeyExchange {
    storage: Array<[string, Crypto.KeyPair]>;
}

export class KeyExchange {
    public static readonly version = 1;
    private static readonly hkdfInfo = encodeUTF8("freesignal/x3dh/" + KeyExchange.version);
    private static readonly maxOPK = 10;
    private static readonly signatureKeySymbol = decodeBase64(crypto.hash(encodeUTF8("signatureKeySymbol")));
    private static readonly identityKeySymbol = decodeBase64(crypto.hash(encodeUTF8("identityKeySymbol")));

    private _identityKey!: Crypto.KeyPair;
    private _signatureKey!: Crypto.KeyPair;
    private readonly storage: LocalStorage<string, Crypto.KeyPair>;

    public constructor(storage: LocalStorage<string, Crypto.KeyPair>, secretSignKey?: Uint8Array, secretIdentityKey?: Uint8Array) {
        this.storage = storage;
        if (secretSignKey)
            this.storage.set(KeyExchange.signatureKeySymbol, crypto.EdDSA.keyPair(secretSignKey))
        else
            this.storage.get(KeyExchange.signatureKeySymbol).then((value) => {
                this._signatureKey = value ?? crypto.EdDSA.keyPair();
                if (!value)
                    this.storage.set(KeyExchange.signatureKeySymbol, this._signatureKey);
            });

        if (secretIdentityKey)
            this.storage.set(KeyExchange.signatureKeySymbol, crypto.EdDSA.keyPair(secretIdentityKey))
        else
            this.storage.get(KeyExchange.identityKeySymbol).then((value) => {
                this._identityKey = value ?? crypto.ECDH.keyPair();
                if (!value)
                    this.storage.set(KeyExchange.identityKeySymbol, this._identityKey);
            });
    }

    public get signatureKey() { return this._signatureKey.publicKey; }

    public get identityKey() { return this._identityKey.publicKey; }

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

    public generateBundle(length?: number): KeyExchangeDataBundle {
        const { signedPreKey, signedPreKeyHash } = this.generateSPK();
        const onetimePreKey = new Array(length ?? KeyExchange.maxOPK).fill(0).map(() => this.generateOPK(signedPreKeyHash).onetimePreKey);
        return {
            version: KeyExchange.version,
            publicKey: decodeBase64(this._signatureKey.publicKey),
            identityKey: decodeBase64(this._identityKey.publicKey),
            signedPreKey: decodeBase64(signedPreKey.publicKey),
            signature: decodeBase64(crypto.EdDSA.sign(signedPreKeyHash, this._signatureKey.secretKey)),
            onetimePreKey: onetimePreKey.map(opk => decodeBase64(opk.publicKey))
        }
    }

    public generateData(): KeyExchangeData {
        const { signedPreKey, signedPreKeyHash } = this.generateSPK();
        const { onetimePreKey } = this.generateOPK(signedPreKeyHash);
        return {
            version: KeyExchange.version,
            publicKey: decodeBase64(this._signatureKey.publicKey),
            identityKey: decodeBase64(this._identityKey.publicKey),
            signedPreKey: decodeBase64(signedPreKey.publicKey),
            signature: decodeBase64(crypto.EdDSA.sign(signedPreKeyHash, this._signatureKey.secretKey)),
            onetimePreKey: decodeBase64(onetimePreKey.publicKey)
        }
    }

    public digestData(message: KeyExchangeData): { session: KeySession, message: KeyExchangeSynMessage, identityKeys: IdentityKeys } {
        const ephemeralKey = crypto.ECDH.keyPair();
        const signedPreKey = encodeBase64(message.signedPreKey);
        if (!crypto.EdDSA.verify(crypto.hash(signedPreKey), encodeBase64(message.signature), encodeBase64(message.publicKey)))
            throw new Error("Signature verification failed");
        const identityKey = encodeBase64(message.identityKey);
        const onetimePreKey = message.onetimePreKey ? encodeBase64(message.onetimePreKey) : undefined;
        const signedPreKeyHash = crypto.hash(signedPreKey);
        const onetimePreKeyHash = onetimePreKey ? crypto.hash(onetimePreKey) : new Uint8Array();
        const rootKey = crypto.hkdf(new Uint8Array([
            ...crypto.ECDH.scalarMult(this._identityKey.secretKey, signedPreKey),
            ...crypto.ECDH.scalarMult(ephemeralKey.secretKey, identityKey),
            ...crypto.ECDH.scalarMult(ephemeralKey.secretKey, signedPreKey),
            ...onetimePreKey ? crypto.ECDH.scalarMult(ephemeralKey.secretKey, onetimePreKey) : new Uint8Array()
        ]), new Uint8Array(KeySession.rootKeyLength).fill(0), KeyExchange.hkdfInfo, KeySession.rootKeyLength);
        const session = new KeySession({ remoteKey: identityKey, rootKey });
        const cyphertext = session.encrypt(concatArrays(crypto.hash(this._identityKey.publicKey), crypto.hash(identityKey)));
        if (!cyphertext) throw new Error("Decryption error");
        return {
            session,
            message: {
                version: KeyExchange.version,
                publicKey: decodeBase64(this._signatureKey.publicKey),
                identityKey: decodeBase64(this._identityKey.publicKey),
                ephemeralKey: decodeBase64(ephemeralKey.publicKey),
                signedPreKeyHash: decodeBase64(signedPreKeyHash),
                onetimePreKeyHash: decodeBase64(onetimePreKeyHash),
                associatedData: decodeBase64(cyphertext.encode())
            },
            identityKeys: {
                publicKey: message.publicKey,
                identityKey: message.identityKey
            },

        }
    }

    public async digestMessage(message: KeyExchangeSynMessage): Promise<{ session: KeySession, identityKeys: IdentityKeys }> {
        const signedPreKey = await this.storage.get(message.signedPreKeyHash);
        const hash = message.signedPreKeyHash.concat(message.onetimePreKeyHash);
        const onetimePreKey = await this.storage.get(hash);
        if (!signedPreKey || !onetimePreKey || !message.identityKey || !message.ephemeralKey) throw new Error("ACK message malformed");
        if (!this.storage.delete(hash)) throw new Error("Bundle store deleting error");
        const identityKey = encodeBase64(message.identityKey);
        const ephemeralKey = encodeBase64(message.ephemeralKey);
        const rootKey = crypto.hkdf(new Uint8Array([
            ...crypto.ECDH.scalarMult(signedPreKey.secretKey, identityKey),
            ...crypto.ECDH.scalarMult(this._identityKey.secretKey, ephemeralKey),
            ...crypto.ECDH.scalarMult(signedPreKey.secretKey, ephemeralKey),
            ...onetimePreKey ? crypto.ECDH.scalarMult(onetimePreKey.secretKey, ephemeralKey) : new Uint8Array()
        ]), new Uint8Array(KeySession.rootKeyLength).fill(0), KeyExchange.hkdfInfo, KeySession.rootKeyLength);
        const session = new KeySession({ secretKey: this._identityKey.secretKey, rootKey })
        const cleartext = session.decrypt(encodeBase64(message.associatedData));
        if (!cleartext) throw new Error("Error decrypting ACK message");
        if (!verifyArrays(cleartext, concatArrays(crypto.hash(identityKey), crypto.hash(this._identityKey.publicKey))))
            throw new Error("Error verifing Associated Data");
        return {
            session,
            identityKeys: {
                publicKey: message.publicKey,
                identityKey: message.identityKey
            }
        };
    }

    public toJSON(): ExportedKeyExchange {
        return {
            storage: Array.from(this.storage.entries())
        }
    }

    public static from(data: ExportedKeyExchange, storage: LocalStorage<string, Crypto.KeyPair>) {
        Promise.all(data.storage.map(([key, value]) => storage.set(key, value)));
        return new KeyExchange(storage);
    }
}