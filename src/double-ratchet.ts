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
import { Crypto } from "@freesignal/interfaces";
import { concatUint8Array, decodeBase64, encodeBase64, verifyUint8Array } from "@freesignal/utils";
import { EncryptedData, EncryptedDataConstructor } from "./types";

type ExportedKeySession = {
    secretKey: string;
    remoteKey: string;
    rootKey: string;
    sendingChain: string;
    receivingChain: string;
    sendingCount: number;
    receivingCount: number;
    previousCount: number;
    previousKeys: [number, Uint8Array][];
}

/**
 * Represents a secure Double Ratchet session.
 * Used for forward-secure encryption and decryption of messages.
 */
export class KeySession {
    private static readonly skipLimit = 1000;
    public static readonly version = 1;
    public static readonly rootKeyLength = crypto.box.keyLength;

    private keyPair: Crypto.KeyPair;
    private _remoteKey?: Uint8Array;
    private rootKey?: Uint8Array;
    private sendingChain?: Uint8Array;
    private sendingCount = 0;
    private previousCount = 0;
    private receivingChain?: Uint8Array;
    private receivingCount = 0;
    private previousKeys = new KeyMap<number, Uint8Array>();

    public constructor(opts: { secretKey?: Uint8Array, remoteKey?: Uint8Array, rootKey?: Uint8Array } = {}) {
        this.keyPair = crypto.ECDH.keyPair(opts.secretKey);
        if (opts.rootKey)
            this.rootKey = opts.rootKey;
        if (opts.remoteKey) {
            this._remoteKey = opts.remoteKey;
            this.sendingChain = this.ratchetKeys();
        }
    }

    /**
     * Whether both the sending and receiving chains are initialized.
     */
    public get handshaked(): boolean { return this.sendingChain && this.receivingChain ? true : false; }

    /**
     * The public key of this session.
     */
    public get publicKey(): Uint8Array { return this.keyPair.publicKey; }

    /**
     * The last known remote public key.
     */
    public get remoteKey(): Uint8Array | undefined { return this._remoteKey; }

    private setRemoteKey(key: Uint8Array): this {
        this._remoteKey = key;
        this.receivingChain = this.ratchetKeys();
        if (this.receivingCount > (EncryptedDataConstructor.maxCount - KeySession.skipLimit * 2))
            this.receivingCount = 0;
        this.previousCount = this.sendingCount;
        this.keyPair = crypto.ECDH.keyPair();
        this.sendingChain = this.ratchetKeys();
        if (this.sendingCount > (EncryptedDataConstructor.maxCount - KeySession.skipLimit * 2))
            this.sendingCount = 0;
        return this;
    }

    private ratchetKeys(info?: Uint8Array): Uint8Array {
        if (!this._remoteKey) throw new Error();
        const sharedKey = crypto.ECDH.scalarMult(this.keyPair.secretKey, this._remoteKey);
        if (!this.rootKey)
            this.rootKey = crypto.hash(sharedKey);
        const hashkey = crypto.hkdf(sharedKey, this.rootKey, info, KeySession.keyLength * 2);
        this.rootKey = hashkey.slice(0, KeySession.keyLength);
        return hashkey.slice(KeySession.keyLength);
    }

    private getSendingKey() {
        if (!this.sendingChain) throw new Error;
        const { chainKey, sharedKey } = KeySession.symmetricRatchet(this.sendingChain);
        this.sendingChain = chainKey;
        this.sendingCount++;
        return sharedKey;
    }

    private getReceivingKey() {
        if (!this.receivingChain) throw new Error();
        const { chainKey, sharedKey } = KeySession.symmetricRatchet(this.receivingChain);
        this.receivingChain = chainKey;
        this.receivingCount++;
        return sharedKey;
    }

    /**
     * Encrypts a message payload using the current sending chain.
     *
     * @param message - The message as a Uint8Array.
     * @returns An EncryptedPayload or undefined if encryption fails.
     */
    public encrypt(message: Uint8Array): EncryptedData {
        const key = this.getSendingKey();
        if (this.sendingCount >= EncryptedDataConstructor.maxCount || this.previousCount >= EncryptedDataConstructor.maxCount) throw new Error();
        const nonce = crypto.randomBytes(EncryptedDataConstructor.nonceLength);
        const ciphertext = crypto.box.encrypt(message, nonce, key);
        return new EncryptedDataConstructor(this.sendingCount, this.previousCount, this.keyPair.publicKey, nonce, ciphertext);
    }

    /**
     * Decrypts an encrypted message.
     *
     * @param payload - The received encrypted message.
     * @returns The decrypted message as a Uint8Array, or undefined if decryption fails.
     */
    public decrypt(payload: Uint8Array | EncryptedData): Uint8Array | undefined {
        const encrypted = EncryptedData.from(payload);
        const publicKey = encrypted.publicKey;
        if (!verifyUint8Array(publicKey, this._remoteKey)) {
            while (this.receivingCount < encrypted.previous)
                this.previousKeys.set(this.receivingCount, this.getReceivingKey());
            this.setRemoteKey(publicKey);
        }
        let key: Uint8Array | undefined;
        const count = encrypted.count;
        if (this.receivingCount < count) {
            let i = 0;
            while (this.receivingCount < count - 1 && i < KeySession.skipLimit) {
                this.previousKeys.set(this.receivingCount, this.getReceivingKey());
            }
            key = this.getReceivingKey()
        } else {
            key = this.previousKeys.get(count);
        }
        if (!key) return undefined;
        return crypto.box.decrypt(encrypted.ciphertext, encrypted.nonce, key) ?? undefined;
    }

    /**
     * Export the state of the session;
     */
    public export(): ExportedKeySession {
        return {
            secretKey: decodeBase64(concatUint8Array(this.keyPair.secretKey)),
            remoteKey: decodeBase64(this._remoteKey),
            rootKey: decodeBase64(this.rootKey),
            sendingChain: decodeBase64(this.sendingChain),
            receivingChain: decodeBase64(this.receivingChain),
            sendingCount: this.sendingCount,
            receivingCount: this.receivingCount,
            previousCount: this.previousCount,
            previousKeys: Array.from(this.previousKeys.entries())
        };
    }

    /**
     * Import a state.
     * 
     * @param json string returned by `export()` method.
     * @returns session with the state parsed.
     */
    public static import(json: string): KeySession {
        const data: ExportedKeySession = JSON.parse(json);
        const session = new KeySession({ secretKey: encodeBase64(data.secretKey), rootKey: encodeBase64(data.rootKey) });
        session._remoteKey = encodeBase64(data.remoteKey);
        session.sendingChain = encodeBase64(data.sendingChain);
        session.receivingChain = encodeBase64(data.receivingChain);
        session.sendingCount = data.sendingCount;
        session.receivingCount = data.receivingCount;
        session.previousCount = data.previousCount;
        session.previousKeys = new KeyMap(data.previousKeys);
        return session;
    }

    /**
     * The fixed key length (in bytes) used throughout the Double Ratchet session.
     * Typically 32 bytes (256 bits) for symmetric keys.
     */
    public static readonly keyLength = 32;

    private static symmetricRatchet(chain: Uint8Array, salt?: Uint8Array, info?: Uint8Array) {
        const hash = crypto.hkdf(chain, salt ?? new Uint8Array(), info, KeySession.keyLength * 2);
        return {
            chainKey: new Uint8Array(hash.buffer, 0, KeySession.keyLength),
            sharedKey: new Uint8Array(hash.buffer, KeySession.keyLength)
        }
    }
}

class KeyMap<K, T> extends Map<K, T> {

    get(key: K): T | undefined {
        const out = super.get(key);
        if (out && !super.delete(key))
            throw new Error();
        return out;
    }

}