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
import { Crypto, LocalStorage } from "@freesignal/interfaces";
import { concatArrays, decodeBase64, encodeBase64, numberFromArray, numberToArray, verifyArrays } from "@freesignal/utils";
import { EncryptedData } from "./types";
import { AsyncMutex } from "semaphore.ts";

export interface ExportedKeySession {
    secretKey: string;
    rootKey?: string;
    sendingChain?: ExportedKeyChain;
    receivingChain?: ExportedKeyChain;
    previousKeys: [string, Uint8Array][];
}

/**
 * Represents a secure Double Ratchet session.
 * Used for forward-secure encryption and decryption of messages.
 */
export class KeySession {
    public static readonly keyLength = 32;
    public static readonly version = 1;
    public static readonly info = "/freesignal/double-ratchet/v0." + KeySession.version;

    public readonly id: string;

    private readonly mutex: { readonly sending: AsyncMutex, readonly receiving: AsyncMutex } = { sending: new AsyncMutex(), receiving: new AsyncMutex() };
    private readonly storage: LocalStorage<string, ExportedKeySession>;
    private keyPair: Crypto.KeyPair;
    private rootKey?: Uint8Array;
    private sendingChain?: KeyChain;
    private receivingChain?: KeyChain;
    private previousKeys = new KeyMap<string, Uint8Array>();

    public constructor(storage: LocalStorage<string, ExportedKeySession>, opts: { id?: string, secretKey?: Uint8Array, remoteKey?: Uint8Array, rootKey?: Uint8Array } = {}) {
        this.id = opts.id ?? crypto.UUID.generate().toString();
        this.keyPair = crypto.ECDH.keyPair(opts.secretKey);
        if (opts.rootKey)
            this.rootKey = opts.rootKey;

        if (opts.remoteKey) {
            this.sendingChain = this.getChain(opts.remoteKey);
        }

        this.storage = storage;
        this.save();
    }

    private getChain(remoteKey: Uint8Array, previousCount?: number): KeyChain {
        const sharedKey = crypto.ECDH.scalarMult(this.keyPair.secretKey, remoteKey);
        if (!this.rootKey)
            this.rootKey = crypto.hash(sharedKey);
        const hashkey = crypto.hkdf(sharedKey, this.rootKey, KeySession.info, KeySession.keyLength * 2);
        this.rootKey = hashkey.subarray(0, KeySession.keyLength);
        return new KeyChain(this.publicKey, remoteKey, hashkey.subarray(KeySession.keyLength), previousCount);
    }

    private save(): Promise<void> {
        return this.storage.set(this.id, this.toJSON());
    }

    /**
     * Encrypts a message payload using the current sending chain.
     *
     * @param message - The message as a Uint8Array.
     * @returns An EncryptedPayload or undefined if encryption fails.
     */
    public async encrypt(message: Uint8Array): Promise<EncryptedData> {
        using lock = await this.mutex.sending.acquire();
        if (!this.sendingChain)
            throw new Error("SendingChain not initialized");
        const key = this.sendingChain.getKey();
        const nonce = crypto.randomBytes(EncryptedDataConstructor.nonceLength);
        const ciphertext = crypto.box.encrypt(message, nonce, key);
        this.save();
        return new EncryptedDataConstructor(this.sendingChain.count, this.sendingChain.previousCount, this.keyPair.publicKey, nonce, ciphertext);
    }

    /**
     * Decrypts an encrypted message.
     *
     * @param payload - The received encrypted message.
     * @returns The decrypted message as a Uint8Array, or undefined if decryption fails.
     */
    public async decrypt(payload: Uint8Array | EncryptedData): Promise<Uint8Array> {
        const encrypted = EncryptedData.from(payload);

        if (!this.previousKeys.has(decodeBase64(encrypted.publicKey) + encrypted.count.toString())) {
            const lock = await this.mutex.receiving.acquire();

            if (!verifyArrays(encrypted.publicKey, this.receivingChain?.remoteKey ?? new Uint8Array())) {
                while (this.receivingChain && this.receivingChain.count < encrypted.previous) {
                    const key = this.receivingChain.getKey();
                    this.previousKeys.set(decodeBase64(this.receivingChain.remoteKey) + this.receivingChain.count.toString(), key);
                }

                this.receivingChain = this.getChain(encrypted.publicKey);
                this.keyPair = crypto.ECDH.keyPair();
                this.sendingChain = this.getChain(encrypted.publicKey, this.sendingChain?.count);
            }
            if (!this.receivingChain)
                throw new Error("Error initializing receivingChain");

            while (this.receivingChain.count < encrypted.count) {
                const key = this.receivingChain.getKey();
                this.previousKeys.set(decodeBase64(this.receivingChain.remoteKey) + this.receivingChain.count.toString(), key);
            }

            lock.release();
        }

        const key = this.previousKeys.get(decodeBase64(encrypted.publicKey) + encrypted.count.toString());
        if (!key)
            throw new Error("Error calculating key");
        this.save();

        const cleartext = crypto.box.decrypt(encrypted.ciphertext, encrypted.nonce, key);
        if (!cleartext)
            throw new Error("Error decrypting ciphertext");

        return cleartext;
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
     * Export the state of the session;
     */
    public toJSON(): ExportedKeySession {
        return {
            secretKey: decodeBase64(this.keyPair.secretKey),
            rootKey: this.rootKey ? decodeBase64(this.rootKey) : undefined,
            sendingChain: this.sendingChain?.toJSON(),
            receivingChain: this.receivingChain?.toJSON(),
            previousKeys: Array.from(this.previousKeys.entries())
        };
    }

    /**
     * Import a state.
     * 
     * @param json string returned by `export()` method.
     * @returns session with the state parsed.
     */
    public static from(data: ExportedKeySession, storage: LocalStorage<string, ExportedKeySession>): KeySession {
        const session = new KeySession(storage, { secretKey: encodeBase64(data.secretKey), rootKey: data.rootKey ? encodeBase64(data.rootKey) : undefined });
        //session._remoteKey = data.remoteKey ? encodeBase64(data.remoteKey) : undefined;
        session.sendingChain = data.sendingChain ? KeyChain.from(data.sendingChain) : undefined;
        session.receivingChain = data.receivingChain ? KeyChain.from(data.receivingChain) : undefined;
        session.previousKeys = new KeyMap(data.previousKeys);
        session.save();
        return session;
    }
}

interface ExportedKeyChain {
    publicKey: string;
    remoteKey: string;
    chainKey: string;
    count: number;
    previousCount: number
}

class KeyChain {
    private _count: number = 0;

    public constructor(public readonly publicKey: Uint8Array, public readonly remoteKey: Uint8Array, private chainKey: Uint8Array, public readonly previousCount: number = 0) { }

    public getKey(): Uint8Array {
        if (++this._count >= EncryptedDataConstructor.maxCount)
            throw new Error("SendingChain count too big");
        const hash = crypto.hkdf(this.chainKey, new Uint8Array(KeySession.keyLength).fill(0), KeySession.info, KeySession.keyLength * 2);
        this.chainKey = hash.subarray(0, KeySession.keyLength);
        return hash.subarray(KeySession.keyLength);
    }

    public toString(): string {
        return "[object KeyChain]";
    }

    public get count(): number {
        return this._count;
    }

    public toJSON(): ExportedKeyChain {
        return {
            publicKey: decodeBase64(this.publicKey),
            remoteKey: decodeBase64(this.remoteKey),
            chainKey: decodeBase64(this.chainKey),
            count: this.count,
            previousCount: this.previousCount
        }
    }

    public static from(obj: ExportedKeyChain): KeyChain {
        const chain = new KeyChain(encodeBase64(obj.publicKey), encodeBase64(obj.remoteKey), encodeBase64(obj.chainKey), obj.previousCount);
        chain._count = obj.count;
        return chain;
    }
}

export class EncryptedDataConstructor implements EncryptedData {
    public static readonly secretKeyLength = crypto.ECDH.secretKeyLength;
    public static readonly publicKeyLength = crypto.ECDH.publicKeyLength;
    public static readonly keyLength = crypto.box.keyLength;
    public static readonly nonceLength = crypto.box.nonceLength;
    public static readonly maxCount = 65536 //32768;
    public static readonly countLength = 2;

    private raw: Uint8Array;

    constructor(count: number | Uint8Array, previous: number | Uint8Array, publicKey: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array, version?: number | Uint8Array)
    constructor(encrypted: Uint8Array | EncryptedData)
    constructor(...arrays: Uint8Array[]) {
        arrays = arrays.filter(value => value !== undefined);
        if (arrays[0] instanceof EncryptedDataConstructor) {
            this.raw = arrays[0].raw;
            return this;
        }
        if (typeof arrays[0] === 'number')
            arrays[0] = numberToArray(arrays[0], EncryptedDataConstructor.countLength);
        if (typeof arrays[1] === 'number')
            arrays[1] = numberToArray(arrays[1], EncryptedDataConstructor.countLength);
        if (arrays.length === 6) {
            arrays.unshift(typeof arrays[5] === 'number' ? numberToArray(arrays[5], 1) : arrays[5]);
            arrays.pop();
        } else if (arrays.length > 1) {
            arrays.unshift(numberToArray(KeySession.version, 1));
        }
        this.raw = concatArrays(...arrays);
    }

    public get length() { return this.raw.length; }

    public get version() { return numberFromArray(new Uint8Array(this.raw.buffer, ...Offsets.version.get)); }

    public get count() { return numberFromArray(new Uint8Array(this.raw.buffer, ...Offsets.count.get)); }

    public get previous() { return numberFromArray(new Uint8Array(this.raw.buffer, ...Offsets.previous.get)); }

    public get publicKey() { return new Uint8Array(this.raw.buffer, ...Offsets.publicKey.get); }

    public get nonce() { return new Uint8Array(this.raw.buffer, ...Offsets.nonce.get); }

    public get ciphertext() { return new Uint8Array(this.raw.buffer, Offsets.ciphertext.start); }

    public toBytes(): Uint8Array {
        return this.raw;
    }

    public toString(): string {
        return decodeBase64(this.raw);
    }

    public toJSON() {
        return {
            version: this.version,
            count: this.count,
            previous: this.previous,
            publicKey: decodeBase64(this.publicKey),
            nonce: decodeBase64(this.nonce),
            ciphertext: decodeBase64(this.ciphertext)
        };
    }
}

class Offsets {

    private static set(start: number, length?: number) {
        class Offset {
            readonly start: number;
            readonly end?: number;
            readonly length?: number;

            constructor(start: number, length?: number) {
                this.start = start;
                this.length = length;

                if (typeof length === 'number')
                    this.end = start + length;
            }

            get get() {
                return [this.start, this.length];
            }
        }
        return new Offset(start, length);
    }

    static readonly checksum = Offsets.set(0, 0);
    static readonly version = Offsets.set(Offsets.checksum.end!, 1);
    static readonly count = Offsets.set(Offsets.version.end!, EncryptedDataConstructor.countLength);
    static readonly previous = Offsets.set(Offsets.count.end!, EncryptedDataConstructor.countLength);
    static readonly publicKey = Offsets.set(Offsets.previous.end!, EncryptedDataConstructor.publicKeyLength);
    static readonly nonce = Offsets.set(Offsets.publicKey.end!, EncryptedDataConstructor.nonceLength);
    static readonly ciphertext = Offsets.set(Offsets.nonce.end!, undefined);

}

class KeyMap<K, T> extends Map<K, T> {

    get(key: K): T | undefined {
        const out = super.get(key);
        if (out && !super.delete(key))
            throw new Error();
        return out;
    }

}