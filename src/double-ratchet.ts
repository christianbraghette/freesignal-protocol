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
import { Encodable } from "./data";
import { concatUint8Array, decodeBase64, encodeBase64, encodeUTF8, numberFromUint8Array, numberToUint8Array, verifyUint8Array } from "./utils";

/**
 * Creates a new Double Ratchet session.
 * 
 * @param opts.remoteKey The public key of the remote party.
 * @param opts.preSharedKey An optional pre-shared key to initialize the session.
 *   
 * @returns A new Double Ratchet session.
 */
export function createSession(opts?: { remoteKey?: Uint8Array, preSharedKey?: Uint8Array }): Session {
    return new Session(opts);
}

/**
 * Represents a secure Double Ratchet session.
 * Used for forward-secure encryption and decryption of messages.
 */
export class Session {
    private static readonly skipLimit = 1000;
    public static readonly version = 1;
    public static readonly rootKeyLength = crypto.box.keyLength;

    private keyPair = crypto.ECDH.keyPair();
    private _remoteKey?: Uint8Array;
    private rootKey?: Uint8Array;
    private sendingChain?: Uint8Array;
    private sendingCount = 0;
    private previousCount = 0;
    private receivingChain?: Uint8Array;
    private receivingCount = 0;
    private previousKeys: KeyMap<number, Uint8Array> = new KeyMap<number, Uint8Array>();

    public constructor(opts: { remoteKey?: Uint8Array, preSharedKey?: Uint8Array } = {}) {
        if (opts.preSharedKey)
            this.rootKey = opts.preSharedKey;
        if (opts.remoteKey) {
            this._remoteKey = opts.remoteKey;
            this.sendingChain = this.dhRatchet();
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

    /**
     * Set remote public key.
     */
    public setRemoteKey(key: Uint8Array): this {
        this._remoteKey = key;
        this.receivingChain = this.dhRatchet();
        if (this.receivingCount > (EncryptedPayloadConstructor.maxCount - Session.skipLimit * 2))
            this.receivingCount = 0;
        this.previousCount = this.sendingCount;
        this.keyPair = crypto.ECDH.keyPair();
        this.sendingChain = this.dhRatchet();
        if (this.sendingCount > (EncryptedPayloadConstructor.maxCount - Session.skipLimit * 2))
            this.sendingCount = 0;
        return this;
    }

    private dhRatchet(info?: Uint8Array): Uint8Array {
        if (!this._remoteKey) throw new Error();
        const sharedKey = crypto.scalarMult(this.keyPair.secretKey, this._remoteKey);
        if (!this.rootKey)
            this.rootKey = crypto.hash(sharedKey);
        const hashkey = crypto.hkdf(sharedKey, this.rootKey, info, Session.keyLength * 2);
        this.rootKey = hashkey.slice(0, Session.keyLength);
        return hashkey.slice(Session.keyLength);
    }

    private getSendingKey() {
        if (!this.sendingChain) throw new Error;
        const out = Session.symmetricRatchet(this.sendingChain);
        this.sendingChain = out[0];
        this.sendingCount++;
        return out[1];
    }

    private getReceivingKey() {
        if (!this.receivingChain) throw new Error();
        const out = Session.symmetricRatchet(this.receivingChain);
        this.receivingChain = out[0];
        this.receivingCount++;
        return out[1];
    }

    /**
     * Encrypts a message payload using the current sending chain.
     *
     * @param message - The message as a Uint8Array.
     * @returns An EncryptedPayload or undefined if encryption fails.
     */
    public encrypt(message: Uint8Array): EncryptedPayload | undefined {
        try {
            const key = this.getSendingKey();
            if (this.sendingCount >= EncryptedPayloadConstructor.maxCount || this.previousCount >= EncryptedPayloadConstructor.maxCount) throw new Error();
            const nonce = crypto.randomBytes(EncryptedPayloadConstructor.nonceLength);
            const ciphertext = crypto.box.encrypt(message, nonce, key);
            return new EncryptedPayloadConstructor(this.sendingCount, this.previousCount, this.keyPair.publicKey, nonce, ciphertext);
        } catch (error) {
            return undefined;
        }

    }

    /**
     * Decrypts an encrypted message.
     *
     * @param payload - The received encrypted message.
     * @returns The decrypted message as a Uint8Array, or undefined if decryption fails.
     */
    public decrypt(payload: Uint8Array | EncryptedPayload): Uint8Array | undefined {
        try {
            const encrypted = EncryptedPayload.from(payload);
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
                while (this.receivingCount < count - 1 && i < Session.skipLimit) {
                    this.previousKeys.set(this.receivingCount, this.getReceivingKey());
                }
                key = this.getReceivingKey()
            } else {
                key = this.previousKeys.get(count);
            }
            if (!key) return undefined;
            return crypto.box.decrypt(encrypted.ciphertext, encrypted.nonce, key) ?? undefined;
        } catch (error) {
            return undefined;
        }
    }

    /**
     * Export the state of the session;
     */
    public export(): string {
        return JSON.stringify({
            remoteKey: encodeBase64(this._remoteKey),
            rootKey: encodeBase64(this.rootKey),
            sendingChain: encodeBase64(this.sendingChain),
            receivingChain: encodeBase64(this.receivingChain),
            sendingCount: this.sendingCount,
            receivingCount: this.receivingCount,
            //previousCount: this.previousCount
        });
    }

    /**
     * Import a state.
     * 
     * @param json string returned by `export()` method.
     * @returns session with the state parsed.
     */
    public static import(json: string): Session {
        const data = JSON.parse(json);
        const session = new Session({ remoteKey: decodeBase64(data.remoteKey), preSharedKey: decodeBase64(data.rootKey) });
        session.sendingChain = decodeBase64(data.sendingChain);
        session.receivingChain = decodeBase64(data.receivingChain);
        session.sendingCount = data.sendingCount;
        session.receivingCount = data.receivingCount;
        return session;
    }

    /**
     * The fixed key length (in bytes) used throughout the Double Ratchet session.
     * Typically 32 bytes (256 bits) for symmetric keys.
     */
    public static readonly keyLength = 32;

    private static symmetricRatchet(chain: Uint8Array, salt?: Uint8Array, info?: Uint8Array) {
        const hash = crypto.hkdf(chain, salt ?? new Uint8Array(), info, Session.keyLength * 2);
        return [new Uint8Array(hash.buffer, 0, Session.keyLength), new Uint8Array(hash.buffer, Session.keyLength)]
    }
}

/**
 * Interface representing an encrypted payload.
 * Provides metadata and de/serialization methods.
 */
export interface EncryptedPayload extends Encodable {

    /**
     * The length of the payload.
     */
    readonly length: number;

    /**
     * Version of the payload.
     */
    readonly version: number;

    /**
     * The current message count of the sending chain.
     */
    readonly count: number;

    /**
     * The count of the previous sending chain.
     */
    readonly previous: number;

    /**
     * The sender's public key used for this message.
     */
    readonly publicKey: Uint8Array;

    /**
     * The nonce used during encryption.
     */
    readonly nonce: Uint8Array;

    /**
     * The encrypted message content.
     */
    readonly ciphertext: Uint8Array;

    /**
     * The payload signature.
     */
    //readonly signature: Uint8Array | undefined;

    /**
     * Set the signature of the payload.
     * 
     * @param signature signature
     */
    //setSignature(signature: Uint8Array): this;

    /**
     * Return the payload without the signature.
     */
    //encodeUnsigned(): Uint8Array;

    /**
     * Serializes the payload into a Uint8Array for transport.
     */
    encode(): Uint8Array;

    /**
     * Decodes the payload into a readable object format.
     */
    /*decode(): {
        count: number;
        previous: number;
        publicKey: string;
        nonce: string;
        ciphertext: string;
        //signature?: string;
    };*/

    /**
     * Returns the payload as a UTF-8 string.
     */
    toString(): string;

    /**
     * Returns the decoded object as a JSON string.
     */
    toJSON(): string;
}
export class EncryptedPayload {

    /**
     * Static factory method that constructs an `EncryptedPayload` from a raw Uint8Array.
     *
     * @param array - A previously serialized encrypted payload.
     * @returns An instance of `EncryptedPayload`.
     */
    public static from(array: Uint8Array | EncryptedPayload) {
        return new EncryptedPayloadConstructor(array) as EncryptedPayload;
    }
}

class EncryptedPayloadConstructor implements EncryptedPayload {
    //public static readonly signatureLength = crypto.EdDSA.signatureLength;
    public static readonly secretKeyLength = crypto.ECDH.secretKeyLength;
    public static readonly publicKeyLength = crypto.ECDH.publicKeyLength;
    public static readonly keyLength = crypto.box.keyLength;
    public static readonly nonceLength = crypto.box.nonceLength;
    //public static readonly minPadLength = 6;
    //public static readonly maxPadLength = 14;
    public static readonly maxCount = 65536 //32768;
    public static readonly countLength = 2;

    private raw: Uint8Array;

    constructor(count: number | Uint8Array, previous: number | Uint8Array, publicKey: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array, version?: number | Uint8Array)
    constructor(encrypted: Uint8Array | EncryptedPayload)
    constructor(...arrays: Uint8Array[]) {
        arrays = arrays.filter(value => value !== undefined);
        if (arrays[0] instanceof EncryptedPayloadConstructor) {
            this.raw = arrays[0].raw;
            return this;
        }
        if (typeof arrays[0] === 'number')
            arrays[0] = numberToUint8Array(arrays[0], EncryptedPayloadConstructor.countLength);
        if (typeof arrays[1] === 'number')
            arrays[1] = numberToUint8Array(arrays[1], EncryptedPayloadConstructor.countLength);
        if (arrays.length > 1) {
            arrays.unshift((typeof arrays[5] === 'number' ? numberToUint8Array(arrays[5]) : arrays[5]) ?? numberToUint8Array(Session.version));
        }
        this.raw = concatUint8Array(...arrays);
    }

    public get length() { return this.raw.length; }

    public get version() { return numberFromUint8Array(new Uint8Array(this.raw.buffer, ...Offsets.version.get)); }

    public get count() { return numberFromUint8Array(new Uint8Array(this.raw.buffer, ...Offsets.count.get)); }

    public get previous() { return numberFromUint8Array(new Uint8Array(this.raw.buffer, ...Offsets.previous.get)); }

    public get publicKey() { return new Uint8Array(this.raw.buffer, ...Offsets.publicKey.get); }

    public get nonce() { return new Uint8Array(this.raw.buffer, ...Offsets.nonce.get); }

    public get ciphertext() { return new Uint8Array(this.raw.buffer, Offsets.ciphertext.start); }

    /*public get signature() { return this.signed ? new Uint8Array(this.raw.buffer, this.raw.length - EncryptedPayloadConstructor.signatureLength) : undefined }

    public setSignature(signature: Uint8Array): this {
        this.raw = concatUint8Array(this.raw, signature);
        this.signed = true;
        return this;
    }

    public encodeUnsigned(): Uint8Array {
        return !this.signed ? this.raw : new Uint8Array(this.raw.buffer, 0, this.raw.length - EncryptedPayloadConstructor.signatureLength);
    }

    public encode(fixedLength?: number): Uint8Array {
        if (fixedLength) {
            var padStart = Math.floor(Math.random() * fixedLength - 2 - this.raw.length);
            var padEnd = Math.floor(padStart + 2 + this.raw.length);
        } else {
            padStart = Math.floor(Math.random() * (EncryptedPayloadConstructor.maxPadLength - EncryptedPayloadConstructor.minPadLength) + 1) + EncryptedPayloadConstructor.minPadLength;
            padEnd = Math.floor(Math.random() * (EncryptedPayloadConstructor.maxPadLength - EncryptedPayloadConstructor.minPadLength) + 1) + EncryptedPayloadConstructor.minPadLength;
        }
        return concatUint8Array(
            randomBytes(padStart - 1).map((value) => value !== 255 ? value : (value - 1)),
            new Uint8Array(1).fill(255), this.raw, new Uint8Array(1).fill(255),
            randomBytes(padEnd).map((value) => value !== 255 ? value : (value - 1)),
        );
    }*/

    public encode(): Uint8Array {
        return this.raw;
    }

    public decode() {
        return {
            version: this.version,
            count: this.count,
            previous: this.previous,
            publicKey: encodeBase64(this.publicKey),
            nonce: encodeBase64(this.nonce),
            ciphertext: encodeUTF8(this.ciphertext),
            //signature: encodeBase64(this.signature)
        }
    }

    public toString(): string {
        return encodeUTF8(this.raw);
    }

    public toJSON(): string {
        return JSON.stringify(this.decode());
    }

    /*public static unpad(array: Uint8Array, opts: { start: boolean, end: boolean } = { start: true, end: true }) {
        let c: number;
        if (opts.start) {
            for (c = 0; c < array.length && array[c] !== 255; c++);
            array = new Uint8Array(array.buffer, c);
        }
        if (opts.end) {
            for (c = array.length; c > 0 && array[c] !== 255; c--);
            array = new Uint8Array(array.buffer, 0, c);
        }
        return array;
    }*/
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
    static readonly count = Offsets.set(Offsets.version.end!, EncryptedPayloadConstructor.countLength);
    static readonly previous = Offsets.set(Offsets.count.end!, EncryptedPayloadConstructor.countLength);
    static readonly publicKey = Offsets.set(Offsets.previous.end!, EncryptedPayloadConstructor.publicKeyLength);
    static readonly nonce = Offsets.set(Offsets.publicKey.end!, EncryptedPayloadConstructor.nonceLength);
    static readonly ciphertext = Offsets.set(Offsets.nonce.end!, undefined);

}

interface KeyMap<K, T> {
    get(key: K): T | undefined;
    has(key: K): boolean;
    set(key: K, value: T): this;
    delete(key: K): boolean;
}
class KeyMap<K, T> {
    constructor(iterable?: Iterable<readonly [K, T]>) {
        return new KeyMapConstructor(iterable);
    }
}

class KeyMapConstructor<K, T> extends Map<K, T> implements KeyMap<K, T> {
    constructor(iterable?: Iterable<readonly [K, T]>) {
        super(iterable);
    }

    get(key: K): T | undefined {
        const out = super.get(key);
        if (out && !super.delete(key))
            throw new Error();
        return out;
    }
}