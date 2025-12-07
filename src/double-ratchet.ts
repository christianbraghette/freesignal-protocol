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
import { decodeBase64, encodeBase64, compareBytes } from "@freesignal/utils";

export interface ExportedKeySession {
    secretKey: string;
    rootKey?: string;
    sendingChain?: ExportedKeyChain;
    receivingChain?: ExportedKeyChain;
    previousKeys: [string, Uint8Array][];
}

export interface EncryptionKeys {
    //readonly version: number;
    readonly count: number;
    readonly previous: number;
    readonly publicKey: Uint8Array;
}

export interface PrivateEncryptionKeys extends EncryptionKeys {
    readonly secretKey: Uint8Array;
}

/**
 * Represents a secure Double Ratchet session.
 * Used for forward-secure encryption and decryption of messages.
 */
export class KeySession {
    public static readonly keyLength = 32;
    public static readonly version = 1;
    public static readonly info = "/freesignal/double-ratchet/v0." + KeySession.version;
    public static readonly maxCount = 65536;

    public readonly id: string;

    private keyPair: Crypto.KeyPair;
    private rootKey?: Uint8Array;
    private sendingChain?: KeyChain;
    private receivingChain?: KeyChain;
    private nextHeaderKey?: Uint8Array
    private previousKeys = new KeyMap<string, Uint8Array>();

    public constructor(opts: { id?: string, secretKey?: Uint8Array, remoteKey?: Uint8Array, headerKey?: Uint8Array, nextHeaderKey?: Uint8Array, rootKey?: Uint8Array, } = {}) {
        this.id = opts.id ?? crypto.UUID.generate().toString();
        this.keyPair = crypto.ECDH.keyPair(opts.secretKey);
        if (opts.rootKey)
            this.rootKey = opts.rootKey;
        if (opts.nextHeaderKey)
            this.nextHeaderKey = opts.nextHeaderKey;

        if (opts.remoteKey) {
            this.sendingChain = this.getChain(opts.remoteKey, opts.headerKey);
        }
    }

    private getChain(remoteKey: Uint8Array, headerKey?: Uint8Array, previousCount?: number): KeyChain {
        const sharedKey = crypto.ECDH.scalarMult(this.keyPair.secretKey, remoteKey);
        if (!this.rootKey)
            this.rootKey = crypto.hash(sharedKey);
        const hashkey = crypto.hkdf(sharedKey, this.rootKey, KeySession.info, KeySession.keyLength * 3);
        this.rootKey = hashkey.subarray(0, KeySession.keyLength);
        return new KeyChain(this.publicKey, remoteKey, hashkey.subarray(KeySession.keyLength, KeySession.keyLength * 2), hashkey.subarray(KeySession.keyLength * 2), headerKey, previousCount);
    }

    public getHeaderKeys(): {
        readonly sending?: Uint8Array,
        readonly receiving?: Uint8Array
    } {
        return {
            sending: this.sendingChain?.headerKey,
            receiving: this.nextHeaderKey ?? this.receivingChain?.headerKey
        }
    }

    public getSendingKey(): PrivateEncryptionKeys | undefined {
        if (!this.sendingChain)
            return;
        const secretKey = this.sendingChain.getKey();
        return {
            //version: KeySession.version,
            count: this.sendingChain.count,
            previous: this.sendingChain.previousCount,
            publicKey: this.sendingChain.publicKey,
            secretKey
        }
    }

    public getReceivingKey(encryptionKeys: EncryptionKeys): Uint8Array | undefined {
        if (!this.previousKeys.has(decodeBase64(encryptionKeys.publicKey) + encryptionKeys.count.toString())) {
            if (!compareBytes(encryptionKeys.publicKey, this.receivingChain?.remoteKey ?? new Uint8Array())) {
                while (this.receivingChain && this.receivingChain.count < encryptionKeys.previous) {
                    const key = this.receivingChain.getKey();
                    this.previousKeys.set(decodeBase64(this.receivingChain.remoteKey) + this.receivingChain.count.toString(), key);
                }

                this.receivingChain = this.getChain(encryptionKeys.publicKey, this.nextHeaderKey ?? this.receivingChain?.nextHeaderKey);
                this.nextHeaderKey = undefined;
                this.keyPair = crypto.ECDH.keyPair();
                this.sendingChain = this.getChain(encryptionKeys.publicKey, this.sendingChain?.nextHeaderKey, this.sendingChain?.count);
            }
            if (!this.receivingChain)
                throw new Error("Error initializing receivingChain");

            while (this.receivingChain.count < encryptionKeys.count) {
                const key = this.receivingChain.getKey();
                this.previousKeys.set(decodeBase64(this.receivingChain.remoteKey) + this.receivingChain.count.toString(), key);
            }
        }

        return this.previousKeys.get(decodeBase64(encryptionKeys.publicKey) + encryptionKeys.count.toString());
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
    public static from(data: ExportedKeySession): KeySession {
        const session = new KeySession({ secretKey: encodeBase64(data.secretKey), rootKey: data.rootKey ? encodeBase64(data.rootKey) : undefined });
        session.sendingChain = data.sendingChain ? KeyChain.from(data.sendingChain) : undefined;
        session.receivingChain = data.receivingChain ? KeyChain.from(data.receivingChain) : undefined;
        session.previousKeys = new KeyMap(data.previousKeys);
        return session;
    }
}

interface ExportedKeyChain {
    publicKey: string;
    remoteKey: string;
    chainKey: string;
    nextHeaderKey: string;
    headerKey?: string;
    count: number;
    previousCount: number
}

class KeyChain {
    private _count: number = 0;

    public constructor(public readonly publicKey: Uint8Array, public readonly remoteKey: Uint8Array, private chainKey: Uint8Array, public readonly nextHeaderKey: Uint8Array, public readonly headerKey?: Uint8Array, public readonly previousCount: number = 0) { }

    public getKey(): Uint8Array {
        if (++this._count >= KeySession.maxCount)
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
            nextHeaderKey: decodeBase64(this.nextHeaderKey),
            headerKey: this.headerKey ? decodeBase64(this.headerKey) : undefined,
            count: this.count,
            previousCount: this.previousCount
        }
    }

    public static from(obj: ExportedKeyChain): KeyChain {
        const chain = new KeyChain(encodeBase64(obj.publicKey), encodeBase64(obj.remoteKey), encodeBase64(obj.chainKey), encodeBase64(obj.nextHeaderKey), obj.headerKey ? encodeBase64(obj.headerKey) : undefined, obj.previousCount);
        chain._count = obj.count;
        return chain;
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