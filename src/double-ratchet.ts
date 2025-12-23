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
import { IdentityKey, UserId } from "./types.js";

export interface KeySessionState {
    identityKey: string;
    sessionTag: string;
    secretKey: string;
    rootKey: string;
    sendingChain?: KeyChainState;
    receivingChain?: KeyChainState;
    headerKeys: [string, string][];
    headerKey?: string;
    nextHeaderKey?: string;
    previousKeys: [string, string][];
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

    public readonly identityKey: IdentityKey;
    public  _sessionTag: string;

    private keyPair: Crypto.KeyPair;
    private rootKey: Uint8Array;
    private sendingChain?: KeyChain;
    private receivingChain?: KeyChain;
    private _headerKeys = new Map<string, Uint8Array>();
    private headerKey?: Uint8Array;
    private nextHeaderKey?: Uint8Array;
    private previousKeys = new KeyMap<string, Uint8Array>();

    public constructor({ identityKey, secretKey, remoteKey, rootKey, headerKey, nextHeaderKey }: { identityKey: IdentityKey, secretKey?: Uint8Array, remoteKey?: Uint8Array, rootKey: Uint8Array, headerKey?: Uint8Array, nextHeaderKey?: Uint8Array }) {
        this.identityKey = identityKey;
        this.rootKey = rootKey;
        this._sessionTag = decodeBase64(crypto.hkdf(rootKey, new Uint8Array(32).fill(0), "/freesignal/session-authtag", 32));
        this.keyPair = crypto.ECDH.keyPair(secretKey);


        if (headerKey)
            this.headerKey = headerKey;

        if (nextHeaderKey) {
            this.nextHeaderKey = nextHeaderKey;
            this._headerKeys.set(decodeBase64(crypto.hash(nextHeaderKey)), nextHeaderKey);
        }

        if (remoteKey) {
            this.sendingChain = this.getChain(remoteKey, this.headerKey);
            this.headerKey = undefined;
        }
    }

    public get userId(): UserId {
        return this.identityKey.userId;
    }

    public get sessionTag() {
        return this._sessionTag;
    }

    public get headerKeys() {
        return this._headerKeys;
    }

    private getChain(remoteKey: Uint8Array, headerKey?: Uint8Array, previousCount?: number): KeyChain {
        const sharedKey = crypto.ECDH.scalarMult(this.keyPair.secretKey, remoteKey);
        if (!this.rootKey)
            this.rootKey = crypto.hash(sharedKey);
        const hashkey = crypto.hkdf(sharedKey, this.rootKey, KeySession.info, KeySession.keyLength * 3);
        this.rootKey = hashkey.subarray(0, KeySession.keyLength);
        return new KeyChain(this.publicKey, remoteKey, hashkey.subarray(KeySession.keyLength, KeySession.keyLength * 2), hashkey.subarray(KeySession.keyLength * 2), headerKey, previousCount);
    }

    public getHeaderKey(hash?: string): Uint8Array | undefined {
        if (!hash)
            return this.headerKey ?? this.sendingChain?.headerKey;
        return this.headerKeys.get(hash);
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

                this.receivingChain = this.getChain(encryptionKeys.publicKey, this.nextHeaderKey ?? this.receivingChain?.nextHeaderKey, this.receivingChain?.count);
                this.headerKeys.set(decodeBase64(crypto.hash(this.receivingChain.nextHeaderKey)), this.receivingChain.nextHeaderKey);
                if (this.nextHeaderKey)
                    this.nextHeaderKey = undefined;
                this.keyPair = crypto.ECDH.keyPair();
                this.sendingChain = this.getChain(encryptionKeys.publicKey, this.headerKey ?? this.sendingChain?.nextHeaderKey, this.sendingChain?.count);
                if (this.headerKey)
                    this.headerKey = undefined;
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
    public toJSON(): KeySessionState {
        return {
            identityKey: this.identityKey.toString(),
            sessionTag: this.sessionTag,
            secretKey: decodeBase64(this.keyPair.secretKey),
            rootKey: decodeBase64(this.rootKey),
            sendingChain: this.sendingChain?.toJSON(),
            receivingChain: this.receivingChain?.toJSON(),
            headerKey: this.headerKey ? decodeBase64(this.headerKey) : undefined,
            nextHeaderKey: this.nextHeaderKey ? decodeBase64(this.nextHeaderKey) : undefined,
            headerKeys: Array.from(this.headerKeys.entries()).map(([key, value]) => [key, decodeBase64(value)]),
            previousKeys: Array.from(this.previousKeys.entries()).map(([key, value]) => [key, decodeBase64(value)]),
        };
    }

    /**
     * Import a state.
     * 
     * @param json string returned by `export()` method.
     * @returns session with the state parsed.
     */
    public static from(data: KeySessionState): KeySession {
        const session = new KeySession({
            identityKey: IdentityKey.from(data.identityKey),
            secretKey: encodeBase64(data.secretKey),
            rootKey: encodeBase64(data.rootKey),
            headerKey: data.headerKey ? encodeBase64(data.headerKey) : undefined,
            nextHeaderKey: data.nextHeaderKey ? encodeBase64(data.nextHeaderKey) : undefined,
        });
        session.sendingChain = data.sendingChain ? KeyChain.from(data.sendingChain) : undefined;
        session.receivingChain = data.receivingChain ? KeyChain.from(data.receivingChain) : undefined;
        session.previousKeys = new KeyMap(data.previousKeys.map(([key, value]) => [key, encodeBase64(value)]));
        session._sessionTag = data.sessionTag;
        session._headerKeys = new Map(data.headerKeys.map(([key, value]) => [key, encodeBase64(value)]));
        return session;
    }
}

interface KeyChainState {
    publicKey: string;
    remoteKey: string;
    chainKey: string;
    headerKey?: string;
    nextHeaderKey: string;
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

    public toJSON(): KeyChainState {
        return {
            publicKey: decodeBase64(this.publicKey),
            remoteKey: decodeBase64(this.remoteKey),
            headerKey: this.headerKey ? decodeBase64(this.headerKey) : undefined,
            nextHeaderKey: decodeBase64(this.nextHeaderKey),
            chainKey: decodeBase64(this.chainKey),
            count: this.count,
            previousCount: this.previousCount
        }
    }

    public static from(obj: KeyChainState): KeyChain {
        //
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