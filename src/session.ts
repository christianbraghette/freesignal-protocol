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

import { compareBytes, decodeBase64, encodeBase64 } from "@freesignal/crypto/utils";
import { Crypto, Bytes, InitialSessionState, KeyChainState, KeyStore, Session, SessionManager, Ciphertext, UserId } from "@freesignal/interfaces";
import { useConstructors } from "./constructors.js";

interface EncryptionKeys {
    readonly count: number;
    readonly previous: number;
    readonly publicKey: Uint8Array;
}

interface PrivateEncryptionKeys extends EncryptionKeys {
    readonly secretKey: Uint8Array;
}

export class SessionManagerConstructor implements SessionManager {
    private readonly users = new Map<string, string>();

    constructor(private readonly keyStore: KeyStore, private readonly crypto: Crypto) { }

    public async createSession(initialState: InitialSessionState | Session): Promise<Session> {
        const session = new SessionConstructor(initialState, this.keyStore, this.crypto);
        this.users.set(session.userId, session.sessionTag);
        await session.save();
        return session;
    }

    public async getSession(sessionTag: string): Promise<Session | null> {
        const state = await this.keyStore.loadSession(sessionTag);
        if (!state)
            return null;
        return state ? new SessionConstructor(state, this.keyStore, this.crypto) : null;
    }

    private async getSessionTag(userId: UserId | string) {
        const sessionTag = this.users.get(userId.toString());
        if (!sessionTag)
            throw new Error("User not found: " + userId);
        return sessionTag;
    }

    public async encrypt(userId: UserId | string, plaintext: Bytes): Promise<Ciphertext> {
        const sessionTag = await this.getSessionTag(userId);
        const session = await this.getSession(sessionTag);
        if (!session)
            throw new Error("Session not found for sessionTag: " + sessionTag);
        const ciphertext = session.encrypt(plaintext);
        await session.save();
        return ciphertext;
    }

    public async decrypt(userId: UserId, ciphertext: Ciphertext | Bytes): Promise<Bytes> {
        const { CiphertextConstructor } = useConstructors(this.crypto);

        const sessionTag = await this.getSessionTag(userId);
        const session = await this.getSession(sessionTag);
        if (!session)
            throw new Error("Session not found for sessionTag: " + sessionTag);
        ciphertext = CiphertextConstructor.from(ciphertext);
        const cleartext = session.decrypt(ciphertext);
        await session.save();
        return cleartext;
    }
}

export class SessionConstructor implements Session {
    public static readonly keyLength = 32;
    public static readonly version = 1;
    public static readonly info = "/freesignal/double-ratchet/v0." + SessionConstructor.version;
    public static readonly maxCount = 65536;

    public readonly userId: string;
    public readonly sessionTag: string;

    #keyPair: Crypto.KeyPair;
    #rootKey: Uint8Array;
    #headerKey?: Uint8Array;
    #nextHeaderKey?: Uint8Array;
    readonly #previousKeys = new KeyMap<string, Uint8Array>();

    private sendingChain?: KeyChain;
    private receivingChain?: KeyChain;
    private readonly headerKeys: Map<string, Uint8Array>;

    constructor(init: InitialSessionState | Session, private readonly keyStore: KeyStore, private readonly crypto: Crypto) {
        if (!(init instanceof SessionConstructor)) {
            const { remoteKey, userId, sessionTag, secretKey, rootKey, sendingChain, receivingChain, headerKey, nextHeaderKey, headerKeys, previousKeys } = init as InitialSessionState;
            this.userId = userId;
            this.sessionTag = sessionTag ?? decodeBase64(this.crypto.hkdf(encodeBase64(rootKey), new Uint8Array(32).fill(0), "/freesignal/session-authtag", 32));
            this.#keyPair = this.crypto.ECDH.keyPair(secretKey ? encodeBase64(secretKey) : undefined);
            this.#rootKey = encodeBase64(rootKey);
            this.sendingChain = sendingChain ? new KeyChain(sendingChain, this.crypto) : undefined;
            this.receivingChain = receivingChain ? new KeyChain(receivingChain, this.crypto) : undefined;
            this.headerKeys = new Map<string, Uint8Array>(headerKeys?.map(([key, value]) => [key, encodeBase64(value)]));
            this.#previousKeys = new Map<string, Uint8Array>(previousKeys?.map(([key, value]) => [key, encodeBase64(value)]));

            if (headerKey)
                this.#headerKey = encodeBase64(headerKey);

            if (nextHeaderKey) {
                this.#nextHeaderKey = encodeBase64(nextHeaderKey);
                this.headerKeys.set(decodeBase64(this.crypto.hash(encodeBase64(nextHeaderKey))), encodeBase64(nextHeaderKey));
            }

            if (remoteKey) {
                this.sendingChain = this.getChain(remoteKey, this.#headerKey);
                this.#headerKey = undefined;
            }
        } else {
            this.userId = init.userId;
            this.#keyPair = init.#keyPair;
            this.#rootKey = init.#rootKey;
            this.#headerKey = init.#headerKey;
            this.#nextHeaderKey = init.#nextHeaderKey;
            this.#previousKeys = init.#previousKeys
            this.sendingChain = init.sendingChain;
            this.receivingChain = init.receivingChain;
            this.sessionTag = init.sessionTag;
            this.headerKeys = init.headerKeys;
        }
    }

    //public get publicKey(): Uint8Array { return this.#keyPair.publicKey; }

    private getChain(remoteKey: Uint8Array, headerKey?: Uint8Array, previousCount?: number): KeyChain {
        const sharedKey = this.crypto.ECDH.scalarMult(this.#keyPair.secretKey, remoteKey);
        if (!this.#rootKey)
            this.#rootKey = this.crypto.hash(sharedKey);
        const hashkey = this.crypto.hkdf(sharedKey, this.#rootKey, SessionConstructor.info, SessionConstructor.keyLength * 3);
        this.#rootKey = hashkey.subarray(0, SessionConstructor.keyLength);
        return new KeyChain({
            publicKey: decodeBase64(this.#keyPair.publicKey),
            remoteKey: decodeBase64(remoteKey),
            chainKey: decodeBase64(hashkey.subarray(SessionConstructor.keyLength, SessionConstructor.keyLength * 2)),
            nextHeaderKey: decodeBase64(hashkey.subarray(SessionConstructor.keyLength * 2)),
            headerKey: headerKey ? decodeBase64(headerKey) : headerKey,
            count: 0,
            previousCount: previousCount ?? 0
        }, this.crypto);
    }

    private getHeaderKey(hash?: string): Uint8Array | undefined {
        if (!hash)
            return this.#headerKey ?? this.sendingChain?.headerKey;
        return this.headerKeys.get(hash);
    }

    private getSendingKey(): PrivateEncryptionKeys | undefined {
        if (!this.sendingChain)
            return;
        const secretKey = this.sendingChain.getKey();
        return {
            count: this.sendingChain.count,
            previous: this.sendingChain.previousCount,
            publicKey: this.sendingChain.publicKey,
            secretKey
        }
    }

    private getReceivingKey(encryptionKeys: EncryptionKeys): Uint8Array | undefined {
        if (!this.#previousKeys.has(decodeBase64(encryptionKeys.publicKey) + encryptionKeys.count.toString())) {
            if (!compareBytes(encryptionKeys.publicKey, this.receivingChain?.remoteKey ?? new Uint8Array())) {
                while (this.receivingChain && this.receivingChain.count < encryptionKeys.previous) {
                    const key = this.receivingChain.getKey();
                    this.#previousKeys.set(decodeBase64(this.receivingChain.remoteKey) + this.receivingChain.count.toString(), key);
                }

                this.receivingChain = this.getChain(encryptionKeys.publicKey, this.#nextHeaderKey ?? this.receivingChain?.nextHeaderKey, this.receivingChain?.count);
                this.headerKeys.set(decodeBase64(this.crypto.hash(this.receivingChain.nextHeaderKey)), this.receivingChain.nextHeaderKey);
                if (this.#nextHeaderKey)
                    this.#nextHeaderKey = undefined;
                this.#keyPair = this.crypto.ECDH.keyPair();
                this.sendingChain = this.getChain(encryptionKeys.publicKey, this.#headerKey ?? this.sendingChain?.nextHeaderKey, this.sendingChain?.count);
                if (this.#headerKey)
                    this.#headerKey = undefined;
            }
            if (!this.receivingChain)
                throw new Error("Error initializing receivingChain");

            while (this.receivingChain.count < encryptionKeys.count) {
                const key = this.receivingChain.getKey();
                this.#previousKeys.set(decodeBase64(this.receivingChain.remoteKey) + this.receivingChain.count.toString(), key);
            }
        }
        return this.#previousKeys.get(decodeBase64(encryptionKeys.publicKey) + encryptionKeys.count.toString());
    }

    public encrypt(data: Bytes): Ciphertext {
        const { CiphertextHeaderConstructor, CiphertextConstructor } = useConstructors(this.crypto);

        const key = this.getSendingKey();
        if (!key)
            throw new Error("Error generating key");
        const nonce = this.crypto.randomBytes(CiphertextHeaderConstructor.nonceLength);
        const payload = this.crypto.Box.encrypt(data, nonce, key.secretKey);
        let header = new CiphertextHeaderConstructor(key.count, key.previous, key.publicKey, nonce).bytes;
        const headerKey = this.getHeaderKey();
        if (!headerKey)
            return new CiphertextConstructor({ header, payload });
        const headerNonce = this.crypto.randomBytes(CiphertextHeaderConstructor.nonceLength)
        if (headerKey)
            header = this.crypto.Box.encrypt(header, headerNonce, headerKey);
        return new CiphertextConstructor({ hashkey: this.crypto.hash(headerKey ?? new Uint8Array(32).fill(0)), header, nonce: headerNonce, payload });
    }

    public decrypt(ciphertext: Ciphertext | Bytes): Bytes {
        const { CiphertextHeaderConstructor, CiphertextConstructor } = useConstructors(this.crypto);

        const encrypted = CiphertextConstructor.from(ciphertext);
        let headerData: Uint8Array = encrypted.header;
        if (encrypted.hashkey && encrypted.nonce) {
            const headerKey = this.getHeaderKey(decodeBase64(encrypted.hashkey));
            if (!headerKey)
                throw new Error("Error calculating headerKey");
            const data = this.crypto.Box.decrypt(encrypted.header, encrypted.nonce, headerKey);
            if (!data)
                throw new Error("Error decrypting header");
            headerData = data;
        }
        const header = CiphertextHeaderConstructor.from(headerData);
        const key = this.getReceivingKey(header);
        if (!key)
            throw new Error("Error calculating key");
        const decrypted = this.crypto.Box.decrypt(encrypted.payload, header.nonce, key);
        if (!decrypted)
            throw new Error("Error decrypting data");
        return decrypted;
    }

    public hasSkippedKeys(): boolean {
        return this.#previousKeys.size > 0;
    }

    public save(): Promise<void> {
        return this.keyStore.storeSession(this.sessionTag, {
            userId: this.userId,
            sessionTag: this.sessionTag,
            secretKey: decodeBase64(this.#keyPair.secretKey),
            rootKey: decodeBase64(this.#rootKey),
            sendingChain: this.sendingChain?.toJSON(),
            receivingChain: this.receivingChain?.toJSON(),
            headerKey: this.#headerKey ? decodeBase64(this.#headerKey) : undefined,
            nextHeaderKey: this.#nextHeaderKey ? decodeBase64(this.#nextHeaderKey) : undefined,
            headerKeys: Array.from(this.headerKeys.entries()).map(([key, value]) => [key, decodeBase64(value)]),
            previousKeys: Array.from(this.#previousKeys.entries()).map(([key, value]) => [key, decodeBase64(value)]),
        });
    }
}

class KeyChain {
    #chainKey: Uint8Array;

    public readonly publicKey: Uint8Array;
    public readonly remoteKey: Uint8Array;
    public readonly nextHeaderKey: Uint8Array;
    public readonly headerKey?: Uint8Array;
    public readonly previousCount: number;

    private _count: number = 0;

    public constructor({ publicKey, remoteKey, nextHeaderKey, chainKey, headerKey, count, previousCount }: KeyChainState, private readonly crypto: Crypto) {
        this.#chainKey = encodeBase64(chainKey);
        this.publicKey = encodeBase64(publicKey);
        this.remoteKey = encodeBase64(remoteKey);
        this.nextHeaderKey = encodeBase64(nextHeaderKey);
        this.headerKey = headerKey ? encodeBase64(headerKey) : undefined;
        this._count = count;
        this.previousCount = previousCount ?? 0;
    }

    public getKey(): Uint8Array {
        if (++this._count >= SessionConstructor.maxCount)
            throw new Error("SendingChain count too big");
        const hash = this.crypto.hkdf(this.#chainKey, new Uint8Array(SessionConstructor.keyLength).fill(0), SessionConstructor.info, SessionConstructor.keyLength * 2);
        this.#chainKey = hash.subarray(0, SessionConstructor.keyLength);
        return hash.subarray(SessionConstructor.keyLength);
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
            chainKey: decodeBase64(this.#chainKey),
            count: this.count,
            previousCount: this.previousCount
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