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

/** */
export interface Encodable {
    encode(): Uint8Array;
    toString(): string;
    toJSON(): string;
}
export namespace Encodable {
    const properties = ['encode', 'toString', 'toJSON'];

    export function isEncodable(obj: any): boolean {
        return !properties.some(prop => !obj[prop]);
    }
}

type LocalStorageIterator<T> = Iterable<T>;

export interface LocalStorage<K, T> {
    set(key: K, value: T): Promise<this>;
    get(key: K): Promise<T | undefined>;
    has(key: K): Promise<boolean>;
    delete(key: K): Promise<boolean>;
    entries(): Promise<LocalStorageIterator<[K, T]>>;
}

export interface KeyExchangeData {
    readonly version: number;
    readonly publicKey: string;
    readonly identityKey: string;
    readonly signedPreKey: string;
    readonly signature: string;
    readonly onetimePreKey: string;
}

export interface KeyExchangeSynMessage {
    readonly version: number;
    readonly publicKey: string;
    readonly identityKey: string;
    readonly ephemeralKey: string;
    readonly signedPreKeyHash: string;
    readonly onetimePreKeyHash: string;
    readonly associatedData: string;
}

export interface KeyExchangeDataBundle {
    readonly version: number;
    readonly publicKey: string;
    readonly identityKey: string;
    readonly signedPreKey: string;
    readonly signature: string;
    readonly onetimePreKey: string[];
}

interface UUIDv4 {
    toString(): string
    toJSON(): string
    toBuffer(): Uint8Array
}

export interface Crypto {
    hash(message: Uint8Array, algorithm?: Crypto.HashAlgorithms): Uint8Array;
    hmac(key: Uint8Array, message: Uint8Array, length?: number, algorithm?: Crypto.HmacAlgorithms): Uint8Array
    hkdf(key: Uint8Array, salt: Uint8Array, info?: Uint8Array | string, length?: number): Uint8Array;

    readonly KeyPair: typeof Crypto.KeyPair;
    readonly box: Crypto.box;
    readonly ECDH: Crypto.ECDH;
    readonly EdDSA: Crypto.EdDSA;
    readonly UUID: Crypto.UUID;

    randomBytes(n: number): Uint8Array;
    scalarMult(n: Uint8Array, p: Uint8Array): Uint8Array;
}
export namespace Crypto {
    export type HashAlgorithms = 'sha224' | 'sha256' | 'sha384' | 'sha512';
    export type HmacAlgorithms = 'kmac128' | 'kmac256';

    export type KeyPair = {
        readonly publicKey: Uint8Array;
        readonly secretKey: Uint8Array;
    }
    export declare namespace KeyPair {
        export function isKeyPair(obj: any): boolean;
    }

    export interface box {
        readonly keyLength: number;
        readonly nonceLength: number;

        encrypt(msg: Uint8Array, nonce: Uint8Array, key: Uint8Array): Uint8Array;
        decrypt(msg: Uint8Array, nonce: Uint8Array, key: Uint8Array): Uint8Array | undefined;
    }

    export interface ECDH {
        readonly publicKeyLength: number;
        readonly secretKeyLength: number;

        keyPair(secretKey?: Uint8Array): KeyPair;
        sharedKey(publicKey: Uint8Array, secretKey: Uint8Array): Uint8Array;
    }

    export interface EdDSA {
        readonly publicKeyLength: number;
        readonly secretKeyLength: number;
        readonly signatureLength: number;
        readonly seedLength: number;

        keyPair(secretKey?: Uint8Array): KeyPair;
        keyPairFromSeed(seed: Uint8Array): KeyPair;
        sign(msg: Uint8Array, secretKey: Uint8Array): Uint8Array;
        verify(msg: Uint8Array, sig: Uint8Array, publicKey: Uint8Array): boolean;
    }

    export interface UUID {
        generate(): UUIDv4;
        stringify(arr: Uint8Array, offset?: number): string;
        parse(uuid: string): Uint8Array;
    }
}