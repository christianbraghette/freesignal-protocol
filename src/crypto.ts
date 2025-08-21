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

import {
    sha3_512,
    sha3_384,
    sha3_256,
    sha3_224,
    kmac128,
    kmac256
} from 'js-sha3';
import nacl from 'tweetnacl';
import { stringify, parse, v4 as uuidv4 } from 'uuid';
import { decodeUTF8 } from './utils';
import { Crypto } from './types';

class CryptoConstructor implements Crypto {
    hash(message: Uint8Array, algorithm: Crypto.HashAlgorithms = 'sha256'): Uint8Array {
        switch (algorithm) {
            case 'sha224':
                return new Uint8Array(sha3_224.digest(message));
            case 'sha256':
                return new Uint8Array(sha3_256.digest(message));
            case 'sha384':
                return new Uint8Array(sha3_384.digest(message));
            case 'sha512':
                return new Uint8Array(sha3_512.digest(message));
            default:
                throw new Error("Error hashing");
        }
    }


    hmac(key: Uint8Array, message: Uint8Array, length: number = 32, algorithm: Crypto.HmacAlgorithms = 'kmac256') {
        length *= 8;
        switch (algorithm) {
            case 'kmac128':
                return new Uint8Array(kmac128.digest(key, message, length, new Uint8Array()));
            case 'kmac256':
                return new Uint8Array(kmac256.digest(key, message, length, new Uint8Array()));
            default:
                throw new Error("Error hashing");
        }

    }

    hkdf(key: Uint8Array, salt: Uint8Array, info?: Uint8Array | string, length: number = 32): Uint8Array {
        return new Uint8Array(kmac256.digest(key, salt, length * 8, info ?? new Uint8Array()));
    }

    readonly KeyPair = {
        isKeyPair(obj: any): boolean {
            if (typeof obj === 'object' && obj.publicKey && obj.secretKey)
                return true;
            return false;
        }
    }

    readonly box = new CryptoConstructor.box();
    readonly ECDH = new CryptoConstructor.ECDH();
    readonly EdDSA = new CryptoConstructor.EdDSA();
    readonly UUID = new CryptoConstructor.UUID();

    randomBytes = nacl.randomBytes;
}
namespace CryptoConstructor {

    export class box implements Crypto.box {
        readonly keyLength = nacl.secretbox.keyLength;
        readonly nonceLength = nacl.secretbox.nonceLength;

        encrypt(msg: Uint8Array, nonce: Uint8Array, key: Uint8Array): Uint8Array {
            return nacl.secretbox(msg, nonce, key);
        }

        decrypt(msg: Uint8Array, nonce: Uint8Array, key: Uint8Array): Uint8Array | undefined {
            return nacl.secretbox.open(msg, nonce, key) ?? undefined;
        }
    }

    export class ECDH implements Crypto.ECDH {
        readonly publicKeyLength = nacl.box.publicKeyLength;
        readonly secretKeyLength = nacl.box.secretKeyLength;

        keyPair(secretKey?: Uint8Array): Crypto.KeyPair {
            if (secretKey)
                return nacl.box.keyPair.fromSecretKey(secretKey) as Crypto.KeyPair;
            return nacl.box.keyPair() as Crypto.KeyPair;
        }

        sharedKey(publicKey: Uint8Array, secretKey: Uint8Array) {
            return nacl.box.before(publicKey, secretKey);
        }

        scalarMult(n: Uint8Array, p: Uint8Array): Uint8Array {
            return nacl.scalarMult(n, p);
        }
    }

    export class EdDSA implements Crypto.EdDSA {
        readonly publicKeyLength = nacl.sign.publicKeyLength;
        readonly secretKeyLength = nacl.sign.secretKeyLength;
        readonly signatureLength = nacl.sign.signatureLength;
        readonly seedLength = nacl.sign.seedLength

        keyPair(secretKey?: Uint8Array): Crypto.KeyPair {
            if (secretKey)
                return nacl.sign.keyPair.fromSecretKey(secretKey);
            return nacl.sign.keyPair() as Crypto.KeyPair;
        }
        keyPairFromSeed(seed: Uint8Array): Crypto.KeyPair {
            return nacl.sign.keyPair.fromSeed(seed);
        }

        sign(msg: Uint8Array, secretKey: Uint8Array): Uint8Array {
            return nacl.sign.detached(msg, secretKey);
        }

        verify(msg: Uint8Array, sig: Uint8Array, publicKey: Uint8Array): boolean {
            return nacl.sign.detached.verify(msg, sig, publicKey);
        }
    }

    export class UUID {
        generate(): UUIDv4 {
            return new UUIDv4();
        }

        stringify(arr: Uint8Array, offset?: number): string {
            return stringify(arr, offset);
        }

        parse(uuid: string): Uint8Array {
            return parse(uuid);
        }
    }

    class UUIDv4 implements UUIDv4 {
        private value: string;

        constructor() {
            this.value = uuidv4();
        }

        toString(): string {
            return this.value;
        }

        toJSON(): string {
            return this.value;
        }

        toBuffer(): Uint8Array {
            return decodeUTF8(this.value);
        }
    }
}

const crypto: Crypto = new CryptoConstructor();
namespace crypto {
    export type KeyPair = Crypto.KeyPair;
}

export default crypto;