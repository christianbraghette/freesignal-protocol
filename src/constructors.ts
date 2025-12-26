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

import { Bytes, Ciphertext, Encodable, Identity, PublicIdentity, UserId, Crypto } from "@freesignal/interfaces";
import { bytesToNumber, concatBytes, decodeBase64, decodeBase64URL, encodeBase64, numberToBytes } from "@freesignal/crypto/utils";

export function useConstructors(crypto: Crypto) {
    class UserIdConstructor implements UserId {
        public static readonly keyLength = 32;

        public constructor(public readonly bytes: Bytes) { };

        public toString(): string {
            return decodeBase64(this.bytes);
        }

        public toUrl(): string {
            return decodeBase64URL(this.bytes);
        }

        public toJSON(): string {
            return this.toString();
        }

        public static fromKey(identityKey: string | Uint8Array | PublicIdentity): UserId {
            if (typeof identityKey === 'string')
                identityKey = encodeBase64(identityKey);
            else if (!(identityKey instanceof Uint8Array))
                identityKey = identityKey.bytes;
            return new UserIdConstructor(crypto.hkdf(identityKey as Uint8Array, new Uint8Array(32).fill(0), "/freesignal/userid", UserIdConstructor.keyLength));
        }

        public static from(userId: string | Uint8Array | UserId): UserId {
            if (typeof userId === 'string')
                userId = encodeBase64(userId);
            return new UserIdConstructor(userId instanceof Uint8Array ? userId : userId.bytes);
        }
    }

    class PublicIdentityConstructor implements PublicIdentity {
        public static readonly keyLength = crypto.EdDSA.publicKeyLength;

        public constructor(public readonly publicKey: Bytes) { }

        public get userId() {
            return UserIdConstructor.fromKey(this.publicKey);
        }

        public toPublicECDHKey(): Bytes {
            return crypto.EdDSA.toPublicECDHKey(this.publicKey)
        }

        public get bytes(): Bytes {
            return this.publicKey;
        }

        public toString(): string {
            return decodeBase64(this.bytes);
        }

        public toJSON(): string {
            return this.toString();
        }

        public static from(publicIdentity: PublicIdentity | Bytes | string): PublicIdentity {
            if (publicIdentity instanceof Uint8Array || typeof publicIdentity === 'string') {
                if (typeof publicIdentity === 'string')
                    publicIdentity = encodeBase64(publicIdentity);
                if (publicIdentity.length !== PublicIdentityConstructor.keyLength)
                    throw new Error("Invalid key length");
            } else {
                publicIdentity = publicIdentity.publicKey;
            }
            return new PublicIdentityConstructor(publicIdentity);
        }
    }

    class IdentityConstructor extends PublicIdentityConstructor implements Identity {
        public static readonly keyLength = crypto.EdDSA.secretKeyLength;

        public constructor(public readonly secretKey: Bytes) {
            const keyPair = crypto.EdDSA.keyPair(secretKey);
            super(keyPair.publicKey);
            this.secretKey = keyPair.secretKey;
        }

        public toSecretECDHKey(): Bytes {
            return crypto.EdDSA.toSecretECDHKey(this.secretKey);
        }

        public static from(identity: Identity | Uint8Array | string): Identity {
            if (identity instanceof Uint8Array || typeof identity === 'string') {
                if (typeof identity === 'string')
                    identity = encodeBase64(identity);
                if (identity.length !== IdentityConstructor.keyLength)
                    throw new Error("Invalid key length");
            } else {
                identity = identity.secretKey;
            }
            return new IdentityConstructor(identity);
        }
    }

    class CiphertextHeaderConstructor implements Encodable {
        public static readonly keyLength = crypto.Box.keyLength;
        public static readonly nonceLength = crypto.Box.nonceLength;
        public static readonly countLength = 2;

        public constructor(public readonly count: number, public readonly previous: number, public readonly publicKey: Uint8Array, public readonly nonce: Uint8Array) { }

        public get bytes(): Bytes {
            return concatBytes(numberToBytes(this.count, CiphertextHeaderConstructor.countLength), numberToBytes(this.previous, CiphertextHeaderConstructor.countLength), this.publicKey, this.nonce)
        }

        public toJSON(): {
            count: number;
            previous: number;
            publicKey: string;
        } {
            return {
                count: this.count,
                previous: this.previous,
                publicKey: decodeBase64(this.publicKey)
            }
        }

        public static from(data: Uint8Array | CiphertextHeaderConstructor): CiphertextHeaderConstructor {
            if (data instanceof CiphertextHeaderConstructor)
                data = data.bytes;
            let offset = 0;
            return new CiphertextHeaderConstructor(
                bytesToNumber(data.subarray(offset, offset += CiphertextHeaderConstructor.countLength)),
                bytesToNumber(data.subarray(offset, offset += CiphertextHeaderConstructor.countLength)),
                data.subarray(offset, offset += CiphertextHeaderConstructor.keyLength),
                data.subarray(offset, offset += CiphertextConstructor.nonceLength)
            );
        }

    }

    class CiphertextConstructor implements Ciphertext {
        public static readonly version = 1;
        public static readonly nonceLength = crypto.Box.nonceLength;

        public readonly version: number;
        public readonly header: Uint8Array;
        public readonly hashkey?: Uint8Array;
        public readonly nonce?: Uint8Array;
        public readonly payload: Uint8Array;

        public constructor(opts: { header: Uint8Array, payload: Uint8Array, version?: number })
        public constructor(opts: { header: Uint8Array, hashkey: Uint8Array, nonce: Uint8Array, payload: Uint8Array, version?: number })
        public constructor({ hashkey, header, nonce, payload, version }: { header: Uint8Array, hashkey?: Uint8Array, nonce?: Uint8Array, payload: Uint8Array, version?: number }) {
            this.version = version ?? CiphertextConstructor.version;
            this.header = header;
            this.hashkey = hashkey;
            this.nonce = nonce;
            this.payload = payload;
        }

        public get length(): number {
            return this.bytes.length;
        }

        public get bytes(): Bytes {
            return concatBytes(numberToBytes(this.version | (this.hashkey && this.nonce ? 128 : 0), 1), numberToBytes(this.header.length, 3), this.header, this.hashkey ?? new Uint8Array(), this.nonce ?? new Uint8Array, this.payload);
        }

        public toJSON(): {
            version: number;
            header: string;
            hashkey?: string;
            nonce?: string;
            payload: string;
        } {
            return {
                version: this.version,
                header: decodeBase64(this.header),
                hashkey: this.hashkey ? decodeBase64(this.hashkey) : undefined,
                nonce: this.nonce ? decodeBase64(this.nonce) : undefined,
                payload: decodeBase64(this.payload)
            }
        }

        public static from(data: Bytes | Ciphertext): Ciphertext {
            if (!(data instanceof Uint8Array))
                data = data.bytes;
            const versionByte = bytesToNumber(data.subarray(0, 1));
            const headerLength = bytesToNumber(data.subarray(1, 4));
            let offset = 4;
            const header = data.subarray(offset, offset += headerLength);
            let hashkey: Uint8Array | undefined, nonce: Uint8Array | undefined;
            if ((versionByte & 128) > 0) {
                hashkey = data.subarray(offset, offset += 32);
                nonce = data.subarray(offset, offset += this.nonceLength);
            }
            const payload = data.subarray(offset);
            const version = versionByte & 127;
            if (!hashkey || !nonce)
                var obj = new CiphertextConstructor({ header, payload, version });
            else
                var obj = new CiphertextConstructor({ header, hashkey, nonce, payload, version });
            return obj;
        }
    }

    return { UserIdConstructor, PublicIdentityConstructor, IdentityConstructor, CiphertextHeaderConstructor, CiphertextConstructor }
}