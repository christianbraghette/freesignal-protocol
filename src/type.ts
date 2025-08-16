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

export class IdentityKey extends Uint8Array {
    public static keyLength = crypto.ECDH.publicKeyLength + crypto.EdDSA.publicKeyLength;

    public readonly secretKey?: Uint8Array;
    public readonly signSecretKey?: Uint8Array;

    constructor(key: Uint8Array | crypto.KeyPair, signKey: Uint8Array | crypto.KeyPair)
    constructor(identityKey: IdentityKey | Uint8Array)
    constructor(key: Uint8Array | crypto.KeyPair | IdentityKey, signKey?: Uint8Array | crypto.KeyPair) {
        super(IdentityKey.keyLength);
        if (IdentityKey.isIdentityKey(key)) {
            const IK = key as IdentityKey;
            this.secretKey = IK.secretKey;
            this.publicKey = IK.publicKey;
            this.signSecretKey = IK.signSecretKey;
            this.signPublicKey = IK.signPublicKey;
            return;
        }
        if (signKey) {
            if (key instanceof Uint8Array) {
                this.publicKey = key;
            } else {
                this.secretKey = key.secretKey;
                this.publicKey = key.publicKey;
            }
            if (signKey instanceof Uint8Array) {
                this.signPublicKey = signKey;
            } else {
                this.signSecretKey = signKey.secretKey;
                this.signPublicKey = signKey.publicKey;
            }
        } else {
            if (key instanceof Uint8Array) {
                this.publicKey = key.subarray(0, crypto.ECDH.publicKeyLength);
                this.signPublicKey = key.subarray(crypto.EdDSA.publicKeyLength);
            } else throw new Error();
        }
    }

    public get publicKey() {
        return this.subarray(0, crypto.ECDH.publicKeyLength);
    }
    protected set publicKey(key: Uint8Array) {
        this.set(key);
    }

    public get signPublicKey() {
        return this.subarray(crypto.EdDSA.publicKeyLength);
    }
    protected set signPublicKey(key: Uint8Array) {
        this.set(key, crypto.EdDSA.publicKeyLength);
    }

    public static isIdentityKey(obj: any): boolean {
        if (obj instanceof Uint8Array && obj.length === IdentityKey.keyLength)
            return true;
        return false;
    }

    public static from(identityKey: IdentityKey | Uint8Array): IdentityKey {
        return new IdentityKey(identityKey);
    }
}

export class PrivateIdentityKey extends IdentityKey {
    declare readonly secretKey: Uint8Array;
    declare readonly signSecretKey: Uint8Array;

    public export(): IdentityKey {
        return new IdentityKey(this.publicKey, this.signPublicKey);
    }

    public static isIdentityKey(obj: any): boolean {
        if (IdentityKey.isIdentityKey(obj) && (obj as IdentityKey).secretKey && (obj as IdentityKey).signSecretKey)
            return true;
        return false;
    }
}