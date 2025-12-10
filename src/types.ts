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

import { concatBytes, decodeBase64, encodeBase64, bytesToNumber, numberToBytes } from "@freesignal/utils";
import crypto from "@freesignal/crypto";
import type { LocalStorage, Encodable, KeyExchangeData } from "@freesignal/interfaces";
import { EncryptionKeys, KeySession } from "./double-ratchet";

export function encryptData(session: KeySession, data: Uint8Array): EncryptedData {
    const key = session.getSendingKey();
    if (!key)
        throw new Error("Error generating key");
    const nonce = crypto.randomBytes(EncryptionHeader.nonceLength);
    const payload = crypto.box.encrypt(data, nonce, key.secretKey);
    let header = new EncryptionHeader(key, nonce).toBytes();
    const headerKey = session.getHeaderKey();
    if (!headerKey)
        return new EncryptedData({ header, payload });
    const headerNonce = crypto.randomBytes(EncryptionHeader.nonceLength)
    if (headerKey)
        header = crypto.box.encrypt(header, headerNonce, headerKey);
    return new EncryptedData({ hashkey: crypto.hash(headerKey ?? new Uint8Array(32).fill(0)), header, nonce: headerNonce, payload });
}

export function decryptData(session: KeySession, encryptedData: Uint8Array): Uint8Array {
    const encrypted = EncryptedData.from(encryptedData);
    let headerData: Uint8Array = encrypted.header;
    if (encrypted.hashkey && encrypted.nonce) {
        const headerKey = session.getHeaderKey(decodeBase64(encrypted.hashkey));
        if (!headerKey)
            throw new Error("Error getting key");
        const data = crypto.box.decrypt(encrypted.header, encrypted.nonce, headerKey);
        if (!data)
            throw new Error("Error calculating header");
        headerData = data;
    }
    const header = EncryptionHeader.from(headerData);
    const key = session.getReceivingKey(header);
    if (!key)
        throw new Error("Error calculating key");
    const decrypted = crypto.box.decrypt(encrypted.payload, header.nonce, key);
    if (!decrypted)
        throw new Error("Error decrypting data");
    return decrypted;
}

export class UserId implements Encodable {
    private constructor(private readonly array: Uint8Array) { };

    public toString(): string {
        return decodeBase64(this.array)
    }

    public toJSON(): string {
        return this.toString();
    }

    public toBytes(): Uint8Array {
        return this.array;
    }

    public static fromKey(identityKey: string | Uint8Array | IdentityKey): UserId {
        if (typeof identityKey === 'string')
            identityKey = encodeBase64(identityKey);
        else if (identityKey instanceof IdentityKey)
            identityKey = (identityKey).toBytes();
        return new UserId(crypto.hkdf(identityKey as Uint8Array, new Uint8Array(32).fill(0), "/freesignal/userid"));
    }

    public static from(userId: string | Uint8Array | UserId): UserId {
        if (typeof userId === 'string')
            userId = encodeBase64(userId);
        return new UserId(userId instanceof Uint8Array ? userId : userId.array);
    }
}

export class IdentityKey implements Encodable {
    public static readonly keyLength = crypto.EdDSA.publicKeyLength + crypto.ECDH.publicKeyLength + 1;
    public static readonly version = 1;
    private static readonly info = 0x70;

    public readonly info: number;
    public readonly signatureKey: Uint8Array;
    public readonly exchangeKey: Uint8Array;

    constructor(identityKey: IdentityKey | Uint8Array | string) {
        if (identityKey instanceof IdentityKey) {
            this.info = identityKey.info;
            this.signatureKey = identityKey.signatureKey;
            this.exchangeKey = identityKey.exchangeKey;
        } else {
            if (typeof identityKey === 'string')
                identityKey = encodeBase64(identityKey);
            if (identityKey.length !== IdentityKey.keyLength)
                throw new Error("Invalid key length");
            this.info = (identityKey as Uint8Array)[0];
            this.signatureKey = (identityKey as Uint8Array).subarray(1, crypto.EdDSA.publicKeyLength + 1);
            this.exchangeKey = (identityKey as Uint8Array).subarray(crypto.EdDSA.publicKeyLength + 1, IdentityKey.keyLength);
        }
    }

    get userId() {
        return UserId.fromKey(this.toBytes());
    }

    toBytes(): Uint8Array {
        return concatBytes(numberToBytes(this.info, 1), this.signatureKey, this.exchangeKey);
    }

    toString(): string {
        return decodeBase64(this.toBytes());
    }

    toJSON(): string {
        return this.toString();
    }

    public static from(identityKey: IdentityKey | Uint8Array | string): IdentityKey
    public static from(signatureKey: Uint8Array | string, exchangeKey: Uint8Array | string): IdentityKey
    public static from(...keys: (IdentityKey | Uint8Array | string)[]): IdentityKey {
        keys = keys.map(key => {
            if (key instanceof IdentityKey)
                return key.toBytes();
            else if (typeof key === 'string')
                return encodeBase64(key);
            else
                return key as Uint8Array;
        });
        return new IdentityKey(keys.length === 2 ? concatBytes(numberToBytes(IdentityKey.info + IdentityKey.version, 1), ...keys as Uint8Array[]) : keys[0]);
    }
}

export class PrivateIdentityKey implements Encodable {
    public static readonly keyLength = crypto.EdDSA.secretKeyLength + crypto.ECDH.secretKeyLength + 1;
    public static readonly version = 1;
    private static readonly info = 0x4E;


    public readonly info: number;
    public readonly signatureKey: Uint8Array;
    public readonly exchangeKey: Uint8Array;
    public readonly identityKey: IdentityKey;

    constructor(privateIdentityKey: PrivateIdentityKey | Uint8Array | string) {
        if (privateIdentityKey instanceof PrivateIdentityKey) {
            this.info = privateIdentityKey.info;
            this.signatureKey = privateIdentityKey.signatureKey;
            this.exchangeKey = privateIdentityKey.exchangeKey;
            this.identityKey = privateIdentityKey.identityKey;
        } else {
            if (typeof privateIdentityKey === 'string')
                privateIdentityKey = encodeBase64(privateIdentityKey);
            if (!PrivateIdentityKey.isIdentityKeys(privateIdentityKey))
                throw new Error("Invalid key length");
            this.info = (privateIdentityKey as Uint8Array)[0];
            this.signatureKey = (privateIdentityKey as Uint8Array).subarray(1, crypto.EdDSA.secretKeyLength + 1);
            this.exchangeKey = (privateIdentityKey as Uint8Array).subarray(crypto.EdDSA.secretKeyLength + 1, PrivateIdentityKey.keyLength);
            this.identityKey = IdentityKey.from(crypto.EdDSA.keyPair(this.signatureKey).publicKey, crypto.ECDH.keyPair(this.exchangeKey).publicKey);
        }
    }

    get userId() {
        return UserId.fromKey(this.identityKey.toBytes()).toString();
    }

    toBytes(): Uint8Array {
        return concatBytes(numberToBytes(this.info, 1), this.signatureKey, this.exchangeKey);
    }

    toString(): string {
        return decodeBase64(this.toBytes());
    }

    toJSON(): string {
        return this.toString();
    }

    public static isIdentityKeys(obj: any): boolean {
        return (obj instanceof Uint8Array && obj.length === PrivateIdentityKey.keyLength) || obj instanceof PrivateIdentityKey;
    }

    public static from(identityKey: PrivateIdentityKey | Uint8Array | string): PrivateIdentityKey
    public static from(signatureKey: Uint8Array | string, exchangeKey: Uint8Array | string): PrivateIdentityKey
    public static from(...keys: (PrivateIdentityKey | Uint8Array | string)[]): PrivateIdentityKey {
        keys = keys.map(key => {
            if (key instanceof PrivateIdentityKey)
                return key.toBytes();
            else if (typeof key === 'string')
                return encodeBase64(key);
            else
                return key as Uint8Array;
        });
        return new PrivateIdentityKey(keys.length === 2 ? concatBytes(numberToBytes(PrivateIdentityKey.info + PrivateIdentityKey.version, 1), ...keys as Uint8Array[]) : keys[0]);
    }
}

export enum DiscoverType {
    REQUEST,
    RESPONSE
}

export interface DiscoverMessage {
    type: DiscoverType,
    discoverId: string,
    data?: KeyExchangeData
}

export enum Protocols {
    PING = '/freesignal/ping',
    MESSAGE = '/freesignal/message',
    RELAY = '/freesignal/relay',
    HANDSHAKE = '/freesignal/handshake',
    DISCOVER = '/freesignal/discover',
    BOOTSTRAP = '/freesignal/bootstrap'
}
export namespace Protocols {

    export function isProtocol(protocol: any): boolean {
        return Object.values(Protocols).includes(protocol);
    }

    export function fromCode(code: number): Protocols {
        return Object.values(Protocols)[code] as Protocols;
    }

    export function toCode(protocol: Protocols): number {
        return Object.values(Protocols).indexOf(protocol);
    }

    export function encode(protocol: Protocols, length: number = 1): Uint8Array {
        return numberToBytes(Protocols.toCode(protocol), length);
    }

    export function decode(array: Uint8Array): Protocols {
        return Protocols.fromCode(bytesToNumber(array));
    }
}

interface DatagramJSON {
    id: string;
    version: number;
    sender: string;
    receiver: string;
    protocol: Protocols;
    createdAt: number;
    payload: string | undefined;
    signature: string | undefined;
};

export interface SignedDatagram extends Datagram {
    signature: string;
}

export class DatagramHeader implements Encodable {
    public static readonly headerLength = 26 + crypto.EdDSA.publicKeyLength * 2;

    readonly id: string;
    readonly version: number;
    readonly sender: string;
    readonly receiver: string;
    readonly protocol: Protocols;
    readonly createdAt: number;

    private constructor(data: Uint8Array) {
        this.version = data[0] & 127;
        this.protocol = Protocols.decode(data.subarray(1, 2));
        this.id = crypto.UUID.stringify(data.subarray(2, 18));
        this.createdAt = bytesToNumber(data.subarray(18, 26));
        this.sender = decodeBase64(data.subarray(26, 26 + crypto.EdDSA.publicKeyLength));
        this.receiver = decodeBase64(data.subarray(26 + crypto.EdDSA.publicKeyLength, DatagramHeader.headerLength));
    }

    public toBytes(): Uint8Array {
        return concatBytes(
            numberToBytes(this.version, 1),
            Protocols.encode(this.protocol, 1),
            crypto.UUID.parse(this.id),
            numberToBytes(this.createdAt, 8),
            encodeBase64(this.sender),
            encodeBase64(this.receiver)
        );
    }

    public static from(data: Uint8Array | string) {
        if (typeof data === 'string')
            data = encodeBase64(data);
        return new DatagramHeader(data);
    }
}

export class Datagram implements Encodable, DatagramHeader {
    public static version = 1;

    private _id: string;
    private _version: number;
    public readonly sender: string;
    public readonly receiver: string;
    public readonly protocol: Protocols;
    private _createdAt: number;
    private _payload?: Uint8Array;
    private _signature?: Uint8Array;

    public constructor(sender: Uint8Array | string, receiver: Uint8Array | string, protocol: Protocols, payload?: Uint8Array | Encodable) {
        this._id = crypto.UUID.generate().toString();
        this._version = Datagram.version;
        this.sender = typeof sender === 'string' ? sender : decodeBase64(sender);
        this.receiver = typeof receiver === 'string' ? receiver : decodeBase64(receiver!);
        this.protocol = protocol!;
        this._createdAt = Date.now();
        this._payload = payload instanceof Uint8Array ? payload : payload?.toBytes();
    }

    public get id() {
        return this._id;
    }

    public get version() {
        return this._version;
    }

    public get createdAt() {
        return this._createdAt;
    }

    public set payload(data: Uint8Array) {
        this._signature = undefined;
        this._payload = data;
    }

    public get payload(): Uint8Array | undefined {
        return this._payload;
    }

    public get signature(): string | undefined {
        return this._signature ? decodeBase64(this._signature) : undefined;
    }

    private get unsigned(): Uint8Array {
        const data = this.toBytes();
        data[0] &= 127;
        return data.subarray(0, data.length - (this._signature ? crypto.EdDSA.signatureLength : 0));
    }

    get header(): DatagramHeader {
        return DatagramHeader.from(this.toBytes().slice(0, DatagramHeader.headerLength));
    }

    public toBytes(): Uint8Array {
        return concatBytes(
            new Uint8Array(1).fill(this.version | (this.signature ? 128 : 0)), //1
            Protocols.encode(this.protocol), //1
            crypto.UUID.parse(this.id) ?? [], //16
            new Uint8Array(numberToBytes(this._createdAt, 8)), //8
            encodeBase64(this.sender), //32
            encodeBase64(this.receiver), //32
            this._payload ?? new Uint8Array(),
            this._signature ?? new Uint8Array()
        );
    }

    public sign(secretKey: Uint8Array): SignedDatagram {
        this._signature = crypto.EdDSA.sign(this.unsigned, secretKey);
        return this as SignedDatagram;
    }

    public toString(): string {
        return decodeBase64(this.toBytes());
    }

    public toJSON(): DatagramJSON {
        return {
            id: this.id,
            version: this.version,
            sender: this.sender,
            receiver: this.receiver,
            protocol: this.protocol,
            createdAt: this.createdAt,
            payload: this.payload ? decodeBase64(this.payload) : undefined,
            signature: this._signature ? decodeBase64(this._signature) : undefined
        };
    }

    public static verify(datagram: Datagram, publicKey: Uint8Array) {
        if (!datagram._signature)
            throw new Error("Datagram not signed");
        return crypto.EdDSA.verify(
            datagram.unsigned,
            datagram._signature,
            publicKey
        );
    }

    public static from(data: Uint8Array | Datagram | string): Datagram {
        if (typeof data === 'string')
            data = encodeBase64(data);
        if (data instanceof Uint8Array) {
            const datagram = new Datagram(
                decodeBase64(data.subarray(26, 26 + crypto.EdDSA.publicKeyLength)),
                decodeBase64(data.subarray(26 + crypto.EdDSA.publicKeyLength, DatagramHeader.headerLength)),
                Protocols.decode(data.subarray(1, 2)),
                data.subarray(DatagramHeader.headerLength, data.length - (data[0] & 128 ? crypto.EdDSA.signatureLength : 0))
            );
            datagram._version = data[0] & 127;
            datagram._id = crypto.UUID.stringify(data.subarray(2, 18));
            datagram._createdAt = bytesToNumber(data.subarray(18, 26));
            if (data[0] & 128)
                datagram._signature = data.subarray(data.length - crypto.EdDSA.signatureLength);
            return datagram;
        } else if (data instanceof Datagram) {
            const datagram = new Datagram(data.sender, data.receiver, data.protocol, data.payload);
            datagram._id = data.id;
            datagram._version = data.version;
            datagram._createdAt = data._createdAt;
            datagram._signature = data._signature;
            return datagram;
        } else
            throw new Error('Invalid constructor arguments for Datagram');
    }
}

export class EncryptionHeader implements EncryptionKeys, Encodable {
    public static readonly keyLength = crypto.box.keyLength;
    public static readonly nonceLength = crypto.box.nonceLength;
    public static readonly countLength = 2;


    public readonly count: number;
    public readonly previous: number;
    public readonly publicKey: Uint8Array;

    public constructor(keys: EncryptionKeys, public readonly nonce: Uint8Array) {
        this.count = keys.count;
        this.previous = keys.previous;
        this.publicKey = keys.publicKey;
    }

    public toBytes(): Uint8Array {
        return concatBytes(numberToBytes(this.count, EncryptionHeader.countLength), numberToBytes(this.previous, EncryptionHeader.countLength), this.publicKey, this.nonce)
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

    public static from(data: Uint8Array | EncryptionHeader): EncryptionHeader {
        if (data instanceof EncryptionHeader)
            data = data.toBytes();
        let offset = 0;
        return new EncryptionHeader({
            count: bytesToNumber(data.subarray(offset, offset += EncryptionHeader.countLength)),
            previous: bytesToNumber(data.subarray(offset, offset += EncryptionHeader.countLength)),
            publicKey: data.subarray(offset, offset += EncryptionHeader.keyLength)
        }, data.subarray(offset, offset += EncryptedData.nonceLength));
    }

}

export class EncryptedData implements Encodable {
    public static readonly version = 1;
    public static readonly nonceLength = crypto.box.nonceLength;

    private _version: number = EncryptedData.version;
    public readonly header: Uint8Array;
    public readonly hashkey?: Uint8Array;
    public readonly nonce?: Uint8Array;
    public readonly payload: Uint8Array;

    public constructor(opts: { header: Uint8Array, payload: Uint8Array })
    public constructor(opts: { header: Uint8Array, hashkey: Uint8Array, nonce: Uint8Array, payload: Uint8Array })
    public constructor({ hashkey, header, nonce, payload }: { header: Uint8Array, hashkey?: Uint8Array, nonce?: Uint8Array, payload: Uint8Array }) {
        this.header = header;
        this.hashkey = hashkey;
        this.nonce = nonce;
        this.payload = payload;
    }

    public get version(): number {
        return this._version;
    }

    public get length(): number {
        return this.toBytes().length;
    }

    public toBytes(): Uint8Array {
        return concatBytes(numberToBytes(this._version | (this.hashkey && this.nonce ? 128 : 0), 1), numberToBytes(this.header.length, 3), this.header, this.hashkey ?? new Uint8Array(), this.nonce ?? new Uint8Array, this.payload);
    }

    public toJSON(): {
        version: number;
        header: string;
        hashkey?: string;
        nonce?: string;
        payload: string;
    } {
        return {
            version: this._version,
            header: decodeBase64(this.header),
            hashkey: this.hashkey ? decodeBase64(this.hashkey) : undefined,
            nonce: this.nonce ? decodeBase64(this.nonce) : undefined,
            payload: decodeBase64(this.payload)
        }
    }

    public static from(data: Uint8Array | EncryptedData): EncryptedData {
        if (data instanceof EncryptedData)
            data = data.toBytes();
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
        if (!hashkey || !nonce)
            var obj = new EncryptedData({ header, payload });
        else
            var obj = new EncryptedData({ header, hashkey, nonce, payload });
        obj._version = versionByte & 127;
        return obj;
    }
}

export class AsyncMap<K, V> implements LocalStorage<K, V> {
    private readonly map: Map<K, V>;

    constructor(iterable?: Iterable<readonly [K, V]>) {
        this.map = new Map<K, V>(iterable);
    }

    async set(key: K, value: V): Promise<void> {
        this.map.set(key, value);
        return;
    }

    async get(key: K): Promise<V | undefined> {
        return this.map.get(key);
    }

    async has(key: K): Promise<boolean> {
        return this.map.has(key);
    }

    async delete(key: K): Promise<boolean> {
        return this.map.delete(key);
    }

    async clear(): Promise<void> {
        return this.map.clear();
    }

    async entries(): Promise<Iterable<[K, V]>> {
        return this.map.entries();
    }
}