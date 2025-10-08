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

import { concatArrays, decodeBase64, decodeJSON, decodeUTF8, encodeBase64, encodeJSON, encodeUTF8, numberFromArray, numberToArray } from "@freesignal/utils";
import crypto from "@freesignal/crypto";
import { Encodable } from "@freesignal/interfaces";
import { KeySession } from "./double-ratchet";
import fflate from 'fflate';

export type UserId = string;
export namespace UserId {

    class UserIdConstructor {
        public constructor(private readonly array: Uint8Array) { };

        public toString(): string {
            return decodeBase64(this.array)
        }

        public toJSON(): string {
            return this.toString();
        }

        public toUint8Array(): Uint8Array {
            return this.array;
        }
    }

    export function getUserId(publicKey: string | Uint8Array): UserIdConstructor {
        return new UserIdConstructor(crypto.hash(publicKey instanceof Uint8Array ? publicKey : encodeBase64(publicKey)));
    }

    export function from(userId: string | Uint8Array): UserIdConstructor {
        return new UserIdConstructor(userId instanceof Uint8Array ? userId : encodeBase64(userId));
    }
}

export interface IdentityKeys {
    readonly publicKey: string;
    readonly identityKey: string;
}
export namespace IdentityKeys {
    export const keyLength = crypto.ECDH.publicKeyLength;

    class IdentityKeysConstructor implements IdentityKeys, Encodable {
        public readonly publicKey: string;
        public readonly identityKey: string;

        constructor(identityKeys: IdentityKeys | Uint8Array | string) {
            if (typeof identityKeys === 'string')
                identityKeys = encodeBase64(identityKeys);
            if (identityKeys instanceof Uint8Array) {
                this.publicKey = decodeBase64(identityKeys.subarray(0, IdentityKeys.keyLength));
                this.identityKey = decodeBase64(identityKeys.subarray(IdentityKeys.keyLength));
            } else {
                this.publicKey = identityKeys.publicKey;
                this.identityKey = identityKeys.identityKey;
            }
        }

        encode(): Uint8Array {
            return concatArrays(encodeBase64(this.publicKey), encodeBase64(this.identityKey));
        }

        toString(): string {
            throw decodeBase64(this.encode());
        }

        toJSON(): string {
            throw this.toString();
        }
    }

    export function isIdentityKeys(obj: any): boolean {
        return (typeof obj === 'object' && obj.publicKey && obj.identityKey);
    }

    export function from(identityKeys: IdentityKeys): IdentityKeysConstructor {
        return new IdentityKeysConstructor(identityKeys);
    }
}

export enum Protocols {
    NULL = '',
    MESSAGE = '/freesignal/message',
    RELAY = '/freesignal/relay',
    HANDSHAKE = '/freesignal/handshake'
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

    export function encode(protocol: Protocols, length?: number): Uint8Array {
        return numberToArray(Protocols.toCode(protocol), length);
    }

    export function decode(array: Uint8Array): Protocols {
        return Protocols.fromCode(numberFromArray(array));
    }
}

export interface Datagram {
    readonly id: string;
    readonly version: number;
    readonly sender: string;
    readonly receiver: string;
    readonly protocol: Protocols;
    readonly createdAt: number;
    payload?: Uint8Array;
    readonly signature?: string;
}
export namespace Datagram {
    export const version = 1;

    class DatagramConstructor implements Encodable, Datagram {
        public readonly id: string;
        public readonly version: number;
        public readonly sender: UserId;
        public readonly receiver: UserId;
        public readonly protocol: Protocols;
        public readonly createdAt: number;
        public _payload?: Uint8Array;
        public _signature?: Uint8Array;
        private secretKey?: Uint8Array;

        private static headerOffset = 26 + crypto.EdDSA.publicKeyLength * 2;

        public constructor(sender: Uint8Array | string, receiver: Uint8Array | string, protocol: Protocols, payload?: Uint8Array | Encodable)
        public constructor(data: Uint8Array | Datagram)
        public constructor(data: Uint8Array | string | Datagram, receiver?: Uint8Array | string, protocol?: Protocols, payload?: Uint8Array | Encodable) {
            if (!receiver && !protocol && !payload) {
                if (data instanceof Uint8Array) {
                    this.version = data[0] & 127;
                    this.protocol = Protocols.decode(data.subarray(1, 2));
                    this.id = crypto.UUID.stringify(data.subarray(2, 18));
                    this.createdAt = numberFromArray(data.subarray(18, 26));
                    this.sender = decodeBase64(data.subarray(26, 26 + crypto.EdDSA.publicKeyLength));
                    this.receiver = decodeBase64(data.subarray(26 + crypto.EdDSA.publicKeyLength, DatagramConstructor.headerOffset));
                    if (data[0] & 128)
                        this._signature = data.subarray(data.length - crypto.EdDSA.signatureLength);
                    this._payload = data.subarray(DatagramConstructor.headerOffset, data.length);
                } else if (Datagram.isDatagram(data)) {
                    const datagram = data as Datagram;
                    this.id = datagram.id;
                    this.version = datagram.version;
                    this.sender = datagram.sender;
                    this.receiver = datagram.receiver;
                    this.protocol = datagram.protocol;
                    this.createdAt = datagram.createdAt;
                    this._payload = datagram.payload;
                    this._signature = encodeBase64(datagram.signature);
                } else throw new Error('Invalid constructor arguments for Datagram');
            } else if (typeof data === 'string' || data instanceof Uint8Array) {
                this.id = crypto.UUID.generate().toString();
                this.version = Datagram.version;
                this.sender = typeof data === 'string' ? data : decodeBase64(data);
                this.receiver = typeof receiver === 'string' ? receiver : decodeBase64(receiver);
                this.protocol = protocol!;
                this.createdAt = Date.now();
                this._payload = payload instanceof Uint8Array ? payload : payload?.encode();
            } else throw new Error('Invalid constructor arguments for Datagram');
        }

        public get signed(): boolean {
            return !this._signature && !this.secretKey ? false : true;
        }

        public get signature(): string | undefined {
            if (this.signed) {
                if (!this._signature)
                    this.encode();
                return decodeBase64(this._signature);
            }
        }

        public set payload(data: Uint8Array) {
            this._signature = undefined;
            this._payload = data;
        }

        public get payload(): Uint8Array | undefined {
            return this._payload;
        }

        public encode(): Uint8Array {
            const data = concatArrays(
                new Uint8Array(1).fill(this.version | (this.secretKey ? 128 : 0)), //1
                Protocols.encode(this.protocol), //1
                crypto.UUID.parse(this.id) ?? [], //16
                numberToArray(this.createdAt, 8), //8
                encodeBase64(this.sender), //32
                encodeBase64(this.receiver), //32
                this._payload ?? new Uint8Array()
            );
            if (this.secretKey) this._signature = crypto.EdDSA.sign(data, this.secretKey);
            return concatArrays(data, this._signature ?? new Uint8Array());
        }

        public sign(secretKey: Uint8Array): this {
            this.secretKey = secretKey;
            return this
        }

        public toString(): string {
            return decodeBase64(this.encode());
        }

        public toJSON(): string {
            return this.toString();
        }
    }

    export function create(sender: Uint8Array | string, receiver: Uint8Array | string, protocol: Protocols, payload?: Uint8Array | Encodable): DatagramConstructor {
        return new DatagramConstructor(sender, receiver, protocol, payload);
    }

    export function isDatagram(obj: any): boolean {
        return obj instanceof DatagramConstructor || (obj && typeof obj === 'object' && 'id' in obj && 'version' in obj && 'sender' in obj && 'receiver' in obj && 'protocol' in obj && 'createdAt' in obj);
    }

    export function from(data: Uint8Array | Datagram | string): DatagramConstructor {
        if (typeof data === 'string') {
            const decoded = encodeBase64(data);
            return new DatagramConstructor(decoded);
        } else return new DatagramConstructor(data);
    }
}

/**
 * Interface representing an encrypted payload.
 * Provides metadata and de/serialization methods.
 */
export interface EncryptedData extends Encodable {

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
     * Serializes the payload into a Uint8Array for transport.
     */
    encode(): Uint8Array;

    /**
     * Returns the payload as a Base64 string.
     */
    toString(): string;

    /**
     * Returns the decoded object as a JSON string.
     */
    toJSON(): {
        version: number;
        count: number;
        previous: number;
        publicKey: string;
        nonce: string;
        ciphertext: string;
    };
}
export class EncryptedData {

    /**
     * Static factory method that constructs an `EncryptedPayload` from a raw Uint8Array.
     *
     * @param array - A previously serialized encrypted payload.
     * @returns An instance of `EncryptedPayload`.
     */
    public static from(array: Uint8Array | EncryptedData) {
        return new EncryptedDataConstructor(array) as EncryptedData;
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
            arrays.unshift(typeof arrays[5] === 'number' ? numberToArray(arrays[5]) : arrays[5]);
            arrays.pop();
        } else if (arrays.length > 1) {
            arrays.unshift(numberToArray(KeySession.version));
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

    public encode(): Uint8Array {
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

enum DataType {
    UKNOWN = -1,
    RAW,
    NUMBER,
    STRING,
    ARRAY,
    OBJECT,
}
namespace DataType {
    export function getType(type: string): DataType {
        return Object.values(DataType).indexOf(type.toLocaleUpperCase());
    }

    export function getName(type: DataType): string {
        return DataType[type].toLowerCase();
    }

    export function from(data: any): DataType {
        if (data instanceof Uint8Array)
            return DataType.RAW;
        return getType(typeof data);
    }
}

export class DataEncoder<T> implements Encodable {
    public readonly type: string;

    public constructor(public readonly data: T) {
        this.type = DataType.getName(DataType.from(this.data));
    }

    protected get _type(): DataType {
        return DataType.getType(this.type);
    }

    public encode(): Uint8Array {
        let data: Uint8Array
        switch (this._type) {
            case DataType.RAW:
                data = this.data as Uint8Array;
                break;

            case DataType.NUMBER:
                data = numberToArray(this._type);
                break;

            case DataType.STRING:
                data = encodeUTF8(this.data as string);
                break;

            case DataType.ARRAY:
                data = concatArrays(...Array.from(this.data as any[]).flatMap(value => {
                    const data = new DataEncoder(value).encode();
                    return [numberToArray(data.length, 8), data]
                }));
                break;

            case DataType.OBJECT:
                data = encodeJSON(this.data);
                break;

            default:
                throw new Error("Uknown type");
        }
        return concatArrays(numberToArray(this._type), data);
    }

    public toString(): string {
        return "[Object XFreeSignalData]";
    }

    public toJSON(): T {
        return this.data;
    }

    public static from<T = any>(array: Uint8Array) {
        const type = array[0];
        let rawData = array.subarray(1), data: T;
        switch (type) {
            case DataType.RAW:
                data = rawData as T;
                break;

            case DataType.NUMBER:
                data = numberFromArray(rawData) as T;
                break;

            case DataType.STRING:
                data = decodeUTF8(rawData) as T;
                break;

            case DataType.ARRAY:
                const arrayData: any[] = [];
                let offset = 0;
                while (offset < rawData.length) {
                    const length = rawData.subarray(offset, offset + 8);
                    if (length.length < 8)
                        throw new Error('Invalid data length');
                    const messageLength = numberFromArray(length);
                    offset += 8;
                    if (offset + messageLength > rawData.length) {
                        throw new Error('Invalid data length');
                    }
                    arrayData.push(rawData.subarray(offset, offset + messageLength));
                    offset += messageLength;
                }
                data = arrayData as T;
                break;

            case DataType.OBJECT:
                data = decodeJSON(rawData);
                break;

            default:
                throw new Error('Invalid data format');
        }
        return new DataEncoder<T>(data);
    }
}

export namespace XFreeSignal {
    export const MIME = "application/x-freesignal";
    export const version = 1;

    export function encodeBody(type: 'data' | 'error', data: any, compressed = false): BodyInit {
        return new Body(type, data).encode(compressed) as BodyInit;
    }

    export function decodeBody<T = any>(body: Uint8Array): Body<T> {
        return Body.from(body);
    }

    enum BodyType {
        DATA,
        ERROR
    }
    namespace BodyType {
        export function getName(type: BodyType): 'data' | 'error' {
            return BodyType[type].toLowerCase() as any;
        }
    }

    class Body<T> implements Encodable {

        public constructor(public readonly type: 'data' | 'error', public readonly data: T) { }

        encode(compressed = false): Uint8Array {
            const data = new DataEncoder(this.data).encode();
            return concatArrays(
                numberToArray(
                    ((this.type === 'data' ? BodyType.DATA : BodyType.ERROR) << 6)
                    + (compressed ? 32 : 0)
                    + XFreeSignal.version
                ), compressed ? fflate.deflateSync(data) : data);
        }

        toString(): string {
            return "[Object XFreeSignalBody]";
        }

        toJSON() {
            return {
                type: this.type,
                data: this.data
            };
        }

        public static from<T = any>(array: Uint8Array): Body<T> {
            return new Body<T>(BodyType.getName((array[0] & 64) >> 6), DataEncoder.from((array[0] & 32) >> 5 === 1 ? fflate.inflateSync(array.subarray(1)) : array.subarray(1)).data);
        }
    }

}