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

import { concatUint8Array, decodeBase64, decodeUTF8, encodeBase64, encodeUTF8, numberFromUint8Array, numberToUint8Array } from "./utils";
import crypto from "./crypto";
import fflate from "fflate";
import { Encodable } from "./types";

export enum Protocols {
    NULL = '',
    MESSAGE = '/freesignal/message/1.0.0',
    RELAY = '/freesignal/relay/1.0.0',
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
        /*const raw = numberToUint8Array(Protocols.toCode(protocol), length).reverse();
        raw[0] |= (raw.length - 1) << 6;
        return raw;*/
        return numberToUint8Array(Protocols.toCode(protocol), length ?? 4, 'big');
    }

    export function decode(array: Uint8Array): Protocols {
        array[0] &= 63;
        array = array.reverse();
        return Protocols.fromCode(numberFromUint8Array(array));
    }
}

export interface Datagram {
    readonly id: string;
    readonly version: number;
    readonly senderKey: string;
    readonly senderRelay?: string;
    readonly receiverKey: string;
    readonly receiverRelay?: string;
    readonly protocol: Protocols;
    readonly createdAt: number;
    payload?: Uint8Array;
}
export namespace Datagram {
    export const version = 1;

    export function create(sender: Uint8Array | string, receiver: Uint8Array | string, protocol: Protocols, payload?: Uint8Array | Encodable): DatagramConstructor {
        return new DatagramConstructor(sender, receiver, protocol, payload);
    }

    export function isDatagram(obj: any): boolean {
        return obj instanceof DatagramConstructor || (obj && typeof obj === 'object' && 'id' in obj && 'version' in obj && 'sender' in obj && 'receiver' in obj && 'protocol' in obj && 'createdAt' in obj);
    }

    export function from(data: Uint8Array): DatagramConstructor {
        return new DatagramConstructor(data);
    }
}

class DatagramConstructor implements Encodable, Datagram {
    public readonly id: string;
    public readonly version: number;
    public readonly senderKey: string;
    public readonly senderRelay?: string;
    public readonly receiverKey: string;
    public readonly receiverRelay?: string;
    public readonly protocol: Protocols;
    public readonly createdAt: number;
    public payload?: Uint8Array;

    private static headerOffset = 28 + crypto.EdDSA.publicKeyLength * 2;

    public constructor(sender: Uint8Array | string, receiver: Uint8Array | string, protocol: Protocols, payload?: Uint8Array | Encodable)
    public constructor(data: Uint8Array | Datagram)
    public constructor(data: Uint8Array | string | Datagram, receiver?: Uint8Array | string, protocol?: Protocols, payload?: Uint8Array | Encodable) {
        if (!receiver && !protocol && !payload) {
            if (data instanceof Uint8Array) {
                this.version = data[0] & 63;
                this.protocol = Protocols.decode(data.subarray(1, 4));
                this.id = crypto.UUID.stringify(data.subarray(4, 20));
                this.createdAt = numberFromUint8Array(data.subarray(20, 28));
                this.senderKey = encodeBase64(data.subarray(28, 28 + crypto.EdDSA.publicKeyLength));
                this.receiverKey = encodeBase64(data.subarray(28 + crypto.EdDSA.publicKeyLength, DatagramConstructor.headerOffset));
                const senderRelayOffset = data.indexOf(255, DatagramConstructor.headerOffset);
                const receiverRelayOffset = data.indexOf(255, senderRelayOffset + 1);
                this.senderRelay = encodeUTF8(data.subarray(DatagramConstructor.headerOffset, senderRelayOffset)) ? "" : undefined;
                this.receiverRelay = encodeUTF8(data.subarray(senderRelayOffset + 1, receiverRelayOffset)) ? "" : undefined;
                if (data[0] & 128) {
                    const signature = data.subarray(data.length - crypto.EdDSA.signatureLength);
                    if (!crypto.EdDSA.verify(data.subarray(0, data.length - crypto.EdDSA.signatureLength), signature, data.subarray(28, 28 + crypto.EdDSA.publicKeyLength)))
                        throw new Error('Invalid signature for Datagram');
                }
                if (data[0] & 64)
                    this.payload = fflate.inflateSync(data.subarray(receiverRelayOffset + 1, data.length));
                else
                    this.payload = data.subarray(receiverRelayOffset + 1, data.length);
            } else if (Datagram.isDatagram(data)) {
                const datagram = data as Datagram;
                this.id = datagram.id;
                this.version = datagram.version;
                this.senderKey = datagram.senderKey;
                this.receiverKey = datagram.receiverKey;
                this.protocol = datagram.protocol;
                this.createdAt = datagram.createdAt;
                this.senderRelay = datagram.senderRelay;
                this.receiverRelay = datagram.receiverRelay;
                this.payload = datagram.payload;
            } else throw new Error('Invalid constructor arguments for Datagram');
        } else if (typeof data === 'string' || data instanceof Uint8Array) {
            this.id = crypto.UUID.generate().toString();
            this.version = Datagram.version;
            if (typeof data === 'string') {
                const address = data.split('@');
                this.senderKey = address[0];
                this.senderRelay = address[1];
            } else
                this.senderKey = encodeBase64(data);
            if (typeof receiver === 'string') {
                const address = receiver.split('@');
                this.receiverKey = address[0];
                this.receiverRelay = address[1];
            } else
                this.receiverKey = encodeBase64(receiver);
            this.protocol = protocol!;
            this.createdAt = Date.now();
            this.payload = payload instanceof Uint8Array ? payload : payload?.encode();
        } else throw new Error('Invalid constructor arguments for Datagram');
    }

    public encode(compression: boolean = true): Uint8Array {
        compression = compression && this.payload != undefined && this.payload.length > 1024;
        return concatUint8Array(
            new Uint8Array(1).fill(this.version | (compression ? 64 : 0)), //1
            Protocols.encode(this.protocol, 3), //3
            crypto.UUID.parse(this.id) ?? [], //16
            numberToUint8Array(this.createdAt, 8), //8
            decodeBase64(this.senderKey), //32
            decodeBase64(this.receiverKey), //32
            ...(this.senderRelay ? [decodeUTF8(this.senderRelay)] : []),
            new Uint8Array(1).fill(255),
            ...(this.receiverRelay ? [decodeUTF8(this.receiverRelay)] : []),
            new Uint8Array(1).fill(255),
            ...(this.payload ? [compression ? fflate.deflateSync(this.payload) : this.payload] : [])
        );
    }

    public encodeSigned(secretKey: Uint8Array, compression?: boolean): Uint8Array {
        //if (!this.payload) throw new Error('Cannot sign a datagram without payload');
        const header = this.encode(compression);
        header[0] |= 128; // Set the sign bit
        const signature = crypto.EdDSA.sign(header, secretKey);
        return concatUint8Array(header, signature);
    }

    public toString(): string {
        return encodeBase64(this.encode());
    }

    public toJSON(): string {
        /*return JSON.stringify({
            id: this.id,
            version: this.version,
            senderKey: this.senderKey,
            senderRelay: this.senderRelay,
            receiverKey: this.receiverKey,
            receiverRelay: this.receiverRelay,
            protocol: this.protocol,
            createdAt: this.createdAt,
            payload: this.payload ? encodeBase64(this.payload) : undefined
        });*/
        return this.toString();
    }
}