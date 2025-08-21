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
import { Encodable, Protocols } from "./types";

export interface Datagram {
    readonly id: string;
    readonly version: number;
    readonly sender: string;
    readonly receiver: string;
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

    export function from(data: Uint8Array | Datagram | string): DatagramConstructor {
        if (typeof data === 'string') {
            const decoded = decodeBase64(data);
            return new DatagramConstructor(decoded);
        } else return new DatagramConstructor(data);
    }
}

class DatagramConstructor implements Encodable, Datagram {
    public readonly id: string;
    public readonly version: number;
    public readonly sender: string;
    public readonly receiver: string;
    public readonly protocol: Protocols;
    public readonly createdAt: number;
    public payload?: Uint8Array;

    private static headerOffset = 26 + crypto.EdDSA.publicKeyLength * 2;

    public constructor(sender: Uint8Array | string, receiver: Uint8Array | string, protocol: Protocols, payload?: Uint8Array | Encodable)
    public constructor(data: Uint8Array | Datagram)
    public constructor(data: Uint8Array | string | Datagram, receiver?: Uint8Array | string, protocol?: Protocols, payload?: Uint8Array | Encodable) {
        if (!receiver && !protocol && !payload) {
            if (data instanceof Uint8Array) {
                this.version = data[0] & 63;
                this.protocol = Protocols.decode(data.subarray(1, 2));
                this.id = crypto.UUID.stringify(data.subarray(2, 18));
                this.createdAt = numberFromUint8Array(data.subarray(18, 26));
                this.sender = encodeBase64(data.subarray(26, 26 + crypto.EdDSA.publicKeyLength));
                this.receiver = encodeBase64(data.subarray(26 + crypto.EdDSA.publicKeyLength, DatagramConstructor.headerOffset));
                if (data[0] & 128) {
                    const signature = data.subarray(data.length - crypto.EdDSA.signatureLength);
                    if (!crypto.EdDSA.verify(data.subarray(0, data.length - crypto.EdDSA.signatureLength), signature, data.subarray(26, 26 + crypto.EdDSA.publicKeyLength)))
                        throw new Error('Invalid signature for Datagram');
                }
                if (data[0] & 64)
                    this.payload = fflate.inflateSync(data.subarray(DatagramConstructor.headerOffset, data.length));
                else
                    this.payload = data.subarray(DatagramConstructor.headerOffset, data.length);
            } else if (Datagram.isDatagram(data)) {
                const datagram = data as Datagram;
                this.id = datagram.id;
                this.version = datagram.version;
                this.sender = datagram.sender;
                this.receiver = datagram.receiver;
                this.protocol = datagram.protocol;
                this.createdAt = datagram.createdAt;
                this.payload = datagram.payload;
            } else throw new Error('Invalid constructor arguments for Datagram');
        } else if (typeof data === 'string' || data instanceof Uint8Array) {
            this.id = crypto.UUID.generate().toString();
            this.version = Datagram.version;
            this.sender = typeof data === 'string' ? data : encodeBase64(data);
            this.receiver = typeof receiver === 'string' ? receiver : encodeBase64(receiver);
            this.protocol = protocol!;
            this.createdAt = Date.now();
            this.payload = payload instanceof Uint8Array ? payload : payload?.encode();
        } else throw new Error('Invalid constructor arguments for Datagram');
    }

    public encode(compression: boolean = true): Uint8Array {
        compression = compression && this.payload != undefined && this.payload.length > 1024;
        return concatUint8Array(
            new Uint8Array(1).fill(this.version | (compression ? 64 : 0)), //1
            Protocols.encode(this.protocol), //1
            crypto.UUID.parse(this.id) ?? [], //16
            numberToUint8Array(this.createdAt, 8), //8
            decodeBase64(this.sender), //32
            decodeBase64(this.receiver), //32
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