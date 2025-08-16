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
import { Encodable } from "./type";

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
                this.id = crypto.UUID.stringify(data.subarray(0, 16));
                this.version = data[16];
                this.protocol = Protocols.decode(data.subarray(17, 20));
                this.createdAt = numberFromUint8Array(data.subarray(20, 28));
                this.senderKey = encodeBase64(data.subarray(28, 28 + crypto.EdDSA.publicKeyLength));
                this.receiverKey = encodeBase64(data.subarray(28 + crypto.EdDSA.publicKeyLength, DatagramConstructor.headerOffset));
                const senderRelayOffset = data.indexOf(255, DatagramConstructor.headerOffset)
                const receiverRelayOffset = data.indexOf(255, senderRelayOffset + 1);
                this.senderRelay = encodeUTF8(data.subarray(DatagramConstructor.headerOffset, senderRelayOffset)) ? "" : undefined;
                this.receiverRelay = encodeUTF8(data.subarray(senderRelayOffset + 1, receiverRelayOffset)) ? "" : undefined;
                /*try {
                    this.payload = fflate.inflateSync(data.subarray(receiverRelayOffset + 1, data.length));
                } catch (error) {*/
                    this.payload = data.subarray(receiverRelayOffset + 1, data.length);
                //}
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

    public encode(): Uint8Array {
        return concatUint8Array(
            crypto.UUID.parse(this.id) ?? [], //16
            new Uint8Array(1).fill(this.version), //1
            Protocols.encode(this.protocol, 3), //3
            numberToUint8Array(this.createdAt, 8), //8
            decodeBase64(this.senderKey), //32
            decodeBase64(this.receiverKey), //32
            ...(this.senderRelay ? [decodeUTF8(this.senderRelay)] : []),
            new Uint8Array(1).fill(255),
            ...(this.receiverRelay ? [decodeUTF8(this.receiverRelay)] : []),
            new Uint8Array(1).fill(255),
            //...(this.payload ? [this.payload.length > 100 ? fflate.deflateSync(this.payload) : this.payload] : [])
            ...(this.payload ? [this.payload] : [])
        );
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

type Attachment = Encodable | Uint8Array; // Define Attachment type as needed

export interface Message {
    readonly id: string;
    readonly version: number;
    text: string;
    group?: string;
    attachments?: Attachment[];
}
export namespace Message {
    export function isMessage(obj: any): boolean {
        return obj instanceof MessageConstructor || (obj && typeof obj === 'object' && 'version' in obj && 'text' in obj && 'group' in obj && 'attachments' in obj);
    }

    export function create(opts?: { text?: string, group?: string, attachments?: Attachment[] }): MessageConstructor {
        return new MessageConstructor(opts);
    };

    export function from(data: Uint8Array | Message): MessageConstructor {
        return new MessageConstructor(data);
    }
}

class MessageConstructor implements Encodable, Message {
    public static readonly version = 1;

    public readonly id;
    public readonly version: number = MessageConstructor.version;
    public text: string = "";
    public group?: string;
    public attachments?: Attachment[];

    constructor(opts?: { text?: string, group?: string, attachments?: Attachment[] })
    constructor(data: Uint8Array | Message)
    constructor(opts?: { text?: string, group?: string, attachments?: Attachment[] } | Uint8Array | Message) {
        if (Message.isMessage(opts)) {
            const json: Message = opts as Message;
            this.id = json.id;
            this.version = json.version;
            this.text = json.text;
            this.group = json.group;
            this.attachments = json.attachments;
        } else if (!opts) {
            this.id = crypto.UUID.generate().toString()
            this.text = "";
        } else if (opts instanceof Uint8Array) {
            this.id = crypto.UUID.stringify(opts.subarray(0, 16));
            this.version = opts[16];
            const textOffset = opts.indexOf(255, 17);
            const groupOffset = opts.indexOf(255, textOffset + 1);
            this.text = encodeUTF8(opts.subarray(17, textOffset));
            this.group = encodeUTF8(opts.subarray(textOffset + 1, groupOffset));
            //this.attachments = 
        } else if (typeof opts === 'object') {
            const { text, group, attachments } = opts as { text?: string, group?: string, attachments?: Attachment[] };
            this.id = crypto.UUID.generate().toString()
            this.text = text || "";
            this.group = group;
            this.attachments = attachments || [];
        } else {
            throw new Error('Invalid constructor arguments for Message');
        }
    }

    public setText(str: string): this {
        this.text = str;
        return this;
    }

    public setGroup(str: string): this {
        this.group = str;
        return this;
    }

    public addAttachment(obj: Attachment): this {
        if (this.attachments)
            this.attachments.push(obj)
        else
            this.attachments = [obj];
        return this;
    }

    public delAttachment(obj: Attachment): this | undefined {
        const index = this.attachments?.indexOf(obj)
        if (!index || !this.attachments) return undefined;
        this.attachments = this.attachments.filter((v, i) => index !== i)
        return this;
    }

    public encode(): Uint8Array {
        return concatUint8Array(
            crypto.UUID.parse(this.id), //16
            new Uint8Array(1).fill(this.version),
            ...(this.text === "" ? [] : [decodeUTF8(this.text)]),
            new Uint8Array(1).fill(255),
            ...(this.text ? [] : [decodeUTF8(this.group)]),
            new Uint8Array(1).fill(255),
            ...(this.attachments?.flatMap(value => {
                if (value instanceof Uint8Array) {
                    return [new Uint8Array(4).fill(value.length), value]
                } else {
                    const encoded = value.encode();
                    return [new Uint8Array(4).fill(encoded.length), encoded]
                }
            }) ?? [])
        )
    }

    public toString(): string {
        return this.toJSON();
    }

    public toJSON(): string {
        return JSON.stringify({
            version: MessageConstructor.version,
            text: this.text,
            group: this.group,
            attachments: JSON.stringify(this.attachments)
        });
    }
}

type LocalStorageIterator<T> = Iterable<T>;

export interface LocalStorage<K, T> {
    set(key: K, value: T): this;
    get(key: K): T | undefined;
    has(key: K): boolean;
    delete(key: K): boolean;
    entries(): LocalStorageIterator<[K, T]>
}