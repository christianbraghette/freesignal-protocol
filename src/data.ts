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

import { decodeUTF8, encodeBase64, encodeUTF8, numberFromUint8Array, numberToUint8Array } from "./utils";
import crypto from "./crypto";

export interface Encodable {
    readonly length: number;

    encode(): Uint8Array;
    toString(): string;
    toJSON(): string;
}
export namespace Encodable {
    const properties = ['length', 'encode', 'toString', 'toJSON'];

    export function isEncodable(obj: any): boolean {
        return !properties.some(prop => !obj[prop]);
    }
}

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
        const raw = numberToUint8Array(Protocols.toCode(protocol), length).reverse();
        raw[0] |= (raw.length - 1) << 6;
        return raw;
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
    readonly sender: string;
    readonly receiver: string;
    readonly protocol: Protocols;
    payload?: Uint8Array;
    readonly createdAt: number;
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
    public readonly createdAt: number;
    public readonly id: string;
    public readonly version: number;
    public readonly sender: string;
    public readonly receiver: string;
    public readonly protocol: Protocols;
    public payload?: Uint8Array;

    public constructor(sender: Uint8Array | string, receiver: Uint8Array | string, protocol: Protocols, payload?: Uint8Array | Encodable)
    public constructor(data: Uint8Array | Datagram)
    public constructor(data: Uint8Array | string | Datagram, receiver?: Uint8Array | string, protocol?: Protocols, payload?: Uint8Array | Encodable) {
        if (!receiver && !protocol && !payload) {
            if (data instanceof Uint8Array) {
                const obj = encodeUTF8(data).split(',');
                this.id = obj[0];
                this.version = parseInt(obj[1]);
                this.sender = obj[2];
                this.receiver = obj[3];
                this.protocol = Protocols.fromCode(parseInt(obj[4]));
                this.payload = obj[5] ? decodeUTF8(obj[5]) : undefined;
                this.createdAt = parseInt(obj[6]);

            } else {
                const datagram = data as Datagram;
                this.id = datagram.id;
                this.version = datagram.version;
                this.sender = datagram.sender;
                this.receiver = datagram.receiver;
                this.protocol = datagram.protocol;
                this.payload = datagram.payload;
                this.createdAt = datagram.createdAt;
            }
        } else if (typeof data === 'string' || data instanceof Uint8Array) {
            this.id = crypto.generateId().toString();
            this.version = Datagram.version;
            this.sender = typeof data === 'string' ? data : encodeBase64(data);
            this.receiver = typeof receiver === 'string' ? receiver : encodeBase64(receiver);
            this.protocol = protocol!;
            this.payload = payload instanceof Uint8Array ? payload : payload?.encode();
            this.createdAt = Date.now();
        } else throw new Error('Invalid constructor arguments for Datagram');
    }

    public get length() { return this.encode().length; }

    public encode(): Uint8Array {
        return decodeUTF8([
            this.id,
            this.version,
            this.sender,
            this.receiver,
            Protocols.toCode(this.protocol).toString(),
            this.payload ? this.payload : undefined, this.createdAt
        ].filter(x => x !== undefined).join(','));
    }

    public toString(): string {
        return this.toJSON();
    }

    public toJSON(): string {
        return JSON.stringify({
            id: this.id,
            version: this.version,
            sender: this.sender,
            receiver: this.receiver,
            protocol: this.protocol,
            payload: this.payload ? encodeUTF8(this.payload) : undefined,
            createdAt: this.createdAt
        });
    }
}

type Attachment = any; // Define Attachment type as needed

export interface Message {
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

    public readonly version: number = MessageConstructor.version;
    public text: string = "";
    public group?: string;
    public attachments?: Attachment[];

    constructor(opts?: { text?: string, group?: string, attachments?: Attachment[] })
    constructor(data: Uint8Array | Message)
    constructor(opts?: { text?: string, group?: string, attachments?: Attachment[] } | Uint8Array | Message) {
        if (Message.isMessage(opts)) {
            const json: Message = opts as Message;
            this.version = json.version;
            this.text = json.text;
            this.group = json.group;
            this.attachments = json.attachments;
        } else if (!opts) {
            this.text = "";
        } else if (opts instanceof Uint8Array) {
            const arr: Array<any> = encodeUTF8(opts).split(',');
            this.version = arr[0];
            this.text = arr[1] ?? "";
            this.group = arr[2];
            this.attachments = arr[3] ? JSON.parse(arr[3]) : undefined;
        } else if (typeof opts === 'object') {
            const { text, group, attachments } = opts as { text?: string, group?: string, attachments?: Attachment[] };
            this.text = text || "";
            this.group = group;
            this.attachments = attachments || [];
        } else {
            throw new Error('Invalid constructor arguments for Message');
        }
    }

    public get length(): number { return this.encode().length; }

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
        return decodeUTF8([this.version, this.text, this.group, JSON.stringify(this.attachments || [])].join(','));
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