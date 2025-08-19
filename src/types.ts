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
    set(key: K, value: T): this;
    get(key: K): T | undefined;
    has(key: K): boolean;
    delete(key: K): boolean;
    entries(): LocalStorageIterator<[K, T]>
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