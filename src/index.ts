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

import crypto from "@freesignal/crypto";
import { LocalStorage, Crypto, Database } from "@freesignal/interfaces";
import { ExportedKeySession, KeySession } from "./double-ratchet";
import { KeyExchange } from "./x3dh";
import { IdentityKey, PrivateIdentityKey } from "./types";
import { FreeSignalNode } from "./node";

/**
 * Creates a new Double Ratchet session for secure message exchange.
 *
 * @param opts - Optional parameters for session initialization.
 * @param opts.secretKey - The local party's secret key as a Uint8Array.
 * @param opts.remoteKey - The remote party's public key as a Uint8Array.
 * @param opts.rootKey - An optional root key to initialize the session.
 * @returns A new instance of {@link KeySession}.
 */
/*export function createKeySession(storage: LocalStorage<string, ExportedKeySession>, opts?: { secretKey?: Uint8Array, remoteKey?: Uint8Array, rootKey?: Uint8Array }): KeySession {
    return new KeySession(storage, opts);
}*/

/**
 * Creates a new X3DH (Extended Triple Diffie-Hellman) key exchange session.
 *
 * @param storage - Local storage for keys.
 * @returns A new instance of {@link KeyExchange}.
 */
/*export function createKeyExchange(storage: { keys: LocalStorage<string, Crypto.KeyPair>, sessions: LocalStorage<string, ExportedKeySession> }, privateIdentityKey?: PrivateIdentityKey): KeyExchange {
    return new KeyExchange(storage, privateIdentityKey);
}*/

/**
 * Generates identity key
 *
 * @param seed - Seed to generate the key.
 * @returns An object containing readonly signing and box key pairs.
 */
export function createIdentity(seed?: Uint8Array): PrivateIdentityKey {
    seed ??= crypto.randomBytes(crypto.EdDSA.seedLength);
    const signatureSeed = crypto.hkdf(seed, new Uint8Array(crypto.EdDSA.seedLength).fill(0), "identity-ed25519", crypto.EdDSA.seedLength);
    const exchangeSeed = crypto.hkdf(seed, new Uint8Array(crypto.ECDH.secretKeyLength).fill(0), "identity-x25519", crypto.ECDH.secretKeyLength);
    const signatureKeyPair = crypto.EdDSA.keyPairFromSeed(signatureSeed);
    const exchangeKeyPair = crypto.ECDH.keyPair(exchangeSeed);
    return PrivateIdentityKey.from(signatureKeyPair.secretKey, exchangeKeyPair.secretKey);
}

/** */
export function createNode(storage: Database<{
    sessions: LocalStorage<string, ExportedKeySession>;
    keyExchange: LocalStorage<string, Crypto.KeyPair>;
    users: LocalStorage<string, IdentityKey>;
}>, privateIdentityKey?: PrivateIdentityKey): FreeSignalNode {
    return new FreeSignalNode(storage, privateIdentityKey);
}

export * from "./types";