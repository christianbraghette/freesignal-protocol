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
import { LocalStorage, Crypto } from "@freesignal/interfaces";
import { ExportedKeySession, KeySession } from "./double-ratchet";
import { KeyExchange } from "./x3dh";
import { IdentityKey } from "./types";

/**
 * Creates a new Double Ratchet session for secure message exchange.
 *
 * @param opts - Optional parameters for session initialization.
 * @param opts.secretKey - The local party's secret key as a Uint8Array.
 * @param opts.remoteKey - The remote party's public key as a Uint8Array.
 * @param opts.rootKey - An optional root key to initialize the session.
 * @returns A new instance of {@link KeySession}.
 */
export function createKeySession(storage: LocalStorage<string, ExportedKeySession>, opts?: { secretKey?: Uint8Array, remoteKey?: Uint8Array, rootKey?: Uint8Array }): KeySession {
    return new KeySession(storage, opts);
}

/**
 * Creates a new X3DH (Extended Triple Diffie-Hellman) key exchange session.
 *
 * @param storage - Local storage for keys.
 * @returns A new instance of {@link KeyExchange}.
 */
export function createKeyExchange(storage: { keys: LocalStorage<string, Crypto.KeyPair>, sessions: LocalStorage<string, ExportedKeySession> }, secretSignKey?: Uint8Array, secretIdentityKey?: Uint8Array): KeyExchange {
    return new KeyExchange(storage, secretSignKey, secretIdentityKey);
}

/**
 * Generates key pairs for signing and encryption.
 *
 * @param signSecretKey - Optional secret key for EdDSA signing.
 * @param boxSecretKey - Optional secret key for ECDH encryption.
 * @returns An object containing readonly signing and box key pairs.
 */
export function createIdentityKeys(signSecretKey?: Uint8Array, boxSecretKey?: Uint8Array): { readonly identityKey: IdentityKey, readonly signatureKeyPair: Crypto.KeyPair, readonly exchangeKeyPair: Crypto.KeyPair } {
    const signatureKeyPair = crypto.EdDSA.keyPair(signSecretKey);
    const exchangeKeyPair = crypto.ECDH.keyPair(boxSecretKey);
    return { signatureKeyPair, exchangeKeyPair, identityKey: IdentityKey.from(signatureKeyPair.publicKey, exchangeKeyPair.publicKey) };
}

export * from "./types";