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
import { KeySession } from "./double-ratchet";
import { KeyExchange } from "./x3dh";

/**
 * Creates a new Double Ratchet session.
 * 
 * @param opts.remoteKey The public key of the remote party.
 * @param opts.preSharedKey An optional pre-shared key to initialize the session.
 *   
 * @returns A new Double Ratchet session.
 */
export function createKeySession(opts?: { secretKey?: Uint8Array, remoteKey?: Uint8Array, rootKey?: Uint8Array }): KeySession {
    return new KeySession(opts);
}

/**
 * Creates a new X3DH session.
 * 
 * @param signKeyPair 
 * @param bundleStore 
 * @returns A new X3DH session.
 */
export function createKeyExchange(signSecretKey: Uint8Array, boxSecretKey: Uint8Array, bundleStore?: LocalStorage<string, crypto.KeyPair>): KeyExchange {
    return new KeyExchange(signSecretKey, boxSecretKey, bundleStore);
}

export function createIdentityKeys(signSecretKey?: Uint8Array, boxSecretKey?: Uint8Array): { sign: Crypto.KeyPair, box: Crypto.KeyPair } {
    return {
        sign: crypto.EdDSA.keyPair(signSecretKey),
        box: crypto.ECDH.keyPair(boxSecretKey)
    };
}

/*export function createAPI(opts: {
    secretSignKey: Uint8Array;
    secretBoxKey: Uint8Array;
    sessions: LocalStorage<UserId, KeySession>;
    keyExchange: LocalStorage<string, Crypto.KeyPair>;
    users: LocalStorage<UserId, IdentityKeys>;
}): FreeSignalAPI {
    return new FreeSignalAPI(opts);
}*/

export { IdentityKeys, Protocols, EncryptedData, Datagram } from "./types";