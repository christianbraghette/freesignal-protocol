import crypto from "./crypto";
import { LocalStorage } from "./data";
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
export function createKeyExchange(signKeyPair: crypto.KeyPair, bundleStore?: LocalStorage<string, crypto.KeyPair>): KeyExchange {
    return new KeyExchange(signKeyPair, bundleStore);
}