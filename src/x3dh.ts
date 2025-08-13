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

import crypto from "./crypto";
import { LocalStorage } from "./data";
import { KeySession } from "./double-ratchet";
import { concatUint8Array, decodeBase64, decodeUTF8, encodeBase64, encodeUTF8, verifyUint8Array } from "./utils";

interface SynMessage {
    readonly version: number;
    readonly publicKey: string;
    readonly identityKey: string;
    readonly signedPreKey: string;
    readonly signature: string;
    readonly onetimePreKey: string;
}

interface AckMessage {
    readonly version: number;
    readonly publicKey: string;
    readonly identityKey: string;
    readonly ephemeralKey: string;
    readonly signedPreKeyHash: string;
    readonly onetimePreKeyHash: string;
    readonly associatedData: string;
}

export interface Bundle {
    readonly version: number;
    readonly publicKey: string;
    readonly identityKey: string;
    readonly signedPreKey: string;
    readonly signature: string;
    readonly onetimePreKeyHash: string[];
}

export class KeyExchange {
    public static readonly version = 1;
    private static readonly hkdfInfo = decodeUTF8("freesignal/x3dh/" + KeyExchange.version);
    private static readonly maxOPK = 10;

    private readonly publicKey: crypto.KeyPair;
    private readonly identityKey: crypto.KeyPair;
    private readonly bundleStore: LocalStorage<string, crypto.KeyPair>;

    public constructor(signKeyPair: crypto.KeyPair, bundleStore?: LocalStorage<string, crypto.KeyPair>) {
        this.publicKey = signKeyPair;
        this.identityKey = crypto.ECDH.keyPair(crypto.hash(signKeyPair.secretKey));
        this.bundleStore = bundleStore ?? new Map<string, crypto.KeyPair>();
    }

    private generateSPK(): { signedPreKey: crypto.KeyPair, signedPreKeyHash: Uint8Array } {
        const signedPreKey = crypto.ECDH.keyPair();
        const signedPreKeyHash = crypto.hash(signedPreKey.publicKey);
        this.bundleStore.set(encodeBase64(signedPreKeyHash), signedPreKey);
        return { signedPreKey, signedPreKeyHash };
    }

    private generateOPK(spkHash: Uint8Array): { onetimePreKey: crypto.KeyPair, onetimePreKeyHash: Uint8Array } {
        const onetimePreKey = crypto.ECDH.keyPair();
        const onetimePreKeyHash = crypto.hash(onetimePreKey.publicKey);
        this.bundleStore.set(encodeBase64(spkHash).concat(encodeBase64(onetimePreKeyHash)), onetimePreKey);
        return { onetimePreKey, onetimePreKeyHash };
    }

    public generateBundle(length?: number): Bundle {
        const { signedPreKey, signedPreKeyHash } = this.generateSPK();
        const onetimePreKey = new Array(length ?? KeyExchange.maxOPK).fill(0).map(() => this.generateOPK(signedPreKeyHash).onetimePreKey);
        return {
            version: KeyExchange.version,
            publicKey: encodeBase64(this.publicKey.publicKey),
            identityKey: encodeBase64(this.identityKey.publicKey),
            signedPreKey: encodeBase64(signedPreKey.publicKey),
            signature: encodeBase64(crypto.EdDSA.sign(signedPreKeyHash, this.publicKey.secretKey)),
            onetimePreKeyHash: onetimePreKey.map(opk => encodeBase64(opk.publicKey))
        }
    }

    public generateSyn(): SynMessage {
        const { signedPreKey, signedPreKeyHash } = this.generateSPK();
        const { onetimePreKey } = this.generateOPK(signedPreKeyHash);
        return {
            version: KeyExchange.version,
            publicKey: encodeBase64(this.publicKey.publicKey),
            identityKey: encodeBase64(this.identityKey.publicKey),
            signedPreKey: encodeBase64(signedPreKey.publicKey),
            signature: encodeBase64(crypto.EdDSA.sign(signedPreKeyHash, this.publicKey.secretKey)),
            onetimePreKey: encodeBase64(onetimePreKey.publicKey)
        }
    }

    public digestSyn(message: SynMessage): { session: KeySession, ackMessage: AckMessage } {
        const ephemeralKey = crypto.ECDH.keyPair();
        const signedPreKey = decodeBase64(message.signedPreKey);
        const identityKey = decodeBase64(message.identityKey);
        const onetimePreKey = message.onetimePreKey ? decodeBase64(message.onetimePreKey) : undefined;
        const signedPreKeyHash = crypto.hash(signedPreKey);
        const onetimePreKeyHash = onetimePreKey ? crypto.hash(onetimePreKey) : new Uint8Array();
        const rootKey = crypto.hkdf(new Uint8Array([
            ...crypto.scalarMult(this.identityKey.secretKey, signedPreKey),
            ...crypto.scalarMult(ephemeralKey.secretKey, identityKey),
            ...crypto.scalarMult(ephemeralKey.secretKey, signedPreKey),
            ...onetimePreKey ? crypto.scalarMult(ephemeralKey.secretKey, onetimePreKey) : new Uint8Array()
        ]), new Uint8Array(KeySession.rootKeyLength).fill(0), KeyExchange.hkdfInfo, KeySession.rootKeyLength);
        const session = new KeySession({ secretKey: this.identityKey.secretKey, remoteKey: identityKey, rootKey });
        const cyphertext = session.encrypt(concatUint8Array(crypto.hash(this.identityKey.publicKey), crypto.hash(identityKey)));
        if (!cyphertext) throw new Error();
        return {
            session,
            ackMessage: {
                version: KeyExchange.version,
                publicKey: encodeBase64(this.publicKey.publicKey),
                identityKey: encodeBase64(this.identityKey.publicKey),
                ephemeralKey: encodeBase64(ephemeralKey.publicKey),
                signedPreKeyHash: encodeBase64(signedPreKeyHash),
                onetimePreKeyHash: encodeBase64(onetimePreKeyHash),
                associatedData: encodeBase64(cyphertext.encode())
            }
        }
    }

    public digestAck(message: AckMessage): { session: KeySession, cleartext: Uint8Array } {
        const signedPreKey = this.bundleStore.get(message.signedPreKeyHash);
        const hash = message.signedPreKeyHash.concat(message.onetimePreKeyHash);
        const onetimePreKey = this.bundleStore.get(hash);
        if (!signedPreKey || !onetimePreKey || !message.identityKey || !message.ephemeralKey) throw new Error("ACK message malformed");
        if (!this.bundleStore.delete(hash)) throw new Error("Bundle store deleting error");
        const identityKey = decodeBase64(message.identityKey);
        const ephemeralKey = decodeBase64(message.ephemeralKey);
        const rootKey = crypto.hkdf(new Uint8Array([
            ...crypto.scalarMult(signedPreKey.secretKey, identityKey),
            ...crypto.scalarMult(this.identityKey.secretKey, ephemeralKey),
            ...crypto.scalarMult(signedPreKey.secretKey, ephemeralKey),
            ...onetimePreKey ? crypto.scalarMult(onetimePreKey.secretKey, ephemeralKey) : new Uint8Array()
        ]), new Uint8Array(KeySession.rootKeyLength).fill(0), KeyExchange.hkdfInfo, KeySession.rootKeyLength);
        const session = new KeySession({ secretKey: this.identityKey.secretKey, rootKey })
        const cleartext = session.decrypt(decodeBase64(message.associatedData));
        if (!cleartext) throw new Error("Error decrypting ACK message");
        return { session, cleartext };
    }
}