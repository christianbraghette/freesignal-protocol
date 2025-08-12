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
import { Session } from "./double-ratchet";
import { concatUint8Array, decodeBase64, decodeUTF8, encodeBase64, encodeUTF8, verifyUint8Array } from "./utils";

type BoxKeyPair = crypto.KeyPair;
type SignKeyPair = crypto.KeyPair;

type BundleStore = {
    readonly SPK: Map<string, BoxKeyPair>,
    readonly OPK: Map<string, BoxKeyPair>
}

type ExportedX3DH = [
    SignKeyPair,
    [
        Array<[string, BoxKeyPair]>,
        Array<[string, BoxKeyPair]>
    ]
];

interface SynMessage {
    readonly version: number;
    readonly PK: string;
    readonly IK: string;
    readonly SPK: string;
    readonly SPKsign: string;
    readonly OPK: string;
}

interface AckMessage {
    readonly version: number;
    readonly PK: string;
    readonly IK: string;
    readonly EK: string;
    readonly SPKhash: string;
    readonly OPKhash: string;
    readonly AD: string;
}

export interface Bundle {
    readonly version: number;
    readonly PK: string;
    readonly IK: string;
    readonly SPK: string;
    readonly SPKsign: string;
    readonly OPK: string[];
}

export class X3DH {
    public static readonly version = 1;
    private static readonly hkdfInfo = decodeUTF8("freesignal/x3dh/" + X3DH.version);
    private static readonly maxOPK = 10;

    private readonly PK: SignKeyPair;
    private readonly IK: BoxKeyPair;
    private readonly bundleStore: BundleStore;

    public constructor(signKeyPair: SignKeyPair, instance?: [Iterable<[string, BoxKeyPair]>, Iterable<[string, BoxKeyPair]>]) {
        this.PK = signKeyPair;
        this.IK = crypto.ECDH.keyPair(crypto.hash(signKeyPair.secretKey));
        this.bundleStore = {
            SPK: new Map(instance ? instance[0] : []),
            OPK: new Map(instance ? instance[1] : [])
        };
    }

    private generateSPK(): {
        SPK: BoxKeyPair,
        SPKhash: Uint8Array
    } {
        const SPK = crypto.ECDH.keyPair();
        const SPKhash = crypto.hash(SPK.publicKey);
        this.bundleStore.SPK.set(encodeBase64(SPKhash), SPK);
        return { SPK, SPKhash };
    }

    private generateOPK(spkHash: Uint8Array): { OPK: BoxKeyPair, OPKhash: Uint8Array } {
        const OPK = crypto.ECDH.keyPair();
        const OPKhash = crypto.hash(OPK.publicKey);
        this.bundleStore.OPK.set(encodeBase64(spkHash).concat(encodeBase64(OPKhash)), OPK);
        return { OPK, OPKhash };
    }

    public generateBundle(length?: number): Bundle {
        const { SPK, SPKhash } = this.generateSPK();
        const OPK = new Array(length ?? X3DH.maxOPK).fill(0).map(() => this.generateOPK(SPKhash).OPK);
        return {
            version: X3DH.version,
            PK: encodeBase64(this.PK.publicKey),
            IK: encodeBase64(this.IK.publicKey),
            SPK: encodeBase64(SPK.publicKey),
            SPKsign: encodeBase64(crypto.EdDSA.sign(concatUint8Array(crypto.hash(this.IK.publicKey), SPKhash), this.PK.secretKey)),
            OPK: OPK.map(opk => encodeBase64(opk.publicKey))
        }
    }

    public generateSyn(): SynMessage {
        const { SPK, SPKhash } = this.generateSPK();
        const { OPK } = this.generateOPK(SPKhash);
        return {
            version: X3DH.version,
            PK: encodeBase64(this.PK.publicKey),
            IK: encodeBase64(this.IK.publicKey),
            SPK: encodeBase64(SPK.publicKey),
            SPKsign: encodeBase64(crypto.EdDSA.sign(concatUint8Array(crypto.hash(this.IK.publicKey), SPKhash), this.PK.secretKey)),
            OPK: encodeBase64(OPK.publicKey)
        }
    }

    public digestSyn(message: SynMessage, encrypter?: (msg: Uint8Array, key: Uint8Array) => Uint8Array): { rootKey: Uint8Array, ackMessage: AckMessage } {
        const EK = crypto.ECDH.keyPair();
        const SPK = decodeBase64(message.SPK);
        const IK = decodeBase64(message.IK);
        const OPK = message.OPK ? decodeBase64(message.OPK) : undefined;
        const spkHash = crypto.hash(SPK);
        const opkHash = OPK ? crypto.hash(OPK) : new Uint8Array();
        const rootKey = crypto.hkdf(new Uint8Array([
            ...crypto.scalarMult(this.IK.secretKey, SPK),
            ...crypto.scalarMult(EK.secretKey, IK),
            ...crypto.scalarMult(EK.secretKey, SPK),
            ...OPK ? crypto.scalarMult(EK.secretKey, OPK) : new Uint8Array()
        ]), new Uint8Array(Session.rootKeyLength).fill(0), X3DH.hkdfInfo, Session.rootKeyLength)
        if (!encrypter) encrypter = (msg, key) => crypto.box.encrypt(msg, new Uint8Array(crypto.box.nonceLength).fill(0), key);
        return {
            rootKey,
            ackMessage: {
                version: X3DH.version,
                PK: encodeBase64(this.PK.publicKey),
                IK: encodeBase64(this.IK.publicKey),
                EK: encodeBase64(EK.publicKey),
                SPKhash: encodeBase64(spkHash),
                OPKhash: encodeBase64(opkHash),
                AD: encodeBase64(encrypter(concatUint8Array(crypto.hash(this.IK.publicKey), crypto.hash(IK)), rootKey))
            }
        }
    }

    public digestAck(message: AckMessage, verifier?: (ciphertext: Uint8Array, key: Uint8Array) => boolean): Uint8Array | undefined {
        const SPK = this.bundleStore.SPK.get(message.SPKhash);
        const OPK = this.bundleStore.OPK.get(message.SPKhash.concat(message.OPKhash));
        if (!SPK || !OPK || !message.IK || !message.EK) return;
        const IK = decodeBase64(message.IK);
        const EK = decodeBase64(message.EK);
        const rootKey = crypto.hkdf(new Uint8Array([
            ...crypto.scalarMult(SPK.secretKey, IK),
            ...crypto.scalarMult(this.IK.secretKey, EK),
            ...crypto.scalarMult(SPK.secretKey, EK),
            ...OPK ? crypto.scalarMult(OPK.secretKey, EK) : new Uint8Array()
        ]), new Uint8Array(Session.rootKeyLength).fill(0), X3DH.hkdfInfo, Session.rootKeyLength);
        if (!verifier) verifier = (ciphertext, key) => verifyUint8Array(crypto.box.decrypt(ciphertext, new Uint8Array(crypto.box.nonceLength).fill(0), key), concatUint8Array(crypto.hash(IK), crypto.hash(this.IK.publicKey)));
        if (!verifier(decodeBase64(message.AD), rootKey)) return;
        return rootKey;
    }

    public export(): ExportedX3DH {
        return [
            this.IK,
            [
                Array.from(this.bundleStore.SPK.entries()),
                Array.from(this.bundleStore.OPK.entries())
            ]
        ]
    }

    public static import(input: ExportedX3DH): X3DH {
        return new X3DH(...input);
    }
}