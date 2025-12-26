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

import { KeyExchangeManager, KeyStore, PreKeyBundle, PreKeyMessage, PublicIdentity, Session, TransportEvents, Crypto } from "@freesignal/interfaces";
import { SessionConstructor } from "./session.js";
import { useConstructors } from "./constructors.js";
import { EventEmitter } from "easyemitter.ts";

export class KeyExchangeManagerConstructor implements KeyExchangeManager {
    public static readonly version = 1;
    private static readonly hkdfInfo = "freesignal/x3dh/v." + KeyExchangeManagerConstructor.version;
    private static readonly maxOPK = 10;

    public readonly emitter = new EventEmitter<TransportEvents<PreKeyMessage> & { session: Session; }>();

    public constructor(public readonly publicIdentity: PublicIdentity, private readonly keyStore: KeyStore, private readonly crypto: Crypto) {
        this.emitter.on('receive', (message) => this.processPreKeyMessage(message));
    }

    private generateSPK(): { signedPreKey: Crypto.KeyPair, signedPreKeyHash: Uint8Array } {
        const signedPreKey = this.crypto.ECDH.keyPair();
        const signedPreKeyHash = this.crypto.hash(signedPreKey.publicKey);
        this.keyStore.storePreKey(this.crypto.Utils.decodeBase64(signedPreKeyHash), signedPreKey);
        return { signedPreKey, signedPreKeyHash };
    }

    private generateOPK(spkHash: Uint8Array): { onetimePreKey: Crypto.KeyPair, onetimePreKeyHash: Uint8Array } {
        const onetimePreKey = this.crypto.ECDH.keyPair();
        const onetimePreKeyHash = this.crypto.hash(onetimePreKey.publicKey);
        this.keyStore.storePreKey(this.crypto.Utils.decodeBase64(spkHash).concat(this.crypto.Utils.decodeBase64(onetimePreKeyHash)), onetimePreKey);
        return { onetimePreKey, onetimePreKeyHash };
    }

    private readonly processPreKeyMessage = async (message: PreKeyMessage): Promise<void> => {
        const { PublicIdentityConstructor, UserIdConstructor } = useConstructors(this.crypto);

        const signedPreKey = await this.keyStore.loadPreKey(message.signedPreKeyHash);
        const hash = message.signedPreKeyHash.concat(message.onetimePreKeyHash);
        const onetimePreKey = await this.keyStore.loadPreKey(hash);
        const identityKey = PublicIdentityConstructor.from(message.identityKey);
        if (!signedPreKey || !onetimePreKey || !message.identityKey || !message.ephemeralKey)
            throw new Error("ACK message malformed");
        await this.keyStore.removePreKey(hash);
        const ephemeralKey = this.crypto.Utils.encodeBase64(message.ephemeralKey);
        const secretKey = this.crypto.EdDSA.toSecretECDHKey((await this.keyStore.getIdentity()).secretKey);
        const derivedKey = this.crypto.hkdf(new Uint8Array([
            ...this.crypto.ECDH.scalarMult(signedPreKey.secretKey, identityKey.toPublicECDHKey()),
            ...this.crypto.ECDH.scalarMult(secretKey, ephemeralKey),
            ...this.crypto.ECDH.scalarMult(signedPreKey.secretKey, ephemeralKey),
            ...onetimePreKey ? this.crypto.ECDH.scalarMult(onetimePreKey.secretKey, ephemeralKey) : new Uint8Array()
        ]), new Uint8Array(SessionConstructor.keyLength).fill(0), KeyExchangeManagerConstructor.hkdfInfo, SessionConstructor.keyLength * 3);
        const session = new SessionConstructor({
            userId: UserIdConstructor.fromKey(identityKey).toString(),
            secretKey: this.crypto.Utils.decodeBase64(secretKey),
            rootKey: this.crypto.Utils.decodeBase64(derivedKey.subarray(0, SessionConstructor.keyLength)),
            nextHeaderKey: this.crypto.Utils.decodeBase64(derivedKey.subarray(SessionConstructor.keyLength, SessionConstructor.keyLength * 2)),
            headerKey: this.crypto.Utils.decodeBase64(derivedKey.subarray(SessionConstructor.keyLength * 2))
        }, this.keyStore, this.crypto);
        const data = session.decrypt(this.crypto.Utils.encodeBase64(message.associatedData));
        if (!this.crypto.Utils.compareBytes(data.subarray(0, 64), this.crypto.Utils.concatBytes(this.crypto.hash(identityKey.bytes), this.crypto.hash(this.publicIdentity.bytes))))
            throw new Error("Error verifing Associated Data");
        this.emitter.emit('session', session);
    }

    public async createPreKeyBundle(): Promise<PreKeyBundle> {
        const { signedPreKey, signedPreKeyHash } = this.generateSPK();
        const onetimePreKey = new Array(KeyExchangeManagerConstructor.maxOPK).fill(0).map(() => this.generateOPK(signedPreKeyHash).onetimePreKey);
        return {
            version: KeyExchangeManagerConstructor.version,
            identityKey: this.publicIdentity.toString(),
            signedPreKey: this.crypto.Utils.decodeBase64(signedPreKey.publicKey),
            signature: this.crypto.Utils.decodeBase64(this.crypto.EdDSA.sign(signedPreKeyHash, (await this.keyStore.getIdentity()).secretKey)),
            onetimePreKeys: onetimePreKey.map(opk => this.crypto.Utils.decodeBase64(opk.publicKey))
        }
    }

    public async processPreKeyBundle(bundle: PreKeyBundle): Promise<Session> {
        const { PublicIdentityConstructor, UserIdConstructor } = useConstructors(this.crypto);

        const ephemeralKey = this.crypto.ECDH.keyPair();
        const signedPreKey = this.crypto.Utils.encodeBase64(bundle.signedPreKey);
        const identityKey = PublicIdentityConstructor.from(bundle.identityKey);
        if (!this.crypto.EdDSA.verify(this.crypto.Utils.encodeBase64(bundle.signature), this.crypto.hash(signedPreKey), identityKey.publicKey))
            throw new Error("Signature verification failed");
        const shiftKey = bundle.onetimePreKeys.shift();
        const onetimePreKey = shiftKey ? this.crypto.Utils.encodeBase64(shiftKey) : undefined;
        const signedPreKeyHash = this.crypto.hash(signedPreKey);
        const onetimePreKeyHash = onetimePreKey ? this.crypto.hash(onetimePreKey) : new Uint8Array();
        const derivedKey = this.crypto.hkdf(new Uint8Array([
            ...this.crypto.ECDH.scalarMult(this.crypto.EdDSA.toSecretECDHKey((await this.keyStore.getIdentity()).secretKey), signedPreKey),
            ...this.crypto.ECDH.scalarMult(ephemeralKey.secretKey, identityKey.toPublicECDHKey()),
            ...this.crypto.ECDH.scalarMult(ephemeralKey.secretKey, signedPreKey),
            ...onetimePreKey ? this.crypto.ECDH.scalarMult(ephemeralKey.secretKey, onetimePreKey) : new Uint8Array()
        ]), new Uint8Array(SessionConstructor.keyLength).fill(0), KeyExchangeManagerConstructor.hkdfInfo, SessionConstructor.keyLength * 3);
        const session = new SessionConstructor({
            userId: UserIdConstructor.fromKey(identityKey).toString(),
            remoteKey: identityKey.toPublicECDHKey(),
            rootKey: this.crypto.Utils.decodeBase64(derivedKey.subarray(0, SessionConstructor.keyLength)),
            headerKey: this.crypto.Utils.decodeBase64(derivedKey.subarray(SessionConstructor.keyLength, SessionConstructor.keyLength * 2)),
            nextHeaderKey: this.crypto.Utils.decodeBase64(derivedKey.subarray(SessionConstructor.keyLength * 2))
        }, this.keyStore, this.crypto);
        const encrypted = session.encrypt(this.crypto.Utils.concatBytes(this.crypto.hash(this.publicIdentity.bytes), this.crypto.hash(identityKey.bytes)));
        if (!encrypted)
            throw new Error("Encryption error");

        this.emitter.emit('send', {
            version: KeyExchangeManagerConstructor.version,
            identityKey: this.publicIdentity.toString(),
            ephemeralKey: this.crypto.Utils.decodeBase64(ephemeralKey.publicKey),
            signedPreKeyHash: this.crypto.Utils.decodeBase64(signedPreKeyHash),
            onetimePreKeyHash: this.crypto.Utils.decodeBase64(onetimePreKeyHash),
            associatedData: this.crypto.Utils.decodeBase64(encrypted.bytes)
        });
        return session;
    }
}