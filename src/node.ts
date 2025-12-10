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

import { Database, LocalStorage, Crypto, KeyExchangeDataBundle, KeyExchangeData, KeyExchangeSynMessage } from "@freesignal/interfaces";
import { Datagram, DatagramHeader, decryptData, DiscoverMessage, DiscoverType, encryptData, IdentityKey, PrivateIdentityKey, Protocols, UserId } from "./types";
import { KeyExchange } from "./x3dh";
import { ExportedKeySession, KeySession } from "./double-ratchet";
import { createIdentity } from ".";
import { decodeData, encodeBase64, encodeData, compareBytes } from "@freesignal/utils";
import crypto from "@freesignal/crypto";

export class BootstrapRequest {
    #status: 'pending' | 'accepted' | 'denied' = 'pending';

    public constructor(public readonly senderId: UserId | string, private readonly datagram: Datagram) { }

    public get status() {
        return this.#status;
    }

    public async get(): Promise<Datagram | undefined> {
        return this.#status === 'accepted' ? this.datagram : undefined;
    }

    public async accept(): Promise<Datagram | undefined> {
        if (this.status === 'pending')
            this.#status = 'accepted';
        return await this.get();
    }

    public deny() {
        if (this.status === 'pending')
            this.#status = 'denied';
        return;
    }

}

export class FreeSignalNode {
    protected readonly privateIdentityKey: PrivateIdentityKey
    protected readonly sessions: SessionMap;
    protected readonly bundles: LocalStorage<string, KeyExchangeDataBundle>;
    protected readonly keyExchange: KeyExchange;
    protected readonly discovers: Set<string> = new Set();
    protected readonly bootstraps: LocalStorage<string, BootstrapRequest>;

    public constructor(storage: Database<{
        sessions: LocalStorage<string, ExportedKeySession>,
        keyExchange: LocalStorage<string, Crypto.KeyPair>,
        bundles: LocalStorage<string, KeyExchangeDataBundle>,
        bootstraps: LocalStorage<string, BootstrapRequest>
    }>, privateIdentityKey?: PrivateIdentityKey) {
        this.privateIdentityKey = privateIdentityKey ?? createIdentity();
        this.sessions = new SessionMap(storage.sessions);
        this.keyExchange = new KeyExchange(storage.keyExchange, this.privateIdentityKey);
        this.bundles = storage.bundles;
        this.bootstraps = storage.bootstraps;
    }

    public get identityKey(): IdentityKey {
        return this.privateIdentityKey.identityKey;
    }

    public get userId(): UserId {
        return this.identityKey.userId;
    }

    public onRequest: (request: BootstrapRequest) => void = () => { };

    public async getRequest(userId: string): Promise<Datagram | undefined> {
        return (await this.bootstraps.get(userId))?.get();
    }

    protected async encrypt(receiverId: string | UserId, protocol: Protocols, data: Uint8Array): Promise<Datagram> {
        if (receiverId instanceof UserId)
            receiverId = receiverId.toString();
        const session = await this.sessions.get(receiverId);
        if (!session)
            throw new Error("Session not found for user: " + receiverId);
        const encrypted = encryptData(session, data);
        this.sessions.set(receiverId, session);
        return new Datagram(this.userId.toString(), receiverId, protocol, encrypted).sign(this.privateIdentityKey.signatureKey);
    }

    public async packHandshake(data: KeyExchangeData): Promise<Datagram>
    public async packHandshake(receiverId: string | UserId): Promise<Datagram>
    public async packHandshake(data: KeyExchangeData | string | UserId): Promise<Datagram> {
        if (typeof data === 'string' || data instanceof UserId) {
            //console.debug("Packing Handshake Ack");
            const userId = data.toString();
            const identityKey = (await this.sessions.get(userId))?.identityKey;
            if (!identityKey)
                throw new Error("Missing user");
            const res = await this.encrypt(userId, Protocols.HANDSHAKE, crypto.ECDH.scalarMult(this.privateIdentityKey.exchangeKey, identityKey.exchangeKey))
            return res;
        }
        //console.debug("Packing Handshake Syn");
        const { session, message } = await this.keyExchange.digestData(data, encodeData(await this.keyExchange.generateBundle()));
        await this.sessions.set(session.userId.toString(), session);
        return new Datagram(this.userId.toString(), UserId.fromKey(data.identityKey).toString(), Protocols.HANDSHAKE, encodeData(message)).sign(this.privateIdentityKey.signatureKey);
    }

    public packData<T>(receiverId: string | UserId, data: T): Promise<Datagram> {
        //console.debug("Packing Data");
        return this.encrypt(receiverId, Protocols.MESSAGE, encodeData(data));
    }

    public packRelay(receiverId: string | UserId, data: Datagram): Promise<Datagram> {
        //console.debug("Packing Relay");
        return this.encrypt(receiverId, Protocols.RELAY, data.toBytes());
    }

    public async packDiscover(receiverId: string | UserId, discoverId: string | UserId): Promise<Datagram> {
        //console.debug("Packing Discover");
        if (receiverId instanceof UserId)
            receiverId = receiverId.toString();
        if (discoverId instanceof UserId)
            discoverId = discoverId.toString();
        const message: DiscoverMessage = {
            type: DiscoverType.REQUEST,
            discoverId
        };
        this.discovers.add(receiverId);
        return this.encrypt(receiverId, Protocols.DISCOVER, encodeData(message));
    }

    public async packBootstrap(receiverId: string | UserId) {
        //console.debug("Packing Bootstrap");
        return new Datagram(this.userId.toString(), receiverId.toString(), Protocols.BOOTSTRAP, encodeData(await this.keyExchange.generateData()));
    }

    public async packGetBootstrap(receiverId: string | UserId) {
        //console.debug("Packing GetBootstrap");
        return new Datagram(this.userId.toString(), receiverId.toString(), Protocols.BOOTSTRAP);
    }

    protected async decrypt(datagram: Datagram): Promise<Uint8Array> {
        const identityKey = (await this.sessions.get(datagram.sender))?.identityKey;
        if (!identityKey)
            throw new Error("User IdentityKey not found");
        if (!Datagram.verify(datagram, identityKey.signatureKey))
            throw new Error("Signature not verified");
        const session = await this.sessions.get(datagram.sender);
        if (!session)
            throw new Error("Session not found for user: " + datagram.sender);
        if (!datagram.payload)
            throw new Error("Missing payload");
        const decrypted = decryptData(session, datagram.payload);
        this.sessions.set(datagram.sender, session);
        return decrypted;
    }

    /**
     * Open the datagram and execute operation of Discover and Handshake.
     * 
     * @param datagram 
     * @returns Header and decrypted payload
     */
    public async open(datagram: Datagram | Uint8Array): Promise<{
        header: DatagramHeader,
        payload?: Uint8Array,
        datagram?: Datagram
    }> {
        if (datagram instanceof Uint8Array)
            datagram = Datagram.from(datagram);
        let out: {
            header: DatagramHeader,
            payload?: Uint8Array,
            datagram?: Datagram
        } = {
            header: DatagramHeader.from(datagram.header)
        };
        switch (datagram.protocol) {
            case Protocols.HANDSHAKE:
                if (!datagram.payload)
                    throw new Error("Missing payload");
                if (await this.sessions.has(datagram.sender)) {
                    //console.debug("Opening Handshake Ack");
                    const payload = await this.decrypt(datagram);
                    const identityKey = (await this.sessions.get(datagram.sender))?.identityKey;
                    if (!identityKey)
                        throw new Error("Missing user");
                    if (!compareBytes(payload, crypto.ECDH.scalarMult(this.privateIdentityKey.exchangeKey, identityKey.exchangeKey)))
                        throw new Error("Error validating handshake data");
                    return out;
                }
                //console.debug("Opening Handshake Syn");
                const data = decodeData<KeyExchangeSynMessage>(datagram.payload);
                if (!Datagram.verify(datagram, IdentityKey.from(data.identityKey).signatureKey))
                    throw new Error("Signature not verified");
                const { session, associatedData } = await this.keyExchange.digestMessage(data);
                await this.sessions.set(session.userId.toString(), session);
                await this.bundles.set(session.userId.toString(), decodeData<KeyExchangeDataBundle>(associatedData));
                out.datagram = await this.packHandshake(session.userId);
                if (!out.datagram)
                    throw new Error("Error during handshake");
                return out;

            case Protocols.MESSAGE:
                //console.debug("Opening Message");
                out.payload = await this.decrypt(datagram);
                return out;

            case Protocols.RELAY:
                //console.debug("Opening Relay");
                out.payload = await this.decrypt(datagram);
                return out;

            case Protocols.DISCOVER:
                //console.debug("Opening Discover");
                const message = decodeData<DiscoverMessage>(await this.decrypt(datagram));
                if (message.type === DiscoverType.REQUEST && message.discoverId && !(await this.sessions.has(message.discoverId))) {
                    let data: KeyExchangeData;
                    if (message.discoverId === this.userId.toString()) {
                        data = await this.keyExchange.generateData();
                    } else {
                        const bundle = await this.bundles.get(message.discoverId);
                        if (!bundle)
                            return out;
                        const { version, identityKey, signedPreKey, signature } = bundle;
                        const onetimePreKey = bundle.onetimePreKeys.shift();
                        if (!onetimePreKey) {
                            await this.bundles.delete(message.discoverId);
                            return out;
                        }
                        data = {
                            version,
                            identityKey,
                            signedPreKey,
                            signature,
                            onetimePreKey
                        };
                    }
                    const response: DiscoverMessage = { type: DiscoverType.RESPONSE, discoverId: message.discoverId, data };
                    out.datagram = await this.encrypt(datagram.sender, Protocols.DISCOVER, encodeData(response));
                } else if (message.type === DiscoverType.RESPONSE && this.discovers.has(message.discoverId)) {
                    this.discovers.delete(message.discoverId);
                    if (message.data)
                        out.datagram = await this.packHandshake(message.data);
                }
                return out;

            case Protocols.BOOTSTRAP:
                //console.debug("Opening Bootstrap");
                if (datagram.payload) {
                    const data = decodeData<KeyExchangeData>(datagram.payload);
                    if (!compareBytes(UserId.fromKey(data.identityKey).toBytes(), encodeBase64(datagram.sender)))
                        new Error("Malicious bootstrap request");
                    const request = new BootstrapRequest(datagram.sender, await this.packHandshake(data));
                    await this.bootstraps.set(datagram.sender, request);
                    this.onRequest(request);
                };
                const handshakeDatagram = await (await this.bootstraps.get(datagram.sender))?.get();
                if (handshakeDatagram)
                    out.datagram = handshakeDatagram;
                return out;

            case Protocols.PING:
                return out;

            default:
                throw new Error("Invalid protocol");
        }

    }
}

class SessionMap implements LocalStorage<string, KeySession> {
    private readonly cache = new Map<string, KeySession>()

    public constructor(public readonly storage: LocalStorage<string, ExportedKeySession>, public readonly maxSize = 50) { }

    public set(key: string, value: KeySession): Promise<void> {
        this.cache.set(key, value);
        return this.storage.set(key, value.toJSON());
    }

    public async get(key: string): Promise<KeySession | undefined> {
        const session = this.cache.get(key);
        if (!session) {
            const sessionData = await this.storage.get(key);
            if (!sessionData)
                return undefined;
            return KeySession.from(sessionData);
        }
        return session;
    }

    public async has(key: string): Promise<boolean> {
        return this.cache.has(key) || await this.storage.has(key);
    }

    public async delete(key: string): Promise<boolean> {
        return this.cache.delete(key) || await this.storage.delete(key);
    }

    public clear(): Promise<void> {
        this.cache.clear();
        return this.storage.clear();
    }

    public entries(): Promise<Iterable<[string, KeySession]>> {
        throw new Error("Method not implemented.");
    }
}