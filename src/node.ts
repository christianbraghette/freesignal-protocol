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

export class BootstrapRequest {
    #status: 'pending' | 'accepted' | 'denied' = 'pending';

    public constructor(public readonly senderId: UserId | string, private readonly data: KeyExchangeData) { }

    public get status() {
        return this.#status;
    }

    public async get(): Promise<KeyExchangeData | undefined> {
        return this.#status === 'accepted' ? this.data : undefined;
    }

    public async accept(): Promise<KeyExchangeData | undefined> {
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
    protected readonly users: LocalStorage<string, IdentityKey>;
    protected readonly bundles: LocalStorage<string, KeyExchangeDataBundle>;
    protected readonly keyExchange: KeyExchange;
    protected readonly discovers: Set<string> = new Set();
    protected readonly bootstraps: LocalStorage<string, BootstrapRequest>;

    public constructor(storage: Database<{
        sessions: LocalStorage<string, ExportedKeySession>,
        keyExchange: LocalStorage<string, Crypto.KeyPair>,
        users: LocalStorage<string, IdentityKey>,
        bundles: LocalStorage<string, KeyExchangeDataBundle>,
        bootstraps: LocalStorage<string, BootstrapRequest>
    }>, privateIdentityKey?: PrivateIdentityKey) {
        this.privateIdentityKey = privateIdentityKey ?? createIdentity();
        this.sessions = new SessionMap(storage.sessions);
        this.keyExchange = new KeyExchange(storage.keyExchange, this.privateIdentityKey);
        this.users = storage.users;
        this.bundles = storage.bundles;
        this.bootstraps = storage.bootstraps;
    }

    public get identityKey(): IdentityKey {
        return this.privateIdentityKey.identityKey;
    }

    public get userId(): UserId {
        return UserId.fromKey(this.identityKey);
    }

    public onRequest: (request: BootstrapRequest) => void = () => { };

    public async getRequest(userId: string): Promise<KeyExchangeData | undefined> {
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

    public async packHandshake(data: KeyExchangeData): Promise<Datagram> {
        const { session, message, identityKey } = await this.keyExchange.digestData(data, encodeData(await this.keyExchange.generateBundle()));
        const remoteId = UserId.fromKey(identityKey);
        await this.users.set(remoteId.toString(), identityKey);
        await this.sessions.set(remoteId.toString(), session);
        return new Datagram(this.userId.toString(), UserId.fromKey(data.identityKey).toString(), Protocols.HANDSHAKE, encodeData(message)).sign(this.privateIdentityKey.signatureKey);
    }

    public packData<T>(receiverId: string | UserId, data: T): Promise<Datagram> {
        return this.encrypt(receiverId, Protocols.MESSAGE, encodeData(data));
    }

    public packRelay(receiverId: string | UserId, data: Datagram): Promise<Datagram> {
        return this.encrypt(receiverId, Protocols.RELAY, encodeData(data));
    }

    public async packDiscover(receiverId: string | UserId, discoverId: string | UserId): Promise<Datagram> {
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
        return new Datagram(this.userId.toString(), receiverId.toString(), Protocols.BOOTSTRAP, encodeData(await this.keyExchange.generateData()));
    }

    protected async decrypt(datagram: Datagram): Promise<Uint8Array> {
        const signatureKey = await this.users.get(datagram.sender);
        if (!signatureKey)
            throw new Error("User IdentityKey not found");
        if (!Datagram.verify(datagram, signatureKey.signatureKey))
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
        payload?: Uint8Array
    }> {
        if (datagram instanceof Uint8Array)
            datagram = Datagram.from(datagram);
        let out: {
            header: DatagramHeader,
            payload?: Uint8Array
        } = {
            header: DatagramHeader.from(datagram.header)
        };
        switch (datagram.protocol) {
            case Protocols.HANDSHAKE:
                if (!datagram.payload)
                    throw new Error("Missing payload");
                const data = decodeData<KeyExchangeSynMessage>(datagram.payload);
                if (!Datagram.verify(datagram, IdentityKey.from(data.identityKey).signatureKey))
                    throw new Error("Signature not verified");
                const { session, identityKey, associatedData } = await this.keyExchange.digestMessage(data);
                const userId = UserId.fromKey(identityKey);
                await this.users.set(userId.toString(), identityKey);
                await this.sessions.set(userId.toString(), session);
                await this.bundles.set(userId.toString(), decodeData<KeyExchangeDataBundle>(associatedData));
                return out;

            case Protocols.MESSAGE:
                out.payload = decodeData(await this.decrypt(datagram));
                return out;

            case Protocols.RELAY:
                out.payload = decodeData(await this.decrypt(datagram));
                return out;

            case Protocols.DISCOVER:
                const message = decodeData<DiscoverMessage>(await this.decrypt(datagram));
                if (message.type === DiscoverType.REQUEST && message.discoverId && !(await this.users.has(message.discoverId))) {
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
                    out.payload = (await this.encrypt(datagram.sender, Protocols.DISCOVER, encodeData(response))).toBytes();
                } else if (message.type === DiscoverType.RESPONSE && this.discovers.has(message.discoverId)) {
                    this.discovers.delete(message.discoverId);
                    if (message.data)
                        out.payload = encodeData(message.data);
                }
                return out;

            case Protocols.BOOTSTRAP:
                if (datagram.payload) {
                    const data = decodeData<KeyExchangeData>(datagram.payload);
                    if (!compareBytes(UserId.fromKey(data.identityKey).toBytes(), encodeBase64(datagram.sender)))
                        new Error("Malicious bootstrap request");
                    const request = new BootstrapRequest(datagram.sender, data);
                    await this.bootstraps.set(datagram.sender, request);
                    this.onRequest(request);
                };
                const request = await this.bootstraps.get(datagram.sender);
                if (request) {
                    const data = await request.get()
                    if (data)
                        out.payload = encodeData(data);
                }
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
}