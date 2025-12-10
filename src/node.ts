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
import EventEmitter, { EventCall } from "easyemitter.ts";

export class BootstrapRequest extends EventEmitter<'change', BootstrapRequest> {
    #status: 'pending' | 'accepted' | 'denied' = 'pending';

    public constructor(public readonly senderId: UserId | string, private readonly keyExchangeData: KeyExchangeData) {
        super();
        this.on('change', (data) => this.onChange(data));
    }

    public onChange: EventCall<'change', BootstrapRequest> = () => { };

    public get status() {
        return this.#status;
    }

    public get data(): KeyExchangeData | undefined {
        return this.#status === 'accepted' ? this.keyExchangeData : undefined;
    }

    public accept(): void {
        if (this.status === 'pending')
            this.#status = 'accepted';
        this.emit('change', this);
    }

    public deny(): void {
        if (this.status === 'pending')
            this.#status = 'denied';
        this.emit('change', this);
    }

}

type NodeEventData = {
    header: DatagramHeader,
    payload?: Uint8Array,
    datagram?: Datagram
};

type MessageEventData = {
    header: DatagramHeader,
    payload: Uint8Array
};

export class FreeSignalNode {
    protected readonly privateIdentityKey: PrivateIdentityKey
    protected readonly sessions: SessionMap;
    protected readonly bundles: LocalStorage<string, KeyExchangeDataBundle>;
    protected readonly keyExchange: KeyExchange;
    protected readonly discovers: Set<string> = new Set();
    protected readonly bootstraps: LocalStorage<string, BootstrapRequest>;
    protected readonly emitter = new EventEmitter<'send' | 'handshaked' | 'message' | 'ping', NodeEventData>();

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

        this.emitter.on('send', (data) => this.onSend(data.data!.datagram!.toBytes()));
        this.emitter.on('handshaked', (data) => this.onHandshaked(UserId.from(data.data!.header.sender)));
    }

    public onMessage: (data: MessageEventData) => void = () => { };
    public onSend: (data: Uint8Array) => void = () => { };
    public onHandshaked: (userId: UserId) => void = () => { };

    public async waitHandshaked(userId: UserId | string, timeout?: number): Promise<void> {
        if (timeout)
            setTimeout(() => { throw new Error(); }, timeout);
        while ((await this.emitter.wait('handshaked', timeout))?.header.sender !== userId.toString());
    }

    public get identityKey(): IdentityKey {
        return this.privateIdentityKey.identityKey;
    }

    public get userId(): UserId {
        return this.identityKey.userId;
    }

    public readonly requests: {
        onRequest: (request: BootstrapRequest) => void;
        getRequest: (userId: string) => Promise<BootstrapRequest | undefined>
    } = {
            onRequest: () => { },
            getRequest: (userId: string): Promise<BootstrapRequest | undefined> => {
                return this.bootstraps.get(userId);
            }
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

    public async sendHandshake(data: KeyExchangeData): Promise<void>
    public async sendHandshake(receiverId: string | UserId): Promise<void>
    public async sendHandshake(data: KeyExchangeData | string | UserId): Promise<void> {
        if (typeof data === 'string' || data instanceof UserId) {
            //console.debug("Sending Handshake Ack");
            const userId = data.toString();
            const identityKey = (await this.sessions.get(userId))?.identityKey;
            if (!identityKey)
                throw new Error("Missing user");
            const datagram = await this.encrypt(userId, Protocols.HANDSHAKE, crypto.ECDH.scalarMult(this.privateIdentityKey.exchangeKey, identityKey.exchangeKey));
            this.emitter.emit('send', { header: datagram.header, datagram });
            return;
        }
        //console.debug("Sending Handshake Syn");
        const { session, message } = await this.keyExchange.digestData(data, encodeData(await this.keyExchange.generateBundle()));
        await this.sessions.set(session.userId.toString(), session);
        const datagram = new Datagram(this.userId.toString(), UserId.fromKey(data.identityKey).toString(), Protocols.HANDSHAKE, encodeData(message)).sign(this.privateIdentityKey.signatureKey);
        this.emitter.emit('send', { header: datagram.header, datagram });
    }

    public async sendData<T>(receiverId: string | UserId, data: T): Promise<void> {
        //console.debug("Sending Data");
        const datagram = await this.encrypt(receiverId, Protocols.MESSAGE, encodeData(data));
        this.emitter.emit('send', { header: datagram.header, datagram });
    }

    public async sendRelay(receiverId: string | UserId, data: Datagram): Promise<void> {
        //console.debug("Sending Relay");
        const datagram = await this.encrypt(receiverId, Protocols.RELAY, data.toBytes());
        this.emitter.emit('send', { header: datagram.header, datagram });
    }

    public async sendPing(receiverId: string | UserId): Promise<void> {
        //console.debug("Sending Ping");
        const datagram = new Datagram(this.userId.toString(), receiverId.toString(), Protocols.PING);
        this.emitter.emit('send', { header: datagram.header, datagram });
    }

    public async sendDiscover(receiverId: string | UserId, discoverId: string | UserId): Promise<void> {
        //console.debug("Sending Discover");
        if (receiverId instanceof UserId)
            receiverId = receiverId.toString();
        if (discoverId instanceof UserId)
            discoverId = discoverId.toString();
        const message: DiscoverMessage = {
            type: DiscoverType.REQUEST,
            discoverId
        };
        this.discovers.add(receiverId);
        const datagram = await this.encrypt(receiverId, Protocols.DISCOVER, encodeData(message));
        this.emitter.emit('send', { header: datagram.header, datagram });
    }

    public async sendBootstrap(receiverId: string | UserId): Promise<void> {
        //console.debug("Sending Bootstrap");
        const datagram = new Datagram(this.userId.toString(), receiverId.toString(), Protocols.BOOTSTRAP, encodeData(await this.keyExchange.generateData()));
        this.emitter.emit('send', { header: datagram.header, datagram });
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

    protected async open(datagram: Datagram | Uint8Array): Promise<void> {
        if (datagram instanceof Uint8Array)
            datagram = Datagram.from(datagram);
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
                    this.emitter.emit('handshaked', { header: datagram.header });
                    return;
                }
                //console.debug("Opening Handshake Syn");
                const data = decodeData<KeyExchangeSynMessage>(datagram.payload);
                if (!Datagram.verify(datagram, IdentityKey.from(data.identityKey).signatureKey))
                    throw new Error("Signature not verified");
                const { session, associatedData } = await this.keyExchange.digestMessage(data);
                await this.sessions.set(session.userId.toString(), session);
                await this.bundles.set(session.userId.toString(), decodeData<KeyExchangeDataBundle>(associatedData));
                await this.sendHandshake(session.userId);
                this.emitter.emit('handshaked', { header: datagram.header });
                return;

            case Protocols.MESSAGE:
                //console.debug("Opening Message");
                this.emitter.emit('message', { header: datagram.header, payload: await this.decrypt(datagram) });
                return;

            case Protocols.RELAY:
                //console.debug("Opening Relay");
                this.emitter.emit('send', { header: Datagram.from(await this.decrypt(datagram)) });
                return;

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
                            return;
                        const { version, identityKey, signedPreKey, signature } = bundle;
                        const onetimePreKey = bundle.onetimePreKeys.shift();
                        if (!onetimePreKey) {
                            await this.bundles.delete(message.discoverId);
                            return;
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
                    this.emitter.emit('send', await this.encrypt(datagram.sender, Protocols.DISCOVER, encodeData(response)));
                } else if (message.type === DiscoverType.RESPONSE && this.discovers.has(message.discoverId)) {
                    this.discovers.delete(message.discoverId);
                    if (message.data)
                        await this.sendHandshake(message.data);
                }
                return;

            case Protocols.BOOTSTRAP:
                //console.debug("Opening Bootstrap");
                if (!datagram.payload)
                    throw new Error("Invalid Bootstrap");
                const keyExchangeData = decodeData<KeyExchangeData>(datagram.payload);
                if (!compareBytes(UserId.fromKey(keyExchangeData.identityKey).toBytes(), encodeBase64(datagram.sender)))
                    new Error("Malicious bootstrap request");
                const request = new BootstrapRequest(datagram.sender, keyExchangeData);
                request.onChange = () => {
                    if (!request.data)
                        throw new Error("Error sending handshake");
                    this.sendHandshake(request.data);
                }
                await this.bootstraps.set(datagram.sender, request);
                this.requests.onRequest(request);
                return;

            case Protocols.PING:
                this.emitter.emit('ping', { header: datagram.header });
                return;

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