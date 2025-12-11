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
import { Datagram, decryptData, DiscoverMessage, DiscoverType, encryptData, EncryptedDatagram, IdentityKey, PrivateIdentityKey, Protocols, UserId } from "./types";
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
    session?: KeySession,
    payload?: Uint8Array,
    datagram?: Datagram,
    request?: BootstrapRequest
};

type HandshakeEventData = {
    session: KeySession
};

type SendEventData = {
    session?: KeySession,
    datagram: Datagram
};

type MessageEventData = {
    session: KeySession,
    payload: Uint8Array
};

export class FreeSignalNode {
    protected readonly privateIdentityKey: PrivateIdentityKey
    protected readonly sessions: SessionMap;
    protected readonly users: LocalStorage<string, string>;
    protected readonly bundles: LocalStorage<string, KeyExchangeDataBundle>;
    protected readonly keyExchange: KeyExchange;
    protected readonly discovers: Set<string> = new Set();
    protected readonly bootstraps: LocalStorage<string, BootstrapRequest>;
    protected readonly emitter = new EventEmitter<'send' | 'handshake' | 'message' | 'ping' | 'bootstrap', NodeEventData>();

    public constructor(storage: Database<{
        sessions: LocalStorage<string, ExportedKeySession>,
        users: LocalStorage<string, string>,
        keyExchange: LocalStorage<string, Crypto.KeyPair>,
        bundles: LocalStorage<string, KeyExchangeDataBundle>,
        bootstraps: LocalStorage<string, BootstrapRequest>
    }>, privateIdentityKey?: PrivateIdentityKey) {
        this.privateIdentityKey = privateIdentityKey ?? createIdentity();
        this.sessions = new SessionMap(storage.sessions);
        this.users = storage.users;
        this.keyExchange = new KeyExchange(storage.keyExchange, this.privateIdentityKey);
        this.bundles = storage.bundles;
        this.bootstraps = storage.bootstraps;

        this.emitter.on('message', this.messageHandler);
        this.emitter.on('send', this.sendHandler);
        this.emitter.on('handshake', this.handshakeHandler);
        this.emitter.on('bootstrap', this.bootstrapHandler);
    }

    protected messageHandler: EventCall<"message", NodeEventData> = (data) => this.onMessage({ session: data.data?.session!, payload: data.data?.payload! })
    protected sendHandler: EventCall<"send", NodeEventData> = (data) => this.onSend(data.data!.datagram!.toBytes());
    protected handshakeHandler: EventCall<"handshake", NodeEventData> = (data) => this.onHandshake(UserId.from(data.data?.session?.userId!));
    protected bootstrapHandler: EventCall<"bootstrap", NodeEventData> = (data) => this.onRequest(data.data?.request!);

    public onMessage: (data: MessageEventData) => void = () => { };
    public onSend: (data: Uint8Array) => void = () => { };
    public onHandshake: (userId: UserId) => void = () => { };
    public onRequest: (request: BootstrapRequest) => void = () => { };

    public getRequest(userId: string): Promise<BootstrapRequest | undefined> {
        return this.bootstraps.get(userId);
    }

    public async waitHandshaked(userId: UserId | string, timeout?: number): Promise<void> {
        if (timeout)
            setTimeout(() => { throw new Error(); }, timeout);
        while ((await this.emitter.wait('handshake', timeout))?.session?.userId.toString() !== userId.toString());
    }

    public get identityKey(): IdentityKey {
        return this.privateIdentityKey.identityKey;
    }

    public get userId(): UserId {
        return this.identityKey.userId;
    }
    protected async encrypt(receiverId: string | UserId, protocol: Protocols, data: Uint8Array): Promise<SendEventData> {
        const sessionTag = await this.users.get(receiverId.toString());
        if (!sessionTag)
            throw new Error("User not found: " + receiverId);
        const session = await this.sessions.get(sessionTag);
        if (!session)
            throw new Error("Session not found for sessionTag: " + sessionTag);
        const encrypted = encryptData(session, data);
        this.sessions.set(receiverId.toString(), session);
        return { session, datagram: new EncryptedDatagram(protocol, session.sessionTag, encrypted).sign(this.privateIdentityKey.signatureKey) };
    }

    public async sendHandshake(data: KeyExchangeData): Promise<void>
    public async sendHandshake(session: KeySession): Promise<void>
    public async sendHandshake(data: KeyExchangeData | KeySession): Promise<void> {
        if (data instanceof KeySession) {
            //console.debug("Sending Handshake Ack");
            const session = await this.sessions.get(data.sessionTag);
            if (!session)
                throw new Error("Session not found for user: " + data);
            this.emitter.emit('send', await this.encrypt(session.userId, Protocols.HANDSHAKE, crypto.ECDH.scalarMult(this.privateIdentityKey.exchangeKey, session.identityKey.exchangeKey)));
            return;
        }
        //console.debug("Sending Handshake Syn");
        const { session, message } = await this.keyExchange.digestData(data, encodeData(await this.keyExchange.generateBundle()));
        await this.sessions.set(session.sessionTag, session);
        await this.users.set(session.userId.toString(), session.sessionTag);
        const datagram = new Datagram(Protocols.HANDSHAKE, encodeData(message), session.sessionTag).sign(this.privateIdentityKey.signatureKey);
        this.emitter.emit('send', { session, datagram });
    }

    public async sendData<T>(receiverId: string | UserId, data: T): Promise<void> {
        //console.debug("Sending Data");
        this.emitter.emit('send', await this.encrypt(receiverId, Protocols.MESSAGE, encodeData(data)));
    }

    public async sendRelay(receiverId: string | UserId, data: Datagram): Promise<void> {
        //console.debug("Sending Relay");
        this.emitter.emit('send', await this.encrypt(receiverId, Protocols.RELAY, data.toBytes()));
    }

    public async sendPing(receiverId: string | UserId): Promise<void> {
        //console.debug("Sending Ping");
        const sessionTag = await this.users.get(receiverId.toString());
        if (!sessionTag)
            throw new Error("Session not found for user: " + receiverId);
        const session = await this.sessions.get(sessionTag);
        if (!session)
            throw new Error("Session not found for sessionTag: " + sessionTag);
        const datagram = new Datagram(Protocols.PING, undefined, session.sessionTag);
        this.emitter.emit('send', { session, datagram });
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
        this.emitter.emit('send', await this.encrypt(receiverId, Protocols.DISCOVER, encodeData(message)));
    }

    public async sendBootstrap(receiverId: string | UserId): Promise<void> {
        //console.debug("Sending Bootstrap");
        if (await this.sessions.has(receiverId.toString()))
            throw new Error("Session exists");
        const datagram = new Datagram(Protocols.BOOTSTRAP, encodeData(await this.keyExchange.generateData()));
        this.emitter.emit('send', { datagram });
    }

    protected async decrypt(datagram: EncryptedDatagram | Datagram | Uint8Array): Promise<MessageEventData> {
        datagram = EncryptedDatagram.from(datagram);
        if (!datagram.sessionTag)
            throw new Error("Datagram not encrypted");
        const session = await this.sessions.get(datagram.sessionTag);
        if (!session)
            throw new Error("Session not found for sessionTag: " + datagram.sessionTag);
        if (!datagram.verify(session.identityKey.signatureKey))
            throw new Error("Signature not verified");
        if (!datagram.payload)
            throw new Error("Missing payload");
        const decrypted = decryptData(session, datagram.payload);
        this.sessions.set(datagram.sessionTag, session);
        return { session, payload: decrypted };
    }

    protected async open(datagram: Datagram | EncryptedDatagram | Uint8Array): Promise<void> {
        if (datagram instanceof Uint8Array)
            datagram = Datagram.from(datagram);
        switch (datagram.protocol) {
            case Protocols.HANDSHAKE: {
                const encrypted = EncryptedDatagram.from(datagram);
                if (!encrypted.payload)
                    throw new Error("Missing payload");
                if (await this.sessions.has(encrypted.sessionTag)) {
                    //console.debug("Opening Handshake Ack");
                    const session = await this.sessions.get(encrypted.sessionTag);
                    const { payload } = await this.decrypt(encrypted);
                    if (!session)
                        throw new Error("Session not found for sessionTag: " + datagram.sessionTag);
                    if (!compareBytes(payload, crypto.ECDH.scalarMult(this.privateIdentityKey.exchangeKey, session.identityKey.exchangeKey)))
                        throw new Error("Error validating handshake data");
                    this.emitter.emit('handshake', { session });
                    return;
                }
                //console.debug("Opening Handshake Syn");
                const data = decodeData<KeyExchangeSynMessage>(encrypted.payload);
                if (!datagram.verify(IdentityKey.from(data.identityKey).signatureKey))
                    throw new Error("Signature not verified");
                const { session, associatedData } = await this.keyExchange.digestMessage(data);
                await this.sessions.set(session.sessionTag, session);
                await this.users.set(session.userId.toString(), session.sessionTag);
                await this.bundles.set(session.userId.toString(), decodeData<KeyExchangeDataBundle>(associatedData));
                await this.sendHandshake(session);
                this.emitter.emit('handshake', { session });
                return;
            }

            case Protocols.MESSAGE:
                //console.debug("Opening Message");
                this.emitter.emit('message', await this.decrypt(datagram));
                return;

            case Protocols.RELAY:
                //console.debug("Opening Relay");
                this.emitter.emit('send', await this.decrypt(datagram));
                return;

            case Protocols.DISCOVER: {
                //console.debug("Opening Discover");
                const { session, payload } = await this.decrypt(datagram);
                const message = decodeData<DiscoverMessage>(payload);
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
                    this.emitter.emit('send', await this.encrypt(session.userId, Protocols.DISCOVER, encodeData(response)));
                } else if (message.type === DiscoverType.RESPONSE && this.discovers.has(message.discoverId)) {
                    this.discovers.delete(message.discoverId);
                    if (message.data)
                        await this.sendHandshake(message.data);
                }
                return;
            }

            case Protocols.BOOTSTRAP: {
                //console.debug("Opening Bootstrap");
                if (!datagram.payload)
                    throw new Error("Invalid Bootstrap");
                const keyExchangeData = decodeData<KeyExchangeData>(datagram.payload);
                const userId = UserId.fromKey(keyExchangeData.identityKey);
                const request = new BootstrapRequest(userId, keyExchangeData);
                request.onChange = (event) => {
                    if (!request.data)
                        throw new Error("Error sending handshake");
                    this.sendHandshake(event.data?.data!);
                }
                await this.bootstraps.set(userId.toString(), request);
                this.emitter.emit('bootstrap', { request });
                return;
            }

            case Protocols.PING:
                datagram = EncryptedDatagram.from(datagram);
                const session = await this.sessions.get(datagram.sessionTag!);
                if (!session)
                    throw new Error("Session not found for sessionTag: " + datagram.sessionTag);
                this.emitter.emit('ping', { session });
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