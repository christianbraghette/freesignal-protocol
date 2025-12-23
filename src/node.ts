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

import { KeyExchangeDataBundle, KeyExchangeData, KeyExchangeSynMessage, Crypto } from "@freesignal/interfaces";
import { Datagram, decryptData, encryptData, EncryptedDatagram, IdentityKey, PrivateIdentityKey, Protocols, UserId } from "./types.js";
import { KeyExchange } from "./x3dh.js";
import { KeySessionState as KeySessionState, KeySession } from "./double-ratchet.js";
import { createIdentity } from "./index.js";
import { decodeData, encodeData, compareBytes, concatBytes, decodeBase64 } from "@freesignal/utils";
import crypto from "@freesignal/crypto";
import { EventEmitter, EventCallback } from "easyemitter.ts";

export class BootstrapRequest extends EventEmitter<'change', BootstrapRequest> {
    #status: 'pending' | 'accepted' | 'denied' = 'pending';

    public constructor(public readonly senderId: UserId | string, public readonly data: KeyExchangeData) {
        super();
        this.on('change', (data, emitter) => this.onChange(data, emitter));
    }

    public onChange: EventCallback<BootstrapRequest, this> = () => { };

    public get status() {
        return this.#status;
    }

    public accept(): void {
        if (this.status === 'pending') {
            this.#status = 'accepted';
            this.emit('change', this);
        }
    }

    public deny(): void {
        if (this.status === 'pending') {
            this.#status = 'denied';
            this.emit('change', this);
        }
    }

}

export type NodeEventData = {
    session?: KeySession,
    payload?: Uint8Array,
    datagram?: Datagram,
    request?: BootstrapRequest,
    userId?: UserId
};

interface ErrorEventData extends NodeEventData {
    error: any
}

interface DebugEventData extends NodeEventData {
    debug: any[]
}

export type HandshakeEventData = {
    session: KeySession
};

export type SendEventData = {
    session?: KeySession,
    datagram: Datagram,
    userId: UserId
};

export type MessageEventData = {
    session: KeySession,
    payload: Uint8Array
};

export type FreeSignalNodeState = {
    privateIdentityKey: string;
    sessions: Array<[string, KeySessionState]>;
    users: Array<[string, string]>;
    bundles: Array<[string, KeyExchangeDataBundle]>;
    keyExchange: Array<[string, Crypto.KeyPair]>;
}

export class FreeSignalNode {
    protected readonly privateIdentityKey: PrivateIdentityKey
    protected readonly sessions: Map<string, KeySession>;
    protected readonly users: Map<string, string>;
    protected readonly bundles: Map<string, KeyExchangeDataBundle>;
    protected readonly keyExchange: KeyExchange;
    protected readonly bootstraps = new Map<string, BootstrapRequest>();
    protected readonly emitter = new EventEmitter<'send' | 'handshake' | 'message' | 'bootstrap' | 'error' | 'debug', NodeEventData>();

    public constructor({ privateIdentityKey, sessions, users, bundles, keyExchange }: Partial<FreeSignalNodeState> = {}) {
        this.privateIdentityKey = privateIdentityKey ? PrivateIdentityKey.from(privateIdentityKey) : createIdentity();
        this.sessions = new Map<string, KeySession>(sessions?.map(([key, value]) => [key, KeySession.from(value)]) ?? []);
        this.users = new Map<string, string>(users);
        this.bundles = new Map<string, KeyExchangeDataBundle>(bundles);
        this.keyExchange = new KeyExchange({ privateIdentityKey: this.privateIdentityKey, storage: keyExchange });

        this.emitter.on('message', this.messageHandler);
        this.emitter.on('send', this.sendHandler);
        this.emitter.on('handshake', this.handshakeHandler);
        this.emitter.on('bootstrap', this.bootstrapHandler);
        this.emitter.on<'error', ErrorEventData>('error', (e) => this.onError(e.error));
        this.emitter.on<'debug', DebugEventData>('debug', (e) => this.onDebug(e.debug));
    }

    protected messageHandler: EventCallback<NodeEventData, typeof this.emitter> = (data) => this.onMessage({ session: data.session!, payload: data.payload! })
    protected sendHandler: EventCallback<NodeEventData, typeof this.emitter> = (data) => this.onSend(data.datagram!.toBytes());
    protected handshakeHandler: EventCallback<NodeEventData, typeof this.emitter> = (data) => this.onHandshake(UserId.from(data.session?.userId!));
    protected bootstrapHandler: EventCallback<NodeEventData, typeof this.emitter> = (data) => this.onRequest(data.request!);

    public onMessage: (data: MessageEventData) => void = () => { };
    public onSend: (data: Uint8Array) => void = () => { };
    public onHandshake: (userId: UserId) => void = () => { };
    public onRequest: (request: BootstrapRequest) => void = () => { };
    public onError: (error: any) => void = () => { };
    public onDebug: (...args: any[]) => void = () => { };

    private error(error: any) {
        this.emitter.emit<ErrorEventData>('error', { error });
    }

    private debug(...args: any[]) {
        this.emitter.emit<DebugEventData>('debug', { debug: args });
    }

    public getRequest(userId: string): BootstrapRequest | undefined {
        return this.bootstraps.get(userId);
    }

    public waitHandshaked(userId: UserId | string, timeout?: number): Promise<void> {
        return new Promise(async (resolve, reject) => {
            if (timeout)
                setTimeout(() => reject(), timeout);
            while ((await this.emitter.wait('handshake', timeout))?.session?.userId.toString() !== userId.toString());
            resolve();
        });
    }

    public get identityKey(): IdentityKey {
        return this.privateIdentityKey.identityKey;
    }

    public get userId(): UserId {
        return this.identityKey.userId;
    }

    protected async encrypt(receiverId: string | UserId, protocol: Protocols, data: Uint8Array): Promise<SendEventData> {
        try {
            const sessionTag = this.users.get(receiverId.toString());
            if (!sessionTag)
                throw new Error("User not found: " + receiverId);
            const session = this.sessions.get(sessionTag);
            if (!session)
                throw new Error("Session not found for sessionTag: " + sessionTag);
            const encrypted = encryptData(session, data);
            return { session, userId: UserId.from(receiverId), datagram: new EncryptedDatagram(protocol, session.sessionTag, encrypted).sign(this.privateIdentityKey.signatureKey) };
        } catch (error) {
            this.error(error);
            throw error;
        }
    }

    public async sendHandshake(data: KeyExchangeData): Promise<void>;
    public async sendHandshake(session: KeySession): Promise<void>;
    public async sendHandshake(userId: UserId | string): Promise<void>;
    public async sendHandshake(data: KeyExchangeData | KeySession | UserId | string): Promise<void> {
        try {
            if (data instanceof UserId || typeof data === 'string') {
                const sessionTag = this.users.get(data.toString());
                if (!sessionTag)
                    throw new Error("User not found: " + data.toString());
                const session = this.sessions.get(sessionTag);
                if (!session)
                    throw new Error("Session not found for sessionTag: " + sessionTag);
                data = session;
            }
            if (data instanceof KeySession) {
                //console.debug("Sending Handshake Ack");
                const session = this.sessions.get(data.sessionTag);
                if (!session)
                    throw new Error("Session not found for sessionTag: " + data.sessionTag);
                this.emitter.emit('send', await this.encrypt(session.userId, Protocols.HANDSHAKE, crypto.ECDH.scalarMult(this.privateIdentityKey.exchangeKey, session.identityKey.exchangeKey)));
                return;
            }
        } catch (error) {
            this.error(error);
            throw error;
        }
        //console.debug("Sending Handshake Syn");
        const { session, message } = this.keyExchange.digestData(data, encodeData(this.keyExchange.generateBundle()));
        this.sessions.set(session.sessionTag, session);
        this.users.set(session.userId.toString(), session.sessionTag);
        const datagram = new Datagram(Protocols.HANDSHAKE, encodeData(message), session.sessionTag).sign(this.privateIdentityKey.signatureKey);
        this.emitter.emit('send', { session, datagram, userId: session.userId });
    }

    public async sendData<T>(receiverId: string | UserId, data: T): Promise<void> {
        //console.debug("Sending Data");
        this.emitter.emit('send', await this.encrypt(receiverId, Protocols.MESSAGE, encodeData(data)));
    }

    public async sendRelay(relayId: string | UserId, receiverId: string | UserId, data: Datagram): Promise<void> {
        //console.debug("Sending Relay");
        this.emitter.emit('send', await this.encrypt(relayId, Protocols.RELAY, concatBytes(UserId.from(receiverId).toBytes(), data.toBytes())));
    }

    /*public async sendPing(receiverId: string | UserId): Promise<void> {
        //console.debug("Sending Ping");
        const sessionTag = await this.users.get(receiverId.toString());
        if (!sessionTag)
            throw new Error("Session not found for user: " + receiverId);
        const session = await this.sessions.get(sessionTag);
        if (!session)
            throw new Error("Session not found for sessionTag: " + sessionTag);
        const datagram = new Datagram(Protocols.PING, undefined, session.sessionTag);
        this.emitter.emit('send', { session, datagram, userId: session.userId });
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
    }*/

    public packBootstrap() {
        return new Datagram(Protocols.BOOTSTRAP, encodeData(this.keyExchange.generateData()));
    }

    public async sendBootstrap(receiverId: string | UserId): Promise<void> {
        try {
            //console.debug("Sending Bootstrap");
            const sessionTag = this.users.get(receiverId.toString())
            if (sessionTag && this.sessions.has(sessionTag))
                throw new Error("Session exists");
            const datagram = this.packBootstrap();
            this.emitter.emit('send', { datagram, userId: UserId.from(receiverId) });
        } catch (error) {
            this.error(error);
            throw error;
        }
    }

    protected async decrypt(datagram: EncryptedDatagram | Datagram | Uint8Array): Promise<MessageEventData> {
        try {
            datagram = EncryptedDatagram.from(datagram);
            if (!datagram.sessionTag)
                throw new Error("Datagram not encrypted");
            const session = this.sessions.get(datagram.sessionTag);
            if (!session)
                throw new Error("Session not found for sessionTag: " + datagram.sessionTag);
            if (!datagram.verify(session.identityKey.signatureKey))
                throw new Error("Signature not verified");
            if (!datagram.payload)
                throw new Error("Missing payload");
            const decrypted = decryptData(session, datagram.payload);
            return { session, payload: decrypted };
        } catch (error) {
            this.error(error);
            throw error;
        }
    }

    protected async openHandshake(datagram: Datagram | EncryptedDatagram | Uint8Array): Promise<"syn" | "ack"> {
        try {
            const encrypted = EncryptedDatagram.from(datagram);
            if (!encrypted.payload)
                throw new Error("Missing payload");
            if (this.sessions.has(encrypted.sessionTag)) {
                //console.debug("Opening Handshake Ack");
                const session = this.sessions.get(encrypted.sessionTag);
                const { payload } = await this.decrypt(encrypted);
                if (!session)
                    throw new Error("Session not found for sessionTag: " + encrypted.sessionTag);
                if (!compareBytes(payload, crypto.ECDH.scalarMult(this.privateIdentityKey.exchangeKey, session.identityKey.exchangeKey)))
                    throw new Error("Error validating handshake data");
                return 'ack';
            }
            //console.debug("Opening Handshake Syn");
            const data = decodeData<KeyExchangeSynMessage>(encrypted.payload);
            if (!encrypted.verify(IdentityKey.from(data.identityKey).signatureKey))
                throw new Error("Signature not verified");
            const { session, associatedData } = this.keyExchange.digestMessage(data);
            this.sessions.set(session.sessionTag, session);
            this.users.set(session.userId.toString(), session.sessionTag);
            this.bundles.set(session.userId.toString(), decodeData<KeyExchangeDataBundle>(associatedData));
            return 'syn';
        } catch (error) {
            this.error(error);
            throw error;
        }
    }

    protected async open(datagram: Datagram | EncryptedDatagram | Uint8Array): Promise<void> {
        try {
            if (datagram instanceof Uint8Array)
                datagram = Datagram.from(datagram);
            switch (datagram.protocol) {
                case Protocols.HANDSHAKE: {
                    const encrypted = EncryptedDatagram.from(datagram);
                    if (!encrypted.payload)
                        throw new Error("Missing payload");
                    const handshakeState = await this.openHandshake(datagram)
                    const session = this.sessions.get(encrypted.sessionTag);
                    if (!session)
                        throw new Error("Session not found for sessionTag: " + encrypted.sessionTag);
                    if (handshakeState === 'syn')
                        this.sendHandshake(session);
                    this.emitter.emit('handshake', { session });
                    return;
                }

                case Protocols.MESSAGE:
                    //console.debug("Opening Message");
                    this.emitter.emit('message', await this.decrypt(datagram));
                    return;

                case Protocols.RELAY: {
                    //console.debug("Opening Relay");
                    const opened = await this.decrypt(datagram);
                    const userId = decodeBase64(opened.payload.subarray(0, UserId.keyLength));
                    const sessionTag = this.users.get(userId);
                    if (!sessionTag)
                        throw new Error("Session not found for user: " + userId);
                    const session = this.sessions.get(sessionTag);
                    if (!session)
                        throw new Error("Session not found for sessionTag: " + datagram.sessionTag);
                    this.emitter.emit('send', { session, datagram: Datagram.from(opened.payload.slice(UserId.keyLength)), userId: session.userId });
                    return;
                }

                case Protocols.BOOTSTRAP: {
                    //console.debug("Opening Bootstrap");
                    if (!datagram.payload)
                        throw new Error("Invalid Bootstrap");
                    const keyExchangeData = decodeData<KeyExchangeData>(datagram.payload);
                    const userId = UserId.fromKey(keyExchangeData.identityKey);
                    const request = new BootstrapRequest(userId, keyExchangeData);
                    let sended = false;
                    request.onChange = (request) => {
                        if (request.status === 'accepted' && !sended) {
                            sended = true;
                            this.sendHandshake(request.data);
                        }
                    }
                    this.bootstraps.set(userId.toString(), request);
                    this.emitter.emit('bootstrap', { request });
                    return;
                }

                /*case Protocols.DISCOVER: {
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
    
                case Protocols.PING:
                    datagram = EncryptedDatagram.from(datagram);
                    const session = await this.sessions.get(datagram.sessionTag!);
                    if (!session)
                        throw new Error("Session not found for sessionTag: " + datagram.sessionTag);
                    this.emitter.emit('ping', { session });
                    return;*/

                default:
                    throw new Error("Invalid protocol");
            }
        } catch (error) {
            this.error(error);
            throw error;
        }
    }

    public toJSON(): FreeSignalNodeState {
        return {
            privateIdentityKey: this.privateIdentityKey.toString(),
            sessions: Array.from(this.sessions.entries()).map(([key, session]) => [key, session.toJSON()]),
            users: Array.from(this.users.entries()),
            bundles: Array.from(this.bundles),
            keyExchange: this.keyExchange.toJSON().storage,
        }
    }
}

/*class SessionMap implements LocalStorage<string, KeySession> {
    private readonly cache = new Map<string, KeySession>()

    public constructor(public readonly storage: LocalStorage<string, KeySessionState>, public readonly maxSize = 50) { }

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
}*/