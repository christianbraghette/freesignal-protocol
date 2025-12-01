import { Database, LocalStorage, Crypto, KeyExchangeDataBundle, KeyExchangeData, KeyExchangeSynMessage } from "@freesignal/interfaces";
import { Datagram, DiscoverMessage, DiscoverType, IdentityKey, PrivateIdentityKey, Protocols, UserId } from "./types";
import { KeyExchange } from "./x3dh";
import { ExportedKeySession, KeySession } from "./double-ratchet";
import { createIdentity } from ".";
import { decodeData, encodeData, encodeJSON } from "@freesignal/utils";

export class FreeSignalNode {
    protected readonly privateIdentityKey: PrivateIdentityKey
    protected readonly sessions: SessionMap;
    protected readonly users: LocalStorage<string, IdentityKey>;
    protected readonly bundles: LocalStorage<string, KeyExchangeDataBundle>;
    protected readonly keyExchange: KeyExchange;
    protected readonly discovers: Set<DiscoverMessage> = new Set();

    public constructor(storage: Database<{
        sessions: LocalStorage<string, ExportedKeySession>,
        keyExchange: LocalStorage<string, Crypto.KeyPair>,
        users: LocalStorage<string, IdentityKey>,
        bundles: LocalStorage<string, KeyExchangeDataBundle>
    }>, privateIdentityKey?: PrivateIdentityKey) {
        this.privateIdentityKey = privateIdentityKey ?? createIdentity();
        this.sessions = new SessionMap(storage.sessions);
        this.keyExchange = new KeyExchange({ keys: storage.keyExchange, sessions: storage.sessions }, this.privateIdentityKey);
        this.users = storage.users;
        this.bundles = storage.bundles;
    }

    public get identityKey(): IdentityKey {
        return this.privateIdentityKey.identityKey;
    }

    public get userId(): UserId {
        return UserId.fromKey(this.identityKey);
    }

    public generateKeyExchangeData(): Promise<KeyExchangeData> {
        return this.keyExchange.generateData();
    };

    public generateKeyExchangeBundle(length?: number): Promise<KeyExchangeDataBundle> {
        return this.keyExchange.generateBundle(length);
    };

    protected async encrypt(receiverId: string | UserId, protocol: Protocols, data: Uint8Array): Promise<Datagram> {
        if (receiverId instanceof UserId)
            receiverId = receiverId.toString();
        const session = await this.sessions.get(receiverId);
        if (!session)
            throw new Error("Session not found for user: " + receiverId);
        return new Datagram(this.userId.toString(), receiverId, protocol, await session.encrypt(data)).sign(this.privateIdentityKey.signatureKey);
    }

    public async packHandshake(data: KeyExchangeData): Promise<Datagram> {
        const { session, message, identityKey } = await this.keyExchange.digestData(data);
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

    public packDiscover(receiverId: string | UserId, message: DiscoverMessage): Promise<Datagram> {
        return this.encrypt(receiverId, Protocols.DISCOVER, encodeData(message));
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
        const decrypted = await session.decrypt(datagram.payload);
        if (!decrypted)
            throw new Error("Decryption failed");
        return decrypted;
    }

    public async open<T extends Uint8Array | UserId | Datagram | UserId | KeyExchangeData | undefined | void>(datagram: Datagram | Uint8Array): Promise<T>
    public async open(datagram: Datagram | Uint8Array): Promise<Uint8Array | UserId | Datagram | UserId | KeyExchangeData | undefined> {
        if (datagram instanceof Uint8Array)
            datagram = Datagram.from(datagram);
        switch (datagram.protocol) {
            case Protocols.HANDSHAKE:
                if (!datagram.payload)
                    throw new Error("Missing payload");
                const data = decodeData<KeyExchangeSynMessage>(datagram.payload);
                if (!Datagram.verify(datagram, IdentityKey.from(data.identityKey).signatureKey))
                    throw new Error("Signature not verified");
                const { session, identityKey } = await this.keyExchange.digestMessage(data);
                const userId = UserId.fromKey(identityKey);
                await this.users.set(userId.toString(), identityKey);
                await this.sessions.set(userId.toString(), session);
                return;

            case Protocols.MESSAGE:
                return decodeData(await this.decrypt(datagram));

            case Protocols.RELAY:
                return decodeData<Datagram>(await this.decrypt(datagram));

            case Protocols.DISCOVER:
                const message = decodeData<DiscoverMessage>(await this.decrypt(datagram));
                if (message.type === DiscoverType.REQUEST && message.discoverId && !(await this.users.has(message.discoverId))) {
                    const bundle = await this.bundles.get(message.discoverId);
                    if (!bundle) return;
                    const { version, identityKey, signedPreKey, signature } = bundle;
                    const onetimePreKey = bundle.onetimePreKeys.shift();
                    if (!onetimePreKey) {
                        await this.bundles.delete(message.discoverId);
                        return;
                    }
                    const data: KeyExchangeData = {
                        version,
                        identityKey,
                        signedPreKey,
                        signature,
                        onetimePreKey
                    };
                    return await this.packDiscover(datagram.sender, { type: DiscoverType.RESPONSE, data });
                } else if (message.type === DiscoverType.RESPONSE && this.discovers.has(message)) {
                    return message.data;
                }
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
            return KeySession.from(sessionData, this.storage);
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