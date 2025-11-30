import { Database, LocalStorage, Crypto, KeyExchangeDataBundle, KeyExchangeData, KeyExchangeSynMessage } from "@freesignal/interfaces";
import { Datagram, IdentityKey, PrivateIdentityKey, Protocols, UserId } from "./types";
import { KeyExchange } from "./x3dh";
import { ExportedKeySession, KeySession } from "./double-ratchet";
import { createIdentity } from ".";
import { decodeData, encodeData } from "@freesignal/utils";

export class FreeSignalNode {
    protected readonly privateIdentityKey: PrivateIdentityKey
    protected readonly sessions: SessionMap;
    protected readonly users: LocalStorage<string, IdentityKey>;
    protected readonly keyExchange: KeyExchange;

    public constructor(storage: Database<{
        sessions: LocalStorage<string, ExportedKeySession>,
        keyExchange: LocalStorage<string, Crypto.KeyPair>,
        users: LocalStorage<string, IdentityKey>
    }>, privateIdentityKey?: PrivateIdentityKey) {
        this.privateIdentityKey = privateIdentityKey ?? createIdentity();
        this.sessions = new SessionMap(storage.sessions);
        this.keyExchange = new KeyExchange({ keys: storage.keyExchange, sessions: storage.sessions }, this.privateIdentityKey);
        this.users = storage.users;
    }

    public get userId(): UserId {
        return UserId.fromKey(this.privateIdentityKey.identityKey);
    }

    public get identityKey(): IdentityKey {
        return this.privateIdentityKey.identityKey;
    }

    public generateKeyData(): Promise<KeyExchangeData> {
        return this.keyExchange.generateData();
    };

    public generateKeyBundle(length?: number): Promise<KeyExchangeDataBundle> {
        return this.keyExchange.generateBundle(length);
    };

    public async encrypt(receiverId: string, protocol: Protocols, data: Uint8Array): Promise<Datagram> {
        const session = await this.sessions.get(receiverId);
        if (!session)
            throw new Error("Session not found for user: " + receiverId);
        return new Datagram(this.userId.toString(), receiverId, protocol, await session.encrypt(data));
    }

    public async sendHandshake(data: KeyExchangeData): Promise<Datagram> {
        const { session, message, identityKey } = await this.keyExchange.digestData(data);
        const remoteId = UserId.fromKey(identityKey);
        this.sessions.set(remoteId.toString(), session);
        return new Datagram(this.userId.toString(), UserId.fromKey(data.identityKey).toString(), Protocols.HANDSHAKE, encodeData(message));
    }

    public sendData<T>(receiverId: string, data: T): Promise<Datagram> {
        return this.encrypt(receiverId, Protocols.MESSAGE, encodeData(data));
    }

    public sendRelay(receiverId: string, data: Datagram): Promise<Datagram> {
        return this.encrypt(receiverId, Protocols.RELAY, encodeData(data));
    }

    public sendDiscover(receiverId: string, discoverId: string): Promise<Datagram> {
        return this.encrypt(receiverId, Protocols.DISCOVER, encodeData(discoverId));
    }

    public async decrypt(datagram: Datagram): Promise<Uint8Array> {
        const userId = datagram.sender;
        const session = await this.sessions.get(userId);
        if (!session)
            throw new Error("Session not found for user: " + userId);
        if (!datagram.payload)
            throw new Error("Missing payload");
        const decrypted = await session.decrypt(datagram.payload);
        if (!decrypted)
            throw new Error("Decryption failed");
        return decrypted;
    }

    public async receive<T extends Uint8Array | UserId | Datagram | UserId | void>(datagram: Datagram | Uint8Array): Promise<T>
    public async receive(datagram: Datagram | Uint8Array): Promise<Uint8Array | UserId | Datagram | UserId | void> {
        if (datagram instanceof Uint8Array)
            datagram = Datagram.from(datagram);
        switch (datagram.protocol) {
            case Protocols.HANDSHAKE:
                if (!datagram.payload)
                    throw new Error("Missing payload");
                const data = decodeData<KeyExchangeSynMessage>(datagram.payload);
                const { session, identityKey } = await this.keyExchange.digestMessage(data);
                this.sessions.set(UserId.fromKey(identityKey).toString(), session);
                return;

            case Protocols.MESSAGE:
                return await this.decrypt(datagram);

            case Protocols.RELAY:
                return decodeData<Datagram>(await this.decrypt(datagram));

            case Protocols.DISCOVER:
                return UserId.from(decodeData<string>(await this.decrypt(datagram)));

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