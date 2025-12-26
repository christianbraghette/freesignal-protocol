import { decodeBase64 } from "@freesignal/crypto/utils";
import { Identity, KeyStore, PreKey, PreKeyId, SessionState, KeyStoreFactory, PublicIdentity, Bytes, UserId } from "@freesignal/interfaces";

export class InMemoryKeystoreFactory implements KeyStoreFactory {
    #stores = new Map<string, KeyStore>();

    public async createStore(identity: Identity): Promise<KeyStore> {
        this.#stores.set(identity.toString(), new InMemoryKeystore(identity))
        const store = await this.getStore(identity.toString())
        if (!store)
            throw new Error("Error creting keyStore");
        return store;
    }

    public async getStore(identity: PublicIdentity | string): Promise<KeyStore | null> {
        return this.#stores.get(identity.toString()) ?? null;
    }

    public async deleteStore(identity: PublicIdentity | string): Promise<void> {
        this.#stores.delete(identity.toString());
    }

}

class InMemoryKeystore implements KeyStore {
    readonly #identity: Identity;
    #sessions = new Map<string, SessionState>();
    #preKeys = new Map<string, PreKey>();
    #users = new Map<string, string>();
    #hashkeys = new Map<string, string>();


    constructor(identity: Identity) {
        this.#identity = identity;
    }


    public async getIdentity(): Promise<Identity> {
        return this.#identity;
    }

    public async getUserSession(userId: UserId | string): Promise<string | null> {
        return this.#users.get(userId.toString()) ?? null;
    }

    public async getSessionTag(hashkey: Bytes | string): Promise<string | null> {
        return this.#hashkeys.get(typeof hashkey === 'string' ? hashkey : decodeBase64(hashkey)) ?? null;
    }

    public async setSessionTag(hashkey: Bytes | string, sessionTag: string): Promise<void> {
        this.#hashkeys.set(typeof hashkey === 'string' ? hashkey : decodeBase64(hashkey), sessionTag);
    }

    public async loadSession(sessionTag: string): Promise<SessionState | null> {
        return this.#sessions.get(sessionTag) ?? null;
    }

    public async storeSession(session: SessionState): Promise<void> {
        this.#users.set(session.userId, session.sessionTag);
        this.#sessions.set(session.sessionTag, session);
    }


    public async storePreKey(id: PreKeyId, value: PreKey): Promise<void> {
        this.#preKeys.set(id, value);
    }

    public async loadPreKey(id: PreKeyId): Promise<PreKey | null> {
        return this.#preKeys.get(id) ?? null;
    }

    public async removePreKey(id: PreKeyId): Promise<void> {
        this.#preKeys.delete(id);
    }
}