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

import { KeyExchangeManager, KeyStore, PreKeyBundle, PublicIdentity, SessionManager, User, UserFactory, Crypto, Bytes, Ciphertext, UserId, KeyStoreFactory } from "@freesignal/interfaces";
import { KeyExchangeManagerConstructor } from "./keyexchange.js";
import { SessionManagerConstructor } from "./session.js";
import { useConstructors } from "./constructors.js";

export class UserFactoryConstructor implements UserFactory {
    readonly #objestStore = new WeakSet();

    constructor(private readonly keyStoreFactory: KeyStoreFactory, private readonly crypto: Crypto) { }

    public async create(seed?: Bytes): Promise<User> {
        const { IdentityConstructor } = useConstructors(this.crypto);

        const identity = IdentityConstructor.from((seed ? this.crypto.EdDSA.keyPairFromSeed(seed) : this.crypto.EdDSA.keyPair()).secretKey);
        const user = new UserConstructor(identity, await this.keyStoreFactory.createStore(identity), this.crypto);
        this.#objestStore.add(user);
        return user;
    };

    public destroy(user: User): boolean {
        return this.#objestStore.delete(user);
    }
}

class UserConstructor implements User {
    readonly #sessionManager: SessionManager;
    readonly #keyExchangeManager: KeyExchangeManager;

    constructor(public readonly publicIdentity: PublicIdentity, keyStore: KeyStore, private readonly crypto: Crypto) {
        this.#sessionManager = new SessionManagerConstructor(keyStore, crypto);
        this.#keyExchangeManager = new KeyExchangeManagerConstructor(publicIdentity, keyStore, crypto);
        this.#keyExchangeManager.socket.on('session', async (session) => {
            this.#sessionManager.createSession(session);
        });
    }

    public get socket() {
        return this.#keyExchangeManager.socket;
    }

    public get id(): UserId {
        return this.publicIdentity.userId;
    }

    public encrypt<T>(to: UserId | string, plaintext: T): Promise<Ciphertext> {
        return this.#sessionManager.encrypt(to, this.crypto.Utils.encodeData(plaintext));
    }

    public async decrypt<T>(from: UserId | string, ciphertext: Ciphertext | Bytes): Promise<T> {
        return this.crypto.Utils.decodeData<T>(await this.#sessionManager.decrypt(from, ciphertext));
    }

    public waitHandshake(from: UserId | string, timeout?: number): Promise<void> {
        return new Promise(async (resolve, reject) => {
            if (timeout)
                setTimeout(() => reject(), timeout);
            while ((await this.#keyExchangeManager.socket.wait('session', timeout))?.userId.toString() !== from.toString());
            resolve();
        });
    }

    public generatePreKeyBundle(): Promise<PreKeyBundle> {
        return this.#keyExchangeManager.createPreKeyBundle();
    }

    public async handleIncomingPreKeyBundle(bundle: PreKeyBundle): Promise<void> {
        const session = await this.#keyExchangeManager.processPreKeyBundle(bundle)
        await this.#sessionManager.createSession(session);
    }

}