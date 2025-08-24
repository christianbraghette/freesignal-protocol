import { Crypto, LocalStorage } from "@freesignal/interfaces";
import crypto from "@freesignal/crypto";
import { KeySession } from "./double-ratchet";
import { KeyExchange } from "./x3dh";
import { concatUint8Array, decodeBase64, encodeBase64, numberFromUint8Array, numberToUint8Array, verifyUint8Array } from "@freesignal/utils";
import { Datagram, IdentityKeys, EncryptedData, UserId } from "./types";
import fflate from "fflate";

export const FREESIGNAL_MIME = "application/x-freesignal";

type DatagramId = string;

export class FreeSignalAPI {
    protected readonly signKey: Crypto.KeyPair;
    protected readonly boxKey: Crypto.KeyPair;
    protected readonly sessions: LocalStorage<UserId, KeySession>;
    protected readonly keyExchange: KeyExchange;
    protected readonly users: LocalStorage<UserId, IdentityKeys>;

    public constructor(opts: {
        secretSignKey: Uint8Array,
        secretBoxKey: Uint8Array,
        sessions: LocalStorage<UserId, KeySession>,
        keyExchange: LocalStorage<string, Crypto.KeyPair>,
        users: LocalStorage<UserId, IdentityKeys>
    }) {
        const { secretSignKey, secretBoxKey, sessions, keyExchange, users } = opts;
        this.signKey = crypto.EdDSA.keyPair(secretSignKey);
        this.boxKey = crypto.ECDH.keyPair(secretBoxKey);
        this.sessions = sessions;
        this.keyExchange = new KeyExchange(secretSignKey, secretBoxKey, keyExchange);
        this.users = users;
    }

    public get userId(): Uint8Array {
        return crypto.hash(this.signKey.publicKey);
    }

    public get identityKeys(): IdentityKeys {
        return {
            publicKey: encodeBase64(this.signKey.publicKey),
            identityKey: encodeBase64(this.boxKey.publicKey)
        }
    }

    public async encryptData(data: Uint8Array, userId: string): Promise<EncryptedData> {
        const session = await this.sessions.get(userId);
        if (!session) throw new Error('Session not found for user: ' + userId);
        const encrypted = session.encrypt(data);
        this.sessions.set(userId, session); // Ensure session is updated
        return encrypted;
    }

    public async decryptData(data: Uint8Array, userId: string): Promise<Uint8Array> {
        const session = await this.sessions.get(userId);
        if (!session) throw new Error('Session not found for user: ' + userId);
        const decrypted = session.decrypt(data);
        if (!decrypted) throw new Error('Decryption failed for user: ' + userId);
        this.sessions.set(userId, session); // Ensure session is updated
        return decrypted;
    }

    public async getDatagrams(publicKey: string | Uint8Array, url: string): Promise<Datagram[]> {
        const res = await fetch(url, {
            method: 'GET',
            headers: {
                authorization: this.createToken(publicKey instanceof Uint8Array ? publicKey : decodeBase64(publicKey))
            }
        })
        return this.unpackDatagrams(await this.decryptData(new Uint8Array(await res.arrayBuffer()), FreeSignalAPI.getUserId(publicKey)));
    }

    public async postDatagrams(datagrams: Datagram[], publicKey: string | Uint8Array, url: string): Promise<number> {
        const data = await this.encryptData(this.packDatagrams(datagrams), FreeSignalAPI.getUserId(publicKey));
        const res = await fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': FREESIGNAL_MIME,
                authorization: this.createToken(publicKey instanceof Uint8Array ? publicKey : decodeBase64(publicKey))
            },
            body: data.encode() as any
        });
        return numberFromUint8Array(await this.decryptData(new Uint8Array(await res.arrayBuffer()), FreeSignalAPI.getUserId(publicKey)));
    }

    public async deleteDatagrams(datagramIds: DatagramId[], publicKey: string | Uint8Array, url: string): Promise<number> {
        const data = await this.encryptData(this.packIdList(datagramIds), FreeSignalAPI.getUserId(publicKey));
        const res = await fetch(url, {
            method: 'DELETE',
            headers: {
                'Content-Type': FREESIGNAL_MIME,
                authorization: this.createToken(publicKey instanceof Uint8Array ? publicKey : decodeBase64(publicKey))
            },
            body: data.encode() as any
        });
        return numberFromUint8Array(await this.decryptData(new Uint8Array(await res.arrayBuffer()), FreeSignalAPI.getUserId(publicKey)));
    }

    public createToken(publicKey: Uint8Array): string {
        const sharedId = crypto.hash(crypto.ECDH.scalarMult(publicKey, this.boxKey.secretKey));
        return `Bearer ${encodeBase64(this.userId)}:${encodeBase64(sharedId)}`;
    };

    protected async digestToken(auth?: string): Promise<{ identityKeys: IdentityKeys, userId: UserId }> {
        if (auth && auth.startsWith("Bearer ")) {
            const [userId, sharedId] = auth.substring(7).split(":");
            const identityKeys = await this.users.get(userId);
            if (!identityKeys)
                throw new Error('User not found or invalid auth token');
            if (verifyUint8Array(crypto.hash(crypto.ECDH.scalarMult(decodeBase64(identityKeys.publicKey), this.boxKey.secretKey)), decodeBase64(sharedId)))
                return { identityKeys, userId: auth };
            else
                throw new Error('Authorization token not valid');
        }
        throw new Error('Authorization header is required');
    }

    protected packIdList(datagramIds: DatagramId[]): Uint8Array {
        return datagramIds.map(datagramId => crypto.UUID.parse(datagramId)).reduce((prev, curr) => new Uint8Array([...prev, ...curr]), new Uint8Array())
    }

    protected unpackIdList(data: Uint8Array): DatagramId[] {
        const ids: DatagramId[] = []
        for (let i = 0; i < data.length; i += 16) {
            ids.push(crypto.UUID.stringify(data.subarray(i, i + 16)));
        }
        return ids;
    }

    protected packDatagrams(messages: Datagram[]): Uint8Array {
        return fflate.deflateSync(concatUint8Array(...messages.flatMap(
            datagram => {
                const encoded = Datagram.from(datagram).encode();
                return [numberToUint8Array(encoded.length, 8), encoded]
            }
        )))
    }

    protected unpackDatagrams(data: Uint8Array): Datagram[] {
        const messages: Datagram[] = [];
        let offset = 0
        data = fflate.inflateSync(data);
        while (offset < data.length) {
            const length = data.subarray(offset, offset + 8);
            if (length.length < 8) {
                throw new Error('Invalid message length');
            }
            const messageLength = numberFromUint8Array(length);
            offset += 8;
            if (offset + messageLength > data.length) {
                throw new Error('Invalid message length');
            }
            const messageData = data.subarray(offset, offset + messageLength);
            offset += messageLength;
            try {
                const datagram = Datagram.from(messageData);
                messages.push(datagram);
            } catch (error) {
                throw new Error('Invalid datagram format');
            }
        }
        return messages;
    }

    public static getUserId(publicKey: string | Uint8Array): string {
        return encodeBase64(crypto.hash(publicKey instanceof Uint8Array ? publicKey : decodeBase64(publicKey)));
    }
}