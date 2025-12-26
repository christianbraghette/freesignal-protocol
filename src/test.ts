import { decodeBase64 } from "@freesignal/crypto/utils";
import { UserFactory, InMemoryKeystoreFactory } from "./index.js";
import crypto from "@freesignal/crypto";

const userFactory = new UserFactory(new InMemoryKeystoreFactory(), crypto);

const alice = await userFactory.create();
const bob = await userFactory.create();

alice.emitter.on('send', data => bob.emitter.emit('receive', data));
bob.emitter.on('send', data => alice.emitter.emit('receive', data));

const bundle = await alice.generatePreKeyBundle();
bob.handleIncomingPreKeyBundle(bundle);
await alice.waitHandshake(bob.id);
console.log("Handshaked");

const cyphertext = await alice.encrypt(bob.id, "Testone");
console.log(await bob.decrypt(cyphertext));

console.log("Starting big test...");

setTimeout(async () => {
    console.log("Big Test started!");
    const messages = await Promise.all(Array(2950).fill(0).map(() => alice.encrypt(bob.id, crypto.randomBytes(64))));
    console.log("2950 encrypted messages");
    await Promise.all(messages.map(async (message) => console.log(decodeBase64(await bob.decrypt(message)))));
    console.log("2950 decrypted messages");
}, 1000)