import { decodeBase64, decodeData, encodeData, numberToArray, } from "@freesignal/utils";
import { AsyncMap, createNode } from ".";
import crypto from "@freesignal/crypto";

const bob = createNode({ keyExchange: new AsyncMap(), sessions: new AsyncMap(), users: new AsyncMap(), bundles: new AsyncMap() });
const alice = createNode({ keyExchange: new AsyncMap(), sessions: new AsyncMap(), users: new AsyncMap(), bundles: new AsyncMap() });

setImmediate(async () => {
    const aliceHandshake = await alice.packHandshake(await bob.generateKeyExchangeData());

    await bob.open<void>(aliceHandshake);
    const first = (await bob.packData(alice.userId, "Hi Alice!")).toBytes();

    console.log("Bob: ", await alice.open(first));
    const second = await alice.packData(bob.userId, "Hi Bob!");

    console.log("Alice: ", await bob.open(second));
    const third = await Promise.all(["How are you?", "How are this days?", "For me it's a good time"].map(msg => bob.packData(alice.userId, msg)));

    third.forEach(async data => {
        console.log("Bob: ", await alice.open(data));
    });
    const fourth = await alice.packData(bob.userId, "Not so bad my man");

    console.log("Alice: ", await bob.open(fourth));

    const testone = await Promise.all(Array(2699).fill(0).map(() => alice.packData(bob.userId, decodeBase64(crypto.randomBytes(64)))));

    console.log((await bob.open<Uint8Array>(testone[2000])));
});