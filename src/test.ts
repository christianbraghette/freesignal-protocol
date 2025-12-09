import { compareBytes, decodeData } from "@freesignal/utils";
import { AsyncMap, createNode, Datagram } from ".";

console.log("FreeSignal protocol test");

const bob = createNode({ keyExchange: new AsyncMap(), sessions: new AsyncMap(), users: new AsyncMap(), bundles: new AsyncMap(), bootstraps: new AsyncMap() });
const alice = createNode({ keyExchange: new AsyncMap(), sessions: new AsyncMap(), users: new AsyncMap(), bundles: new AsyncMap(), bootstraps: new AsyncMap() });

setImmediate(async () => {
    const bobBootstrap = await bob.packBootstrap(alice.userId);

    alice.onRequest = (request) => { request.accept(); };

    const test = (await alice.open(bobBootstrap)).datagram;
    const aliceHandshake = await alice.getRequest(bob.userId.toString());
    if (!aliceHandshake)
        throw new Error("Bootstrap Failed");

    const bobHandshake = (await bob.open(aliceHandshake)).datagram;
    if (!bobHandshake)
        throw new Error("Handshake Failed");
    
    console.log(!!(await alice.open(bobHandshake)).header);

    const first = (await bob.packData(alice.userId, "Hi Alice!")).toBytes();

    console.log("Bob: ", decodeData<string>((await alice.open(first)).payload!));
    const second = await alice.packData(bob.userId, "Hi Bob!");

    console.log("Test");

    console.log("Alice: ", decodeData<string>((await bob.open(second)).payload!));
    const third = await Promise.all(["How are you?", "How are this days?", "For me it's a good time"].map(msg => bob.packData(alice.userId, msg)));

    third.forEach(async data => {
        console.log("Bob: ", decodeData<string>((await alice.open(data)).payload!));
    });
    const fourth = await alice.packData(bob.userId, "Not so bad my man");

    console.log("Alice: ", decodeData<string>((await bob.open(fourth)).payload!));

    const fifth = await Promise.all(["I'm thinking...", "His this secure?"].map(msg => bob.packData(alice.userId, msg)));
    fifth.forEach(async data => {
        console.log("Bob: ", decodeData<string>((await alice.open(data)).payload!));
    });

    //const testone = await Promise.all(Array(400).fill(0).map(() => alice.packData(bob.userId, decodeBase64(crypto.randomBytes(64)))));
    //console.log(((await bob.open(testone[350])).payload));
});