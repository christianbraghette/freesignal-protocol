import { decodeBase64, decodeData } from "@freesignal/utils";
import { Datagram } from "./index.js";
import { FreeSignalNode } from "./node.js";
import crypto from "@freesignal/crypto";

console.log("FreeSignal protocol test");

class TestNode extends FreeSignalNode {

    public open(datagram: Datagram | Uint8Array) {
        return super.open(datagram);
    }
}

const bob = new TestNode();
const alice = new TestNode();

//bob.onHandshaked = (userId) => console.log(userId.toString());
bob.onSend = (data) => alice.open(data);
bob.onMessage = (data) => console.log("Alice: ", decodeData<string>(data.payload));
//alice.onHandshaked = (userId) => console.log(userId.toString());
alice.onSend = (data) => bob.open(data);
alice.onMessage = (data) => console.log("Bob: ", decodeData<string>(data.payload));
alice.onRequest = (request) => request.accept();

setImmediate(async () => {
    bob.sendBootstrap(alice.userId);
    await bob.waitHandshaked(alice.userId);
    await bob.sendData(alice.userId, "Hi Alice!");
    await alice.sendData(bob.userId, "Hi Bob!");
    await Promise.all(["How are you?", "How are this days?", "For me it's a good time"].map(msg => bob.sendData(alice.userId, msg)));
    await alice.sendData(bob.userId, "Not so bad my man");
    await Promise.all(["I'm thinking...", "Is this secure?"].map(msg => bob.sendData(alice.userId, msg)));
    console.log("Starting big test...");

    setTimeout(async () => {
        console.log("Big Test started!");
        await Promise.all(Array(2950).fill(0).map(() => alice.sendData(bob.userId, decodeBase64(crypto.randomBytes(64)))));
        console.log("2950 messages encrypted and decrypted");
    }, 1000)
});