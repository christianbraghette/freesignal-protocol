import { compareBytes, decodeBase64, decodeData, encodeData, encodeUTF8 } from "@freesignal/utils";
import { AsyncMap, createNode, Datagram } from ".";
import { FreeSignalNode } from "./node";

console.log("FreeSignal protocol test");

class TestNode extends FreeSignalNode {

    public open(datagram: Datagram | Uint8Array) {
        return super.open(datagram);
    }
}

const bob = new TestNode({ keyExchange: new AsyncMap(), sessions: new AsyncMap(), users: new AsyncMap(), bundles: new AsyncMap(), bootstraps: new AsyncMap() });
const alice = new TestNode({ keyExchange: new AsyncMap(), sessions: new AsyncMap(), users: new AsyncMap(), bundles: new AsyncMap(), bootstraps: new AsyncMap() });

//bob.onHandshaked = (userId) => console.log(userId.toString());
bob.onSend = (data) => alice.open(data);
bob.onMessage = (data) => console.log("Alice: ", decodeData<string>(data.payload));
//alice.onHandshaked = (userId) => console.log(userId.toString());
alice.onSend = (data) => bob.open(data);
alice.onMessage = (data) => console.log("Bob: ", decodeData<string>(data.payload));
alice.onRequest = (request) => request.accept();

setImmediate(async () => {
    await bob.sendBootstrap(alice.userId);
    await bob.waitHandshaked(alice.userId);
    await bob.sendData(alice.userId, "Hi Alice!");
    await alice.sendData(bob.userId, "Hi Bob!");
    await Promise.all(["How are you?", "How are this days?", "For me it's a good time"].map(msg => bob.sendData(alice.userId, msg)));
    await alice.sendData(bob.userId, "Not so bad my man");
    await Promise.all(["I'm thinking...", "His this secure?"].map(msg => bob.sendData(alice.userId, msg)));
});