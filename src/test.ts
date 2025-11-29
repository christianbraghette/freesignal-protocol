import { decodeData, encodeData } from "@freesignal/utils";
import { AsyncMap, Protocols } from ".";
import { FreeSignalNode } from "./node";

const bob = new FreeSignalNode({ keyExchange: new AsyncMap(), sessions: new AsyncMap(), users: new AsyncMap() });
const alice = new FreeSignalNode({ keyExchange: new AsyncMap(), sessions: new AsyncMap(), users: new AsyncMap() });

setImmediate(async () => {
    const aliceHandshake = await alice.sendHandshake(await bob.generateKeyData());
    await bob.receive<void>(aliceHandshake);

    console.log("Session established successfully between Alice and Bob.");

    const data = (await bob.encrypt(alice.userId.toString(), Protocols.MESSAGE, encodeData("Hi Alice!"))).toBytes();

    console.log(decodeData<string>(await alice.receive(data)));

    const longmsg = await alice.sendData(bob.userId.toString(), new Uint8Array(1000000).fill(33).map(val => val + Math.floor(Math.random() * 93)));

    console.log(longmsg.toBytes().length);
});