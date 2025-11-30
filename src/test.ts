import { decodeData, encodeData } from "@freesignal/utils";
import { AsyncMap, createNode } from ".";
import { KeyExchange } from "./x3dh";

const bob = createNode({ keyExchange: new AsyncMap(), sessions: new AsyncMap(), users: new AsyncMap() });
const alice = createNode({ keyExchange: new AsyncMap(), sessions: new AsyncMap(), users: new AsyncMap() });

setImmediate(async () => {
    const aliceHandshake = await alice.sendHandshake(await bob.generateKeyData());
    await bob.receive<void>(aliceHandshake);

    console.log("Session established successfully between Alice and Bob.");

    const first = (await bob.sendData(alice.userId.toString(), encodeData("Hi Alice!"))).toBytes();

    console.log("Bob: ", decodeData<string>(await alice.receive(first)));

    const second = await alice.sendData(bob.userId.toString(), encodeData("Hi Bob!"));

    console.log("Alice: ", decodeData<string>(await bob.receive(second)));

    const third = await Promise.all(["How are you?", "How are this days?", "For me it's a good time"].map(msg => bob.sendData(alice.userId.toString(), encodeData(msg))));

    third.forEach(async value => {
        console.log("Bob: ", decodeData<string>(await alice.receive(value)));
    });
});

/*const bob = new KeyExchange({ keys: new AsyncMap(), sessions: new AsyncMap() });
const alice = new KeyExchange({ keys: new AsyncMap(), sessions: new AsyncMap() });

setImmediate(async () => {
    const { session: aliceSession, message, identityKey: bobIK } = await alice.digestData(await bob.generateData());
    const { session: bobSession, identityKey: aliceIK } = await bob.digestMessage(message);

    const first = await aliceSession.encrypt(encodeData("Testing"));

    console.log("Alice: ", decodeData<string>(await bobSession.decrypt(first)));

    const second = await bobSession.encrypt(encodeData("Sucker"));

    console.log("Bob: ", decodeData<string>(await aliceSession.decrypt(second)));

    console.log("Handshaked: ", aliceSession.handshaked && bobSession.handshaked);

    const third = await Promise.all(["How are you?", "How are this days?", "For me it's a good time"].map(msg => bobSession.encrypt(encodeData(msg))));
    
    console.log(decodeData<string>(await aliceSession.decrypt(third[1])));
    console.log(decodeData<string>(await aliceSession.decrypt(third[0])));
    console.log(decodeData<string>(await aliceSession.decrypt(third[2])));

});*/