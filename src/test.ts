import { AsyncMap, createKeyExchange, DataDecoder, DataEncoder, Datagram, IdentityKey, Protocols } from ".";
import crypto from "@freesignal/crypto";

const bob = createKeyExchange({ keys: new AsyncMap(), sessions: new AsyncMap() }, crypto.EdDSA.keyPair().secretKey, crypto.ECDH.keyPair().secretKey);
const alice = createKeyExchange({ keys: new AsyncMap(), sessions: new AsyncMap() }, crypto.EdDSA.keyPair().secretKey, crypto.ECDH.keyPair().secretKey);

bob.generateData().then(async bobdata => {
    const { session: alicesession, message: aliceack } = await alice.digestData(bobdata);
    const { session: bobsession, identityKey } = await bob.digestMessage(aliceack);

    if (bobsession && identityKey) {
        console.log("Session established successfully between Alice and Bob.");

        const data = new DataEncoder("Hi Alice!");
        const datagram = Datagram.create((await bob.getIdentityKey()).signatureKey, (await alice.getIdentityKey()).signatureKey, Protocols.MESSAGE, (await bobsession.encrypt(data.encode())).encode());

        const msg = datagram.encode();

        console.log(new DataDecoder(await alicesession.decrypt(Datagram.from(msg).payload!) ?? new Uint8Array()).decode());

        if (alicesession.handshaked && bobsession.handshaked)
            console.log("Successfully handshaked");
        else
            console.log("Error during handshake")

        const longmsg = Datagram.create((await bob.getIdentityKey()).signatureKey, (await alice.getIdentityKey()).signatureKey, Protocols.MESSAGE, await alicesession.encrypt(
            new Uint8Array(1000000).fill(33).map(
                val => val + Math.floor(Math.random() * 93)
            )
        ));

        console.log(longmsg.encode().length);
    } else console.log("Error")
});