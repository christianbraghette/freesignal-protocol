import { createKeyExchange } from ".";
import crypto from "./crypto";
import { Datagram, Protocols } from "./data";
import { decodeUTF8, encodeUTF8 } from "./utils";

const bob = createKeyExchange(crypto.EdDSA.keyPair());
const alice = createKeyExchange(crypto.EdDSA.keyPair());

const bobmessage = bob.generateData();

const { session: alicesession, message: aliceack } = alice.digestData(bobmessage);

const { session: bobsession, cleartext } = bob.digestSyn(aliceack) ?? {};

if (bobsession && cleartext) {
    console.log("Session established successfully between Alice and Bob.");

    const datagram = Datagram.create(bob.publicKey, alice.publicKey, Protocols.MESSAGE, bobsession.encrypt(decodeUTF8("Hi Alice!"))?.encode());

    //console.log(datagram.payload);

    const msg = datagram.encode();

    console.log(encodeUTF8(alicesession.decrypt(Datagram.from(msg!).payload!)));

    if (alicesession.handshaked && bobsession.handshaked)
        console.log("Successfully handshaked");
    else
        console.log("Error during handshake")
} else console.log("Error")