import { createKeyExchange } from ".";
import crypto from "./crypto";
import { decodeUTF8, encodeUTF8 } from "./utils";

const bob = createKeyExchange(crypto.EdDSA.keyPair());
const alice = createKeyExchange(crypto.EdDSA.keyPair());

const bobmessage = bob.generateSyn();

const { session: alicesession, ackMessage: aliceack } = alice.digestSyn(bobmessage);

const { session: bobsession, cleartext } = bob.digestAck(aliceack) ?? {};

if (bobsession && cleartext) {
    console.log("Session established successfully between Alice and Bob.");

    const msg = bobsession.encrypt(decodeUTF8("Hi Alice!"))?.encode();

    console.log(encodeUTF8(alicesession.decrypt(msg!)));

    if (alicesession.handshaked && bobsession.handshaked)
        console.log("Successfully handshaked");
    else
        console.log("Error during handshake")
} else console.log("Error")