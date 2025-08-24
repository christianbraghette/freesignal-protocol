import { createKeyExchange, Datagram, Protocols } from ".";
import crypto from "@freesignal/crypto";
import { decodeUTF8, encodeUTF8 } from "@freesignal/utils";

const bob = createKeyExchange(crypto.EdDSA.keyPair().secretKey, crypto.ECDH.keyPair().secretKey);
const alice = createKeyExchange(crypto.EdDSA.keyPair().secretKey, crypto.ECDH.keyPair().secretKey);

const bobmessage = bob.generateData();

const { session: alicesession, message: aliceack } = alice.digestData(bobmessage);

bob.digestMessage(aliceack).then(({ session: bobsession, cleartext }) => {
    if (bobsession && cleartext) {
        console.log("Session established successfully between Alice and Bob.");

        const datagram = Datagram.create(bob.signatureKey, alice.signatureKey, Protocols.MESSAGE, bobsession.encrypt(encodeUTF8("Hi Alice!"))?.encode());

        //console.log(datagram.payload);

        const msg = datagram.encode();

        console.log(decodeUTF8(alicesession.decrypt(Datagram.from(msg!).payload!)));

        if (alicesession.handshaked && bobsession.handshaked)
            console.log("Successfully handshaked");
        else
            console.log("Error during handshake")

        const longmsg = Datagram.create(alice.signatureKey, bob.signatureKey, Protocols.MESSAGE, alicesession.encrypt(
            new Uint8Array(1000000).fill(33).map(
                val => val + Math.floor(Math.random() * 93)
            )
        ));

        console.log(longmsg.encode().length);
        console.log(longmsg.encode(false).length);
    } else console.log("Error")
});