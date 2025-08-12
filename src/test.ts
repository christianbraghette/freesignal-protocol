import { X3DH } from "./x3dh";
import crypto from "./crypto";
import { decodeUTF8, encodeUTF8, verifyUint8Array } from "./utils";

const bob = new X3DH(crypto.EdDSA.keyPair());
const alice = new X3DH(crypto.EdDSA.keyPair());

const bobmessage = bob.generateSyn();
const { rootKey, ackMessage: aliceack } = alice.digestSyn(bobmessage);

if (verifyUint8Array(rootKey, bob.digestAck(aliceack))) {
    console.log("Session established successfully between Alice and Bob.");

} else console.log("Error")