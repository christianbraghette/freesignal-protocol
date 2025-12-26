# freesignal-protocol

> TypeScript primitives and reference implementations for the FreeSignal secure messaging protocol.

This repository contains low-level protocol building blocks — key exchange (X3DH-like), an in-memory keystore, a double-ratchet style session implementation, and small constructor helpers — intended for building secure messaging clients or protocol tooling.

**Highlights**
- User factories and test harness for peer handshakes and message exchange.
- Pure TypeScript implementation with pluggable Crypto provider (see `@freesignal/crypto`).
- In-memory keystore reference implementation for testing: [src/keystore.ts](src/keystore.ts).

## Features

- Key exchange manager: `KeyExchangeManagerConstructor` — create and process pre-key bundles and orchestrate session handshakes. See [src/keyexchange.ts](src/keyexchange.ts).
- Session manager: `SessionManagerConstructor`, `SessionConstructor` — double-ratchet like session, encrypt/decrypt payloads, skip/rotate keys. See [src/session.ts](src/session.ts).
- Keystore factory: `InMemoryKeystoreFactory` — ephemeral, in-memory storage used by the reference `User` implementation. See [src/keystore.ts](src/keystore.ts).
- Convenience constructors: `useConstructors` — helpers for `UserId`, `Identity`, `Ciphertext`, etc. See [src/constructors.ts](src/constructors.ts).
- User factory: `UserFactoryConstructor` / `User` — high-level glue that wires keystore, key-exchange and session managers together. See [src/user.ts](src/user.ts).

## Installation

This project is published as a package name (if available) or can be used locally.

Clone and install dependencies:

```bash
git clone <repo-url>
cd freesignal-protocol
npm install
```

This library expects a compatible Crypto provider implementing the FreeSignal crypto interfaces — the test harness uses `@freesignal/crypto`.

## Quick Example

The repository includes a small test/example in [src/test.ts](src/test.ts) which demonstrates creating two users, performing a handshake and exchanging messages.

Example (based on `src/test.ts`):

```ts
import crypto from "@freesignal/crypto";
import { UserFactory, InMemoryKeystoreFactory } from "freesignal-protocol"; // or local import

const userFactory = new UserFactory(new InMemoryKeystoreFactory(), crypto);
const alice = await userFactory.create();
const bob = await userFactory.create();

// Wire transport (in-memory) — the test uses event sockets to simulate transport
alice.emitter.on('send', data => bob.emitter.emit('receive', data));
bob.emitter.on('send', data => alice.emitter.emit('receive', data));

// Exchange pre-key bundle and complete handshake
const bundle = await alice.generatePreKeyBundle();
bob.handleIncomingPreKeyBundle(bundle);
await alice.waitHandshake(bob.id);

// Encrypt / decrypt
const ciphertext = await alice.encrypt(bob.id, "Hello from Alice");
const plaintext = await bob.decrypt(alice.id, ciphertext);
console.log(plaintext);
```

This pattern demonstrates how `UserFactory` composes the keystore, key-exchange manager and session manager to create a usable `User` object with `encrypt`, `decrypt`, and `emitter` (transport) hooks.

## API Overview

- `UserFactory` (exported from [src/index.ts](src/index.ts))
  - `create(seed?: Bytes): Promise<User>` — create a `User` with a fresh identity or deterministic seed.
  - `destroy(user: User): boolean` — optional cleanup for the factory.

- `User` (see [src/user.ts](src/user.ts))
  - `id: UserId` — the user's stable identifier derived from the public identity.
  - `emitter` — an EventEmitter used by the `KeyExchangeManager` to send and receive `PreKeyMessage` payloads. Use your transport to route `send`/`receive` events between peers.
  - `encrypt(to, plaintext)` / `decrypt(from, ciphertext)` — convenience methods that use the session manager.
  - `generatePreKeyBundle()` / `handleIncomingPreKeyBundle(bundle)` — helpers for the initial X3DH-like key bundle exchange.

- `InMemoryKeystoreFactory` (see [src/keystore.ts](src/keystore.ts))
  - `createStore(identity)` — returns an in-memory `KeyStore` for testing.
  - `getStore(identity)` / `deleteStore(identity)` — access helpers.

- `KeyExchangeManagerConstructor` (see [src/keyexchange.ts](src/keyexchange.ts))
  - `createPreKeyBundle()` — produce a `PreKeyBundle` that can be published to a server or delivered to a peer.
  - `processPreKeyBundle(bundle)` — perform the client-side handshake to create a `Session` and emit the initial `send` event.

- `SessionConstructor` / `SessionManagerConstructor` (see [src/session.ts](src/session.ts))
  - Implements session creation, `encrypt` and `decrypt`, and `save()` to persist session state into the provided `KeyStore`.

## Development

- Build (if project uses a build step):

```bash
npm run build
```

- Run the included test harness (compile first if needed):

```bash
node dist/test.js   # or `ts-node src/test.ts` in dev
```

## Contributing

- Fork, add tests, keep changes focused. The codebase is intended to be a minimal reference implementation — please add tests for protocol behavior and edge cases.

## License

This project includes a GPL-3.0 license header in source files. See the `LICENSE` file in the repository root.

## Notes & Compatibility

- The code uses a pluggable `Crypto` provider from `@freesignal/crypto`. To use the library in applications, supply a `crypto` object that conforms to the FreeSignal crypto interfaces (EdDSA, ECDH, Box, hkdf utilities, hashing and random bytes).
- The `InMemoryKeystoreFactory` is a testing convenience only — for production you should implement a durable `KeyStore`.

---

If you want, I can also:
- run the TypeScript build and execute `src/test.ts` locally to verify the example,
- add a short CONTRIBUTING.md or API reference, or
- create a durable keystore example (LevelDB / SQLite).
