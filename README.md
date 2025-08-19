# freesignal-protocol

This library implements a secure messaging protocol inspired by Signal, with support for encryption, data management, and key exchange.

## Main File Structure

- **[src/crypto.ts](src/crypto.ts)**  
    Contains cryptographic primitives, including box, ECDH, EdDSA, and UUID.  
    See [`crypto.box`](src/crypto.ts), [`crypto.ECDH`](src/crypto.ts), [`crypto.EdDSA`](src/crypto.ts), [`crypto.UUID`](src/crypto.ts).

- **[src/data.ts](src/data.ts)**  
    Defines data structures for messages and datagrams, including attachments and serialization.  
    See [`Datagram`](src/data.ts), [`Message`](src/data.ts).

- **[src/double-ratchet.ts](src/double-ratchet.ts)**  
    Implements the Double Ratchet algorithm for forward secrecy in conversations.

- **[src/types.ts](src/types.ts)**  
    Defines types and interfaces used throughout the project.

- **[src/utils.ts](src/utils.ts)**  
    Utility functions for manipulating arrays, strings, and binary data.

- **[src/x3dh.ts](src/x3dh.ts)**  
    Implements the X3DH protocol for secure key exchange between users.

## How to Use

Import the required modules from [src/index.ts](src/index.ts) to access the main protocol features.

## License

Distributed under the GPL v3 license.  
See [LICENSE](LICENSE) for details.