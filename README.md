# Ring Signature Implementation

## Overview

This project implements a **Ring Signature** for two users, Alice and Bob. A ring signature allows a user to sign a message on behalf of a group without revealing the actual signer. The implementation uses **RSA** for asymmetric encryption and **AES** for symmetric encryption during the signing process.

## Key Concepts

- **Ring Signature**: A signature valid for the group, but the signer remains anonymous.
- **RSA Encryption**: Used for generating public/private key pairs and encrypting parts of the signature.
- **AES Encryption**: Used for encrypting intermediate values during signing.

## What I learnt

- How to implement a **Ring Signature** using cryptographic techniques, including **RSA encryption** for public-key cryptography and **AES encryption** for symmetric-key encryption.
- How to combine multiple cryptographic techniques in a real-world scenario to create a secure and verifiable signature system. This helped deepen my understanding of cryptography and how different algorithms work together to provide security.

## Implementation

- **Key Generation**: RSA keys for Alice and Bob are stored in `publickey.txt`.
- **Signing**: The `sign()` method combines values using XOR and encrypts them with AES. The result is saved to `signature.txt`.
- **Verification**: The `verify()` method checks if the signature is valid for the message and keys.

## Files Used

- `publickey.txt`: RSA public keys.
- `message.txt`: Message to be signed.
- `signature.txt`: Generated ring signature.

## How to Run

1. **Generate Keys**: Option 1 generates RSA keys.
2. **Sign the Message**: Option 2 signs the message.
3. **Verify the Signature**: Option 3 checks the validity of the signature.
4. **Quit**: Option 4 exits the program.



