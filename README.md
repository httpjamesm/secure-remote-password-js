# secure-remote-password-js

This is a client and server implementation of 1Password's [fantastic SRP library](https://github.com/1Password/srp) in TypeScript.

[Bun](https://bun.sh) is recommended.

## Installation

```bash
bun add secure-remote-password-js
```

## Usage

SRP is a fascinating protocol. I highly recommend reading through [1Password's explainer](https://blog.1password.com/developers-how-we-use-srp-and-you-can-too/) to get familiar with its innerworkings and processes first.

### Step 1: Pick a group

This library uses RFC 5054 groups between 2048 and 8192 bits. 4096 and above are highly recommended. Any lower is unlikely to be secure for the near future.

On your client and server, agree on a group:

```typescript
import { knownGroups } from "secure-remote-password-js";

const group = knownGroups[4096];
```

### Step 2: Pick a KDF

You'll need a Key Derivation Function (KDF) to convert your password into a secure format. While this library includes a simple KDF for testing, you should use a strong KDF like Argon2id, bcrypt, or scrypt in production.

[@phi-ag/argon2](https://github.com/phi-ag/argon2) is a great library for Argon2 in TS.

```typescript
import { Argon2Type } from "@phi-ag/argon2";
import wasm from "@phi-ag/argon2/argon2.wasm?url";
import initialize from "@phi-ag/argon2/fetch";

const argon2 = await initialize(wasm);
const hash = argon2.hash(password, {
  salt,
  memoryCost: 64 * 1024,
  timeCost: 1,
  parallelism: 4,
  hashLength: 32,
  type: Argon2Type.Argon2id,
});

return hash;
```

### Step 3: Initialize SRP Client

Create an SRP client instance for both server and client sides:

```typescript
import { SrpClient, knownGroups } from "secure-remote-password-js";

// On client side
const client = new SrpClient(knownGroups[4096], x, undefined, "client");

// On server side (using verifier)
const verifier = client.verifier(); // Generate this during registration
const server = new SrpClient(knownGroups[4096], verifier, undefined, "server");
```

### Step 4: Exchange Public Keys

Exchange ephemeral public keys between client and server:

```typescript
// Client generates and sends A to server
const clientPublicA = client.ephemeralPublic();

// Server generates and sends B to client
const serverPublicB = server.ephemeralPublic();

// Each side sets the other's public key
client.setOthersPublic(serverPublicB);
server.setOthersPublic(clientPublicA);
```

### Step 5: Generate Session Key

Both sides can now generate the shared session key:

```typescript
// On both client and server
const key = client.getKey(); // or server.getKey()
```

### Step 6: Verify Both Parties

Finally, verify that both parties derived the same key:

```typescript
// Server generates proof and sends to client
const serverProof = server.computeM(salt, username);
const serverIsLegit = client.goodServerProof(salt, username, serverProof);

// Client generates proof and sends to server
const clientProof = client.clientProof();
const clientIsLegit = server.goodClientProof(clientProof);

if (serverIsLegit && clientIsLegit) {
  // Both parties have authenticated successfully
  // The shared key can now be used for secure communication
}
```

### Encoding Notes

When transporting data between client and server, you may choose to encode the data in hex, base64 or just utf-8 for big integers. Base64 is recommended for consistency.
