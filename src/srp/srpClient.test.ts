import { expect, test } from "bun:test";
import { SrpClient } from "./srpClient";
import { knownGroups } from "./srpGroup";
import { randomBytes } from "node:crypto";
import { uint8ArrayToBigInt } from "../utils";
import { simpleKDF } from "../utils/kdf";

test("srp client and server", () => {
  // in real world, use a better KDF like argon2, seriously.
  const salt = new Uint8Array(randomBytes(16));
  const username = "billgates";
  const x = uint8ArrayToBigInt(
    new Uint8Array(simpleKDF("password", salt).buffer)
  );

  const client = new SrpClient(knownGroups[8192], x, undefined, "client");
  const clientA = client.ephemeralPublic();

  const verifier = client.verifier();

  const server = new SrpClient(
    knownGroups[8192],
    verifier,
    undefined,
    "server"
  );

  const serverB = server.ephemeralPublic();

  client.setOthersPublic(serverB);

  server.setOthersPublic(clientA);

  server.getKey();
  client.getKey();

  const serverProof = server.computeM(salt, username);

  const serverProved = client.goodServerProof(salt, username, serverProof);
  expect(serverProved).toBe(true);

  const clientProof = client.clientProof();

  const clientProved = server.goodClientProof(clientProof);
  expect(clientProved).toBe(true);
});
