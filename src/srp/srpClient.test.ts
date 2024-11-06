import { expect, test } from "bun:test";
import { SrpClient } from "./srpClient";
import { knownGroups } from "./srpGroup";
import { randomBytes } from "node:crypto";
import { uint8ArrayToBigInt } from "../utils";
import { simpleKDF } from "../utils/kdf";

const runSrpTest = (passwordLength: number) => {
  const salt = new Uint8Array(randomBytes(16));
  const username = "billgates";
  const passwordBytes = new Uint8Array(randomBytes(passwordLength));
  const passwordString = Buffer.from(passwordBytes)
    .toString("base64")
    .substring(0, passwordLength);
  const x = uint8ArrayToBigInt(
    new Uint8Array(simpleKDF(passwordString, salt).buffer)
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
};

test("srp with 8 character password", () => {
  runSrpTest(8);
});

test("srp with 9 character password", () => {
  runSrpTest(9);
});

test("srp with 16 character password", () => {
  runSrpTest(16);
});

test("srp with 17 character password", () => {
  runSrpTest(17);
});

test("srp with random length password", () => {
  runSrpTest(Math.floor(Math.random() * 100));
});
