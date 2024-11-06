import { createHash } from "node:crypto";
import { BigInteger } from "jsbn";
import { hexToBigInt } from "../utils/hex";
import { knownGroups } from "./srpGroup";
import { bigIntToBytes } from "../utils/bigint";
import { describe, expect, test } from "bun:test";

const makeLittleK = (N: BigInteger, g: BigInteger) => {
  const hash = createHash("sha256");
  const nBytes = bigIntToBytes(N);
  const gBytes = bigIntToBytes(g);
  console.log(Buffer.from(gBytes).toString("base64"));
  hash.update(nBytes);
  hash.update(gBytes);
  return hexToBigInt(hash.digest("hex"));
};

const k = makeLittleK(
  knownGroups[8192].getN(),
  knownGroups[8192].getGenerator()
);
describe("k value should match", () => {
  test("littleK", () => {
    expect(k.toString()).toBe(
      "41355140986095207529712434517822669449058164734798422081556677809506232522678"
    );
  });
});
