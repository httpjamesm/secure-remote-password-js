import { createHash } from "node:crypto";
import { BigInteger } from "jsbn";
import { hexToBigInt } from "../utils/hex";
import { knownGroups } from "./srpGroup";
import { bigIntToBytes } from "../utils/bigint";

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
console.log(k.toString());
