import { createHash } from "node:crypto";
import { BigInteger } from "jsbn";
import { bigIntToBytes } from "../utils/bigint";
import { hexToBigInt } from "../utils/hex";

export const makeLittleK = (N: BigInteger, g: BigInteger) => {
  const hash = createHash("sha256");
  const nBytes = bigIntToBytes(N);
  const gBytes = bigIntToBytes(g);
  console.log(Buffer.from(gBytes).toString("base64"));
  hash.update(nBytes);
  hash.update(gBytes);
  return hexToBigInt(hash.digest("hex"));
};
