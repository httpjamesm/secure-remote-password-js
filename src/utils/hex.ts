import { BigInteger } from "jsbn";

export const hexToBigInt = (hex: string): BigInteger => {
  const cleaned = hex.replace(/^0x/, "");

  return new BigInteger(cleaned, 16);
};
