import { BigInteger } from "jsbn";

export function bigIntToBytes(bigInt: BigInteger): Uint8Array {
  let hex = bigInt.toString(16);
  // Ensure even length
  if (hex.length % 2 !== 0) {
    hex = "0" + hex;
  }

  // Convert to big-endian byte array
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

export const maxInt = (n1: number, ...nums: number[]): number => {
  let max: number = n1;
  for (const n of nums) {
    if (n > max) {
      max = n;
    }
  }
  return max;
};
