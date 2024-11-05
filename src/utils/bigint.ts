import { BigInteger } from "jsbn";
export function bigIntToBytes(bigInt: BigInteger): Uint8Array {
  let hex = bigInt.toString(16);
  if (hex.length % 2 !== 0) {
    hex = "0" + hex;
  }
  // Remove leading zeros but keep at least one byte
  while (hex.length > 2 && hex.startsWith("00")) {
    hex = hex.slice(2);
  }
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

export const uint8ArrayToBigInt = (arr: Uint8Array): BigInteger => {
  return new BigInteger([...arr]);
};

export function serverStyleHexFromBigInt(bn: BigInteger): string {
  // Convert BigInteger to byte array
  const bytes = bn.toByteArray();

  // Convert bytes to hex string and ensure lowercase
  const hexString = bytes
    .map((b) => (b & 0xff).toString(16).padStart(2, "0"))
    .join("")
    .toLowerCase();

  // Remove leading zeros
  return hexString.replace(/^0+/, "") || "0";
}

export function setBigIntegerFromBytes(buf: Uint8Array): BigInteger {
  // Convert bytes to hex string (big-endian)
  const hexString = Array.from(buf)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  // Create BigInteger from hex string
  return new BigInteger(hexString, 16);
}
