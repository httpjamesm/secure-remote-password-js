import { BigInteger } from "jsbn";

// Converts BigInteger to Uint8Array (big-endian)
export function bigIntToBytes(bigInt: BigInteger): Uint8Array {
  let hex = bigInt.toString(16);
  
  // Ensure even number of hex digits
  if (hex.length % 2 !== 0) {
    hex = "0" + hex;
  }

  // Convert hex to Uint8Array
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }

  return bytes;
}

// Converts Uint8Array to BigInteger (big-endian)
export const uint8ArrayToBigInt = (arr: Uint8Array): BigInteger => {
  const hexString = Array.from(arr)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return new BigInteger(hexString, 16);
};

// Converts BigInteger to lowercase hex string without leading zeros
export function serverStyleHexFromBigInt(bn: BigInteger): string {
  const hexString = bn.toString(16).toLowerCase();
  return hexString.replace(/^0+/, "") || "0";
}

// Converts Uint8Array to BigInteger, ensuring big-endian interpretation
export function setBigIntegerFromBytes(buf: Uint8Array): BigInteger {
  const hexString = Array.from(buf)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return new BigInteger(hexString, 16);
}

// Utility function to find maximum number using built-in Math.max
export const maxInt = (n1: number, ...nums: number[]): number => {
  return Math.max(n1, ...nums);
};