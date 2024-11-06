import { describe, expect, test } from "bun:test";
import { BigInteger } from "jsbn";
import {
  bigIntToBytes,
  uint8ArrayToBigInt,
  serverStyleHexFromBigInt,
  setBigIntegerFromBytes,
  maxInt,
} from "./bigint";

describe("bigIntToBytes", () => {
  test("converts BigInteger to Uint8Array (big-endian)", () => {
    const bigInt = new BigInteger("123456789abcdef", 16);
    const result = bigIntToBytes(bigInt);
    const expected = Uint8Array.from([
      0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    ]);
    expect(result).toEqual(expected);
  });

  test("converts BigInteger zero correctly", () => {
    const bigInt = new BigInteger("0", 16);
    const result = bigIntToBytes(bigInt);
    const expected = Uint8Array.from([0x00]);
    expect(result).toEqual(expected);
  });
});

describe("uint8ArrayToBigInt", () => {
  test("converts Uint8Array to BigInteger (big-endian)", () => {
    const arr = Uint8Array.from([
      0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    ]);
    const result = uint8ArrayToBigInt(arr);
    const expected = new BigInteger("123456789abcdef", 16);
    expect(result.equals(expected)).toBe(true);
  });

  test("converts empty Uint8Array to BigInteger zero", () => {
    const arr = Uint8Array.from([]);
    const result = uint8ArrayToBigInt(arr);
    const expected = new BigInteger("0", 16);
    expect(result.equals(expected)).toBe(true);
  });
});

describe("serverStyleHexFromBigInt", () => {
  test("converts BigInteger to hex string without leading zeros", () => {
    const bigInt = new BigInteger("00123456789abcdef", 16);
    const result = serverStyleHexFromBigInt(bigInt);
    const expected = "123456789abcdef";
    expect(result).toBe(expected);
  });

  test("returns '0' for BigInteger zero", () => {
    const bigInt = new BigInteger("0", 16);
    const result = serverStyleHexFromBigInt(bigInt);
    expect(result).toBe("0");
  });
});

describe("setBigIntegerFromBytes", () => {
  test("converts Uint8Array to BigInteger ensuring big-endian interpretation", () => {
    const arr = Uint8Array.from([
      0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    ]);
    const result = setBigIntegerFromBytes(arr);
    const expected = new BigInteger("123456789abcdef", 16);
    expect(result.equals(expected)).toBe(true);
  });

  test("converts empty Uint8Array to BigInteger zero", () => {
    const arr = Uint8Array.from([]);
    const result = setBigIntegerFromBytes(arr);
    const expected = new BigInteger("0", 16);
    expect(result.equals(expected)).toBe(true);
  });
});

describe("maxInt", () => {
  test("finds the maximum of given numbers", () => {
    expect(maxInt(1, 2, 3, 4, 5)).toBe(5);
    expect(maxInt(-1, -5, 0, 10)).toBe(10);
  });

  test("returns single argument when only one number is provided", () => {
    expect(maxInt(42)).toBe(42);
  });
});
