import { describe, it, expect } from "bun:test";
import { safeXORBytes } from "./ops";

describe("safeXORBytes", () => {
  it("should correctly XOR two equal-length Uint8Arrays", () => {
    const dst = new Uint8Array(3);
    const a = new Uint8Array([1, 2, 3]);
    const b = new Uint8Array([4, 5, 6]);
    const result = safeXORBytes(dst, a, b);

    expect(result).toBe(3);
    expect(dst).toEqual(new Uint8Array([5, 7, 5]));
  });

  it("should correctly XOR two Uint8Arrays when 'a' is longer than 'b'", () => {
    const dst = new Uint8Array(4);
    const a = new Uint8Array([1, 2, 3, 4]);
    const b = new Uint8Array([4, 5, 6]);
    const result = safeXORBytes(dst, a, b);

    expect(result).toBe(3);
    expect(dst.slice(0, 3)).toEqual(new Uint8Array([5, 7, 5]));
  });

  it("should correctly XOR two Uint8Arrays when 'b' is longer than 'a'", () => {
    const dst = new Uint8Array(3);
    const a = new Uint8Array([1, 2, 3]);
    const b = new Uint8Array([4, 5, 6, 7]);
    const result = safeXORBytes(dst, a, b);

    expect(result).toBe(3);
    expect(dst).toEqual(new Uint8Array([5, 7, 5]));
  });

  it("should return 0 and leave 'dst' unchanged if one of the arrays is empty", () => {
    const dst = new Uint8Array(3);
    const a = new Uint8Array([]);
    const b = new Uint8Array([4, 5, 6]);
    const result = safeXORBytes(dst, a, b);

    expect(result).toBe(0);
    expect(dst).toEqual(new Uint8Array([0, 0, 0]));
  });

  it("should handle cases where 'dst' is larger than 'a' and 'b'", () => {
    const dst = new Uint8Array(5);
    const a = new Uint8Array([1, 2]);
    const b = new Uint8Array([4, 5]);
    const result = safeXORBytes(dst, a, b);

    expect(result).toBe(2);
    expect(dst.slice(0, 2)).toEqual(new Uint8Array([5, 7]));
    expect(dst.slice(2)).toEqual(new Uint8Array([0, 0, 0]));
  });
});
