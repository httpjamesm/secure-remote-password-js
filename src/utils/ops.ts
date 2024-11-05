export function safeXORBytes(
  dst: Uint8Array,
  a: Uint8Array,
  b: Uint8Array
): number {
  let n: number = a.length;
  if (b.length < n) {
    n = b.length;
  }

  for (let i = 0; i < n; i++) {
    dst[i] = a[i] ^ b[i];
  }

  return n;
}
