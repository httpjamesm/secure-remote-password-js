import { createHash } from "node:crypto";

// simple KDF for testing. DO NOT USE IN PRODUCTION, SERIOUSLY.
export const simpleKDF = (
  password: string,
  salt: Uint8Array,
  iterations: number = 1
): Buffer => {
  const passwordBuffer = new TextEncoder().encode(password);
  let result = Buffer.from(new Uint8Array([...passwordBuffer, ...salt]));

  for (let i = 0; i < iterations; i++) {
    result = createHash("sha256")
      .update(new Uint8Array(result.buffer))
      .digest();
  }

  return result;
};
