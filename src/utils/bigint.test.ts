import assert from "assert";
import { bigIntToBytes } from "./bigint";

// Test cases
function runTests() {
  // Test zero
  assert.deepStrictEqual(
    Array.from(bigIntToBytes(0n)),
    [],
    "Zero should return empty array"
  );

  // Test single byte values
  assert.deepStrictEqual(
    Array.from(bigIntToBytes(255n)),
    [255],
    "255 should be [255]"
  );

  // Test two byte values
  assert.deepStrictEqual(
    Array.from(bigIntToBytes(256n)),
    [1, 0],
    "256 should be [1, 0]"
  );

  // Test negative values
  assert.deepStrictEqual(
    Array.from(bigIntToBytes(-255n)),
    [255],
    "Negative values should return same as positive"
  );

  // Test larger numbers
  assert.deepStrictEqual(
    Array.from(bigIntToBytes(65535n)),
    [255, 255],
    "65535 should be [255, 255]"
  );

  // Test very large number
  assert.deepStrictEqual(
    Array.from(bigIntToBytes(0x123456789an)),
    [18, 52, 86, 120, 154],
    "0x123456789a should be [18, 52, 86, 120, 154]"
  );

  console.log("All tests passed!");
}

try {
  runTests();
} catch (error) {
  console.error("Test failed:", (error as Error).message);
}
