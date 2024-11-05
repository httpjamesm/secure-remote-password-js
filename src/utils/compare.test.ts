import assert from "assert";
import { constantTimeEqual } from "./compare";
function runTests() {
  // Test equal arrays
  assert.strictEqual(
    constantTimeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3])),
    true,
    "Equal arrays should return true"
  );

  // Test different arrays
  assert.strictEqual(
    constantTimeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 4])),
    false,
    "Different arrays should return false"
  );

  // Test different lengths
  assert.strictEqual(
    constantTimeEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2, 3])),
    false,
    "Different length arrays should return false"
  );

  // Test empty arrays
  assert.strictEqual(
    constantTimeEqual(new Uint8Array([]), new Uint8Array([])),
    true,
    "Empty arrays should return true"
  );

  console.log("All tests passed!");
}

runTests();
