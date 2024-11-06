import { describe, expect, test } from "bun:test";
import { knownGroups } from "./srpGroup";
import { makeLittleK } from "./littleK";

const k = makeLittleK(
  knownGroups[8192].getN(),
  knownGroups[8192].getGenerator()
);
describe("k value should match", () => {
  test("littleK", () => {
    expect(k.toString()).toBe(
      "41355140986095207529712434517822669449058164734798422081556677809506232522678"
    );
  });
});
