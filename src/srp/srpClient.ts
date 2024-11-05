import { bigIntToBytes, maxInt } from "../utils/bigint";
import { hexToBigInt } from "../utils/hex";
import { minExponentSize, SrpGroup } from "./srpGroup";
import { createHash, randomBytes } from "node:crypto";
import { BigInteger } from "jsbn";

const zero = new BigInteger("0");

export class SrpClient {
  private ephemeralPrivate: BigInteger = zero;
  private ephemeralPublicA: BigInteger = zero;
  private ephemeralPublicB: BigInteger = zero;
  private x: BigInteger = zero;
  private v: BigInteger = zero;
  private u: BigInteger | null = zero;
  private k: BigInteger = zero;
  private premasterKey: BigInteger;
  private key: Uint8Array | null = null;
  private m: Uint8Array | null = null;
  private cProof: Uint8Array | null = null;
  private isServerProved: boolean = false;
  private group: SrpGroup;
  private badState = false;

  constructor(group: SrpGroup, v: BigInteger, k?: BigInteger) {
    this.group = group;

    if (k) {
      this.k = k;
    } else {
    }
  }

  private makeLittleK(): BigInteger {
    const hash = createHash("sha256");
    hash.update(new Uint8Array(this.group.getN().toByteArray()));
    hash.update(new Uint8Array(this.group.getGenerator().toByteArray()));
    return hexToBigInt(hash.digest("hex"));
  }

  private generateMySecret(): BigInteger {
    const eSize = maxInt(this.group.exponentSize, minExponentSize);
    // get eSize random bytes
    const bytes = randomBytes(eSize);
    this.ephemeralPrivate = hexToBigInt(bytes.toString("hex"));
    return this.ephemeralPrivate;
  }

  private makeA(): BigInteger {
    if (this.ephemeralPrivate === zero) {
      this.generateMySecret();
    }
    this.ephemeralPublicA = this.group
      .getGenerator()
      .modPow(this.ephemeralPrivate, this.group.getN());
    return this.ephemeralPublicA;
  }

  private isUValid(): boolean {
    if (this.u === null || this.badState) {
      this.u = null;
      return false;
    }
    if (this.u.compareTo(zero) === 0) {
      return false;
    }
    return true;
  }

  private makeVerifier(): BigInteger {
    if (this.badState) {
      throw new Error("we have bad data");
    }
    if (this.x.equals(zero)) {
      throw new Error("x must be known to calculate v");
    }
    this.v = this.group.getGenerator().modPow(this.x, this.group.getN());
    return this.v;
  }

  public isPublicValid(AorB: BigInteger): boolean {
    if (this.group.getGenerator().compareTo(zero) === 0) {
      return false;
    }

    if (AorB.mod(this.group.getGenerator()).compareTo(zero) === 0) {
      return false;
    }
    const bigOne = new BigInteger("1");
    if (AorB.gcd(this.group.getN()).compareTo(bigOne) !== 0) {
      return false;
    }

    return true;
  }
  private calculateU(): BigInteger {
    if (
      !this.isPublicValid(this.ephemeralPublicB) ||
      !this.isPublicValid(this.ephemeralPublicA)
    ) {
      this.u = null;
      throw new Error("both A and B must be known to calculate u");
    }

    const hash = createHash("sha256");
    hash.update(
      new TextEncoder().encode(
        this.ephemeralPublicA.toString() + this.ephemeralPublicB.toString()
      )
    );

    this.u = new BigInteger(hash.digest().toString("hex"), 16);
    if (this.u.compareTo(zero) === 0) {
      throw new Error("u == 0, which is a bad thing");
    }
    return this.u;
  }
}
