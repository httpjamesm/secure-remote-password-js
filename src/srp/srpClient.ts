import {
  bigIntToBytes,
  maxInt,
  serverStyleHexFromBigInt,
  setBigIntegerFromBytes,
} from "../utils/bigint";
import { hexToBigInt } from "../utils/hex";
import { minExponentSize, SrpGroup } from "./srpGroup";
import { createHash, randomBytes } from "node:crypto";
import { BigInteger } from "jsbn";
import { safeXORBytes } from "../utils/ops";
import { constantTimeEqual } from "../utils/compare";

const zero = new BigInteger("0");
const SHA256_SIZE = 32;

export class SrpClient {
  private ephemeralPrivate: BigInteger = zero;
  private ephemeralPublicA: BigInteger = zero;
  private ephemeralPublicB: BigInteger = zero;
  private x: BigInteger = zero;
  private v: BigInteger = zero;
  private u: BigInteger | null = zero;
  private k: BigInteger = zero;
  private premasterKey: BigInteger | null = null;
  private key: Uint8Array | null = null;
  private m: Uint8Array | null = null;
  private cProof: Uint8Array | null = null;
  private isServerProved: boolean = false;
  private group: SrpGroup | null = null;
  private badState = false;
  private isServer = false;
  private debug: boolean = false;

  constructor(
    group: SrpGroup,
    x: BigInteger,
    k?: BigInteger,
    party: "client" | "server" = "client"
  ) {
    this.isServer = party === "server";
    this.group = group;
    if (this.isServer) {
      this.v = x;
    } else {
      this.x = x;
    }
    if (k) {
      this.k = k;
    } else {
      this.k = this.makeLittleK();
    }
    this.generateMySecret();
    this.makeA();
  }

  private makeLittleK(): BigInteger {
    const hash = createHash("sha256");
    if (!this.group) {
      throw new Error("group is not set");
    }
    hash.update(bigIntToBytes(this.group.getN()));
    hash.update(bigIntToBytes(this.group.getGenerator()));
    return hexToBigInt(hash.digest("hex"));
  }

  private generateMySecret(): BigInteger {
    if (!this.group) {
      throw new Error("group is not set");
    }
    const eSize = maxInt(this.group.exponentSize, minExponentSize);
    // get eSize random bytes
    const bytes = randomBytes(eSize);
    this.ephemeralPrivate = hexToBigInt(bytes.toString("hex"));
    return this.ephemeralPrivate;
  }

  private makeA(): BigInteger {
    if (this.ephemeralPrivate.compareTo(zero) === 0) {
      this.generateMySecret();
    }
    if (!this.group) {
      throw new Error("group is not set");
    }
    this.ephemeralPublicA = this.group
      .getGenerator()
      .modPow(this.ephemeralPrivate, this.group.getN());
    return this.ephemeralPublicA;
  }

  private makeB(): BigInteger {
    // Absolute Prerequisites: Group, isServer, v
    if (this.group === null) {
      throw new Error("group is not set");
    }
    if (!this.isServer) {
      throw new Error("isServer is not set");
    }
    if (this.v.compareTo(zero) === 0) {
      throw new Error("v is not set");
    }
    // if no k, make k
    if (this.k.compareTo(zero) === 0) {
      this.k = this.makeLittleK();
    }

    // if ephemeralPrivate is 0, generate ephemeralPrivate
    if (this.ephemeralPrivate.compareTo(zero) === 0) {
      this.generateMySecret();
    }
    // B = kv + g^b  (term1 is kv, term2 is g^b)
    // We also do some modular reduction on some of our intermediate values
    let term1 = this.k.multiply(this.v);
    let term2 = this.group
      .getGenerator()
      .modPow(this.ephemeralPrivate, this.group.getN());
    term1 = this.group.reduce(term1);
    this.ephemeralPublicB = term1.add(term2);
    this.ephemeralPublicB = this.group.reduce(this.ephemeralPublicB);
    return this.ephemeralPublicB;
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
    if (!this.group) {
      throw new Error("group is not set");
    }
    this.v = this.group.getGenerator().modPow(this.x, this.group.getN());
    return this.v;
  }

  public isPublicValid(AorB: BigInteger): boolean {
    if (!this.group) {
      throw new Error("group is not set");
    }

    const N = this.group.getN();

    // Ensure AorB is greater than 0 and less than N
    if (AorB.compareTo(zero) <= 0 || AorB.compareTo(N) >= 0) {
      return false;
    }

    // Ensure gcd(AorB, N) == 1
    const bigOne = new BigInteger("1");
    if (AorB.gcd(N).compareTo(bigOne) !== 0) {
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

    const trimmedHexPublicA = serverStyleHexFromBigInt(this.ephemeralPublicA);
    const trimmedHexPublicB = serverStyleHexFromBigInt(this.ephemeralPublicB);

    const hash = createHash("sha256");
    hash.update(
      new TextEncoder().encode(trimmedHexPublicA + trimmedHexPublicB)
    );

    const hashed = hash.digest();
    this.debug && console.log("u hash:", hashed.toString("hex"));

    this.u = setBigIntegerFromBytes(new Uint8Array(hashed));
    if (this.u.compareTo(zero) === 0) {
      throw new Error("u == 0, which is a bad thing");
    }
    this.debug && console.log("u:", this.u.toString(16));
    return this.u;
  }

  public ephemeralPublic(): BigInteger {
    if (this.isServer) {
      if (this.ephemeralPublicB.compareTo(zero) === 0) {
        this.makeB();
      }
      return this.ephemeralPublicB;
    }
    if (this.ephemeralPublicA.compareTo(zero) === 0) {
      this.makeA();
    }
    return this.ephemeralPublicA;
  }

  public verifier(): BigInteger {
    return this.makeVerifier();
  }

  public setOthersPublic(AorB: BigInteger) {
    if (!this.isPublicValid(AorB)) {
      throw new Error("invalid public exponent");
    }
    if (!this.isServer) {
      this.ephemeralPublicB = AorB;
    } else {
      this.ephemeralPublicA = AorB;
    }
  }

  /*
Key creates and returns the session Key.

Caller MUST check error status.

Once the ephemeral public key is received from the other party and properly
set, SRP should have enough information to compute the session key.

If and only if, each party knowns their respective long term secret
(x for client, v for server) will both parties compute the same Key.
Be sure to confirm that client and server have the same key before
using it.

Note that although the resulting key is 256 bits, its effective strength
is (typically) far less and depends on the group used.
8 * (SRP.Group.ExponentSize / 2) should provide a reasonable estimate if you
need that.
*/
  public getKey(): Uint8Array {
    if (this.key !== null) {
      return this.key;
    }
    if (this.badState) {
      throw new Error("we have bad data");
    }
    if (this.u === null || !this.isUValid()) {
      this.u = this.calculateU();
    }
    if (!this.isUValid()) {
      this.badState = true;
      throw new Error("invalid u");
    }
    if (this.ephemeralPrivate.compareTo(zero) === 0) {
      throw new Error("cannot make Key with my ephemeral secret");
    }

    this.debug &&
      console.log("ephemeral private:", this.ephemeralPrivate.toString(16));

    let b: BigInteger;
    let e: BigInteger;

    if (!this.group) {
      throw new Error("group is not set");
    }

    if (this.isServer) {
      // S = (Av^u) ^ b
      if (
        this.v.compareTo(zero) === 0 ||
        this.ephemeralPublicA.compareTo(zero) === 0
      ) {
        throw new Error("not enough is known to create Key");
      }
      b = this.v.modPow(this.u, this.group.getN());
      b = b.multiply(this.ephemeralPublicA);
      e = this.ephemeralPrivate;
    } else {
      // S = (B - kg^x) ^ (a + ux)
      if (
        this.ephemeralPublicB.compareTo(zero) === 0 ||
        this.k.compareTo(zero) === 0 ||
        this.x.compareTo(zero) === 0
      ) {
        throw new Error("not enough is known to create Key");
      }

      e = this.u.multiply(this.x);
      this.debug && console.log("e after u*x:", e.toString(16));
      e = e.add(this.ephemeralPrivate);
      this.debug && console.log("e after e+ephemeralPrivate:", e.toString(16));

      b = this.group.getGenerator().modPow(this.x, this.group.getN().abs());
      this.debug && console.log("b after generator^x mod N:", b.toString(16));
      b = b.multiply(this.k);
      this.debug && console.log("b after b*k:", b.toString(16));
      b = this.ephemeralPublicB.subtract(b);
      this.debug && console.log("b after b-ephemeralPublicB:", b.toString(16));
      b = b.mod(this.group.getN());
      this.debug && console.log("b after b mod N:", b.toString(16));
    }

    this.premasterKey = b.modPow(e, this.group.getN().abs());
    this.debug && console.log("premasterKey:", this.premasterKey.toString(16));

    const hash = createHash("sha256");
    hash.update(new TextEncoder().encode(this.premasterKey.toString(16)));
    this.key = new Uint8Array(hash.digest());
    return this.key;
  }

  /*
From http://srp.stanford.edu/design.html

	Client -> Server:  M = H(H(N) xor H(g), H(I), s, A, B, Key)
	Server >- Client: H(A, M, K)

	The client must show its proof first

To make that useful, we are going to need to define the hash of big ints.
We will use math/big Bytes() to get the absolute value as a big-endian byte
slice (without padding to size of N)
*/
  public computeM(salt: Uint8Array, uname: string): Uint8Array {
    if (!this.group) {
      throw new Error("group is not set");
    }
    const nLen = bigIntToBytes(this.group.getN()).length;
    this.debug && console.log("Server padding length:", nLen);

    if (this.m !== null) {
      return this.m;
    }

    if (this.key === null) {
      throw new Error("don't try to prove anything before you have the key");
    }

    // First lets work on the H(H(A) ⊕ H(g)) part.
    const nHashBuffer = createHash("sha256")
      .update(bigIntToBytes(this.group.getN()))
      .digest();
    const nHash = new Uint8Array(nHashBuffer);
    const gHashBuffer = createHash("sha256")
      .update(bigIntToBytes(this.group.getGenerator()))
      .digest();
    const gHash = new Uint8Array(gHashBuffer);

    let groupXOR = new Uint8Array(SHA256_SIZE);
    const length = safeXORBytes(groupXOR, nHash, gHash);
    if (length !== SHA256_SIZE) {
      throw new Error(
        `XOR had length ${length} bytes instead of  ${SHA256_SIZE}`
      );
    }
    const groupHashBuffer = createHash("sha256").update(groupXOR).digest();
    const groupHash = new Uint8Array(groupHashBuffer);

    const uHashBuffer = createHash("sha256")
      .update(new TextEncoder().encode(uname))
      .digest();
    const uHash = new Uint8Array(uHashBuffer);

    let m1 = createHash("sha256");
    m1.update(groupHash);
    this.debug && console.log("m1:", m1.digest().toString("hex"));

    let m2 = createHash("sha256");
    m2.update(groupHash);
    m2.update(uHash);
    this.debug && console.log("m2:", m2.digest().toString("hex"));

    let m3 = createHash("sha256");
    m3.update(groupHash);
    m3.update(uHash);
    m3.update(salt);
    this.debug && console.log("m3:", m3.digest().toString("hex"));

    let m4 = createHash("sha256");
    m4.update(groupHash);
    m4.update(uHash);
    m4.update(salt);
    m4.update(bigIntToBytes(this.ephemeralPublicA));
    this.debug && console.log("m4:", m4.digest().toString("hex"));

    let m5 = createHash("sha256");
    m5.update(groupHash);
    m5.update(uHash);
    m5.update(salt);
    m5.update(bigIntToBytes(this.ephemeralPublicA));
    m5.update(bigIntToBytes(this.ephemeralPublicB));
    this.debug && console.log("m5:", m5.digest().toString("hex"));

    let m6 = createHash("sha256");
    m6.update(groupHash);
    m6.update(uHash);
    m6.update(salt);
    m6.update(bigIntToBytes(this.ephemeralPublicA));
    m6.update(bigIntToBytes(this.ephemeralPublicB));
    m6.update(this.key);
    const m6Digest = m6.digest();
    this.debug && console.log("m6:", m6Digest.toString("hex"));

    this.m = new Uint8Array(m6Digest.buffer);
    return this.m;
  }

  public goodServerProof(
    salt: Uint8Array,
    uname: string,
    proof: Uint8Array
  ): boolean {
    let myM: Uint8Array | null = null;
    try {
      myM = this.computeM(salt, uname);
    } catch (e) {
      console.error(e);
      // well that's odd. Better return false if something is wrong here
      this.isServerProved = false;
      return false;
    }
    this.isServerProved = constantTimeEqual(myM, proof);
    return this.isServerProved;
  }

  public goodClientProof(proof: Uint8Array): boolean {
    const clientProof = this.clientProof();
    return constantTimeEqual(clientProof, proof);
  }

  public clientProof(): Uint8Array {
    if (!this.isServer && !this.isServerProved) {
      throw new Error("don't construct client proof until server is proved");
    }
    if (this.cProof !== null) {
      return this.cProof;
    }

    if (
      this.ephemeralPublicA.compareTo(zero) === 0 ||
      this.m === null ||
      this.key === null
    ) {
      throw new Error("not enough pieces in place to construct client proof");
    }

    const hash = createHash("sha256");
    hash.update(bigIntToBytes(this.ephemeralPublicA));
    hash.update(this.m);
    hash.update(this.key);

    this.cProof = new Uint8Array(hash.digest());
    return this.cProof;
  }

  public setDebug = (enabled: boolean): void => {
    this.debug = enabled;
  };
}
