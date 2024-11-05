import { bigIntToBytes, maxInt } from "../utils/bigint";
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

  constructor(group: SrpGroup, x: BigInteger, k?: BigInteger) {
    this.group = group;
    this.x = x;
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
    hash.update(new Uint8Array(this.group.getN().toByteArray()));
    hash.update(new Uint8Array(this.group.getGenerator().toByteArray()));
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
    if (this.ephemeralPrivate === zero) {
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

  public ephemeralPublic(): BigInteger {
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
    this.ephemeralPublicB = AorB;
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

    let b = new BigInteger("0");
    let e = new BigInteger("0");

    if (
      this.ephemeralPublicB.compareTo(zero) === 0 ||
      this.k.compareTo(zero) === 0 ||
      this.x.compareTo(zero) === 0
    ) {
      throw new Error("not enough is known to create Key");
    }
    e = this.u.multiply(this.x);
    e = e.add(this.ephemeralPrivate);

    if (!this.group) {
      throw new Error("group is not set");
    }

    b = this.group.getGenerator().modPow(this.x, this.group.getN());
    b = b.multiply(this.k);
    b = this.ephemeralPublicB.subtract(b);
    b = b.mod(this.group.getN());

    this.premasterKey = b.modPow(e, this.group.getN());

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
    console.log(`Server padding length: ${nLen}`);

    if (this.m !== null) {
      return this.m;
    }

    if (this.key === null) {
      throw new Error("don't try to prove anything before you have the key");
    }

    // First lets work on the H(H(A) ⊕ H(g)) part.
    const nHash = new Uint8Array(
      createHash("sha256").update(bigIntToBytes(this.group.getN())).digest()
    );
    const gHash = new Uint8Array(
      createHash("sha256")
        .update(bigIntToBytes(this.group.getGenerator()))
        .digest()
    );
    let groupXOR = new Uint8Array(SHA256_SIZE);
    const length = safeXORBytes(groupXOR, nHash, gHash);
    if (length !== SHA256_SIZE) {
      throw new Error(
        `XOR had length ${length} bytes instead of  ${SHA256_SIZE}`
      );
    }
    const groupHash = new Uint8Array(
      createHash("sha256").update(groupXOR).digest()
    );

    const uHash = new Uint8Array(
      createHash("sha256").update(new TextEncoder().encode(uname)).digest()
    );

    const m = createHash("sha256");

    m.update(groupHash);
    m.update(uHash);
    m.update(salt);
    m.update(bigIntToBytes(this.ephemeralPublicA));
    m.update(bigIntToBytes(this.ephemeralPublicB));
    m.update(this.key);

    this.m = new Uint8Array(m.digest());
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

  public clientProof(): Uint8Array {
    if (!this.isServerProved) {
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
}
