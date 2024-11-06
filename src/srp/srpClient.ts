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

// mathematical constants
const zero = new BigInteger("0");
const SHA256_SIZE = 32;

export class SrpClient {
  // ephemeral values are temporary, generated fresh for each authentication session
  private ephemeralPrivate: BigInteger = zero; // random secret 'a' or 'b'
  private ephemeralPublicA: BigInteger = zero; // g^a mod N
  private ephemeralPublicB: BigInteger = zero; // B = kv + g^b mod N
  private x: BigInteger = zero; // private key derived from password
  private v: BigInteger = zero; // password verifier = g^x mod N
  private u: BigInteger | null = zero; // random scrambling parameter
  private k: BigInteger = zero; // multiplier parameter
  private premasterKey: BigInteger | null = null; // shared secret before final hashing
  private key: Uint8Array | null = null; // final shared session key
  private m: Uint8Array | null = null; // proof of key for server verification
  private cProof: Uint8Array | null = null; // proof of key for client verification
  private isServerProved: boolean = false;
  private group: SrpGroup | null = null; // defines N (prime) and g (generator)
  private badState = false;
  private isServer = false;
  private debug: boolean = false;

  // constructor initializes with either x (client) or v (server)
  constructor(
    group: SrpGroup,
    x: BigInteger,
    k?: BigInteger,
    party: "client" | "server" = "client"
  ) {
    this.isServer = party === "server";
    this.group = group;
    // server uses verifier (v), client uses private key (x)
    if (this.isServer) {
      this.v = x;
    } else {
      this.x = x;
    }
    // k is a constant derived from N and g
    if (k) {
      this.k = k;
    } else {
      this.k = this.makeLittleK();
    }
    this.generateMySecret();
    this.makeA();
  }

  // k = H(N || g) - used to prevent some number theoretic attacks
  private makeLittleK(): BigInteger {
    const hash = createHash("sha256");
    if (!this.group) {
      throw new Error("group is not set");
    }
    hash.update(bigIntToBytes(this.group.getN()));
    hash.update(bigIntToBytes(this.group.getGenerator()));
    return hexToBigInt(hash.digest("hex"));
  }

  // generates random ephemeral private key (a or b)
  private generateMySecret(): BigInteger {
    if (!this.group) {
      throw new Error("group is not set");
    }
    const eSize = maxInt(this.group.exponentSize, minExponentSize);
    const bytes = randomBytes(eSize);
    this.ephemeralPrivate = hexToBigInt(bytes.toString("hex"));
    return this.ephemeralPrivate;
  }

  // computes A = g^a mod N
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

  // computes B = kv + g^b mod N
  private makeB(): BigInteger {
    // prerequisites check
    if (this.group === null) {
      throw new Error("group is not set");
    }
    if (!this.isServer) {
      throw new Error("isServer is not set");
    }
    if (this.v.compareTo(zero) === 0) {
      throw new Error("v is not set");
    }
    if (this.k.compareTo(zero) === 0) {
      this.k = this.makeLittleK();
    }
    if (this.ephemeralPrivate.compareTo(zero) === 0) {
      this.generateMySecret();
    }

    // B = kv + g^b mod N
    let term1 = this.k.multiply(this.v);
    let term2 = this.group
      .getGenerator()
      .modPow(this.ephemeralPrivate, this.group.getN());
    term1 = this.group.reduce(term1);
    this.ephemeralPublicB = term1.add(term2);
    this.ephemeralPublicB = this.group.reduce(this.ephemeralPublicB);
    return this.ephemeralPublicB;
  }

  // validates scrambling parameter u is not zero (security requirement)
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

  // computes password verifier v = g^x mod N
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

  // validates public values against group parameters
  public isPublicValid(AorB: BigInteger): boolean {
    if (!this.group) {
      throw new Error("group is not set");
    }

    const N = this.group.getN();

    // must be: 0 < AorB < N
    if (AorB.compareTo(zero) <= 0 || AorB.compareTo(N) >= 0) {
      return false;
    }

    // must be coprime with N
    const bigOne = new BigInteger("1");
    if (AorB.gcd(N).compareTo(bigOne) !== 0) {
      return false;
    }

    return true;
  }

  // computes scrambling parameter u = H(A || B)
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

  // returns public ephemeral key (A for client, B for server)
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

  // sets other party's public ephemeral key
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

  // computes shared session key
  // server: K = H((A * v^u)^b mod N)
  // client: K = H((B - k * g^x)^(a + u * x) mod N)
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
      // S = (A * v^u)^b mod N
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
      // S = (B - k * g^x)^(a + u * x) mod N
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

    // final key derivation
    const hash = createHash("sha256");
    hash.update(new TextEncoder().encode(this.premasterKey.toString(16)));
    this.key = new Uint8Array(hash.digest());
    return this.key;
  }

  // computes proof of key for server verification
  // M = H(H(N) XOR H(g), H(I), s, A, B, Key)
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

    // compute H(N) XOR H(g)
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

    // build proof incrementally for debugging
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

  // verifies server's proof matches computed proof
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
      this.isServerProved = false;
      return false;
    }
    this.isServerProved = constantTimeEqual(myM, proof);
    return this.isServerProved;
  }

  // verifies client's proof matches computed proof
  public goodClientProof(proof: Uint8Array): boolean {
    const clientProof = this.clientProof();
    return constantTimeEqual(clientProof, proof);
  }

  // computes client's proof of key
  // H(A, M, K)
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
