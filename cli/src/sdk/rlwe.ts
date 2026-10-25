/**
 * The client side of the RLWE scheme: key generation, encryption, decryption,
 * and the same homomorphic operations the program runs.
 *
 * This mirrors the arithmetic in `crates/fhe-core` but is written independently,
 * because the client needs the two things the chain can never have: randomness
 * and the secret key. Correctness is not assumed, it is tested: the committed
 * vector file in `crates/fhe-core/tests/vectors` is produced here and verified
 * there, and `tests/e2e.test.ts` decrypts what the program computed.
 *
 * What this is:
 *
 * * RLWE over `Z_q[x] / (x^n + 1)`, message packed coefficient by coefficient.
 * * Additively homomorphic: addition and public-scalar multiplication.
 * * Symmetric: encryption takes the secret key directly, so no public key is
 *   generated. That keeps the noise analysis simple and keeps the key where it
 *   belongs. A public key variant is a documented extension, not a shipped one.
 *
 * What this is not:
 *
 * * It is not fully homomorphic. There is no ciphertext multiplication here or
 *   on chain. `src/sdk/seal.ts` is where the full engine lives.
 * * The error is sampled from a centered binomial distribution, which is a
 *   standard lattice sampler but is not the discrete Gaussian the published
 *   security tables assume. The parameter sizes are documented; the security
 *   guarantee is not claimed.
 */

import type { Params } from "./params.js";
import { delta } from "./params.js";
import type { RandomSource } from "./random.js";

/** Centered binomial parameter for the error distribution. */
export const ERROR_ETA = 8;

/** Ternary secret coefficients, as in most RLWE deployments. */
export function mod(x: bigint, q: bigint): bigint {
  const r = x % q;
  return r < 0n ? r + q : r;
}

/** `a * b mod (x^n + 1)`, the negacyclic product the ring needs. */
export function negacyclicMul(a: readonly bigint[], b: readonly bigint[], q: bigint): bigint[] {
  const n = a.length;
  const out = new Array<bigint>(n).fill(0n);
  for (let i = 0; i < n; i += 1) {
    const ai = a[i]!;
    if (ai === 0n) continue;
    for (let j = 0; j < n; j += 1) {
      const bj = b[j]!;
      if (bj === 0n) continue;
      const index = i + j;
      const product = ai * bj;
      if (index < n) {
        out[index] = out[index]! + product;
      } else {
        // x^n = -1, so the wrapped term is subtracted.
        out[index - n] = out[index - n]! - product;
      }
    }
  }
  return out.map((value) => mod(value, q));
}

/** A polynomial with coefficients uniform in `[0, q)`. */
export function uniformPoly(p: Params, random: RandomSource): bigint[] {
  const out = new Array<bigint>(p.n);
  const perCoeff = 8;
  const bytes = random.bytes(p.n * perCoeff);
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  for (let i = 0; i < p.n; i += 1) {
    // A 64 bit draw reduced into [0, q): biased by a factor below 2^-10 for the
    // standard tier. Documented rather than hidden; it does not affect the
    // arithmetic this kit demonstrates.
    out[i] = view.getBigUint64(i * perCoeff, true) % p.q;
  }
  return out;
}

/** A polynomial with coefficients from a centered binomial, so in `[-eta, eta]`. */
export function centeredBinomialPoly(p: Params, random: RandomSource, eta: number): bigint[] {
  const bitsPerCoeff = 2 * eta;
  const totalBits = p.n * bitsPerCoeff;
  const bytes = random.bytes(Math.ceil(totalBits / 8));
  const out = new Array<bigint>(p.n);
  for (let i = 0; i < p.n; i += 1) {
    let ones = 0;
    for (let bit = 0; bit < bitsPerCoeff; bit += 1) {
      const index = i * bitsPerCoeff + bit;
      ones += (bytes[index >> 3]! >> (index & 7)) & 1;
    }
    out[i] = BigInt(ones - eta);
  }
  return out;
}

/** A ternary secret: coefficients in `{-1, 0, 1}`. */
export function ternaryPoly(p: Params, random: RandomSource): bigint[] {
  const bytes = random.bytes(p.n);
  const out = new Array<bigint>(p.n);
  for (let i = 0; i < p.n; i += 1) {
    const r = bytes[i]! % 3;
    out[i] = r === 0 ? 0n : r === 1 ? 1n : p.q - 1n;
  }
  return out;
}

export interface SecretKey {
  readonly params: Params;
  /** Kept on the machine that made it. Never uploaded. */
  readonly s: bigint[];
}

export interface Ciphertext {
  readonly params: Params;
  readonly c0: bigint[];
  readonly c1: bigint[];
}

export function keygen(params: Params, random: RandomSource): SecretKey {
  return { params, s: ternaryPoly(params, random) };
}

/**
 * Encrypt up to `n` values, one per slot.
 *
 * `c0 = delta * m - (a * s + e)`, `c1 = a`, so decryption recovers
 * `delta * m - e` and the noise is exactly `e`, bounded by `eta`.
 */
export function encrypt(
  secret: SecretKey,
  values: readonly bigint[],
  random: RandomSource,
): Ciphertext {
  const p = secret.params;
  if (values.length > p.n) {
    throw new Error(`${p.name} carries at most ${p.n} slots, got ${values.length}`);
  }
  for (const value of values) {
    if (value < 0n || value >= p.t) {
      throw new Error(`slot value ${value} is outside [0, ${p.t})`);
    }
  }

  const a = uniformPoly(p, random);
  const e = centeredBinomialPoly(p, random, ERROR_ETA);
  const as = negacyclicMul(a, secret.s, p.q);
  const scale = delta(p);

  const c0 = new Array<bigint>(p.n);
  const c1 = new Array<bigint>(p.n);
  for (let i = 0; i < p.n; i += 1) {
    const message = i < values.length ? values[i]! : 0n;
    c0[i] = mod(scale * message - as[i]! - e[i]!, p.q);
    c1[i] = a[i]!;
  }
  return { params: p, c0, c1 };
}

/** Recover every slot. Returns one entry per coefficient, not per plaintext. */
export function decrypt(secret: SecretKey, ciphertext: Ciphertext): bigint[] {
  const p = secret.params;
  const product = negacyclicMul(ciphertext.c1, secret.s, p.q);
  const scale = delta(p);
  const out = new Array<bigint>(p.n);
  for (let i = 0; i < p.n; i += 1) {
    const v = mod(ciphertext.c0[i]! + product[i]!, p.q);
    // round(v / delta), exactly and without floating point.
    const rounded = (2n * v + scale) / (2n * scale);
    out[i] = mod(rounded, p.t);
  }
  return out;
}

/**
 * Measure the actual noise, in the coefficient magnitude sense.
 *
 * This is possible here only because the caller holds the secret key. The
 * program cannot do this, which is why it propagates a bound instead. Reporting
 * both is the honest way to show the bound is conservative.
 */
export function measureNoise(secret: SecretKey, ciphertext: Ciphertext): bigint {
  const p = secret.params;
  const product = negacyclicMul(ciphertext.c1, secret.s, p.q);
  const scale = delta(p);
  const half = p.q / 2n;
  let worst = 0n;
  for (let i = 0; i < p.n; i += 1) {
    const v = mod(ciphertext.c0[i]! + product[i]!, p.q);
    const rounded = (2n * v + scale) / (2n * scale);
    const message = mod(rounded, p.t);
    let residual = mod(v - scale * message, p.q);
    if (residual > half) residual -= p.q;
    const magnitude = residual < 0n ? -residual : residual;
    if (magnitude > worst) worst = magnitude;
  }
  return worst;
}

export function addCiphertexts(a: Ciphertext, b: Ciphertext): Ciphertext {
  assertSameParams(a, b);
  const p = a.params;
  return {
    params: p,
    c0: a.c0.map((value, i) => mod(value + b.c0[i]!, p.q)),
    c1: a.c1.map((value, i) => mod(value + b.c1[i]!, p.q)),
  };
}

export function scalarMulCiphertext(ciphertext: Ciphertext, k: bigint): Ciphertext {
  const p = ciphertext.params;
  return {
    params: p,
    c0: ciphertext.c0.map((value) => mod(value * k, p.q)),
    c1: ciphertext.c1.map((value) => mod(value * k, p.q)),
  };
}

export function assertSameParams(a: Ciphertext, b: Ciphertext): void {
  if (a.params.id !== b.params.id) {
    throw new Error(
      `cannot combine a ${a.params.name} ciphertext with a ${b.params.name} ciphertext`,
    );
  }
  if (a.c0.length !== b.c0.length) {
    throw new Error("ciphertexts differ in ring degree");
  }
}

/** The noise bound after addition, matching `fhe_core::noise::add_bound`. */
export function addBound(a: bigint, b: bigint): bigint {
  return a + b;
}

/** The noise bound after scaling, matching `fhe_core::noise::scalar_mul_bound`. */
export function scalarMulBound(bound: bigint, k: bigint): bigint {
  return bound * k;
}
