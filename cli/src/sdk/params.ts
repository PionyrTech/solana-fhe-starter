/**
 * Parameter sets, mirroring `crates/fhe-core/src/params.rs`.
 *
 * The two files must agree exactly. `tests/conformance.test.ts` checks this
 * against the Rust constants through the committed vector file, so a change on
 * one side without the other is caught rather than discovered on chain.
 */

export interface Params {
  readonly id: number;
  readonly name: string;
  /** Ring degree. One ciphertext carries this many plaintext slots. */
  readonly n: number;
  readonly q: bigint;
  readonly t: bigint;
  readonly modShift: number;
  readonly modC: bigint;
  /** A conservative bound on the fresh error, matching the Rust constant. */
  readonly freshNoiseBound: bigint;
  readonly security: string;
}

export const DEMO: Params = {
  id: 0,
  name: "demo",
  n: 256,
  q: 8388593n, // 2^23 - 15
  t: 256n,
  modShift: 23,
  modC: 15n,
  freshNoiseBound: 64n,
  security:
    "None. N=256 with a 23 bit modulus is far below every published security threshold " +
    "and can be attacked directly. It exists so the test suite runs fast.",
};

export const STANDARD: Params = {
  id: 1,
  name: "standard",
  n: 2048,
  q: 18014398509481951n, // 2^54 - 33
  t: 65536n,
  modShift: 54,
  modC: 33n,
  freshNoiseBound: 64n,
  security:
    "N and q sit inside the HomomorphicEncryption.org standard table for 128 bit classical " +
    "security at this ring dimension. That is a statement about parameter sizes under the " +
    "table's assumptions; this implementation is unaudited, samples error from a centered " +
    "binomial rather than a discrete Gaussian, and is additively homomorphic only.",
};

export const PARAM_SETS: readonly Params[] = [DEMO, STANDARD];

export function paramsById(id: number): Params {
  const found = PARAM_SETS.find((p) => p.id === id);
  if (!found) throw new Error(`unknown parameter set id ${id}`);
  return found;
}

export function paramsByName(name: string): Params {
  const found = PARAM_SETS.find((p) => p.name === name);
  if (!found) throw new Error(`unknown parameter set ${name}`);
  return found;
}

/** Coefficients in the blob: `c0` and `c1` together. */
export function coeffCount(p: Params): number {
  return 2 * p.n;
}

/** Serialized ciphertext size: two polynomials, eight bytes per coefficient. */
export function blobLen(p: Params): number {
  return coeffCount(p) * 8;
}

/** The plaintext scaling factor. */
export function delta(p: Params): bigint {
  return p.q / p.t;
}

/** Values a slot can hold before it wraps. */
export function maxPlaintext(p: Params): bigint {
  return p.t - 1n;
}

/** The noise bound above which decryption stops being correct. */
export function maxNoiseBound(p: Params): bigint {
  return p.q / (2n * p.t);
}

export const HEADER_LEN = 136;
