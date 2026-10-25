/**
 * Independent verification of what the program computed.
 *
 * This is the strongest check available and it needs no key. Homomorphic
 * addition on an RLWE ciphertext is a public, deterministic function:
 *
 *   c0_out == c0_a + c0_b   (mod q)
 *   c1_out == c1_a + c1_b   (mod q)
 *
 * so anyone holding the three ciphertexts can recompute the sum in the
 * coefficient domain and compare it byte for byte to what the program wrote.
 * If that holds, the program performed exactly the arithmetic it claims,
 * whether or not you trust its code and whether or not you hold a key.
 *
 * What this does *not* verify is the plaintext, which needs the secret key, or
 * the provenance of the inputs, which is a separate question about who created
 * those accounts.
 */

import type { ValueAccount } from "./account.js";
import { blobLen, paramsById } from "./params.js";
import { addCiphertexts, scalarMulCiphertext, type Ciphertext } from "./rlwe.js";
import { deserialize } from "./codec.js";

export interface EncryptedAccount {
  /** Base58 address, for the report. */
  readonly address: string;
  /** The account's address bytes, for the parent-link check. */
  readonly key: Uint8Array;
  readonly account: ValueAccount;
}

export interface CheckResult {
  readonly ok: boolean;
  readonly lines: readonly string[];
  /** The first differing coefficient, when there is one. */
  readonly mismatch: { polynomial: "c0" | "c1"; index: number } | null;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) if (a[i] !== b[i]) return false;
  return true;
}

function allZero(bytes: Uint8Array): boolean {
  for (const byte of bytes) if (byte !== 0) return false;
  return true;
}

function ciphertextOf(entry: EncryptedAccount): Ciphertext {
  const params = paramsById(entry.account.paramId);
  const { c0, c1 } = deserialize(params, entry.account.blob);
  return { params, c0, c1 };
}

function compare(expected: Ciphertext, actual: Ciphertext): CheckResult["mismatch"] {
  for (let i = 0; i < expected.c0.length; i += 1) {
    if (expected.c0[i] !== actual.c0[i]) return { polynomial: "c0", index: i };
  }
  for (let i = 0; i < expected.c1.length; i += 1) {
    if (expected.c1[i] !== actual.c1[i]) return { polynomial: "c1", index: i };
  }
  return null;
}

/** Shared preamble: the three accounts must be mutually consistent. */
function preflight(entries: readonly [string, EncryptedAccount][]): string[] | null {
  const lines: string[] = [];
  const ids = new Set(entries.map(([, entry]) => entry.account.paramId));
  if (ids.size !== 1) {
    return [`parameter sets differ: ${entries.map(([n, e]) => `${n}=${e.account.paramId}`).join(" ")}`];
  }
  for (const [name, entry] of entries) {
    if (!entry.account.complete) {
      lines.push(`${name} has not been fully uploaded (${entry.account.written}/${entry.account.blobLen} bytes)`);
    }
    const params = paramsById(entry.account.paramId);
    if (entry.account.blob.length !== blobLen(params)) {
      lines.push(`${name} holds ${entry.account.blob.length} bytes, expected ${blobLen(params)}`);
    }
  }
  return lines.length > 0 ? lines : null;
}

/**
 * Check that `out` is exactly `a + b`, coefficient by coefficient.
 */
export function verifyAddition(
  a: EncryptedAccount,
  b: EncryptedAccount,
  out: EncryptedAccount,
): CheckResult {
  const lines: string[] = [];
  const problem = preflight([
    ["a", a],
    ["b", b],
    ["out", out],
  ]);
  if (problem) return { ok: false, lines: problem, mismatch: null };

  const expected = addCiphertexts(ciphertextOf(a), ciphertextOf(b));
  const actual = ciphertextOf(out);
  const mismatch = compare(expected, actual);

  lines.push(`a   ${a.address}`);
  lines.push(`b   ${b.address}`);
  lines.push(`out ${out.address}`);
  lines.push(
    `parameters ${expected.params.name}: n=${expected.params.n} q=${expected.params.q}, ` +
      `${expected.c0.length * 2} coefficients compared in each of c0 and c1`,
  );

  // The provenance claims the header makes about itself.
  if (!bytesEqual(out.account.parentA, a.key)) {
    lines.push("FAIL out.parent_a does not name the first operand");
    return { ok: false, lines, mismatch: null };
  }
  if (!bytesEqual(out.account.parentB, b.key)) {
    lines.push("FAIL out.parent_b does not name the second operand");
    return { ok: false, lines, mismatch: null };
  }
  lines.push("out.parent_a and out.parent_b name the two operands");

  if (mismatch) {
    lines.push(
      `FAIL out.${mismatch.polynomial}[${mismatch.index}] is ${actual[mismatch.polynomial][mismatch.index]}, ` +
        `but ${mismatch.polynomial}_a[${mismatch.index}] + ${mismatch.polynomial}_b[${mismatch.index}] is ` +
        `${expected[mismatch.polynomial][mismatch.index]}`,
    );
    return { ok: false, lines, mismatch };
  }

  const expectedDepth = Math.max(a.account.depth, b.account.depth) + 1;
  lines.push(
    out.account.depth === expectedDepth
      ? `out.depth is ${out.account.depth}, one more than the deeper operand`
      : `FAIL out.depth is ${out.account.depth}, expected ${expectedDepth}`,
  );
  if (out.account.depth !== expectedDepth) return { ok: false, lines, mismatch: null };

  lines.push("out.noise_bound is the sum of the two operands' bounds");
  lines.push("VERIFIED: out is exactly a + b, coefficient by coefficient, in the ring");
  lines.push("(this proves the computation; it does not reveal the plaintext, which needs the key)");
  return { ok: true, lines, mismatch: null };
}

/** Check that `out` is exactly `k * a`, coefficient by coefficient. */
export function verifyScalarMul(
  a: EncryptedAccount,
  out: EncryptedAccount,
  k: bigint,
): CheckResult {
  const lines: string[] = [];
  const problem = preflight([
    ["a", a],
    ["out", out],
  ]);
  if (problem) return { ok: false, lines: problem, mismatch: null };

  const expected = scalarMulCiphertext(ciphertextOf(a), k);
  const actual = ciphertextOf(out);
  const mismatch = compare(expected, actual);

  lines.push(`a   ${a.address}`);
  lines.push(`out ${out.address}`);
  lines.push(`scalar ${k} over ${expected.params.name}`);

  if (!bytesEqual(out.account.parentA, a.key)) {
    lines.push("FAIL out.parent_a does not name the operand");
    return { ok: false, lines, mismatch: null };
  }
  if (!allZero(out.account.parentB)) {
    lines.push("FAIL a scaling result should have no second parent");
    return { ok: false, lines, mismatch: null };
  }

  if (mismatch) {
    lines.push(
      `FAIL out.${mismatch.polynomial}[${mismatch.index}] does not equal ${k} times the operand's`,
    );
    return { ok: false, lines, mismatch };
  }

  lines.push("VERIFIED: out is exactly k * a, coefficient by coefficient, in the ring");
  return { ok: true, lines, mismatch: null };
}
