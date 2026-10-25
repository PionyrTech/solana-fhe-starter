/**
 * The verifier has to be able to say no.
 *
 * A checker that always reports success is worse than no checker, so these tests
 * feed it a correct result, a tampered result, a wrong parent link and an
 * incomplete upload, and require the right verdict in each case.
 *
 * The accounts here are synthesised rather than read from a chain, so the test
 * needs no validator. `scripts/demo.sh` covers the real on-chain case.
 */

import { describe, expect, it } from "vitest";

import type { ValueAccount } from "../src/sdk/account.js";
import { serialize } from "../src/sdk/codec.js";
import { DEMO } from "../src/sdk/params.js";
import { DeterministicRandom } from "../src/sdk/random.js";
import {
  addCiphertexts,
  encrypt,
  keygen,
  scalarMulCiphertext,
  type Ciphertext,
} from "../src/sdk/rlwe.js";
import { verifyAddition, verifyScalarMul, type EncryptedAccount } from "../src/sdk/verify.js";

const random = new DeterministicRandom(99n);
const secret = keygen(DEMO, random);
const a = encrypt(secret, [7n, 3n], random);
const b = encrypt(secret, [10n, 4n], random);
const sum = addCiphertexts(a, b);

function account(blob: Uint8Array, overrides: Partial<ValueAccount> = {}): ValueAccount {
  return {
    magic: "FHEV",
    version: 1,
    paramId: DEMO.id,
    bump: 1,
    depth: 0,
    n: DEMO.n,
    blobLen: blob.length,
    written: blob.length,
    noiseBound: DEMO.freshNoiseBound,
    createdSlot: 0n,
    owner: new Uint8Array(32),
    parentA: new Uint8Array(32),
    parentB: new Uint8Array(32),
    blob,
    complete: true,
    ...overrides,
  };
}

function bytesOf(ciphertext: Ciphertext): Uint8Array {
  return serialize(ciphertext.c0, ciphertext.c1);
}

const keyA = new Uint8Array(32).fill(1);
const keyB = new Uint8Array(32).fill(2);
const keyOut = new Uint8Array(32).fill(3);

function entries(overrides: {
  out?: Partial<ValueAccount>;
  blob?: Uint8Array;
} = {}): { a: EncryptedAccount; b: EncryptedAccount; out: EncryptedAccount } {
  return {
    a: { address: "addressA", key: keyA, account: account(bytesOf(a)) },
    b: { address: "addressB", key: keyB, account: account(bytesOf(b)) },
    out: {
      address: "addressOut",
      key: keyOut,
      account: account(overrides.blob ?? bytesOf(sum), {
        depth: 1,
        parentA: keyA,
        parentB: keyB,
        ...overrides.out,
      }),
    },
  };
}

describe("verifying an addition from public bytes", () => {
  it("accepts a result that is exactly a + b", () => {
    const { a: ea, b: eb, out } = entries();
    const result = verifyAddition(ea, eb, out);
    expect(result.ok).toBe(true);
    expect(result.mismatch).toBeNull();
    expect(result.lines.join("\n")).toContain("VERIFIED");
  });

  it("rejects a single tampered coefficient and names it", () => {
    const blob = bytesOf(sum);
    // Flip one coefficient by one, exactly the kind of silent corruption the
    // check exists to catch.
    const view = new DataView(blob.buffer, blob.byteOffset, blob.byteLength);
    view.setBigUint64(8, view.getBigUint64(8, true) + 1n, true);

    const { a: ea, b: eb, out } = entries({ blob });
    const result = verifyAddition(ea, eb, out);
    expect(result.ok).toBe(false);
    expect(result.mismatch).toEqual({ polynomial: "c0", index: 1 });
  });

  it("rejects a result whose parent links do not name the operands", () => {
    const { a: ea, b: eb, out } = entries({ out: { parentB: new Uint8Array(32).fill(9) } });
    const result = verifyAddition(ea, eb, out);
    expect(result.ok).toBe(false);
    expect(result.lines.join("\n")).toContain("parent_b");
  });

  it("rejects a result whose depth is not one greater than the deeper operand", () => {
    const { a: ea, b: eb, out } = entries({ out: { depth: 7 } });
    const result = verifyAddition(ea, eb, out);
    expect(result.ok).toBe(false);
    expect(result.lines.join("\n")).toContain("depth");
  });

  it("rejects an operand that was never fully uploaded", () => {
    const { a: ea, b: eb, out } = entries();
    const half = { ...ea, account: { ...ea.account, written: 100, complete: false } };
    const result = verifyAddition(half, eb, out);
    expect(result.ok).toBe(false);
    expect(result.lines.join("\n")).toContain("not been fully uploaded");
  });

  it("rejects operands from different parameter sets", () => {
    const { a: ea, b: eb, out } = entries();
    const wrongTier = { ...eb, account: { ...eb.account, paramId: 1 } };
    const result = verifyAddition(ea, wrongTier, out);
    expect(result.ok).toBe(false);
    expect(result.lines.join("\n")).toContain("parameter sets differ");
  });
});

describe("verifying a scaling from public bytes", () => {
  const scaled = scalarMulCiphertext(a, 5n);

  function scalingEntries(blob?: Uint8Array): { a: EncryptedAccount; out: EncryptedAccount } {
    return {
      a: { address: "addressA", key: keyA, account: account(bytesOf(a)) },
      out: {
        address: "addressOut",
        key: keyOut,
        account: account(blob ?? bytesOf(scaled), {
          depth: 1,
          parentA: keyA,
          parentB: new Uint8Array(32),
        }),
      },
    };
  }

  it("accepts a result that is exactly 5 * a", () => {
    const { a: ea, out } = scalingEntries();
    expect(verifyScalarMul(ea, out, 5n).ok).toBe(true);
  });

  it("rejects the right ciphertext attributed to the wrong scalar", () => {
    const { a: ea, out } = scalingEntries();
    const result = verifyScalarMul(ea, out, 6n);
    expect(result.ok).toBe(false);
    expect(result.mismatch).not.toBeNull();
  });

  it("rejects a scaling result that still carries a second parent", () => {
    const { a: ea, out } = scalingEntries();
    const withParent = { ...out, account: { ...out.account, parentB: keyB } };
    const result = verifyScalarMul(ea, withParent, 5n);
    expect(result.ok).toBe(false);
    expect(result.lines.join("\n")).toContain("second parent");
  });
});
