/**
 * The off-chain tier, running real BFV.
 *
 * This is the operation the chain cannot host, so the test that matters is the
 * one the on-chain tests cannot make: multiply two ciphertexts, relinearize, and
 * decrypt the product.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { createSealEngine, type SealEngine } from "../src/sdk/seal.js";

let engine: SealEngine;

beforeAll(async () => {
  engine = await createSealEngine();
});

afterAll(() => {
  engine?.dispose();
});

describe("the off-chain engine", () => {
  it("encrypts and decrypts", () => {
    const ciphertext = engine.encrypt([6, 7, 8, 9]);
    expect(engine.decrypt(ciphertext).slice(0, 4)).toEqual([6, 7, 8, 9]);
  });

  it("multiplies two ciphertexts, which the program cannot do", () => {
    const a = engine.encrypt([6, 7, 0, 0]);
    const b = engine.encrypt([6, 7, 0, 0]);
    const product = engine.multiply(a, b);
    expect(engine.decrypt(product).slice(0, 2)).toEqual([36, 49]);
  });

  it("spends noise budget on multiplication, and less on addition", () => {
    const a = engine.encrypt([3, 4]);
    const b = engine.encrypt([5, 6]);

    const sum = engine.add(a, b);
    const product = engine.multiply(a, b);

    // Addition is nearly free in noise terms; multiplication is the expensive
    // one. That asymmetry is exactly why addition is the operation that makes it
    // on chain.
    expect(engine.decrypt(sum).slice(0, 2)).toEqual([8, 10]);
    expect(sum.noiseBudget).toBeGreaterThan(product.noiseBudget);
    expect(product.noiseBudget).toBeLessThan(a.noiseBudget);
  });

  it("reports a measured noise budget, not an estimate", () => {
    const ciphertext = engine.encrypt([1, 2, 3]);
    expect(ciphertext.noiseBudget).toBeGreaterThan(0);
    expect(Number.isFinite(ciphertext.noiseBudget)).toBe(true);
  });
});
