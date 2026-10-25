/**
 * The client scheme: does encryption, addition, and decryption actually compose?
 *
 * This is the test that a "toy crypto" project cannot pass. It decrypts, so it
 * proves the homomorphic property rather than asserting it.
 */

import { describe, expect, it } from "vitest";

import { deserialize, serialize } from "../src/sdk/codec.js";
import { DEMO, STANDARD, delta, maxNoiseBound } from "../src/sdk/params.js";
import { DeterministicRandom, systemRandom } from "../src/sdk/random.js";
import {
  ERROR_ETA,
  addCiphertexts,
  decrypt,
  encrypt,
  keygen,
  measureNoise,
  negacyclicMul,
  scalarMulCiphertext,
} from "../src/sdk/rlwe.js";

describe("the ring", () => {
  it("negacyclic product wraps with a sign, matching x^n = -1", () => {
    // x^(n-1) * x = x^n = -1
    const n = 4;
    const a = [0n, 0n, 0n, 1n];
    const b = [0n, 1n, 0n, 0n];
    expect(negacyclicMul(a, b, 17n)).toEqual([16n, 0n, 0n, 0n]);
  });

  it("multiplies by one as the identity", () => {
    const a = [1n, 2n, 3n, 4n];
    const one = [1n, 0n, 0n, 0n];
    expect(negacyclicMul(a, one, 97n)).toEqual(a);
  });
});

describe("encrypt and decrypt", () => {
  it("round trips a handful of slots", () => {
    const random = new DeterministicRandom(1n);
    const secret = keygen(DEMO, random);
    const values = [7n, 3n, 42n, 255n];
    const ciphertext = encrypt(secret, values, random);
    const recovered = decrypt(secret, ciphertext).slice(0, values.length);
    expect(recovered).toEqual(values);
  });

  it("round trips with the system entropy source", () => {
    const secret = keygen(DEMO, systemRandom);
    const values = [123n, 0n, 1n];
    const ciphertext = encrypt(secret, values, systemRandom);
    expect(decrypt(secret, ciphertext).slice(0, values.length)).toEqual(values);
  });

  it("leaves the fresh noise inside the documented bound", () => {
    const random = new DeterministicRandom(7n);
    const secret = keygen(DEMO, random);
    const ciphertext = encrypt(secret, [100n, 200n], random);
    const noise = measureNoise(secret, ciphertext);
    expect(noise).toBeLessThanOrEqual(BigInt(ERROR_ETA));
    expect(noise).toBeLessThan(DEMO.freshNoiseBound);
  });

  it("refuses a slot value above the plaintext modulus", () => {
    const random = new DeterministicRandom(3n);
    const secret = keygen(DEMO, random);
    expect(() => encrypt(secret, [DEMO.t], random)).toThrow(/outside/);
  });
});

describe("homomorphic operations", () => {
  it("adds two ciphertexts so the plaintexts add", () => {
    const random = new DeterministicRandom(11n);
    const secret = keygen(DEMO, random);
    const a = encrypt(secret, [7n, 3n, 0n, 250n], random);
    const b = encrypt(secret, [10n, 4n, 1n, 5n], random);

    const sum = addCiphertexts(a, b);
    expect(decrypt(secret, sum).slice(0, 4)).toEqual([17n, 7n, 1n, 255n]);
  });

  it("scales a ciphertext by a public constant", () => {
    const random = new DeterministicRandom(13n);
    const secret = keygen(DEMO, random);
    const a = encrypt(secret, [3n, 5n], random);

    const scaled = scalarMulCiphertext(a, 7n);
    expect(decrypt(secret, scaled).slice(0, 2)).toEqual([21n, 35n]);
  });

  it("keeps the noise bounded across many additions", () => {
    const random = new DeterministicRandom(17n);
    const secret = keygen(DEMO, random);
    let accumulator = encrypt(secret, [1n], random);
    for (let i = 0; i < 50; i += 1) {
      accumulator = addCiphertexts(accumulator, encrypt(secret, [1n], random));
    }
    expect(decrypt(secret, accumulator)[0]).toBe(51n);
    // The bound the program propagates is 64 per operand, so 51 additions sit
    // at 51 * 64; the measured noise is far below that. Reporting both is the
    // point: the on-chain bound is conservative on purpose.
    const measured = measureNoise(secret, accumulator);
    expect(measured).toBeLessThan(64n);
  });

  it("stops being correct once the plaintext wraps, which is not a bug", () => {
    // Values live modulo t. Two 200s is 400, which wraps to 144 for t=256.
    const random = new DeterministicRandom(19n);
    const secret = keygen(DEMO, random);
    const a = encrypt(secret, [200n], random);
    const b = encrypt(secret, [200n], random);
    expect(decrypt(secret, addCiphertexts(a, b))[0]).toBe(144n);
  });
});

describe("the wire format", () => {
  it("serializes to two polynomials of n coefficients", () => {
    const random = new DeterministicRandom(23n);
    const secret = keygen(DEMO, random);
    const ciphertext = encrypt(secret, [1n, 2n], random);
    const bytes = serialize(ciphertext.c0, ciphertext.c1);
    expect(bytes.length).toBe(2 * DEMO.n * 8);

    const back = deserialize(DEMO, bytes);
    expect(back.c0).toEqual(ciphertext.c0);
    expect(back.c1).toEqual(ciphertext.c1);
  });

  it("refuses a blob from the other tier", () => {
    const random = new DeterministicRandom(29n);
    const secret = keygen(DEMO, random);
    const ciphertext = encrypt(secret, [1n], random);
    const bytes = serialize(ciphertext.c0, ciphertext.c1);
    expect(() => deserialize(STANDARD, bytes)).toThrow(/expected/);
  });
});

describe("the standard tier", () => {
  it("has the room the arithmetic needs", () => {
    expect(delta(DEMO) * DEMO.t <= DEMO.q).toBe(true);
    expect(delta(STANDARD) * STANDARD.t <= STANDARD.q).toBe(true);
    expect(maxNoiseBound(STANDARD)).toBeGreaterThan(maxNoiseBound(DEMO));
  });

  it("round trips at 2048, which is what the demo uses for real work", () => {
    // One mulmod-heavy operation per coefficient, so this is the slow one.
    const random = new DeterministicRandom(31n);
    const secret = keygen(STANDARD, random);
    const ciphertext = encrypt(secret, [1000n, 2000n], random);
    expect(decrypt(secret, ciphertext).slice(0, 2)).toEqual([1000n, 2000n]);
  }, 120_000);
});
