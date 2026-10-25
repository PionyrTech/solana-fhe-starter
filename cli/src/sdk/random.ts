/**
 * Randomness.
 *
 * Key generation, encryption, and the error sampler all need entropy. The
 * interface exists so tests can inject a deterministic source and get the same
 * ciphertext twice, which is what makes the committed conformance vectors
 * meaningful.
 */

import { randomBytes } from "node:crypto";

export interface RandomSource {
  bytes(count: number): Uint8Array;
}

/** The real thing. Never used by the deterministic tests. */
export const systemRandom: RandomSource = {
  bytes(count: number): Uint8Array {
    return new Uint8Array(randomBytes(count));
  },
};

/**
 * A seeded generator, for reproducible test vectors only.
 *
 * This is not cryptographically secure and says so in the name. It exists so a
 * vector file can be regenerated and compared, not to encrypt anything real.
 */
export class DeterministicRandom implements RandomSource {
  private state: bigint;

  constructor(seed: bigint) {
    this.state = seed & 0xffffffffffffffffn;
  }

  bytes(count: number): Uint8Array {
    const out = new Uint8Array(count);
    for (let i = 0; i < count; i += 1) {
      // xorshift64*, chosen because it is three lines and easy to audit.
      this.state ^= this.state >> 12n;
      this.state = (this.state * 0x2545f4914f6cdd1dn) & 0xffffffffffffffffn;
      this.state ^= this.state << 25n;
      this.state &= 0xffffffffffffffffn;
      this.state ^= this.state >> 27n;
      const mixed = (this.state * 0x2545f4914f6cdd1dn) & 0xffffffffffffffffn;
      out[i] = Number(mixed >> 56n) & 0xff;
    }
    return out;
  }
}
