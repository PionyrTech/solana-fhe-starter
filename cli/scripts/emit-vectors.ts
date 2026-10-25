/**
 * Emit the cross-language conformance vectors.
 *
 * Writes `crates/fhe-core/tests/vectors/conformance.json`, which the Rust test
 * suite reads and re-derives. The direction matters and is worth stating
 * plainly: the ciphertexts are produced *here*, by the client that owns the
 * randomness and the secret key, and the Rust side must reproduce the same
 * operation outputs byte for byte. If the two implementations ever disagree
 * about modular arithmetic or about the wire format, `cargo test` fails.
 *
 * The seed is fixed on purpose. Regenerating the file must be a no-op, so a
 * real change shows up as a diff rather than as noise.
 *
 *   npm run vectors
 */

import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { serialize, toHex } from "../src/sdk/codec.js";
import { PARAM_SETS } from "../src/sdk/params.js";
import { freshNoiseBoundOf } from "../src/sdk/util.js";
import { DeterministicRandom } from "../src/sdk/random.js";
import {
  addCiphertexts,
  encrypt,
  keygen,
  scalarMulCiphertext,
} from "../src/sdk/rlwe.js";

const here = dirname(fileURLToPath(import.meta.url));
const out = resolve(join(here, "..", "..", "crates", "fhe-core", "tests", "vectors", "conformance.json"));

const CASES = [
  { seed: 0x0123456789abcdefn, a: [7n, 3n, 200n, 1n], b: [10n, 4n, 50n, 0n], scalar: 5n },
  { seed: 0xfedcba9876543210n, a: [0n, 255n, 128n, 9n], b: [1n, 1n, 127n, 9n], scalar: 300n },
];

const cases = [];
for (const params of PARAM_SETS) {
  for (const testCase of CASES) {
    const random = new DeterministicRandom(testCase.seed);
    const secret = keygen(params, random);
    const a = encrypt(secret, testCase.a, random);
    const b = encrypt(secret, testCase.b, random);
    const sum = addCiphertexts(a, b);
    const scaled = scalarMulCiphertext(a, testCase.scalar);

    cases.push({
      param_id: params.id,
      param_name: params.name,
      n: params.n,
      q: params.q.toString(),
      t: params.t.toString(),
      blob_len: serialize(a.c0, a.c1).length,
      fresh_noise_bound: freshNoiseBoundOf(params).toString(),
      seed: `0x${testCase.seed.toString(16)}`,
      slots_a: testCase.a.map(String),
      slots_b: testCase.b.map(String),
      scalar: testCase.scalar.toString(),
      a: toHex(serialize(a.c0, a.c1)),
      b: toHex(serialize(b.c0, b.c1)),
      sum: toHex(serialize(sum.c0, sum.c1)),
      scaled: toHex(serialize(scaled.c0, scaled.c1)),
    });
  }
}

const document = {
  generated_by: "cli/scripts/emit-vectors.ts",
  note:
    "Produced by the TypeScript client and verified by the Rust test suite. The Rust side " +
    "must reproduce each operation output byte for byte.",
  cases,
};

mkdirSync(dirname(out), { recursive: true });
writeFileSync(out, `${JSON.stringify(document, null, 2)}\n`);
console.log(`wrote ${cases.length} cases to ${out}`);
