/**
 * The ciphertext wire format, mirroring `crates/fhe-core/src/codec.rs`.
 *
 * `c0 || c1`, each a polynomial of `n` coefficients, each an eight byte little
 * endian integer reduced modulo `q`. No header: the parameter set travels with
 * the account that holds the blob.
 */

import type { Params } from "./params.js";

const COEFF_BYTES = 8;

export function serialize(c0: readonly bigint[], c1: readonly bigint[]): Uint8Array {
  if (c0.length !== c1.length) {
    throw new Error(`c0 and c1 differ in length: ${c0.length} vs ${c1.length}`);
  }
  const out = new Uint8Array((c0.length + c1.length) * COEFF_BYTES);
  const view = new DataView(out.buffer);
  for (let i = 0; i < c0.length; i += 1) {
    view.setBigUint64(i * COEFF_BYTES, c0[i]!, true);
    view.setBigUint64((c0.length + i) * COEFF_BYTES, c1[i]!, true);
  }
  return out;
}

export function deserialize(p: Params, bytes: Uint8Array): { c0: bigint[]; c1: bigint[] } {
  const expected = 2 * p.n * COEFF_BYTES;
  if (bytes.length !== expected) {
    throw new Error(`expected ${expected} bytes for ${p.name}, got ${bytes.length}`);
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const c0: bigint[] = new Array(p.n);
  const c1: bigint[] = new Array(p.n);
  for (let i = 0; i < p.n; i += 1) {
    c0[i] = view.getBigUint64(i * COEFF_BYTES, true) % p.q;
    c1[i] = view.getBigUint64((p.n + i) * COEFF_BYTES, true) % p.q;
  }
  return { c0, c1 };
}

export function toHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

export function fromHex(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex, "hex"));
}
