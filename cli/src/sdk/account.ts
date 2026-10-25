/**
 * Reading the account layout, mirroring `crates/fhe-core/src/account.rs`.
 *
 * The value account is not serialized by Anchor, it is a raw layout this kit
 * defines, so the offsets below are the contract between the Rust side and the
 * client. `crates/fhe-core/src/account.rs` asserts the same 136 byte header, and
 * the program asserts it again, so a field cannot move silently.
 */

import { HEADER_LEN } from "./params.js";

export const MAGIC = "FHEV";

export interface ValueAccount {
  readonly magic: string;
  readonly version: number;
  readonly paramId: number;
  readonly bump: number;
  readonly depth: number;
  readonly n: number;
  readonly blobLen: number;
  readonly written: number;
  readonly noiseBound: bigint;
  readonly createdSlot: bigint;
  readonly owner: Uint8Array;
  readonly parentA: Uint8Array;
  readonly parentB: Uint8Array;
  readonly blob: Uint8Array;
  readonly complete: boolean;
}

function u32(data: Uint8Array, offset: number): number {
  return new DataView(data.buffer, data.byteOffset, data.byteLength).getUint32(offset, true);
}

function u64(data: Uint8Array, offset: number): bigint {
  return new DataView(data.buffer, data.byteOffset, data.byteLength).getBigUint64(offset, true);
}

export function decodeValueAccount(data: Uint8Array): ValueAccount {
  if (data.length < HEADER_LEN) {
    throw new Error(`account is ${data.length} bytes, shorter than the ${HEADER_LEN} byte header`);
  }
  const magic = Buffer.from(data.subarray(0, 4)).toString("utf8");
  if (magic !== MAGIC) {
    throw new Error(`account does not start with ${MAGIC}, it starts with ${magic}`);
  }
  const version = u32(data, 4);
  if (version !== 1) {
    throw new Error(`unsupported account layout version ${version}`);
  }
  const blobLen = u32(data, 16);
  const end = HEADER_LEN + blobLen;
  if (data.length < end) {
    throw new Error(`account claims a ${blobLen} byte ciphertext but holds ${data.length - HEADER_LEN}`);
  }
  const written = u32(data, 20);
  return {
    magic,
    version,
    paramId: data[8]!,
    bump: data[9]!,
    depth: u16(data, 10),
    n: u32(data, 12),
    blobLen,
    written,
    noiseBound: u64(data, 24),
    createdSlot: u64(data, 32),
    owner: data.subarray(40, 72),
    parentA: data.subarray(72, 104),
    parentB: data.subarray(104, 136),
    blob: data.subarray(HEADER_LEN, end),
    complete: written === blobLen,
  };
}

function u16(data: Uint8Array, offset: number): number {
  return new DataView(data.buffer, data.byteOffset, data.byteLength).getUint16(offset, true);
}

/** The size a value account needs for a parameter set. */
export function valueAccountSize(blobLen: number): number {
  return HEADER_LEN + blobLen;
}
