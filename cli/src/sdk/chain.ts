/**
 * The on-chain client.
 *
 * Instructions are encoded here rather than generated from an IDL. The program
 * is a normal Anchor program and `anchor build` will produce an IDL for anyone
 * who prefers the Anchor client, but shipping the encoding explicitly means the
 * kit has no code generation step and one less toolchain, and it makes the wire
 * format visible: an eight byte discriminator, then Borsh arguments.
 *
 * The discriminator is `sha256("global:<instruction name>")` truncated to eight
 * bytes, which is Anchor's convention.
 */

import { createHash } from "node:crypto";
import {
  ComputeBudgetProgram,
  Connection,
  Keypair,
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionInstruction,
} from "@solana/web3.js";
import { decodeValueAccount, valueAccountSize, type ValueAccount } from "./account.js";
import type { Params } from "./params.js";
import { blobLen } from "./params.js";

export const VALUE_SEED = Buffer.from("value");
export const EVALUATION_SEED = Buffer.from("evaluation");

/** Chunk size for uploading a ciphertext. One ciphertext is many transactions. */
export const UPLOAD_CHUNK_BYTES = 900;

export function discriminator(name: string): Buffer {
  return createHash("sha256").update(`global:${name}`).digest().subarray(0, 8);
}

function u64le(value: bigint | number): Buffer {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64LE(BigInt(value));
  return buf;
}

function u32le(value: number): Buffer {
  const buf = Buffer.alloc(4);
  buf.writeUInt32LE(value);
  return buf;
}

export function valuePda(programId: PublicKey, owner: PublicKey, index: bigint): PublicKey {
  return PublicKey.findProgramAddressSync(
    [VALUE_SEED, owner.toBuffer(), u64le(index)],
    programId,
  )[0];
}

export function evaluationPda(programId: PublicKey, author: PublicKey, index: bigint): PublicKey {
  return PublicKey.findProgramAddressSync(
    [EVALUATION_SEED, author.toBuffer(), u64le(index)],
    programId,
  )[0];
}

export function createValueInstruction(
  programId: PublicKey,
  payer: PublicKey,
  paramId: number,
  index: bigint,
): TransactionInstruction {
  return new TransactionInstruction({
    programId,
    keys: [
      { pubkey: payer, isSigner: true, isWritable: true },
      { pubkey: valuePda(programId, payer, index), isSigner: false, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: Buffer.concat([discriminator("create_value"), Buffer.from([paramId]), u64le(index)]),
  });
}

export function writeChunkInstruction(
  programId: PublicKey,
  writer: PublicKey,
  value: PublicKey,
  offset: number,
  chunk: Uint8Array,
): TransactionInstruction {
  return new TransactionInstruction({
    programId,
    keys: [
      { pubkey: writer, isSigner: true, isWritable: true },
      { pubkey: value, isSigner: false, isWritable: true },
    ],
    data: Buffer.concat([
      discriminator("write_chunk"),
      u32le(offset),
      u32le(chunk.length),
      Buffer.from(chunk),
    ]),
  });
}

export function homomorphicAddInstruction(
  programId: PublicKey,
  payer: PublicKey,
  a: PublicKey,
  b: PublicKey,
  out: PublicKey,
): TransactionInstruction {
  return new TransactionInstruction({
    programId,
    keys: [
      { pubkey: payer, isSigner: true, isWritable: true },
      { pubkey: a, isSigner: false, isWritable: false },
      { pubkey: b, isSigner: false, isWritable: false },
      { pubkey: out, isSigner: false, isWritable: true },
    ],
    data: discriminator("homomorphic_add"),
  });
}

export function scalarMulInstruction(
  programId: PublicKey,
  payer: PublicKey,
  a: PublicKey,
  out: PublicKey,
  k: bigint,
): TransactionInstruction {
  return new TransactionInstruction({
    programId,
    keys: [
      { pubkey: payer, isSigner: true, isWritable: true },
      { pubkey: a, isSigner: false, isWritable: false },
      { pubkey: out, isSigner: false, isWritable: true },
    ],
    data: Buffer.concat([discriminator("scalar_mul"), u64le(k)]),
  });
}

export function commitEvaluationInstruction(
  programId: PublicKey,
  author: PublicKey,
  index: bigint,
  digest: Uint8Array,
  depth: number,
  noiseBits: number,
): TransactionInstruction {
  if (digest.length !== 32) throw new Error("digest must be 32 bytes");
  const tail = Buffer.alloc(4);
  tail.writeUInt16LE(depth, 0);
  tail.writeUInt16LE(noiseBits, 2);
  return new TransactionInstruction({
    programId,
    keys: [
      { pubkey: author, isSigner: true, isWritable: true },
      { pubkey: evaluationPda(programId, author, index), isSigner: false, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: Buffer.concat([
      discriminator("commit_evaluation"),
      u64le(index),
      Buffer.from(digest),
      tail,
    ]),
  });
}

export interface ChainOptions {
  connection: Connection;
  programId: PublicKey;
  payer: Keypair;
}

/**
 * Retry an RPC call through the rate limiting the public endpoints apply.
 *
 * The public devnet RPC answers `429 Too Many Requests` under any real load, and
 * a ciphertext upload is dozens of transactions, so without this the upload dies
 * part way through. Only transport-level failures are retried: a rejected
 * program is never retried, because retrying it would just fail again.
 */
async function withRetry<T>(label: string, fn: () => Promise<T>, attempts = 20): Promise<T> {
  let delay = 750;
  for (let attempt = 1; ; attempt += 1) {
    try {
      return await fn();
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      const retryable = /\b429\b|Too Many Requests|rate limit|fetch failed|ECONNRESET|ETIMEDOUT|\b50[234]\b/.test(
        message,
      );
      if (!retryable || attempt >= attempts) throw error;
      console.warn(
        `  ${label}: ${message.split("\n")[0].slice(0, 120)} (attempt ${attempt}/${attempts}, retrying in ${delay}ms)`,
      );
      await new Promise((resolve) => setTimeout(resolve, delay));
      delay = Math.min(Math.round(delay * 1.5), 12_000);
    }
  }
}

async function send(options: ChainOptions, instructions: TransactionInstruction[], cu: number) {
  const transaction = new Transaction().add(
    ComputeBudgetProgram.setComputeUnitLimit({ units: cu }),
    ...instructions,
  );
  const latest = await withRetry("blockhash", () => options.connection.getLatestBlockhash());
  transaction.recentBlockhash = latest.blockhash;
  transaction.feePayer = options.payer.publicKey;
  transaction.sign(options.payer);

  // Sign once and resend the same bytes, so a retry after a 429 is the same
  // transaction rather than a differently-signed one.
  const signature = await withRetry("send", () =>
    options.connection.sendRawTransaction(transaction.serialize(), { skipPreflight: false }),
  );
  await withRetry("confirm", () =>
    options.connection.confirmTransaction({ signature, ...latest }, "confirmed"),
  );
  return signature;
}

export interface WriteResult {
  signature: string;
  chunks: number;
  bytes: number;
}

/** The most an account can grow in one instruction when a program allocates it. */
export const MAX_PERMITTED_DATA_INCREASE = 10_240;

export function growValueInstruction(
  programId: PublicKey,
  payer: PublicKey,
  index: bigint,
  newLen: number,
): TransactionInstruction {
  return new TransactionInstruction({
    programId,
    keys: [
      { pubkey: payer, isSigner: true, isWritable: true },
      { pubkey: valuePda(programId, payer, index), isSigner: false, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: Buffer.concat([discriminator("grow_value"), u64le(index), u32le(newLen)]),
  });
}

/**
 * Create a value account and grow it to the size its ciphertext needs.
 *
 * The growth loop is not a workaround invented here. A program can only allocate
 * 10,240 bytes for an account through a cross-program invocation, so a standard
 * tier value account (about 32 KiB) has to arrive in steps. The demo tier fits
 * in the first allocation and the loop does nothing.
 */
export async function createValue(
  options: ChainOptions,
  params: Params,
  index: bigint,
): Promise<{ signature: string; address: PublicKey; allocations: number }> {
  const instruction = createValueInstruction(
    options.programId,
    options.payer.publicKey,
    params.id,
    index,
  );
  const signature = await send(options, [instruction], 60_000);
  const address = valuePda(options.programId, options.payer.publicKey, index);

  const target = valueAccountSize(blobLen(params));
  let allocations = 1;
  let info = await withRetry("account", () => options.connection.getAccountInfo(address));
  let current = info?.data.length ?? 0;
  while (current < target) {
    const next = Math.min(target, current + MAX_PERMITTED_DATA_INCREASE);
    await send(options, [growValueInstruction(options.programId, options.payer.publicKey, index, next)], 60_000);
    allocations += 1;
    current = next;
  }
  info = await withRetry("account", () => options.connection.getAccountInfo(address));
  if ((info?.data.length ?? 0) !== target) {
    throw new Error(`value account is ${info?.data.length} bytes, expected ${target}`);
  }
  return { signature, address, allocations };
}

/**
 * Upload a ciphertext in chunks.
 *
 * This is where the transaction size limit becomes visible: a standard tier
 * ciphertext is 32 KiB and one instruction carries under 1 KiB, so the upload is
 * dozens of transactions. That is not a flaw in the kit, it is the shape of the
 * problem, and `docs/FEASIBILITY.md` records it.
 */
export async function uploadCiphertext(
  options: ChainOptions,
  params: Params,
  index: bigint,
  blob: Uint8Array,
): Promise<WriteResult> {
  if (blob.length !== blobLen(params)) {
    throw new Error(`expected a ${blobLen(params)} byte ciphertext, got ${blob.length}`);
  }
  const address = valuePda(options.programId, options.payer.publicKey, index);
  let chunks = 0;
  for (let offset = 0; offset < blob.length; offset += UPLOAD_CHUNK_BYTES) {
    const chunk = blob.subarray(offset, Math.min(offset + UPLOAD_CHUNK_BYTES, blob.length));
    const instruction = writeChunkInstruction(
      options.programId,
      options.payer.publicKey,
      address,
      offset,
      chunk,
    );
    await send(options, [instruction], 40_000);
    chunks += 1;
  }
  return { signature: address.toBase58(), chunks, bytes: blob.length };
}

/**
 * Read a value account.
 *
 * Takes only a connection, not a payer: reading is not signing, and the
 * verifier has to work for someone who holds no key at all.
 */
export async function fetchValue(
  options: { connection: Connection },
  address: PublicKey,
): Promise<ValueAccount> {
  const info = await withRetry("account", () => options.connection.getAccountInfo(address));
  if (!info) throw new Error(`${address.toBase58()} does not exist`);
  return decodeValueAccount(new Uint8Array(info.data));
}

/** Submit the on-chain addition and return the transaction signature. */
export async function homomorphicAdd(
  options: ChainOptions,
  a: PublicKey,
  b: PublicKey,
  out: PublicKey,
): Promise<string> {
  // The standard tier is 4096 modular additions; measure first, then allow
  // generous headroom. The benchmark in `tests/` records the real figure.
  return send(options, [homomorphicAddInstruction(options.programId, options.payer.publicKey, a, b, out)], 1_400_000);
}

export async function scalarMul(
  options: ChainOptions,
  a: PublicKey,
  out: PublicKey,
  k: bigint,
): Promise<string> {
  return send(
    options,
    [scalarMulInstruction(options.programId, options.payer.publicKey, a, out, k)],
    1_400_000,
  );
}

export async function commitEvaluation(
  options: ChainOptions,
  index: bigint,
  digest: Uint8Array,
  depth: number,
  noiseBits: number,
): Promise<string> {
  return send(
    options,
    [
      commitEvaluationInstruction(
        options.programId,
        options.payer.publicKey,
        index,
        digest,
        depth,
        noiseBits,
      ),
    ],
    60_000,
  );
}

/** Rent the caller must hold for one value account of this parameter set. */
export async function rentLamports(connection: Connection, params: Params): Promise<number> {
  return connection.getMinimumBalanceForRentExemption(valueAccountSize(blobLen(params)));
}

/**
 * Simulate an instruction and report the compute units it consumed.
 *
 * Simulating is how the benchmarks in `docs/BENCHMARKS.md` were produced, and it
 * is how a user checks the claim on their own machine rather than trusting a
 * table. The limit is raised first, so the number reported is the cost, not the
 * refusal at the default 200,000 budget.
 */
export async function measureUnits(
  options: ChainOptions,
  instruction: TransactionInstruction,
): Promise<number> {
  const transaction = new Transaction().add(
    ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
    instruction,
  );
  const latest = await withRetry("blockhash", () => options.connection.getLatestBlockhash());
  transaction.recentBlockhash = latest.blockhash;
  transaction.feePayer = options.payer.publicKey;
  transaction.sign(options.payer);
  const result = await withRetry("simulate", () => options.connection.simulateTransaction(transaction));
  if (result.value.err) {
    throw new Error(`simulation failed: ${JSON.stringify(result.value.err)}`);
  }
  return result.value.unitsConsumed ?? 0;
}

/** Compute units for the on-chain addition at the caller's parameter set. */
export async function measureAddUnits(
  options: ChainOptions,
  a: PublicKey,
  b: PublicKey,
  out: PublicKey,
): Promise<number> {
  return measureUnits(
    options,
    homomorphicAddInstruction(options.programId, options.payer.publicKey, a, b, out),
  );
}

