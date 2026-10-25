/**
 * The off-chain tier: real, full FHE.
 *
 * This is Microsoft SEAL (BFV) through `node-seal`, the same engine that ships
 * in `pionyrfhecli`. It is here for the operation the Solana program cannot
 * host: ciphertext times ciphertext multiplication, with relinearization and
 * an actual, measured noise budget.
 *
 * Why a different engine from the on-chain tier, and why that is honest:
 *
 * SEAL's ciphertext serialization is its own format and its polynomials are
 * stored in NTT form, so a SEAL ciphertext cannot be handed to the program and
 * added coefficient by coefficient without re-implementing SEAL's internals
 * (and it would not fit in the compute budget at SEAL's production parameters
 * anyway). So the two tiers are separate, and the kit says so rather than
 * implying a bridge that does not exist. What crosses the boundary is a digest:
 * `commit_evaluation` records what the off-chain engine produced.
 *
 * What this tier gives you that the on-chain tier does not:
 *
 * * Ciphertext multiplication, so circuits rather than just sums.
 * * A measured noise budget (`invariantNoiseBudget`), not an estimated bound.
 * * Parameters at the 128 bit classical table for real depth.
 */

import SEAL from "node-seal";

export type SealModule = Awaited<ReturnType<typeof SEAL>>;

/** The scheme the off-chain tier speaks. Matches `SCHEME_SEAL_BFV` in the program. */
export const SCHEME_SEAL_BFV = 1;

export interface SealOptions {
  /** Ring degree. Defaults to 4096, which the standard table allows at 109 bits. */
  polyModulusDegree?: number;
  /** Coefficient modulus chain, in bits. Its length bounds the depth. */
  coeffBitSizes?: readonly number[];
  /** Plaintext modulus bits. */
  plainModulusBits?: number;
}

export interface SealEngine {
  readonly scheme: "BFV (Microsoft SEAL)";
  readonly polyModulusDegree: number;
  readonly coeffModulusBits: readonly number[];
  readonly slotCount: number;
  readonly securityLevel: string;
  readonly publicKeyBytes: number;
  encrypt(values: readonly number[]): SealCiphertext;
  decrypt(ciphertext: SealCiphertext): number[];
  multiply(
    a: SealCiphertext,
    b: SealCiphertext,
    options?: { relinearize?: boolean },
  ): SealCiphertext;
  add(a: SealCiphertext, b: SealCiphertext): SealCiphertext;
  noiseBudget(ciphertext: SealCiphertext): number;
  dispose(): void;
}

export interface SealCiphertext {
  /** SEAL's own base64 serialization. Opaque by design. */
  readonly handle: string;
  readonly bytes: number;
  readonly noiseBudget: number;
}

function bytesOf(base64: string): number {
  const padding = base64.endsWith("==") ? 2 : base64.endsWith("=") ? 1 : 0;
  return Math.floor((base64.length * 3) / 4) - padding;
}

export async function createSealEngine(options: SealOptions = {}): Promise<SealEngine> {
  const seal = await SEAL();
  const { SchemeType, SecLevelType, CoeffModulus, PlainModulus, ComprModeType } = seal;

  const polyModulusDegree = options.polyModulusDegree ?? 4096;
  const coeffBitSizes = options.coeffBitSizes ?? [36, 36, 37];
  const plainModulusBits = options.plainModulusBits ?? 20;

  const params = new seal.EncryptionParameters(SchemeType.bfv);
  params.setPolyModulusDegree(polyModulusDegree);
  params.setCoeffModulus(
    CoeffModulus.Create(polyModulusDegree, Int32Array.from(coeffBitSizes)),
  );
  params.setPlainModulus(PlainModulus.Batching(polyModulusDegree, plainModulusBits));

  const context = new seal.SEALContext(params, true, SecLevelType.tc128);
  if (!context.parametersSet()) {
    throw new Error("SEAL rejected these encryption parameters");
  }

  const keyGenerator = new seal.KeyGenerator(context);
  const publicKey = keyGenerator.createPublicKey();
  const secretKey = keyGenerator.secretKey();
  const relinKeys = keyGenerator.createRelinKeys();

  const encryptor = new seal.Encryptor(context, publicKey);
  const decryptor = new seal.Decryptor(context, secretKey);
  const evaluator = new seal.Evaluator(context);
  const batchEncoder = new seal.BatchEncoder(context);
  const slotCount = batchEncoder.slotCount();

  const publicKeyBytes = bytesOf(publicKey.saveToBase64(ComprModeType.zlib));

  function load(handle: string) {
    const ciphertext = new seal.Ciphertext();
    ciphertext.loadFromBase64(context, handle);
    return ciphertext;
  }

  function wrap(ciphertext: InstanceType<SealModule["Ciphertext"]>): SealCiphertext {
    const handle = ciphertext.saveToBase64(ComprModeType.zlib);
    const wrapped: SealCiphertext = {
      handle,
      bytes: bytesOf(handle),
      noiseBudget: decryptor.invariantNoiseBudget(ciphertext),
    };
    ciphertext.delete();
    return wrapped;
  }

  return {
    scheme: "BFV (Microsoft SEAL)",
    polyModulusDegree,
    coeffModulusBits: [...coeffBitSizes],
    slotCount,
    securityLevel: "tc128",
    publicKeyBytes,

    encrypt(values) {
      const padded = new Array<bigint>(slotCount).fill(0n);
      for (let i = 0; i < values.length && i < slotCount; i += 1) {
        padded[i] = BigInt(Math.trunc(values[i] ?? 0));
      }
      const plaintext = new seal.Plaintext();
      batchEncoder.encode(BigInt64Array.from(padded), plaintext);
      const ciphertext = new seal.Ciphertext();
      encryptor.encrypt(plaintext, ciphertext);
      plaintext.delete();
      return wrap(ciphertext);
    },

    decrypt(ciphertext) {
      const loaded = load(ciphertext.handle);
      const plaintext = new seal.Plaintext();
      decryptor.decrypt(loaded, plaintext);
      const values = Array.from(batchEncoder.decodeBigInt64(plaintext) as BigInt64Array).map(Number);
      plaintext.delete();
      loaded.delete();
      return values;
    },

    multiply(a, b, multiplyOptions) {
      const left = load(a.handle);
      const right = load(b.handle);
      const out = new seal.Ciphertext();
      evaluator.multiply(left, right, out);
      if (multiplyOptions?.relinearize ?? true) {
        evaluator.relinearizeInplace(out, relinKeys);
      }
      left.delete();
      right.delete();
      return wrap(out);
    },

    add(a, b) {
      const left = load(a.handle);
      const right = load(b.handle);
      const out = new seal.Ciphertext();
      evaluator.add(left, right, out);
      left.delete();
      right.delete();
      return wrap(out);
    },

    noiseBudget(ciphertext) {
      const loaded = load(ciphertext.handle);
      const budget = decryptor.invariantNoiseBudget(loaded);
      loaded.delete();
      return budget;
    },

    dispose() {
      batchEncoder.delete();
      evaluator.delete();
      decryptor.delete();
      encryptor.delete();
      relinKeys.delete();
      secretKey.delete();
      publicKey.delete();
      keyGenerator.delete();
      context.delete();
      params.delete();
    },
  };
}
