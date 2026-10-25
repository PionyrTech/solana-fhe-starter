/**
 * The command line.
 *
 * Two halves, kept visibly separate in the help text:
 *
 * * **Local**: keygen, encrypt, decrypt, and the same operations the program
 *   runs, all on this machine. Nothing touches a chain.
 * * **On chain**: create a ciphertext account, upload the ciphertext in chunks,
 *   run the addition inside the program, read the result back, decrypt it.
 *
 * And one command for the off-chain tier, `seal`, which runs the operation the
 * program cannot: ciphertext multiplication with Microsoft SEAL.
 *
 *   npx tsx src/cli.ts params
 */

import { readFileSync, writeFileSync } from "node:fs";
import { Connection, Keypair, PublicKey } from "@solana/web3.js";
import {
  createValue,
  fetchValue,
  homomorphicAdd,
  measureAddUnits,
  rentLamports,
  uploadCiphertext,
  valuePda,
  type ChainOptions,
} from "./sdk/chain.js";
import { deserialize, fromHex, serialize, toHex } from "./sdk/codec.js";
import { HEADER_LEN, PARAM_SETS, blobLen, paramsByName, type Params } from "./sdk/params.js";
import { systemRandom } from "./sdk/random.js";
import {
  addCiphertexts,
  decrypt,
  encrypt,
  keygen,
  measureNoise,
  scalarMulCiphertext,
  type Ciphertext,
  type SecretKey,
} from "./sdk/rlwe.js";
import { createSealEngine } from "./sdk/seal.js";
import { humanBytes, sha256 } from "./sdk/util.js";
import { verifyAddition, verifyScalarMul, type EncryptedAccount } from "./sdk/verify.js";

const DEFAULT_PROGRAM_ID = "EJimqNCEMedCWkzUFPMFVWudYpHSvHAWFHyqeegyfqYt";
const VERSION = 1;

interface CiphertextFile {
  kind: "solana-fhe/ciphertext";
  version: number;
  param: string;
  slots: string[];
  ciphertext: string;
}

interface KeyFile {
  kind: "solana-fhe/secret-key";
  version: number;
  param: string;
  secret: string;
}

function arg(args: string[], name: string, fallback?: string): string {
  const index = args.indexOf(`--${name}`);
  if (index === -1) {
    if (fallback === undefined) throw new Error(`missing --${name}`);
    return fallback;
  }
  const value = args[index + 1];
  if (value === undefined) throw new Error(`--${name} needs a value`);
  return value;
}

function positional(args: string[], position: number): string | undefined {
  return args.filter((a) => !a.startsWith("--")).slice(1)[position];
}

function paramsFrom(args: string[]): Params {
  return paramsByName(arg(args, "params", "demo"));
}

function encodeSecret(secret: SecretKey): string {
  const buffer = Buffer.alloc(secret.s.length * 8);
  secret.s.forEach((value, i) => buffer.writeBigUInt64LE(value, i * 8));
  return buffer.toString("hex");
}

function decodeSecret(params: Params, hex: string): SecretKey {
  const buffer = Buffer.from(hex, "hex");
  if (buffer.length !== params.n * 8) {
    throw new Error(`secret key is ${buffer.length} bytes, expected ${params.n * 8}`);
  }
  const s = new Array<bigint>(params.n);
  for (let i = 0; i < params.n; i += 1) s[i] = buffer.readBigUInt64LE(i * 8) % params.q;
  return { params, s };
}

function writeJson(path: string, value: unknown): void {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

function ciphertextFile(params: Params, ciphertext: Ciphertext, slots: bigint[]): CiphertextFile {
  return {
    kind: "solana-fhe/ciphertext",
    version: VERSION,
    param: params.name,
    slots: slots.map(String),
    ciphertext: toHex(serialize(ciphertext.c0, ciphertext.c1)),
  };
}

function readCiphertextFile(path: string): { params: Params; ciphertext: Ciphertext } {
  const file = JSON.parse(readFileSync(path, "utf8")) as CiphertextFile;
  if (file.kind !== "solana-fhe/ciphertext") throw new Error(`${path} is not a ciphertext file`);
  const params = paramsByName(file.param);
  const { c0, c1 } = deserialize(params, fromHex(file.ciphertext));
  return { params, ciphertext: { params, c0, c1 } };
}

function chainOptions(args: string[]): ChainOptions {
  const rpc = arg(args, "rpc", "http://127.0.0.1:8899");
  const walletPath = arg(args, "wallet", `${process.env.HOME}/.config/solana/id.json`);
  const raw = JSON.parse(readFileSync(walletPath, "utf8")) as number[];
  return {
    connection: new Connection(rpc, "confirmed"),
    programId: new PublicKey(arg(args, "program", DEFAULT_PROGRAM_ID)),
    payer: Keypair.fromSecretKey(Uint8Array.from(raw)),
  };
}

function parseSlots(raw: string, params: Params): bigint[] {
  return raw
    .split(",")
    .map((piece) => piece.trim())
    .filter((piece) => piece.length > 0)
    .map((piece) => {
      const value = BigInt(piece);
      if (value < 0n || value >= params.t) {
        throw new Error(`slot value ${value} is outside [0, ${params.t}) for ${params.name}`);
      }
      return value;
    });
}

const HELP = `solana-fhe-starter

  Local
    params                                    list the parameter sets
    keygen <keys.json> [--params demo]        generate a secret key
    encrypt <keys.json> --slots 7,3 -o c.json
    decrypt <keys.json> <c.json>              recover the slots
    add <a.json> <b.json> -o sum.json         homomorphic addition, off chain
    scale <a.json> <k> -o out.json            homomorphic scaling, off chain

  Off-chain FHE (the operation the program cannot run)
    seal                                      multiply two ciphertexts with Microsoft SEAL

  On chain (needs a validator and a deployed program)
    onchain <keys.json> --slots 7,3,10,4      create, upload, add, fetch, decrypt
    bench --params demo                       measure the compute units of one addition
    verify --a <pk> --b <pk> --out <pk>       recompute the sum from public bytes, no key needed
    verify --a <pk> --k 5 --out <pk>          the same for a scaling
`;

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const command = args[0];

  switch (command) {
    case "params": {
      for (const params of PARAM_SETS) {
        console.log(`${params.name} (id ${params.id})`);
        console.log(`  ring degree      n = ${params.n}`);
        console.log(`  modulus          q = ${params.q}`);
        console.log(`  plaintext        t = ${params.t}`);
        console.log(`  ciphertext       ${humanBytes(blobLen(params))} (${blobLen(params)} bytes)`);
        console.log(`  account          ${humanBytes(HEADER_LEN + blobLen(params))} plus rent`);
        console.log(`  slots             ${params.n}`);
        console.log(`  security         ${params.security}`);
        console.log("");
      }
      return;
    }

    case "keygen": {
      const path = positional(args, 0) ?? "keys.json";
      const params = paramsFrom(args);
      const secret = keygen(params, systemRandom);
      writeJson(path, {
        kind: "solana-fhe/secret-key",
        version: VERSION,
        param: params.name,
        secret: encodeSecret(secret),
      } satisfies KeyFile);
      console.log(`wrote a ${params.name} secret key to ${path}`);
      console.log("This file is the secret. Do not commit it, and keep it off any chain.");
      return;
    }

    case "encrypt": {
      const keyPath = positional(args, 0) ?? "keys.json";
      const outPath = arg(args, "out", "ciphertext.json");
      const file = JSON.parse(readFileSync(keyPath, "utf8")) as KeyFile;
      const params = paramsByName(file.param);
      const secret = decodeSecret(params, file.secret);
      const slots = parseSlots(arg(args, "slots"), params);
      const ciphertext = encrypt(secret, slots, systemRandom);
      writeJson(outPath, ciphertextFile(params, ciphertext, slots));
      console.log(`encrypted ${slots.length} slot(s) into ${outPath}`);
      console.log(`ciphertext: ${blobLen(params)} bytes, decrypted only on this machine`);
      return;
    }

    case "decrypt": {
      const keyPath = positional(args, 0) ?? "keys.json";
      const cipherPath = positional(args, 1);
      if (!cipherPath) throw new Error("decrypt needs a ciphertext file");
      const file = JSON.parse(readFileSync(keyPath, "utf8")) as KeyFile;
      const params = paramsByName(file.param);
      const secret = decodeSecret(params, file.secret);
      const { ciphertext } = readCiphertextFile(cipherPath);
      const slotCount = JSON.parse(readFileSync(cipherPath, "utf8")).slots.length;
      const values = decrypt(secret, ciphertext).slice(0, slotCount);
      const noise = measureNoise(secret, ciphertext);
      console.log(`slots:  ${values.map(String).join(", ")}`);
      console.log(`noise:  ${noise} (measured, because this machine holds the secret key)`);
      return;
    }

    case "add":
    case "scale": {
      const aPath = positional(args, 0);
      const bArg = positional(args, 1);
      if (!aPath || !bArg) throw new Error(`${command} needs two operands`);
      const outPath = arg(args, "out", "out.json");
      const a = readCiphertextFile(aPath);
      // The slot list in the output file is informational; the ciphertext is
      // the truth. Reuse the input's so the file stays readable.
      const declared = (JSON.parse(readFileSync(aPath, "utf8")) as CiphertextFile).slots.map(
        (value) => BigInt(value),
      );
      const result =
        command === "add"
          ? addCiphertexts(a.ciphertext, readCiphertextFile(bArg).ciphertext)
          : scalarMulCiphertext(a.ciphertext, BigInt(bArg));
      writeJson(outPath, ciphertextFile(a.params, result, declared));
      console.log(`${command} written to ${outPath}`);
      return;
    }

    case "seal": {
      console.log("off-chain tier: BFV through Microsoft SEAL");
      const engine = await createSealEngine();
      console.log(
        `parameters: n=${engine.polyModulusDegree} coeff=[${engine.coeffModulusBits.join(", ")}] ` +
          `slots=${engine.slotCount} level=${engine.securityLevel}`,
      );
      const a = engine.encrypt([6, 7, 0, 0]);
      const b = engine.encrypt([6, 7, 0, 0]);
      console.log(`fresh noise budget: ${a.noiseBudget} bits`);
      const product = engine.multiply(a, b);
      const values = engine.decrypt(product).slice(0, 2);
      console.log(`6 * 6, 7 * 7 after relinearization: ${values.join(", ")}`);
      console.log(`noise budget after one multiplication: ${product.noiseBudget} bits`);
      console.log(
        "This is the operation the Solana program cannot run. Its digest is what " +
          "commit_evaluation records on chain.",
      );
      engine.dispose();
      return;
    }

    case "bench": {
      const options = chainOptions(args);
      const params = paramsFrom(args);
      const program = await options.connection.getAccountInfo(options.programId);
      if (!program) throw new Error(`no program deployed at ${options.programId.toBase58()}`);
      console.log(`program ${options.programId.toBase58()} is deployed`);
      console.log(`parameter set ${params.name}: one ciphertext is ${humanBytes(blobLen(params))}`);
      console.log(`rent for one value account: ${await rentLamports(options.connection, params)} lamports`);
      const secret = keygen(params, systemRandom);
      const a = encrypt(secret, [1n], systemRandom);
      const b = encrypt(secret, [2n], systemRandom);
      const base = options.payer.publicKey;
      await createValue(options, params, 900n);
      await createValue(options, params, 901n);
      await createValue(options, params, 902n);
      await uploadCiphertext(options, params, 900n, serialize(a.c0, a.c1));
      await uploadCiphertext(options, params, 901n, serialize(b.c0, b.c1));
      const aKey = valuePda(options.programId, base, 900n);
      const bKey = valuePda(options.programId, base, 901n);
      const outKey = valuePda(options.programId, base, 902n);
      const units = await measureAddUnits(options, aKey, bKey, outKey);
      console.log(`compute units for one on-chain addition: ${units}`);
      return;
    }

    case "onchain": {
      const keyPath = positional(args, 0) ?? "keys.json";
      const options = chainOptions(args);
      const file = JSON.parse(readFileSync(keyPath, "utf8")) as KeyFile;
      const params = paramsByName(file.param);
      const secret = decodeSecret(params, file.secret);
      const slots = parseSlots(arg(args, "slots"), params);
      if (slots.length % 2 !== 0) {
        throw new Error("--slots needs an even count: the first half and the second half are added");
      }
      const half = slots.length / 2;
      const owner = options.payer.publicKey;

      const program = await options.connection.getAccountInfo(options.programId);
      if (!program) throw new Error(`no program deployed at ${options.programId.toBase58()}`);

      console.log(`parameter set ${params.name}, ciphertext ${humanBytes(blobLen(params))}`);

      const indices = [
        BigInt(Date.now() % 1_000_000) * 10n + 0n,
        BigInt(Date.now() % 1_000_000) * 10n + 1n,
        BigInt(Date.now() % 1_000_000) * 10n + 2n,
      ];
      const left = encrypt(secret, slots.slice(0, half), systemRandom);
      const right = encrypt(secret, slots.slice(half), systemRandom);

      for (const index of indices) {
        await createValue(options, params, index);
      }
      console.log("created three value accounts");

      const uploads = await Promise.all([
        uploadCiphertext(options, params, indices[0]!, serialize(left.c0, left.c1)),
        uploadCiphertext(options, params, indices[1]!, serialize(right.c0, right.c1)),
      ]);
      console.log(`uploaded in ${uploads[0]!.chunks + uploads[1]!.chunks} transactions`);

      const aKey = valuePda(options.programId, owner, indices[0]!);
      const bKey = valuePda(options.programId, owner, indices[1]!);
      const outKey = valuePda(options.programId, owner, indices[2]!);

      const units = await measureAddUnits(options, aKey, bKey, outKey);
      const signature = await homomorphicAdd(options, aKey, bKey, outKey);
      console.log(`homomorphic_add confirmed: ${signature}`);
      console.log(`compute units consumed: ${units}`);
      console.log("accounts:");
      console.log(`  a   ${aKey.toBase58()}`);
      console.log(`  b   ${bKey.toBase58()}`);
      console.log(`  out ${outKey.toBase58()}`);

      const account = await fetchValue(options, outKey);
      console.log(
        `result account: depth ${account.depth}, noise bound ${account.noiseBound}, ` +
          `complete ${account.complete}`,
      );

      const resultCiphertext: Ciphertext = {
        params,
        ...deserialize(params, account.blob),
      };
      const expected = slots.slice(0, half).map((value, i) => (value + slots[half + i]!) % params.t);
      const recovered = decrypt(secret, resultCiphertext).slice(0, half);
      const measured = measureNoise(secret, resultCiphertext);

      console.log(`decrypted slots:   ${recovered.map(String).join(", ")}`);
      console.log(`expected slots:    ${expected.map(String).join(", ")}`);
      console.log(`measured noise:    ${measured} (the program's bound was ${account.noiseBound})`);
      console.log(
        recovered.every((value, i) => value === expected[i])
          ? "match: the addition happened on chain, on ciphertext, and decrypts correctly"
          : "MISMATCH: the on-chain result does not decrypt to the sum",
      );

      const digest = await sha256(new Uint8Array(account.blob));
      console.log(`result digest (sha256 of the ciphertext): ${Buffer.from(digest).toString("hex")}`);
      return;
    }

    case "verify": {
      // Recomputes the claimed operation from the public ciphertext bytes and
      // compares. No key, and no trust in the program.
      const options = chainOptions(args);
      const load = async (address: string): Promise<EncryptedAccount> => {
        const key = new PublicKey(address);
        return { address, key: key.toBuffer(), account: await fetchValue(options, key) };
      };

      const a = await load(arg(args, "a"));
      const out = await load(arg(args, "out"));
      const b = arg(args, "b", "");
      const k = arg(args, "k", "");

      let result;
      if (b) {
        result = verifyAddition(a, await load(b), out);
      } else if (k) {
        result = verifyScalarMul(a, out, BigInt(k));
      } else {
        throw new Error("verify needs --b (checking an addition) or --k (checking a scaling)");
      }

      for (const line of result.lines) console.log(line);
      if (!result.ok) process.exitCode = 1;
      return;
    }

    default:
      console.log(HELP);
      if (command) process.exitCode = 1;
  }
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
