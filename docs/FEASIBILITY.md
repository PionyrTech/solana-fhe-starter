# Feasibility: can FHE run inside a Solana program?

**Question.** Can a fully homomorphic encryption (FHE) workload execute inside a Solana on-chain
program (SBF), and if not, what is the closest honest thing that can?

**Answer.** No, not at general-purpose parameters. The linear part of a BFV/RLWE ciphertext
(addition, subtraction, multiplication by a plaintext constant) does fit inside the compute budget
at reduced parameters, so this kit runs those operations on-chain. Everything that makes FHE
*fully* homomorphic (ciphertext times ciphertext multiplication, relinearization, bootstrapping)
does not fit, and runs off-chain with a real FHE library. This document records the measurements and
reasoning behind that split.

## 1. The SBF envelope

Solana programs run in SBF, a deterministic, single-threaded, resource-capped bytecode. The numbers
that matter for FHE, from the official documentation:

| Limit | Value | Source |
| --- | --- | --- |
| Default compute units per instruction | 200,000 CU | [Compute Budget](https://solana.com/docs/core/fees/compute-budget) |
| Maximum compute units per transaction | 1,400,000 CU | [Compute Budget](https://solana.com/docs/core/fees/compute-budget) |
| Heap frame | 32 KiB minimum, 256 KiB maximum | [Compute Budget](https://solana.com/docs/core/fees/compute-budget) |
| SBF stack frame | 4,096 bytes | [Compute Budget](https://solana.com/docs/core/fees/compute-budget) |
| SBF call depth | 64 frames | [Limitations](https://solana.com/docs/programs/limitations) |
| Maximum account data | 10 MiB | [Accounts](https://solana.com/docs/core/accounts) |
| Legacy transaction size | 1,232 bytes | [Constants](https://solana.com/docs/core/constants-reference) |
| Floating point | software-emulated, no native support | [Limitations](https://solana.com/docs/programs/limitations) |
| Randomness, threads, filesystem, network | unavailable | [Limitations](https://solana.com/docs/programs/limitations) |

Four of these are individually fatal to naively porting FHE, and the rest compound.

## 2. Why general-purpose FHE does not fit

### 2.1 A ciphertext is far larger than one transaction

A BFV ciphertext is two polynomials in `R_q`. For the common production parameter set
(`N = 4096`, `q` of about 109 bits, carried as three 36-bit limbs), one ciphertext is:

```text
2 polynomials x 4096 coefficients x 3 limbs x 8 bytes = 196,608 bytes  (~192 KiB)
```

Uploading that under the legacy transaction size (1,232 bytes) takes about **160 transactions**.
Even with the larger v1 transaction size (4,096 bytes) it is about 48. Account storage (10 MiB) is
not the binding constraint; getting the bytes in is.

### 2.2 A ciphertext multiplication does not fit in the compute budget

Ciphertext addition is cheap because it is coefficient-wise in `Z_q` and needs no transform: at
`N = 4096` it is `2 x 4096 = 8,192` modular additions, roughly **tens of thousands of compute
units**, which fits.

Multiplication is not. It requires a negacyclic convolution. Naively that is `N^2 = 16.7M` modular
multiplications at `N = 4096`, orders of magnitude past the 1.4M CU transaction cap. With an NTT it
is still four transforms (three forward, one inverse) of size 4096, about **98,304 butterflies**,
each a 64-bit modular multiply and reduction. SBF has no native 64-bit modular multiply, so each
butterfly costs tens of compute units: **millions of CU for a single multiplication**, before
relinearization. Relinearization adds further transforms plus a key-switch decomposition. A single
homomorphic multiplication therefore cannot be expressed as one Solana instruction, and a circuit of
any depth is out of reach.

### 2.3 The heap cannot hold a working set

The heap is capped at 256 KiB. One `N = 4096` ciphertext is about 192 KiB, so holding two operands
and an output (about 576 KiB) already exceeds the cap. Any on-chain evaluation would have to stream
over account data rather than allocate.

### 2.4 Bootstrapping is out of the question

TFHE-style schemes rely on bootstrapping to keep noise bounded, which is on the order of a
millisecond of native CPU time per gate. Expressed in compute units that is millions per gate. Even
if the bytecode existed, the economics would not.

## 3. No production FHE library targets SBF

The kit was asked to prefer existing, actively maintained libraries. The honest finding is that none
of the mainstream ones can be compiled for SBF today:

| Library | Language | Why it does not target SBF |
| --- | --- | --- |
| [TFHE-rs](https://github.com/zama-ai/tfhe-rs) | Rust | Uses `std`, multithreading, and SIMD intrinsics; no `no_std` SBF target; large binary |
| [Microsoft SEAL](https://github.com/microsoft/SEAL) via [node-seal](https://github.com/s0l0ist/node-seal) | C++ / Wasm | No SBF backend; ships as native and WebAssembly only |
| [fhe.rs](https://github.com/tux0r/fhe.rs) | Rust | Pure Rust but not built for `no_std`/SBF; heavy dependency surface |

Solana programs are also denied `rand`, so even key generation has to be handled off-chain.

## 4. What the ecosystem actually does

Every production-adjacent "FHE on Solana" design found during this research puts the FHE evaluation
off-chain and keeps only coordination and settlement on-chain:

- **AURA (AFHE)** states plainly that "a Solana program built with the AURA SDK does not perform FHE
  computation directly. It submits an encrypted compute request to the AURA coprocessor network,
  receives a verifiable ciphertext result, and proceeds with on-chain settlement."
- **FHESTATE** anchors a SHA-256 commitment of the ciphertext on-chain while a separate off-chain
  `fhe-node` performs the homomorphic operations.
- **Encrypt** advertises FHE "directly into the Solana Virtual Machine", but its own developer guide
  carries a pre-alpha disclaimer: "There is no real encryption. All data is completely public and
  stored as plaintext on-chain."
- **Arcium** is frequently filed under Solana privacy, but it is MPC, not FHE.

The two-tier split in this kit is not a compromise invented here; it is where the ecosystem actually
is, stated without the marketing.

## 5. The closest honest thing

The linear layer of BFV/RLWE is genuinely homomorphic and genuinely cheap:

```text
Enc(a) + Enc(b)   = Enc(a + b)        coefficient-wise addition in Z_q
k * Enc(a)        = Enc(k * a)        plaintext-scalar multiplication, k public
```

Neither needs an NTT, randomness, or a secret key, so both fit inside the compute budget. That is
what this kit runs on-chain, in the [`fhe-core`](../crates/fhe-core) crate and the
[`fhe-vault`](../programs/fhe-vault) program. Ciphertext times ciphertext multiplication, the
operation that makes FHE "full", is not attempted on-chain; it runs off-chain in Microsoft SEAL.

The split is stated everywhere it could be misread: the on-chain tier is a **reduced parameter
tier** with a documented, unaudited cryptosystem, and it is for demonstrating that homomorphic
arithmetic executes inside SBF, not for protecting real secrets.

## 6. Consequences for the design

1. **Two tiers, one scheme family.** Both tiers are BFV-style RLWE over `Z_q`. They differ in
   parameters, and a ciphertext cannot be moved between them without re-encryption.
2. **On-chain operations are the linear ones only.** Add, subtract, multiply-by-constant. Each is
   O(N) modular arithmetic, no transforms.
3. **Ciphertexts live in accounts and are written in chunks**, because one ciphertext is far larger
   than one transaction.
4. **Noise is estimated, not measured, on-chain.** Measuring a real noise budget requires the secret
   key, which the chain never has. The program propagates a conservative integer noise bound
   instead, and says so.
5. **The off-chain tier uses SEAL** for multiplication, relinearization, and decryption, and commits
   a digest of the result on-chain so the two halves meet.

See [`ARCHITECTURE.md`](./ARCHITECTURE.md) for how these pieces fit, and
[`LIMITATIONS.md`](./LIMITATIONS.md) for what is not provided.
