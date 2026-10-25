# Architecture

Two tiers of one scheme, split along the line the compute budget draws.

```text
                    ┌──────────────────────────────────────────────────────┐
                    │ OFF CHAIN, on your machine                            │
                    │                                                       │
                    │  secret key · randomness · decryption                 │
                    │                                                       │
   RLWE tier ──────▶│  encrypt(slots) ──▶ ciphertext (c0, c1)               │
   (this kit)       │  decrypt(ciphertext) ──▶ slots                        │
                    │                                                       │
                    │  SEAL tier ──▶ Microsoft SEAL / BFV (node-seal)       │
                    │                multiply · relinearize · noise budget  │
                    └───────────────┬───────────────────────────────┬───────┘
                                    │ upload (many transactions)    │ digest
                                    ▼                               ▼
                    ┌──────────────────────────────────────────────────────┐
                    │ ON CHAIN, inside a Solana program (SBF)               │
                    │                                                       │
                    │  value accounts hold ciphertexts (c0 || c1, u64 LE)   │
                    │                                                       │
                    │  add        Enc(a) + Enc(b) = Enc(a + b)              │
                    │  sub        Enc(a) - Enc(b) = Enc(a - b)              │
                    │  scalar_mul k * Enc(a)      = Enc(k * a)              │
                    │                                                       │
                    │  noise bound propagated · depth recorded              │
                    │  commit_evaluation ──▶ digest of the off-chain result │
                    │                                                       │
                    │  no decryption · no key material · no multiplication  │
                    └──────────────────────────────────────────────────────┘
```

## Why the line falls where it does

`docs/FEASIBILITY.md` has the measurements. In one paragraph: ciphertext addition
is coefficient-wise modular arithmetic, which fits; ciphertext multiplication
needs a negacyclic convolution, which does not, and bootstrapping is further out
still. So the linear operations run on chain and the multiplicative ones do not.

That split is not a shortcut around FHE. It is the boundary of what SBF can
execute, and every production-adjacent "FHE on Solana" design found during
research lands on the same side of it with a coprocessor off chain.

## The scheme

BFV-style RLWE over `R_q = Z_q[x] / (x^n + 1)`, message packed coefficient by
coefficient, so one ciphertext carries `n` plaintext slots.

```text
keygen      s  <- ternary, coefficients in {-1, 0, 1}
encrypt     a  <- uniform in R_q
            e  <- centered binomial, |e| <= eta
            m  = sum_j  m_j x^j          with m_j in [0, t)
            c0 = delta * m - (a * s + e)      mod q
            c1 = a
            delta = floor(q / t)

decrypt     v  = c0 + c1 * s                mod q
            m_j = round(v_j / delta)  mod t
```

Decryption therefore recovers `delta * m - e`, which is correct while
`|e| < delta / 2`, and since `delta = q / t` that is the same as
`|e| < q / (2t)`. [`Params::max_noise_bound`](../crates/fhe-core/src/params.rs)
is that expression.

Addition is `(c0 + c0', c1 + c1')` and scaling is `(k * c0, k * c1)`. Both are
component-wise in `Z_q`, so neither needs a transform. That is the whole reason
they can run on chain.

## Parameter tiers

| | `demo` | `standard` |
| --- | --- | --- |
| ring degree `n` | 256 | 2048 |
| modulus `q` | 8388593 (`2^23 - 15`) | 18014398509481951 (`2^54 - 33`) |
| plaintext modulus `t` | 256 | 65536 |
| slots per ciphertext | 256 | 2048 |
| ciphertext size | 4 KiB | 32 KiB |
| fresh noise bound | 64 | 64 |
| decryptable bound | 16383 | 137438953471 |
| measured addition cost | 20,322 CU | 142,104 CU |
| security | none, deliberately | parameter sizes match the published table |

The `demo` tier exists so the test suite finishes in a second and the demo fits
in a few transactions. It is **not** secure and says so in `params.rs`.

The `standard` tier uses a ring dimension and modulus inside the
HomomorphicEncryption.org table for 128-bit classical security at that size.
That is a statement about parameter sizes under the table's assumptions. The
implementation is unaudited, the error sampler is a centered binomial rather than
the discrete Gaussian the table assumes, and the scheme is additively homomorphic
only. Read [`SECURITY.md`](./SECURITY.md) before trusting any of it.

### Why the moduli look like that

`q = 2^shift - c` for a small `c`. That is deliberate: it lets modular
multiplication reduce by folding `2^shift` down to `c` and then doing a couple of
conditional subtractions, instead of a 128-bit division, which SBF is poor at.
`fhe_core::ops::mul_mod` is that reduction and it is checked against a
`u128` reference in the tests.

## Account layout

A value account is a raw layout defined by this kit, not an Anchor-serialized
struct, because it holds a variable-size blob and needs a known offset.

```text
offset  size  field
0       4     magic, "FHEV"
4       4     version, u32 little endian, currently 1
8       1     parameter set id
9       1     PDA bump seed
10      2     depth, number of homomorphic operations applied
12      4     ring degree n
16      4     ciphertext blob length in bytes
20      4     bytes of the blob written so far
24      8     noise bound
32      8     slot the account was created in
40      32    owner
72      32    first parent (zero for a directly encrypted value)
104     32    second parent (zero for a two-operand operation)
136     ...   the ciphertext blob
```

The header is a fixed 136 bytes so the client can compute where the ciphertext
begins without knowing how the program was compiled. Three places assert that
number: `crates/fhe-core/src/account.rs`, the program's own unit test, and
`cli/src/sdk/account.ts`. A field cannot move silently.

## The instruction set

| Instruction | What it does |
| --- | --- |
| `create_value(param_id, index)` | allocates the PDA and writes the header (up to 10,240 bytes) |
| `grow_value(index, new_len)` | one more allocation step, until the account fits its ciphertext |
| `write_chunk(offset, data)` | writes a slice of the ciphertext, because one ciphertext is many transactions |
| `homomorphic_add` | `out = a + b`, coefficient-wise, on chain |
| `scalar_mul(k)` | `out = k * a`, coefficient-wise, on chain |
| `commit_evaluation(index, digest, depth, noise_bits)` | records a digest of an off-chain result |

## Noise: bound on chain, measured off chain

This is the part most worth being precise about.

* **Off chain**, the SDK holds the secret key, so it computes the real residual
  `v - delta * m` and reports the actual noise magnitude. `measureNoise` in
  `cli/src/sdk/rlwe.ts`.
* **On chain**, the program has no secret key and cannot measure anything. It
  propagates a conservative bound: addition adds the two bounds, scaling
  multiplies the bound by the public scalar, and an operation that would push the
  bound past `q / (2t)` is refused.

The gap is visible in the demo output. At the demo tier the program refuses at a
bound of 16,383 while the measured noise after one addition is 7. The bound is
pessimistic on purpose: it is a guarantee, and a guarantee has to hold in the
worst case.

## What crosses between the tiers, and what cannot

A digest. `commit_evaluation` records a SHA-256 of whatever the off-chain engine
produced, plus the scheme tag, the depth, and the remaining noise bits. The
program does not verify that computation and does not claim to; it records what
was asserted so anyone can check it against the off-chain engine themselves.

What cannot cross is a ciphertext. SEAL stores its polynomials in NTT form inside
its own serialization format, and the two tiers use different parameter sets, so
neither side can be handed the other's bytes. The kit says so rather than
implying a bridge that does not exist.

## Layout of the repository

```text
crates/fhe-core/       the arithmetic the program runs, plus the account layout
programs/fhe-vault/    the Anchor program
cli/src/sdk/           the client: RLWE client crypto, the SEAL tier, the chain client
cli/src/cli.ts         the command line
cli/tests/             scheme, plaintext, conformance and SEAL tests
docs/                  this document and the rest
scripts/demo.sh        validator, deploy, and an end-to-end run
```
