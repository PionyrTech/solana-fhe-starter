# Solana FHE Starter

**Homomorphic encryption that actually runs inside a Solana program.**

[Getting started](#getting-started) · [About](#about) · [Project structure](#project-structure) · [Resources](#resources) · [Support](#support)

![status: working](https://img.shields.io/badge/status-working-3ddc97)
![license](https://img.shields.io/badge/license-MIT-green)
![runs on: SBF](https://img.shields.io/badge/runs%20on-SBF-9945FF)
![chain: Solana](https://img.shields.io/badge/chain-Solana-14F195)

## Getting started

### Prerequisites

`setup.sh` installs what is missing. The goals are `git`, and a machine with about
2 GB of free RAM for the SBF build.

| Tool | Why |
| --- | --- |
| Node 20 or newer | the client, the tests, and the demo |
| Rust (stable) | the program and `fhe-core` |
| Solana CLI 2.0 or newer | `cargo-build-sbf`, and `solana-test-validator` for the demo |

### Quickstart

```bash
git clone https://github.com/pionyrtech/solana-fhe-starter
cd solana-fhe-starter
./setup.sh
```

`setup.sh` installs the toolchains that are missing, builds the program for SBF,
and runs both test suites. It prints every command before it runs it.

### Devnet deployment

The program is live on devnet at `EJimqNCEMedCWkzUFPMFVWudYpHSvHAWFHyqeegyfqYt`.

It was deployed with `--final`, so it is **immutable**: there is no upgrade
authority and the code at that address cannot be changed, by us or anyone. If you
want to modify it, deploy your own copy.

```bash
solana program show EJimqNCEMedCWkzUFPMFVWudYpHSvHAWFHyqeegyfqYt --url devnet
```

Point the CLI at it:

```bash
cd cli
npx tsx src/cli.ts onchain keys.json --params demo --slots 7,3,200,54 \
  --rpc https://api.devnet.solana.com
```

The public devnet RPC rate limits aggressively, so a run may retry a few times.
That is the endpoint, not the program.

### The demo

```bash
scripts/demo.sh
```

That starts a throwaway validator, deploys the program, and runs the whole flow
twice, once at each parameter tier. You should see something like:

```text
End-to-end run, demo tier
parameter set demo, ciphertext 4.0 KiB
created three value accounts
uploaded in 10 transactions
homomorphic_add confirmed: 5zF3Q93...
compute units consumed: 20322
result account: depth 1, noise bound 128, complete true
decrypted slots:   207, 57
expected slots:    207, 57
measured noise:    7 (the program's bound was 128)
match: the addition happened on chain, on ciphertext, and decrypts correctly
```

The addition happened inside the program. The decryption happened on your machine.
The three numbers to look at are the compute units, the transactions the upload
took, and the gap between the measured noise and the bound.

### Commands

Local, nothing touches a chain:

```bash
cd cli
npx tsx src/cli.ts params                                # the parameter sets
npx tsx src/cli.ts keygen keys.json --params demo        # generate a key
npx tsx src/cli.ts encrypt keys.json --slots 7,3 -o a.json
npx tsx src/cli.ts decrypt keys.json a.json
npx tsx src/cli.ts add a.json b.json -o sum.json
npx tsx src/cli.ts seal                                  # the off-chain FHE tier
```

On chain, against a running validator with the program deployed:

```bash
npx tsx src/cli.ts onchain keys.json --slots 7,3,200,54  # create, upload, add, fetch, decrypt
npx tsx src/cli.ts bench --params standard               # compute units for one addition
```

Tests:

```bash
cargo test                          # arithmetic, layout, conformance, 24 tests
npm run --prefix cli test           # scheme, wire format, conformance, SEAL
npm run --prefix cli typecheck
```

### Verifying the claims yourself

Nothing here asks to be taken on faith:

- **That addition is homomorphic on chain.** `scripts/demo.sh` decrypts the
  on-chain result and compares it to the sum. It prints `MISMATCH` if it disagrees.
- **That the two implementations agree.** `npm run --prefix cli vectors` regenerates
  the vector file; `cargo test` then re-derives every operation from it in Rust.
- **That the noise bound is conservative.** The demo prints the measured noise next
  to the bound the program used.
- **That multiplication does not fit.** `docs/FEASIBILITY.md` §2.2 gives the
  arithmetic, and `docs/BENCHMARKS.md` shows how each figure was obtained.

### Citations

```bibtex
@Misc{SolanaFHEStarter,
  title        = {{Solana FHE Starter: homomorphic encryption inside a Solana program}},
  author       = {{Pionyr}},
  year         = {2026},
  note         = {\url{https://github.com/pionyrtech/solana-fhe-starter}}
}
```

### Contributing

See [`CONTRIBUTING.md`](./CONTRIBUTING.md). The short version: run
`cargo test` and `npm run --prefix cli test` before opening a pull request, and
keep the honesty sections honest.

### License

MIT. See [`LICENSE`](./LICENSE).

## About

**Solana FHE Starter** is a working kit for running homomorphic encryption on
Solana. You encrypt values on your machine, upload the ciphertext, and the Solana
program adds the ciphertexts **without ever decrypting them**. You fetch the
result and decrypt it locally. The program never sees a plaintext and never holds
a key.

It is also, deliberately, a record of what does *not* work. Fully homomorphic
encryption means addition *and* multiplication. Addition fits inside a Solana
program's compute budget. Multiplication does not, and no amount of engineering
will make it fit today. So this kit runs the part that fits on chain, runs the
rest off chain with Microsoft SEAL, and is precise about which is which.

```text
Enc(7) + Enc(200) = Enc(207)      inside the Solana program, 20,322 compute units
Enc(7) x Enc(7)   = Enc(49)       off chain, in Microsoft SEAL, because it cannot fit
```

### What this is not

- **Not fully homomorphic on chain.** The on-chain tier is additively homomorphic.
  [`docs/FEASIBILITY.md`](./docs/FEASIBILITY.md) has the measurements that explain
  why, and [`docs/FINDINGS.md`](./docs/FINDINGS.md) has what building it turned up.
- **Not audited.** Read [`docs/SECURITY.md`](./docs/SECURITY.md) before trusting
  anything, and note that the fast `demo` parameter set provides no security at all.

### Table of contents

- [Getting started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Quickstart](#quickstart)
  - [Devnet deployment](#devnet-deployment)
  - [The demo](#the-demo)
  - [Commands](#commands)
  - [Verifying the claims yourself](#verifying-the-claims-yourself)
  - [Citations](#citations)
  - [Contributing](#contributing)
  - [License](#license)
- [About](#about)
  - [What this is not](#what-this-is-not)
- [What runs on chain](#what-runs-on-chain)
- [Project structure](#project-structure)
- [Main features](#main-features)
- [Use cases](#use-cases)
- [Resources](#resources)
- [Support](#support)

## What runs on chain

Measured on a 2 vCPU machine with `solana-cli` 4.3.2. Reproduce with
`scripts/demo.sh` and `npx tsx src/cli.ts bench`.

| Operation | Where | Ring degree | Ciphertext | Compute units |
| --- | --- | --- | --- | --- |
| `Enc(a) + Enc(b)` | **on chain** | 256 | 4 KiB | 20,322 |
| `Enc(a) + Enc(b)` | **on chain** | 2048 | 32 KiB | 142,104 |
| `k * Enc(a)` | **on chain** | 2048 | 32 KiB | on the order of an addition |
| `Enc(a) x Enc(b)` | off chain, SEAL | 4096 | 192 KiB | millions, over the 1.4M transaction cap |
| decrypt | off chain only | | | the program cannot, it has no key |

The default per-instruction budget is 200,000 compute units and the per-transaction
cap is 1,400,000. One multiplication of a degree-2048 ciphertext needs roughly
4.2 million modular multiplications, or about 49,000 modular-multiply butterflies
if done with an NTT. It does not fit, and neither does anything that depends on it.

Two more walls worth knowing before you start:

- A ciphertext is far larger than a transaction. Uploading one standard tier
  ciphertext takes **37 transactions**.
- A program can only allocate **10,240 bytes** for an account per instruction, so
  larger accounts are grown in steps.

## Project structure

```text
crates/fhe-core/        the arithmetic the program runs: parameters, ciphertext
                        format, add, sub, scalar multiply, noise bound, account
                        layout. No dependencies, compiles for SBF. 24 tests.

programs/fhe-vault/     the Anchor program: create a value account, upload a
                        ciphertext in chunks, add, scale, record off-chain results.

cli/                    the client.
  src/sdk/rlwe.ts         encryption, decryption, and the scheme the chain speaks
  src/sdk/seal.ts         the off-chain tier, BFV through Microsoft SEAL
  src/sdk/chain.ts        instruction encoding and the on-chain calls
  src/sdk/account.ts      reading the 136 byte value account header
  src/cli.ts              the command line
  scripts/emit-vectors.ts produces the cross-language conformance vectors

docs/
  FEASIBILITY.md        can FHE run on chain? The measurements, and the verdict.
  ARCHITECTURE.md       how the two tiers fit, the scheme, the account layout.
  FINDINGS.md           eight things building it turned up.
  BENCHMARKS.md         compute units, upload counts, timings, how to reproduce.
  SECURITY.md           what is claimed, and what is not.

scripts/demo.sh         validator, deploy, end-to-end run, compute units.
setup.sh                install what is missing, build, test.
```

## Main features

- **Real homomorphic arithmetic inside SBF.** Addition, subtraction, and public
  scaling on real RLWE ciphertexts, executed by the program. Not a hash, not a
  commitment, not a pointer to someone else's server.
- **Proven, not asserted.** The end-to-end test performs the addition on chain and
  then decrypts the result and checks it equals the sum of the inputs.
- **Cross-language conformance.** The TypeScript client produces the vectors, the
  Rust core reproduces every operation output byte for byte in `cargo test`.
- **Honest noise accounting.** The program propagates a bound because it has no
  secret key; the client measures the real noise because it does. The demo prints
  both, so you can see the gap.
- **Real full FHE off chain.** Ciphertext multiplication with relinearization and
  a measured noise budget, in Microsoft SEAL, with a digest recorded on chain.
- **Runs locally.** One script starts a validator, deploys, and performs the whole
  flow. No account, no devnet, nothing leaves the machine.

## Use cases

Additively homomorphic computation on chain is narrower than FHE, and still useful
wherever a sum is sensitive:

- **Private tallies.** Accumulate votes or scores as ciphertexts; only the total is
  ever decrypted.
- **Confidential balances.** Track an aggregate position without publishing the parts.
- **Sealed bids.** Commit an encrypted bid and compute on it before any reveal.
- **Verifiable aggregation.** Sum encrypted contributions from many parties on chain,
  with the arithmetic done by the program rather than by a server you have to trust.

Where multiplicative depth is required, for example a product of encrypted values,
the off-chain tier is the right place and the kit shows how to record its result.

## Resources

- [`docs/FEASIBILITY.md`](./docs/FEASIBILITY.md): the argument for where the line is.
- [Solana compute budget](https://solana.com/docs/core/fees/compute-budget): the
  limits this kit is designed around.
- [Solana program limitations](https://solana.com/docs/programs/limitations): no
  `rand`, no threads, software-emulated floats.
- [Microsoft SEAL](https://github.com/microsoft/SEAL) and
  [node-seal](https://github.com/s0l0ist/node-seal): the off-chain engine.
- [HomomorphicEncryption.org](https://homomorphicencryption.org/): the parameter
  tables referenced in [`docs/SECURITY.md`](./docs/SECURITY.md).

## Support

Open an issue for bugs, questions, or disagreements.

[↑ Back to top](#solana-fhe-starter)
