# Benchmarks

Every number here was measured on the machine described below, by the commands
shown. Nothing is quoted from a specification.

## Environment

```text
CPU     2 vCPU
RAM     1.9 GiB
OS      Ubuntu 24.04.4 LTS, x86_64
Tool    solana-cli 4.3.2 (Agave), local validator
Rust    1.99.1
Node    22.22.3
```

This is a small machine. The absolute numbers will be lower on a larger one; the
ratios and the compute unit figures will not change much, because compute units
are a deterministic count rather than a wall-clock measurement.

## On-chain ciphertext addition

Compute units are the number that matters, because they are what the runtime
charges and caps. Measured with `measureAddUnits`, which simulates the
instruction with the limit raised to 1,400,000 so the reported figure is the
cost rather than a refusal at the default 200,000.

| Parameter tier | Ring degree | Ciphertext | Slots | Compute units, one addition |
| --- | --- | --- | --- | --- |
| `demo` | 256 | 4 KiB | 256 | **20,322** |
| `standard` | 2048 | 32 KiB | 2048 | **142,104** |

The standard tier therefore fits inside the default 200,000 CU instruction
budget, but only just. Two additions chained in one instruction would not fit,
which is why each operation is its own instruction and the depth accounting lives
in the account rather than in a single call.

Reproduce it:

```bash
scripts/demo.sh                    # validator, deploy, then the demo tier
cd cli && npx tsx src/cli.ts bench --params standard
```

Cost scales linearly in `n`, as expected: eight times the ring degree is about
seven times the compute, 20,322 to 142,104.

### Why multiplication is absent

For comparison, a single coefficient-wise pass over a standard ciphertext costs
on the order of 10^5 CU. A negacyclic convolution of two degree-2048
polynomials is 4.2 million modular multiplications, and an NTT-based one is
about 49,000 butterflies, each a modular multiply with reduction. That is
millions of compute units for one multiplication, before relinearization. The
1,400,000 CU transaction cap is not close to enough.

## Upload cost

One ciphertext cannot be moved in one transaction. Counted by the demo:

| Parameter tier | Ciphertext | Chunk size | Transactions per ciphertext |
| --- | --- | --- | --- |
| `demo` | 4 KiB | 900 B | 5 |
| `standard` | 32 KiB | 900 B | 37 |

An account also takes 1 to 4 transactions to create, because a program can only
allocate 10,240 bytes per instruction (see [`FINDINGS.md`](./FINDINGS.md) §1).

Wall clock for a full standard tier run, including key generation, encryption,
three account creations, 74 uploads, the addition and a decryption: **25
seconds** on the machine above.

## Off-chain SWE

Times from the test suite, which runs the real code paths.

| Operation | Tier | Time |
| --- | --- | --- |
| encrypt + decrypt, 2 slots | `standard` | ~700 ms |
| encrypt + decrypt, 4 slots | `demo` | ~3 ms |
| full test suite, 19 TypeScript tests | both + SEAL | ~4.5 s |
| full Rust test suite, 24 tests | both | ~0.1 s |

The client uses a schoolbook convolution, so cost grows with `n^2`. That is a
deliberate trade: the moduli were picked for cheap reduction on chain, which cost
the NTT off chain. At `n = 2048` it is still well under a second.

## Noise

The two numbers that matter, side by side, after one addition at the demo tier:

```text
measured noise (off chain, has the secret key)      7
propagated bound (on chain, has no secret key)  16,383  <- the point of refusal
```

The gap is the price of being able to make a guarantee without the key. The
standard tier carries the same fresh bound of 64 but a decryptable bound of
137,438,953,471, so it absorbs more than two million additions before refusing.

## The devnet deployment

The program is deployed to devnet at
`EJimqNCEMedCWkzUFPMFVWudYpHSvHAWFHyqeegyfqYt`, deployed with `--final`, so it has
no upgrade authority and cannot be changed.

| | Value |
| --- | --- |
| Program id | `EJimqNCEMedCWkzUFPMFVWudYpHSvHAWFHyqeegyfqYt` |
| Deploy signature | `2ccLydPzxsjUhZBSHm6GCgiMBPC14z648k7JKJbEQ6ufeuiGZSZGxpECYSExWts6UKRkMkqufVswpUekdJzvzWq2` |
| Deployed in slot | 514,887,415 |
| Program account | 170,088 bytes |
| Upgrade authority | none |

The same demo-tier addition was run against it to confirm the deployed artifact
behaves like the local build:

```text
compute units consumed: 20333      (20,322 on a local validator)
decrypted slots:   207, 57
expected slots:    207, 57
measured noise:    9
```

Compute units are a deterministic count for a given runtime, so two runs of the
same code should agree exactly. These differ by 11, and the honest answer is that
the cause was not investigated: the two runs hit different runtimes (the locally
installed `solana-cli` 4.3.2 against devnet's). Both figures are far inside the
200,000 budget, and the 11 units do not change any conclusion here.

The public devnet RPC rate limits hard. A run reports `429 Too Many Requests` and
retries; it completes, but the wall clock is not a meaningful measurement against
that endpoint.

