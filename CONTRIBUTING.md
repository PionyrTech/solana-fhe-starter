# Contributing

The user-facing story is in [`README.md`](./README.md): `./setup.sh`, then
`scripts/demo.sh`. This file is for changing the thing.

## Requirements

- **Node 20+** for the client and the tests.
- **Rust (stable)** for the program and `fhe-core`.
- **Solana CLI** for `cargo-build-sbf` and, for the demo, `solana-test-validator`.

`./setup.sh` installs both if they are missing. Building for SBF wants about 2 GB
of free RAM; on a smaller machine, `CARGO_BUILD_JOBS=1`.

## The gate

Nothing should be committed with either suite failing:

```bash
cargo test                    # arithmetic, account layout, conformance
npm run --prefix cli typecheck
npm run --prefix cli test     # scheme, wire format, conformance, SEAL
```

If you change the wire format, the account layout, or the arithmetic, also run:

```bash
npm run --prefix cli vectors  # regenerate the conformance vectors
cargo test                    # and confirm Rust still agrees
```

## Where things live

```text
crates/fhe-core/src/params.rs     parameter sets, and the folding moduli
crates/fhe-core/src/ops.rs        add, sub, scalar_mul, and the reduction
crates/fhe-core/src/noise.rs      the propagated bound
crates/fhe-core/src/account.rs    the 136 byte account layout
crates/fhe-core/src/codec.rs      the c0 || c1 wire format
programs/fhe-vault/src/lib.rs     the program
cli/src/sdk/rlwe.ts               encryption, decryption, the client operations
cli/src/sdk/seal.ts               the off-chain tier
cli/src/sdk/chain.ts              instruction encoding and the on-chain calls
```

## Conventions

- **The layout is asserted in three places on purpose.** `HEADER_LEN` is checked in
  `crates/fhe-core/src/account.rs`, in the program's unit tests, and the TypeScript
  client hard codes 136. If you add a field, all three tests fail, which is the
  point. Update them together.
- **The two implementations are pinned to each other by the vector file.** The
  TypeScript side produces it, Rust reproduces it. If you change the arithmetic on
  one side, the other side fails, which is again the point.
- **No ciphertext multiplication.** Its absence is the kit's central claim, not an
  unfinished feature. If you have a way to make it fit in 1.4 million compute units,
  that is a paper, and `docs/FEASIBILITY.md` should be rewritten to say so.
- **Keep the honesty sections honest.** If you change what ships, update
  `docs/SECURITY.md` and the claims table in the README in the same change. A
  stale claim is a bug of the worst kind.
- **Rust**: `fhe-core` has no runtime dependencies and should keep it that way. It
  is also the code that runs on chain, so no allocation in the hot paths, no
  floating point, and no `std` items that SBF lacks.
- **TypeScript**: strict mode, and `node:` prefixed imports for built-ins.

## Adding a parameter set

1. Add the constants to `crates/fhe-core/src/params.rs` and to `cli/src/sdk/params.ts`.
2. Pick a modulus of the form `q = 2^shift - c` with small `c`, and prime. The
   folding reduction in `ops.rs` depends on that shape, and `Params::fold_ok`
   asserts it.
3. Add it to `PARAM_SETS` on both sides and rerun `npm run --prefix cli vectors`,
   then `cargo test`. The conformance test checks that every shipped parameter set
   has vectors.
4. If the account is larger than 10,240 bytes, check that the growth loop in
   `chain.ts` still reaches the target, and re-measure the compute units for
   `docs/BENCHMARKS.md`.

## Adding an operation

An operation only belongs on chain if it is coefficient-wise in `Z_q`. Addition,
subtraction, and multiplication by a public scalar qualify. Anything needing a
transform does not.

1. Add it to `crates/fhe-core/src/ops.rs` with a doc comment saying what it is
   homomorphic to.
2. Add the noise rule to `noise.rs`, and a test asserting the bound grows the way
   the rule says.
3. Add the instruction to the program, propagating the bound and refusing an
   operation that would exceed it.
4. Add the client method and the mirrored operation in `rlwe.ts`.
5. Add a test that decrypts, because the arithmetic is not the property that
   matters. The property that matters is that the plaintext comes back right.

## The program keypair

The program keypair is not committed. `declare_id!` in
`programs/fhe-vault/src/lib.rs` must match the keypair you deploy with.
`cargo-build-sbf` will silently generate a fresh keypair at
`target/deploy/fhe_vault-keypair.json` if one is missing, and that key will
disagree with the source. `scripts/demo.sh` handles this by generating a keypair
and rewriting `declare_id!` if none exists; if you are deploying by hand, copy
your keypair into place first, or run `anchor keys sync` if you have Anchor.
