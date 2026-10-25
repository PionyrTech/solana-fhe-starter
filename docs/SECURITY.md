# Security and limitations

Read this before using anything here to protect a secret. The short version: this
is a teaching kit, the on-chain tier is unaudited, and the `demo` parameter set
provides no security at all.

## What is claimed, precisely

| Claim | Status |
| --- | --- |
| Addition, subtraction, and public scaling on ciphertexts are genuinely homomorphic | **Yes.** Tested by decrypting the result, on chain and off. |
| The `demo` parameter set is secure | **No.** `n = 256` with a 23-bit modulus. Stated as insecure in `params.rs`. |
| The `standard` parameter sizes match the published 128-bit classical table | Sizes yes; see the caveats below |
| The implementation has been audited | **No.** Not audited, not reviewed, not constant-time. |
| The scheme is fully homomorphic | **No.** Additively homomorphic. No ciphertext multiplication. |
| The on-chain noise figure is a measurement | **No.** It is a bound. `docs/ARCHITECTURE.md` explains why. |
| Off-chain results are verified on chain | **No.** A digest is recorded, not a proof. |

## Parameter sizes versus implementation security

The `standard` tier uses `n = 2048` and a 54-bit modulus, which is inside the
HomomorphicEncryption.org table for 128-bit classical security at that ring
dimension. That is a statement about parameter sizes.

It is not a statement about this code. Three specific gaps:

1. **The error distribution differs.** The table assumes a discrete Gaussian.
   This kit samples from a centered binomial with `eta = 8`
   (`cli/src/sdk/rlwe.ts`). That is a standard lattice sampler, but it is not the
   one the analysis assumes, so the table's numbers do not transfer exactly.
2. **The implementation is unaudited.** No cryptographic review, no constant-time
   discipline, no side-channel analysis.
3. **The scheme is thinner than the parameter table implies.** Only linear
   operations are supported, so there is no ciphertext multiplication, no
   relinearization, and no bootstrapping in this tier.

Use the parameters as a demonstration of how such a choice is made. Do not use
them as a security guarantee.

## The on-chain tier stores ciphertexts in the clear

Worth stating plainly because it is easy to misread. The program stores the
ciphertext bytes in an ordinary Solana account. Anyone can read them. What they
cannot do is decrypt them without the secret key, which never leaves the machine
that generated it.

So the confidentiality claim is exactly: **the ciphertext is public, the
plaintext is not.** That is the same claim any FHE deployment makes, and it holds
here only to the extent the scheme holds.

## What an observer can see

Even without the key, someone watching the chain can learn things:

* How many ciphertexts exist, and who owns them.
* The size and parameter tier of each, hence roughly how much computation went in.
* The operation graph, because `parent_a` and `parent_b` are recorded.
* The depth and the propagated noise bound.
* Timing and slot, from creation.

Metadata leakage of this kind is normal for on-chain privacy systems and is not
addressed here.

## The noise bound is a bound, and it can refuse a valid operation

The program propagates a worst-case bound and refuses anything that would exceed
`q / (2t)`. The real noise is usually far smaller, so the program may reject an
operation that would in fact have decrypted correctly. That is the deliberate
direction of the error: a false refusal is recoverable, a silent wrong answer is
not.

## The off-chain commitment is an assertion, not a proof

`commit_evaluation` records a SHA-256 digest, a scheme tag, a depth, and the
remaining noise bits. The program cannot check that the off-chain engine did what
was claimed. Anyone relying on the record must re-run the off-chain computation
and compare digests themselves. This is stated in the instruction's own
documentation too, because it is the easiest thing in the kit to over-trust.

## Key material

* The secret key is a JSON file the CLI writes where you tell it to. It is not
  encrypted. `.gitignore` covers the default names, but nothing stops you writing
  it somewhere that gets committed.
* Key generation requires randomness, which Solana programs cannot access, so
  keygen only ever runs off chain. The program never holds a key.
* The program keypair for deployment is not committed. See
  [`CONTRIBUTING.md`](../CONTRIBUTING.md).

## Not handled

* Constant-time execution. Nothing here is written to resist timing attacks.
* Ciphertext multiplication, and therefore any circuit with multiplicative depth.
* Cross-tier ciphertext use. A ciphertext cannot move between parameter sets
  without re-encryption.
* Verification of off-chain computation.
* Any privacy property beyond "the ciphertext does not reveal the plaintext".

## Reporting

This is a demonstration kit published by Pionyr. If you find a problem, open an
issue. There is no security guarantee to void, but a correctness bug is worth
knowing about.
