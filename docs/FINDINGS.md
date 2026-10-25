# Findings

Things this kit discovered by building, rather than by reading. Each one changed
the design, and each is the kind of thing that turns up only when the code meets
the runtime.

## 1. A program can only allocate 10,240 bytes for an account

**What happened.** The first version of `create_value` called
`system_program::create_account` with the full account size. At the demo tier
that is 4,232 bytes and it worked. At the standard tier it is 32,904 bytes and
the transaction failed:

```text
Program log: Account data size realloc limited to 10240 in inner instructions
Program EJimqNCEMedWkw... failed: Failed to reallocate account data
```

**Why.** `MAX_PERMITTED_DATA_INCREASE` caps how much an account's data can grow
in a single instruction when the allocation happens through a cross-program
invocation. A top-level `create_account` is not limited, but a top-level one
needs the new account's signature, and a program-derived address cannot sign a
client-built transaction.

**What changed.** `create_value` now allocates min(size, 10,240) and a separate
`grow_value` instruction adds one step at a time. The client loops until the
account is big enough. The demo tier fits in the first allocation and the loop
does nothing.

## 2. One ciphertext is dozens of transactions

A standard tier ciphertext is 32,768 bytes. A legacy transaction is 1,232 bytes
including signatures and account keys, so the upload is **74 transactions for two
ciphertexts** (37 each at a 900 byte chunk). This is measured by the demo, not
estimated.

Nothing can be done about this within the current transaction format. It is the
clearest illustration of why FHE evaluation on chain is not merely expensive but
awkward at the level of moving bytes around.

## 3. SBF is bad at 128-bit division, so the moduli were chosen for it

Modular multiplication at the standard tier is a 108-bit product reduced modulo a
54-bit prime. The obvious implementation is `(a as u128 * b as u128) % q as u128`,
which pulls in a 128-bit division routine that SBF handles poorly.

**What changed.** Both moduli have the form `q = 2^shift - c` for small `c`
(`2^23 - 15` and `2^54 - 33`), so `2^shift` folds down to `c` and the reduction
becomes two shifts, two multiplies and a short subtraction loop. The tests check
the folding reduction against a `u128 % q` reference over 2,000 random pairs per
tier.

The cost of that choice: the moduli are not NTT-friendly, so the client uses a
schoolbook negacyclic convolution. That is fine off chain at `n = 2048` (about
700 ms) and impossible on chain.

## 4. Program-derived accounts cannot use Anchor's `realloc` constraint

Anchor's `#[account(realloc = ...)]` only accepts typed accounts
(`Account`, `LazyAccount`, `AccountLoader`, `Migration`). A value account is a raw
layout this kit defines, so it is an `UncheckedAccount` and the constraint is
rejected at compile time:

```text
error: realloc must be on an Account, LazyAccount, AccountLoader, or Migration
```

**What changed.** `grow_value` resizes in the instruction body instead, via
`AccountInfo::resize`, after topping the account up to rent exemption.

## 5. `AccountInfo::realloc` is now `resize`

In the Solana version this kit builds against (`solana-account-info` 3.x), the
method is `resize(new_len)` and it always zeroes the new bytes; the older
`realloc(new_len, zero_init)` does not exist. Worth knowing before copying an
older example.

## 6. SEAL ciphertexts cannot be handed to the program

The original plan was one ciphertext format for both tiers, so the program could
add real SEAL ciphertexts. That is not possible without re-implementing SEAL's
internals:

* `node-seal` exposes `saveToArray`/`loadFromArray` and `isNttForm`, but no
  coefficient access. The serialization is SEAL's own format and the polynomials
  are stored in NTT form.
* Even with access, a production SEAL ciphertext (three RNS moduli at
  `n = 4096`) is about 192 KiB, which does not fit in the 256 KiB heap alongside
  anything else.

**What changed.** The two tiers are honestly separate, and a digest crosses the
boundary rather than a ciphertext.

## 7. The measured noise is far below the bound, and that is correct

After one addition the program refuses at a bound of 16,383 while the actual
noise is 7. That is not a bug to tune away: the on-chain number is a
worst-case guarantee computed without the secret key, and the off-chain number is
a measurement. Reporting both, side by side, is how a reader can see the bound is
conservative rather than take it on faith.

## 8. Solana programs have no `rand`

Key generation cannot run on chain at all. It is not a design preference: the
runtime denies access to randomness, so the secret key can only be made
off chain, and the program can only ever hold ciphertext.
