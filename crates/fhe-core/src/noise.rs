//! Noise accounting.
//!
//! This is the part that has to be honest about what it is. A real noise budget
//! is *measured* by decrypting with the secret key, and the chain never has the
//! secret key, so it cannot be measured on-chain. What the program can do, and
//! what this module does, is propagate a conservative upper bound on the noise
//! and refuse any operation that would push it past the point where decryption
//! is guaranteed to return the wrong answer.
//!
//! The bound is a bound, not a measurement. It is deliberately pessimistic: the
//! real noise after `add` is smaller than the sum of the two inputs in almost
//! every case, so the program may refuse an operation that would in fact have
//! decrypted correctly.

use crate::params::Params;

/// `floor(log2(x))`, or 0 for 0.
#[inline]
pub fn ilog2(x: u64) -> u32 {
    if x == 0 {
        0
    } else {
        63 - x.leading_zeros()
    }
}

/// The noise bound after adding two ciphertexts.
///
/// Noise is additive under addition: the errors add because the ciphertext
/// components add.
#[inline]
pub fn add_bound(lhs: u64, rhs: u64) -> u64 {
    lhs.saturating_add(rhs)
}

/// The noise bound after multiplying a ciphertext by a public scalar.
///
/// The error is scaled by the scalar along with the message.
#[inline]
pub fn scalar_mul_bound(bound: u64, k: u64) -> u64 {
    bound.saturating_mul(k)
}

/// Whether a ciphertext at this noise bound is still guaranteed to decrypt.
#[inline]
pub fn is_decryptable(params: &Params, bound: u64) -> bool {
    bound < params.max_noise_bound()
}

/// Roughly how many bits of headroom a ciphertext at this bound has left.
///
/// Reported for humans and for the CLI. It is `log2(max_bound) - log2(bound)`,
/// so it moves in whole bits and should be read as an order of magnitude, not a
/// precise quantity.
pub fn budget_bits(params: &Params, bound: u64) -> u32 {
    ilog2(params.max_noise_bound()).saturating_sub(ilog2(bound.max(1)))
}

/// How many more ciphertext additions fit before the bound is exhausted.
///
/// With a bound that grows additively and a fresh bound of `B`, the answer is
/// `floor((max_bound - 1 - B) / B)`.
pub fn remaining_additions(params: &Params, bound: u64) -> u64 {
    if bound == 0 || !is_decryptable(params, bound) {
        return 0;
    }
    (params.max_noise_bound() - 1 - bound) / bound
}
