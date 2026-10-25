//! The homomorphic operations that run inside the Solana program.
//!
//! All three are coefficient wise modular arithmetic. None of them needs a
//! transform, randomness, or a secret key, which is exactly why they are the
//! ones that fit inside the compute budget (see `docs/FEASIBILITY.md`).
//!
//! ```text
//! add        Enc(a) + Enc(b) = Enc(a + b)
//! sub        Enc(a) - Enc(b) = Enc(a - b)
//! scalar_mul k * Enc(a)      = Enc(k * a)      k is public
//! ```
//!
//! Ciphertext times ciphertext multiplication is absent on purpose. It is not
//! skipped, it is impossible in this environment. `docs/FEASIBILITY.md` section
//! 2.2 has the measurement.

use crate::codec::{read_coeff, validate, write_coeff};
use crate::error::FheError;
use crate::params::Params;

/// `(a + b) mod q`, with `a` and `b` already reduced.
#[inline]
pub fn add_mod(params: &Params, a: u64, b: u64) -> u64 {
    // a and b are below q, and q is below 2^54 in every shipped parameter set,
    // so the sum cannot overflow a u64 and one conditional subtraction is enough.
    let sum = a + b;
    if sum >= params.q {
        sum - params.q
    } else {
        sum
    }
}

/// `(a - b) mod q`, with `a` and `b` already reduced.
#[inline]
pub fn sub_mod(params: &Params, a: u64, b: u64) -> u64 {
    if a >= b {
        a - b
    } else {
        a + params.q - b
    }
}

/// `(a * b) mod q`, with `a` and `b` already reduced.
///
/// The product needs 108 bits for the standard tier, so it goes through `u128`
/// for the multiply and then reduces by folding `2^shift` down to `mod_c`. That
/// avoids a 128 bit division, which is the operation SBF handles badly.
#[inline]
pub fn mul_mod(params: &Params, a: u64, b: u64) -> u64 {
    fold_u128(params, (a as u128) * (b as u128))
}

/// Reduce a value below `2^(2 * shift)` modulo `q = 2^shift - mod_c`.
#[inline]
pub fn fold_u128(params: &Params, value: u128) -> u64 {
    let shift = params.mod_shift;
    let low_mask: u128 = (1u128 << shift) - 1;

    // 2^shift = q + mod_c, so 2^shift == mod_c (mod q).
    let first = (value >> shift) as u64 * params.mod_c + (value & low_mask) as u64;
    // The folded value is still larger than q, so fold it once more. After this
    // it is below 2^shift + shift * mod_c, a couple of subtractions from q.
    let second = (first >> shift) * params.mod_c + (first & ((1u64 << shift) - 1));

    let mut reduced = second;
    while reduced >= params.q {
        reduced -= params.q;
    }
    reduced
}

/// A coefficient wise combination of two validated blobs.
fn combine(
    params: &Params,
    lhs: &[u8],
    rhs: &[u8],
    out: &mut [u8],
    f: impl Fn(u64, u64) -> u64,
) -> Result<(), FheError> {
    validate(params, lhs)?;
    validate(params, rhs)?;
    if out.len() != params.blob_len() {
        return Err(FheError::WrongLength {
            expected: params.blob_len(),
            got: out.len(),
        });
    }
    for index in 0..params.coeff_count() {
        write_coeff(out, index, f(read_coeff(lhs, index), read_coeff(rhs, index)));
    }
    Ok(())
}

/// `out = a + b`, coefficient wise modulo `q`.
pub fn add(params: &Params, a: &[u8], b: &[u8], out: &mut [u8]) -> Result<(), FheError> {
    combine(params, a, b, out, |x, y| add_mod(params, x, y))
}

/// `out = a - b`, coefficient wise modulo `q`.
pub fn sub(params: &Params, a: &[u8], b: &[u8], out: &mut [u8]) -> Result<(), FheError> {
    combine(params, a, b, out, |x, y| sub_mod(params, x, y))
}

/// `accumulator += addend`, coefficient wise modulo `q`.
pub fn add_assign(params: &Params, accumulator: &mut [u8], addend: &[u8]) -> Result<(), FheError> {
    validate(params, accumulator)?;
    validate(params, addend)?;
    for index in 0..params.coeff_count() {
        let sum = add_mod(params, read_coeff(accumulator, index), read_coeff(addend, index));
        write_coeff(accumulator, index, sum);
    }
    Ok(())
}

/// `out = k * a`, coefficient wise modulo `q`. `k` is public.
///
/// The scalar must be reduced, because the noise bound is scaled by exactly the
/// scalar the caller supplies and an unreduced scalar would make that bound a
/// lie.
pub fn scalar_mul(params: &Params, k: u64, a: &[u8], out: &mut [u8]) -> Result<(), FheError> {
    if k >= params.q {
        return Err(FheError::ScalarOutOfRange { value: k, q: params.q });
    }
    validate(params, a)?;
    if out.len() != params.blob_len() {
        return Err(FheError::WrongLength {
            expected: params.blob_len(),
            got: out.len(),
        });
    }
    for index in 0..params.coeff_count() {
        write_coeff(out, index, mul_mod(params, read_coeff(a, index), k));
    }
    Ok(())
}
