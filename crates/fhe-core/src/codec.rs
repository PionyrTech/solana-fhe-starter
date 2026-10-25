//! The ciphertext wire format.
//!
//! A ciphertext blob is `c0 || c1`, two polynomials of `n` coefficients each,
//! every coefficient a `u64` little endian and reduced modulo `q`. There is no
//! header: the parameter set is carried separately, by the account that holds
//! the blob, and [`validate`] is what stops a blob from being read under the
//! wrong parameters.

use crate::error::FheError;
use crate::params::Params;

/// Every coefficient is eight bytes.
pub const COEFF_BYTES: usize = 8;

/// Read coefficient `index` (`u64`, little endian) out of a blob.
///
/// Panics if the blob is too short. Callers run [`validate`] first.
#[inline]
pub fn read_coeff(blob: &[u8], index: usize) -> u64 {
    let offset = index * COEFF_BYTES;
    let mut buf = [0u8; COEFF_BYTES];
    buf.copy_from_slice(&blob[offset..offset + COEFF_BYTES]);
    u64::from_le_bytes(buf)
}

/// Write coefficient `index` (`u64`, little endian) into a blob.
///
/// Panics if the blob is too short. Callers run [`validate`] first.
#[inline]
pub fn write_coeff(blob: &mut [u8], index: usize, value: u64) {
    let offset = index * COEFF_BYTES;
    blob[offset..offset + COEFF_BYTES].copy_from_slice(&value.to_le_bytes());
}

/// Check that a blob is the right size for `params` and fully reduced.
///
/// This is the one check that stands between a hand written account and the
/// arithmetic. A coefficient at or above `q` would silently corrupt every later
/// operation, so it is a hard error rather than a reduction.
pub fn validate(params: &Params, blob: &[u8]) -> Result<(), FheError> {
    let expected = params.blob_len();
    if blob.len() != expected {
        return Err(FheError::WrongLength {
            expected,
            got: blob.len(),
        });
    }
    for index in 0..params.coeff_count() {
        let value = read_coeff(blob, index);
        if value >= params.q {
            return Err(FheError::CoefficientOutOfRange {
                index,
                value,
                q: params.q,
            });
        }
    }
    Ok(())
}

/// The blob that decrypts to all zeros, used as the identity for addition.
pub fn zero_blob(params: &Params, out: &mut [u8]) -> Result<(), FheError> {
    if out.len() != params.blob_len() {
        return Err(FheError::WrongLength {
            expected: params.blob_len(),
            got: out.len(),
        });
    }
    out.fill(0);
    Ok(())
}
