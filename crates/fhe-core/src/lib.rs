//! `fhe-core`: the homomorphic operations this kit runs inside a Solana program.
//!
//! The crate is small on purpose. It holds the parameter sets, the ciphertext
//! wire format, the three linear homomorphic operations, and the noise bound the
//! program enforces. It holds no key generation, no encryption, and no
//! decryption: those need randomness and a secret key, neither of which exists
//! on-chain, and all three live in the off-chain SDK.
//!
//! It also holds no ciphertext times ciphertext multiplication. That operation
//! does not fit in the compute budget, and `docs/FEASIBILITY.md` records the
//! measurement rather than a workaround.
//!
//! ```no_run
//! use fhe_core::{codec, ops, params::DEMO};
//!
//! let fresh = vec![0u8; DEMO.blob_len()];
//! let mut sum = vec![0u8; DEMO.blob_len()];
//! ops::add(&DEMO, &fresh, &fresh, &mut sum).unwrap();
//! codec::validate(&DEMO, &sum).unwrap();
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

pub mod account;
pub mod codec;
pub mod error;
pub mod noise;
pub mod ops;
pub mod params;

pub use error::FheError;
pub use params::{Params, PARAM_ID_DEMO, PARAM_ID_STANDARD, PARAM_SETS};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shipped_moduli_are_of_the_folding_form() {
        for params in PARAM_SETS {
            assert!(
                params.fold_ok(),
                "{} claims q = 2^{} - {} but that is not {}",
                params.name,
                params.mod_shift,
                params.mod_c,
                params.q
            );
        }
    }

    #[test]
    fn blob_length_is_two_reduced_polynomials() {
        for params in PARAM_SETS {
            assert_eq!(params.coeff_count(), 2 * params.n);
            assert_eq!(params.blob_len(), 2 * params.n * codec::COEFF_BYTES);
            assert!(params.delta() * params.t <= params.q);
            assert!(params.delta() > params.t);
        }
    }

    #[test]
    fn parameter_lookup_round_trips() {
        for params in PARAM_SETS {
            assert_eq!(Params::from_id(params.id), Some(params));
            assert_eq!(Params::from_name(params.name), Some(params));
        }
        assert_eq!(Params::from_id(9), None);
    }
}
