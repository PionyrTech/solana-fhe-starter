//! Errors returned by the homomorphic operations.
//!
//! Every variant is a rejection of input the caller can fix. Nothing here means
//! "the cryptography failed": the operations themselves are total functions over
//! well-formed ciphertexts.

/// Why an operation was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FheError {
    /// The parameter set id is not one this kit knows about.
    UnknownParameterSet(u8),
    /// The account does not start with this kit's magic.
    WrongMagic,
    /// The account was written by a layout version this crate does not read.
    UnsupportedVersion(u32),
    /// A ciphertext blob was not `2 * n * 8` bytes.
    WrongLength {
        expected: usize,
        got: usize,
    },
    /// A coefficient was not reduced modulo `q`.
    CoefficientOutOfRange { index: usize, value: u64, q: u64 },
    /// A plaintext scalar was not in `[0, q)`.
    ScalarOutOfRange { value: u64, q: u64 },
    /// The operation would push the noise bound past what can be decrypted.
    NoiseBudgetExceeded { bound: u64, max_bound: u64 },
}

impl core::fmt::Display for FheError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FheError::UnknownParameterSet(id) => write!(f, "unknown parameter set id {id}"),
            FheError::WrongMagic => write!(f, "account does not carry the FHEV magic"),
            FheError::UnsupportedVersion(version) => {
                write!(f, "unsupported account layout version {version}")
            }
            FheError::WrongLength { expected, got } => {
                write!(f, "expected {expected} bytes, got {got}")
            }
            FheError::CoefficientOutOfRange { index, value, q } => {
                write!(f, "coefficient {index} is {value}, which is not reduced modulo {q}")
            }
            FheError::ScalarOutOfRange { value, q } => {
                write!(f, "scalar {value} is outside [0, {q})")
            }
            FheError::NoiseBudgetExceeded { bound, max_bound } => write!(
                f,
                "operation would raise the noise bound to {bound}, above the decryptable bound {max_bound}"
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FheError {}
