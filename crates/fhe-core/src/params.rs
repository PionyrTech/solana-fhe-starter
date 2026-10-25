//! Parameter sets.
//!
//! The kit ships two tiers of the same scheme, and they are not interchangeable:
//! a ciphertext produced under one cannot be used under the other.
//!
//! Both are BFV style RLWE over `Z_q`, with a message polynomial packed
//! coefficient by coefficient, so one ciphertext carries `n` plaintext slots.
//!
//! The modulus in each set is chosen so that `q = 2^shift - c` for small `c`.
//! That is not cosmetic: it lets modular multiplication reduce with shifts and a
//! couple of conditional subtractions instead of a 128 bit division, which SBF
//! is poor at. [`Params::fold_ok`] is asserted in the tests.

/// The fast, deliberately insecure parameter set used by the test suite.
pub const PARAM_ID_DEMO: u8 = 0;
/// The parameter set sized to the published 128-bit classical table.
pub const PARAM_ID_STANDARD: u8 = 1;

/// One parameter set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    /// Wire identifier, stored in every account.
    pub id: u8,
    /// Human readable name.
    pub name: &'static str,
    /// Ring degree. One ciphertext carries `n` plaintext slots.
    pub n: usize,
    /// Coefficient modulus.
    pub q: u64,
    /// Plaintext modulus. Slots hold values in `[0, t)`.
    pub t: u64,
    /// `q = 2^mod_shift - mod_c`.
    pub mod_shift: u32,
    /// See [`Params::mod_shift`].
    pub mod_c: u64,
    /// A conservative bound on `|e|` for a freshly encrypted ciphertext.
    pub fresh_noise_bound: u64,
    /// What the parameter choice does and does not buy, in plain language.
    pub security: &'static str,
}

/// The fast tier. Its whole purpose is to make the test suite and the local demo
/// run in milliseconds.
pub const DEMO: Params = Params {
    id: PARAM_ID_DEMO,
    name: "demo",
    n: 256,
    q: 8_388_593, // 2^23 - 15
    t: 256,
    mod_shift: 23,
    mod_c: 15,
    fresh_noise_bound: 64,
    security: "None. N=256 with a 23 bit modulus is far below every published \
security threshold and can be attacked directly. It exists so the test suite runs fast.",
};

/// The tier the demo uses when it is meant to be taken seriously as a parameter
/// choice.
pub const STANDARD: Params = Params {
    id: PARAM_ID_STANDARD,
    name: "standard",
    n: 2048,
    q: 18_014_398_509_481_951, // 2^54 - 33
    t: 65_536,
    mod_shift: 54,
    mod_c: 33,
    fresh_noise_bound: 64,
    security: "The ring dimension and modulus sit inside the HomomorphicEncryption.org \
standard table for 128 bit classical security at this size. That is a statement about parameter \
sizes under the table's assumptions. This implementation is unaudited, samples error from a \
centered binomial rather than the discrete Gaussian the table assumes, and is additively \
homomorphic only. It ships no ciphertext multiplication.",
};

/// Every parameter set the kit knows about, indexed by id.
pub const PARAM_SETS: [Params; 2] = [DEMO, STANDARD];

impl Params {
    /// Look a parameter set up by its wire id.
    pub fn from_id(id: u8) -> Option<Params> {
        PARAM_SETS.iter().copied().find(|p| p.id == id)
    }

    /// Look a parameter set up by its name.
    pub fn from_name(name: &str) -> Option<Params> {
        PARAM_SETS.iter().copied().find(|p| p.name == name)
    }

    /// Number of coefficients in the blob, `c0` and `c1` together.
    pub fn coeff_count(&self) -> usize {
        2 * self.n
    }

    /// Serialized ciphertext size in bytes: 2 polynomials of `n` coefficients,
    /// each an 8 byte little endian integer.
    pub fn blob_len(&self) -> usize {
        self.coeff_count() * 8
    }

    /// Number of plaintext slots one ciphertext carries.
    pub fn slot_capacity(&self) -> usize {
        self.n
    }

    /// Plaintext scaling factor. Decryption divides by this, so it also controls
    /// how much noise the ciphertext can absorb.
    pub fn delta(&self) -> u64 {
        self.q / self.t
    }

    /// The largest plaintext value a slot can hold.
    pub fn max_plaintext(&self) -> u64 {
        self.t - 1
    }

    /// The noise bound above which decryption starts returning the wrong value.
    ///
    /// Decryption recovers `round((delta * m + e) / delta)`, which is correct
    /// while `|e| < delta / 2` and therefore while `|e| < q / (2t)` (see the
    /// derivation in `docs/ARCHITECTURE.md`).
    pub fn max_noise_bound(&self) -> u64 {
        self.q / (2 * self.t)
    }

    /// Whether `q` really is `2^mod_shift - mod_c`.
    pub fn fold_ok(&self) -> bool {
        (1u64 << self.mod_shift).wrapping_sub(self.mod_c) == self.q
    }
}
