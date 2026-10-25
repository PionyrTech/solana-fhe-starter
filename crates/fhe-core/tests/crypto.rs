//! Host-side tests for the operations the Solana program runs.
//!
//! These prove the arithmetic is right. They cannot prove the *cryptography* is
//! right, because decryption lives in the off-chain SDK that holds the secret
//! key. `cli/tests/` covers decryption, and the on-chain integration test at
//! `tests/` closes the loop by decrypting the result the program produced.

use fhe_core::codec::{self, COEFF_BYTES};
use fhe_core::noise;
use fhe_core::ops;
use fhe_core::params::{Params, DEMO, PARAM_SETS, STANDARD};
use fhe_core::FheError;

/// A deterministic byte source stand-in, so the tests need no `rand`.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }
}

/// A well-formed ciphertext-shaped blob with coefficients in `[0, q)`.
fn random_blob(params: &Params, seed: u64) -> Vec<u8> {
    let mut rng = Lcg(seed);
    let mut blob = vec![0u8; params.blob_len()];
    for index in 0..params.coeff_count() {
        codec::write_coeff(&mut blob, index, rng.below(params.q));
    }
    blob
}

fn blob(params: &Params) -> Vec<u8> {
    vec![0u8; params.blob_len()]
}

#[test]
fn mul_mod_matches_the_u128_reference() {
    for params in PARAM_SETS {
        let mut rng = Lcg(0x243f_6a88_85a3_08d3);
        for _ in 0..2_000 {
            let a = rng.below(params.q);
            let b = rng.below(params.q);
            let reference = ((a as u128 * b as u128) % params.q as u128) as u64;
            assert_eq!(ops::mul_mod(&params, a, b), reference, "{}: {a} * {b}", params.name);
        }
    }
}

#[test]
fn add_and_sub_are_inverses() {
    for params in PARAM_SETS {
        let a = random_blob(&params, 1);
        let b = random_blob(&params, 2);
        let mut sum = blob(&params);
        let mut back = blob(&params);
        ops::add(&params, &a, &b, &mut sum).unwrap();
        ops::sub(&params, &sum, &b, &mut back).unwrap();
        assert_eq!(a, back, "{}", params.name);
    }
}

#[test]
fn addition_is_commutative_and_associative() {
    for params in PARAM_SETS {
        let a = random_blob(&params, 11);
        let b = random_blob(&params, 22);
        let c = random_blob(&params, 33);

        let mut ab = blob(&params);
        let mut ba = blob(&params);
        ops::add(&params, &a, &b, &mut ab).unwrap();
        ops::add(&params, &b, &a, &mut ba).unwrap();
        assert_eq!(ab, ba, "{}", params.name);

        let mut abc = blob(&params);
        let mut t = blob(&params);
        ops::add(&params, &a, &b, &mut t).unwrap();
        ops::add(&params, &t, &c, &mut abc).unwrap();

        let mut bca = blob(&params);
        ops::add(&params, &b, &c, &mut t).unwrap();
        ops::add(&params, &a, &t, &mut bca).unwrap();
        assert_eq!(abc, bca, "{}", params.name);
    }
}

#[test]
fn zero_blob_is_the_additive_identity() {
    for params in PARAM_SETS {
        let a = random_blob(&params, 7);
        let mut zero = blob(&params);
        codec::zero_blob(&params, &mut zero).unwrap();
        let mut out = blob(&params);
        ops::add(&params, &a, &zero, &mut out).unwrap();
        assert_eq!(out, a, "{}", params.name);
    }
}

#[test]
fn add_assign_matches_add() {
    let params = DEMO;
    let a = random_blob(&params, 5);
    let b = random_blob(&params, 6);
    let mut assigned = a.clone();
    ops::add_assign(&params, &mut assigned, &b).unwrap();
    let mut added = blob(&params);
    ops::add(&params, &a, &b, &mut added).unwrap();
    assert_eq!(assigned, added);
}

#[test]
fn scalar_mul_distributes_over_add() {
    // k * (a + b) == k * a + k * b, the property that makes scaling usable.
    for params in PARAM_SETS {
        let a = random_blob(&params, 41);
        let b = random_blob(&params, 42);
        let k = 12_345 % params.q;

        let mut sum = blob(&params);
        ops::add(&params, &a, &b, &mut sum).unwrap();
        let mut scaled_sum = blob(&params);
        ops::scalar_mul(&params, k, &sum, &mut scaled_sum).unwrap();

        let mut ka = blob(&params);
        let mut kb = blob(&params);
        ops::scalar_mul(&params, k, &a, &mut ka).unwrap();
        ops::scalar_mul(&params, k, &b, &mut kb).unwrap();
        let mut rhs = blob(&params);
        ops::add(&params, &ka, &kb, &mut rhs).unwrap();

        assert_eq!(scaled_sum, rhs, "{}", params.name);
    }
}

#[test]
fn every_result_is_reduced() {
    for params in PARAM_SETS {
        let a = random_blob(&params, 100);
        let b = random_blob(&params, 200);
        let mut out = blob(&params);
        ops::add(&params, &a, &b, &mut out).unwrap();
        codec::validate(&params, &out).unwrap();
        ops::sub(&params, &a, &b, &mut out).unwrap();
        codec::validate(&params, &out).unwrap();
        ops::scalar_mul(&params, params.q - 1, &a, &mut out).unwrap();
        codec::validate(&params, &out).unwrap();
    }
}

#[test]
fn validate_rejects_a_wrong_length() {
    let short = vec![0u8; DEMO.blob_len() - COEFF_BYTES];
    assert_eq!(
        codec::validate(&DEMO, &short),
        Err(FheError::WrongLength {
            expected: DEMO.blob_len(),
            got: DEMO.blob_len() - COEFF_BYTES,
        })
    );
}

#[test]
fn validate_rejects_an_unreduced_coefficient() {
    let mut bad = blob(&DEMO);
    codec::write_coeff(&mut bad, 3, DEMO.q);
    assert_eq!(
        codec::validate(&DEMO, &bad),
        Err(FheError::CoefficientOutOfRange {
            index: 3,
            value: DEMO.q,
            q: DEMO.q,
        })
    );
}

#[test]
fn operations_refuse_a_blob_from_the_other_tier() {
    // A demo-tier blob read under standard parameters is the wrong length, and
    // that is the check that keeps the two tiers from being mixed by accident.
    let a = random_blob(&DEMO, 1);
    let b = random_blob(&DEMO, 2);
    let mut out = blob(&STANDARD);
    assert!(matches!(
        ops::add(&STANDARD, &a, &b, &mut out),
        Err(FheError::WrongLength { .. })
    ));
}

#[test]
fn scalar_mul_rejects_an_unreduced_scalar() {
    let a = random_blob(&DEMO, 1);
    let mut out = blob(&DEMO);
    assert_eq!(
        ops::scalar_mul(&DEMO, DEMO.q, &a, &mut out),
        Err(FheError::ScalarOutOfRange {
            value: DEMO.q,
            q: DEMO.q,
        })
    );
}

#[test]
fn noise_bound_grows_the_way_the_operations_say_it_does() {
    let params = STANDARD;
    let fresh = params.fresh_noise_bound;
    assert!(noise::is_decryptable(&params, fresh));

    let once = noise::add_bound(fresh, fresh);
    let twice = noise::add_bound(once, fresh);
    assert_eq!(once, 2 * fresh);
    assert_eq!(twice, 3 * fresh);
    assert!(noise::budget_bits(&params, twice) < noise::budget_bits(&params, fresh));

    let scaled = noise::scalar_mul_bound(fresh, 1_000);
    assert_eq!(scaled, fresh * 1_000);

    // The bound is monotone, so exhausting it is a real stopping point.
    let mut bound = fresh;
    let mut additions = 0u64;
    while noise::is_decryptable(&params, bound) && additions < 1_000 {
        bound = noise::add_bound(bound, fresh);
        additions += 1;
    }
    assert_eq!(additions, 1_000, "the standard tier should absorb far more than 1000 additions");
    assert!(noise::remaining_additions(&params, fresh) > 2_000_000);
    assert!(!noise::is_decryptable(&params, params.max_noise_bound()));
}

#[test]
fn remaining_additions_agrees_with_the_walk() {
    // Walked on the demo tier, where exhaustion takes a couple of hundred steps
    // rather than two million.
    let params = DEMO;
    let fresh = params.fresh_noise_bound;
    let predicted = noise::remaining_additions(&params, fresh);

    let mut bound = fresh;
    let mut walked = 0u64;
    while noise::is_decryptable(&params, noise::add_bound(bound, fresh)) {
        bound = noise::add_bound(bound, fresh);
        walked += 1;
    }
    assert_eq!(predicted, walked, "predicted {predicted}, walked {walked}");
}

#[test]
fn the_demo_tier_refuses_sooner_than_the_standard_tier() {
    assert!(DEMO.max_noise_bound() < STANDARD.max_noise_bound());
    assert!(noise::budget_bits(&STANDARD, DEMO.fresh_noise_bound) >= 30);
}
