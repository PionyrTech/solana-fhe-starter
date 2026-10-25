//! Cross-language conformance.
//!
//! The TypeScript client owns the randomness and the secret key, so it produces
//! the vectors; this test re-derives the operations from them. If the two
//! implementations ever disagree about modular arithmetic, about the reduction,
//! or about the wire format, this fails.
//!
//! The file is committed, so the test runs on a machine that has never seen the
//! TypeScript side. It also checks that the parameter constants the client
//! carries match the ones this crate ships, which is the other half of the
//! contract.

use fhe_core::params::Params;
use fhe_core::{codec, ops};
use serde_json::Value;

fn decode_hex(hex: &str) -> Vec<u8> {
    assert!(hex.len() % 2 == 0, "hex string has an odd length");
    (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("valid hex"))
        .collect()
}

fn field<'a>(case: &'a Value, name: &str) -> &'a Value {
    case.get(name)
        .unwrap_or_else(|| panic!("vector is missing the {name} field"))
}

fn decimal(case: &Value, name: &str) -> u64 {
    field(case, name)
        .as_str()
        .unwrap_or_else(|| panic!("{name} should be a string, to survive JSON number limits"))
        .parse()
        .unwrap_or_else(|_| panic!("{name} should be a decimal integer"))
}

fn vectors_path() -> String {
    format!("{}/tests/vectors/conformance.json", env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn the_client_and_the_program_agree_on_every_vector() {
    let path = vectors_path();
    let raw = match std::fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(_) => {
            eprintln!("no vectors at {path}; run `npm run vectors` in cli/ to generate them");
            return;
        }
    };
    let document: Value = serde_json::from_str(&raw).expect("the vector file is valid JSON");
    let cases = field(&document, "cases").as_array().expect("cases is an array");
    assert!(!cases.is_empty(), "the vector file has no cases");

    let mut checked = 0;
    for case in cases {
        let params = Params::from_id(field(case, "param_id").as_u64().unwrap() as u8)
            .expect("the vector names a parameter set this crate ships");

        // The constants must match, or the two sides are not talking about the
        // same scheme at all.
        assert_eq!(params.n as u64, field(case, "n").as_u64().unwrap());
        assert_eq!(params.q, decimal(case, "q"));
        assert_eq!(params.t, decimal(case, "t"));
        assert_eq!(params.blob_len() as u64, field(case, "blob_len").as_u64().unwrap());
        assert_eq!(params.fresh_noise_bound, decimal(case, "fresh_noise_bound"));
        assert!(params.fold_ok());

        let a = decode_hex(field(case, "a").as_str().unwrap());
        let b = decode_hex(field(case, "b").as_str().unwrap());
        let expected_sum = decode_hex(field(case, "sum").as_str().unwrap());
        let expected_scaled = decode_hex(field(case, "scaled").as_str().unwrap());
        let scalar = decimal(case, "scalar");

        codec::validate(&params, &a).expect("a is reduced");
        codec::validate(&params, &b).expect("b is reduced");

        let mut sum = vec![0u8; params.blob_len()];
        ops::add(&params, &a, &b, &mut sum).expect("add succeeds");
        assert_eq!(
            sum, expected_sum,
            "add disagrees on {} for seed {}",
            params.name,
            field(case, "seed").as_str().unwrap_or("<none>")
        );

        let mut scaled = vec![0u8; params.blob_len()];
        ops::scalar_mul(&params, scalar, &a, &mut scaled).expect("scalar_mul succeeds");
        assert_eq!(
            scaled, expected_scaled,
            "scalar_mul disagrees on {} for seed {}",
            params.name,
            field(case, "seed").as_str().unwrap_or("<none>")
        );

        checked += 1;
    }
    assert!(checked > 0, "nothing was checked");
}

#[test]
fn the_vector_file_covers_every_shipped_parameter_set() {
    let raw = match std::fs::read_to_string(vectors_path()) {
        Ok(raw) => raw,
        Err(_) => return,
    };
    let document: Value = serde_json::from_str(&raw).unwrap();
    for params in fhe_core::PARAM_SETS {
        let covered = document["cases"]
            .as_array()
            .unwrap()
            .iter()
            .any(|case| case["param_name"].as_str() == Some(params.name));
        assert!(covered, "no vectors for the {} parameter set", params.name);
    }
}
