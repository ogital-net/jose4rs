//! End-to-end tests for ML-DSA (FIPS 204 / RFC 9964) support.
//!
//! Gated on the `pq-ml-dsa` feature (which requires `aws-lc`). Each test
//! round-trips a single algorithm or exercises a specific code path:
//!
//! - generate -> sign -> verify for each parameter set;
//! - import from a fixed 32-byte seed and verify the regenerated public key
//!   matches the seed's expected public key (the standard RFC 9964 Section 4 flow);
//! - reject a mismatched parameter set when signing (RFC 9964 Section 3).

#![cfg(all(feature = "pq-ml-dsa", feature = "aws-lc"))]

use jose4rs::{
    error::JoseError,
    jwk::{
        JsonWebKey, JsonWebKeyGenerator, OutputControlLevel,
        ml_dsa::{MlDsaJsonWebKey, MlDsaParameterSet},
    },
    jws::{AlgorithmIdentifier, JsonWebSignature},
    jwx::JsonWebStructure,
};

/// Sign a payload, verify it, and round-trip it through JWS compact serialization.
fn round_trip(alg: AlgorithmIdentifier) {
    let key = JsonWebKeyGenerator::for_signature(alg).generate().unwrap();

    let mut jws = JsonWebSignature::new();
    jws.set_payload(b"hello ML-DSA");
    jws.set_algorithm(alg);
    let compact = jws
        .compact_serialization(&key)
        .expect("sign should succeed");
    assert!(
        compact.contains('.'),
        "compact JWS must have the three-segment form"
    );

    let parsed = JsonWebSignature::from_compact_serialization(&compact).unwrap();
    assert!(
        parsed
            .verify_signature(&key)
            .expect("verify should not error")
    );
}

#[test]
fn ml_dsa_44_round_trip() {
    round_trip(AlgorithmIdentifier::MlDsa44);
}

#[test]
fn ml_dsa_65_round_trip() {
    round_trip(AlgorithmIdentifier::MlDsa65);
}

#[test]
fn ml_dsa_87_round_trip() {
    round_trip(AlgorithmIdentifier::MlDsa87);
}

/// Importing a key from a 32-byte seed (RFC 9964 Section 4) must yield a key whose
/// public component matches another key built from the same seed.
#[test]
fn seed_import_round_trip_ml_dsa_65() {
    // Two copies of the same seed: each `from_seed` call consumes its input,
    // so we need a fresh buffer per call.
    let seed: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];
    let key_a = MlDsaJsonWebKey::from_seed(jose4rs::jwk::ml_dsa::MlDsaParameterSet::MlDsa65, seed)
        .expect("first key build");
    let key_b = MlDsaJsonWebKey::from_seed(jose4rs::jwk::ml_dsa::MlDsaParameterSet::MlDsa65, seed)
        .expect("second key build");

    assert_eq!(
        key_a.public_key_bytes(),
        key_b.public_key_bytes(),
        "two keys built from the same seed must match"
    );
}

/// Signing with an ML-DSA-65 key under an ML-DSA-44 JWS must fail (RFC 9964 Section 3).
#[test]
fn mismatched_parameter_set_is_rejected() {
    let key_65 = JsonWebKeyGenerator::for_signature(AlgorithmIdentifier::MlDsa65)
        .generate()
        .unwrap();
    let mut jws = JsonWebSignature::new();
    jws.set_payload(b"hello");
    jws.set_algorithm(AlgorithmIdentifier::MlDsa44);
    let result = jws.compact_serialization(&key_65);
    assert!(
        result.is_err(),
        "signing with an ML-DSA-65 key under ML-DSA-44 must fail"
    );
}

/// JWS round-trip with the JSON serialization (RFC 7515 Section 7.2) for ML-DSA-87.
#[test]
fn ml_dsa_87_json_serialization_round_trip() {
    let key = JsonWebKeyGenerator::for_signature(AlgorithmIdentifier::MlDsa87)
        .generate()
        .unwrap();
    let mut jws = JsonWebSignature::new();
    jws.set_payload(b"json serialization payload");
    jws.set_algorithm(AlgorithmIdentifier::MlDsa87);
    let json = jws.flattened_json_serialization(&key).unwrap();
    let parsed = JsonWebSignature::from_flattened_json_serialization(&json).unwrap();
    assert!(parsed.verify_signature(&key).unwrap());
}

/// `JsonWebKey::from_json` with an AKP JWK (RFC 9964 Section 5) reconstructs the
/// same ML-DSA key and a verify round-trip succeeds.
#[test]
fn akp_jwk_round_trip() {
    let key = JsonWebKeyGenerator::for_signature(AlgorithmIdentifier::MlDsa65)
        .generate()
        .unwrap();
    let jwk_json = key.to_json(OutputControlLevel::IncludePrivate);
    let parsed: JsonWebKey = JsonWebKey::from_json(&jwk_json).expect("AKP JWK parses");
    assert_eq!(parsed.key_type(), "AKP");
    assert_eq!(parsed.algorithm(), Some("ML-DSA-65"));

    let mut jws = JsonWebSignature::new();
    jws.set_payload(b"akp round-trip");
    jws.set_algorithm(AlgorithmIdentifier::MlDsa65);
    let compact = jws.compact_serialization(&parsed).expect("sign");
    let verified = JsonWebSignature::from_compact_serialization(&compact).unwrap();
    assert!(verified.verify_signature(&parsed).unwrap());
}

#[test]
fn akp_jwk_requires_matching_algorithm() {
    let key = JsonWebKeyGenerator::for_signature(AlgorithmIdentifier::MlDsa65)
        .generate()
        .unwrap();
    let json = key.to_json(OutputControlLevel::PublicOnly);
    let cases = [
        (
            json.replacen(",\"alg\":\"ML-DSA-65\"", "", 1),
            "missing alg",
        ),
        (
            json.replacen("\"alg\":\"ML-DSA-65\"", "\"alg\":\"ML-DSA-44\"", 1),
            "mismatched alg",
        ),
        (
            json.replacen("\"alg\":\"ML-DSA-65\"", "\"alg\":\"RS256\"", 1),
            "unrelated alg",
        ),
    ];

    for (invalid, description) in cases {
        assert!(
            matches!(
                JsonWebKey::from_json(&invalid),
                Err(JoseError::InvalidKey(_) | JoseError::InvalidAlgorithm(_))
            ),
            "AKP JWK with {description} must be rejected"
        );
    }
}

#[test]
fn akp_jwk_serialization_always_includes_algorithm() {
    let key = MlDsaJsonWebKey::from_seed(MlDsaParameterSet::MlDsa44, [0u8; 32]).unwrap();

    assert!(
        key.to_json(OutputControlLevel::PublicOnly)
            .contains("\"alg\":\"ML-DSA-44\"")
    );
}

#[test]
fn rfc9964_ml_dsa_44_thumbprint() {
    let key = MlDsaJsonWebKey::from_seed(MlDsaParameterSet::MlDsa44, [0u8; 32]).unwrap();
    let key = JsonWebKey::MlDsa(key);

    assert_eq!(
        key.thumbprint().unwrap(),
        "T4xl70S7MT6Zeq6r9V9fPJGVn76wfnXJ21-gyo0Gu6o"
    );
}
