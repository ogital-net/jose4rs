//! Data-driven JWE decryption interop test.
//!
//! Every vector in `jwe_test_vectors.txt` was produced by an external JOSE
//! implementation. Each block names its key-management and content-encryption
//! algorithms, carries the recipient private key as a JWK, and gives a compact
//! serialization whose plaintext is always `Hello world!`. The file is parsed
//! at test time and every vector is decrypted and checked, giving true
//! interop coverage of the full key-management x content-encryption matrix
//! (16 x 4 = 112 vectors).

use jose4rs::{
    jwa::{AlgorithmConstraints, ConstraintType},
    jwe::{JsonWebEncryption, KeyManagementAlgorithm},
    jwk::JsonWebKey,
    jwx::JsonWebStructure,
};

const VECTORS: &str = include_str!("jwe_test_vectors.txt");
const EXPECTED_PLAINTEXT: &[u8] = b"Hello world!";

/// One parsed `---- JWE <alg> <enc> ----` block: the recipient JWK JSON and
/// the compact serialization.
struct Vector<'a> {
    alg: &'a str,
    enc: &'a str,
    jwk_json: &'a str,
    compact: &'a str,
}

/// Parses the vector file into its 112 blocks.
///
/// The format is regular: blocks are separated by blank lines, each opens with
/// a `---- JWE <alg> <enc> ----` header, then a `JWK:` label and the JWK JSON
/// on the next line, then a `JWE:` label and the compact serialization on the
/// next line. The file is stored unwrapped, so each of those is a single line.
fn parse_vectors(input: &str) -> Vec<Vector<'_>> {
    let mut vectors = Vec::new();
    let mut lines = input.lines();

    while let Some(line) = lines.next() {
        let header = line.trim();
        if !(header.starts_with("---- JWE ") && header.ends_with(" ----")) {
            continue;
        }
        let title = header
            .trim_start_matches("---- JWE ")
            .trim_end_matches(" ----");
        let (alg, enc) = title
            .split_once(' ')
            .unwrap_or_else(|| panic!("malformed vector header: {header:?}"));

        let jwk_json = read_labeled_value(&mut lines, "JWK:");
        let compact = read_labeled_value(&mut lines, "JWE:");

        vectors.push(Vector {
            alg,
            enc,
            jwk_json,
            compact,
        });
    }

    vectors
}

/// Reads a `<label>` line followed by the value line, returning the trimmed
/// value. Blank lines around the label and value are skipped, since blocks
/// separate their parts with blank lines.
fn read_labeled_value<'a>(lines: &mut std::str::Lines<'a>, label: &str) -> &'a str {
    let mut label_line = lines.next().unwrap_or_else(|| panic!("expected {label}"));
    while label_line.trim().is_empty() {
        label_line = lines.next().unwrap_or_else(|| panic!("expected {label}"));
    }
    assert_eq!(
        label_line.trim(),
        label,
        "expected {label} line, found {label_line:?}"
    );

    let mut value = lines
        .next()
        .unwrap_or_else(|| panic!("expected value after {label}"));
    while value.trim().is_empty() {
        value = lines
            .next()
            .unwrap_or_else(|| panic!("expected value after {label}"));
    }
    let value = value.trim();
    value
}

/// The vector file's `alg` strings use the RFC 7518 spellings, which differ
/// from this crate's [`KeyManagementAlgorithm::name`] only for the ECDH-ES
/// key-wrapping family. Map the file's spelling onto the crate's.
fn key_mgmt_algorithm(alg: &str) -> KeyManagementAlgorithm {
    use KeyManagementAlgorithm as A;
    match alg {
        "RSA1_5" => A::Rsa15,
        "RSA-OAEP" => A::RsaOaep,
        "RSA-OAEP-256" => A::RsaOaep256,
        "RSA-OAEP-384" => A::RsaOaep384,
        "RSA-OAEP-512" => A::RsaOaep512,
        "A128KW" => A::A128Kw,
        "A192KW" => A::A192Kw,
        "A256KW" => A::A256Kw,
        "dir" | "direct" => A::Direct,
        "ECDH-ES" => A::EcdhEs,
        "ECDH-ES+A128KW" => A::EcdhEsA128Kw,
        "ECDH-ES+A192KW" => A::EcdhEsA192Kw,
        "ECDH-ES+A256KW" => A::EcdhEsA256Kw,
        "A128GCMKW" => A::A128GcmKw,
        "A192GCMKW" => A::A192GcmKw,
        "A256GCMKW" => A::A256GcmKw,
        "PBES2-HS256+A128KW" => A::Pbes2Hs256A128Kw,
        "PBES2-HS384+A192KW" => A::Pbes2Hs384A192Kw,
        "PBES2-HS512+A256KW" => A::Pbes2Hs512A256Kw,
        other => panic!("unrecognized key management algorithm: {other}"),
    }
}

#[test]
fn decrypt_all_external_vectors() {
    let vectors = parse_vectors(VECTORS);
    assert_eq!(vectors.len(), 112, "unexpected vector count");

    for (i, v) in vectors.iter().enumerate() {
        let context = format!("vector #{i} ({} {})", v.alg, v.enc);

        // RSA1_5 and the PBES2 family are blocked by the crate's default
        // constraints, so permit explicitly whichever algorithm this vector
        // exercises (mirrors the inline unit tests).
        let alg = key_mgmt_algorithm(v.alg);
        let constraints = AlgorithmConstraints::new(ConstraintType::Permit, [alg]);

        let jwk =
            JsonWebKey::from_json(v.jwk_json).unwrap_or_else(|e| panic!("{context}: bad JWK: {e}"));

        let mut jwe = JsonWebEncryption::new();
        jwe.set_algorithm_constraints(&constraints);
        jwe.set_compact_serialization(v.compact)
            .unwrap_or_else(|e| panic!("{context}: parse failed: {e}"));
        jwe.set_key(&jwk);

        let payload = jwe
            .payload()
            .unwrap_or_else(|e| panic!("{context}: decrypt failed: {e}"));
        assert_eq!(payload, EXPECTED_PLAINTEXT, "{context}: wrong plaintext");
    }
}
