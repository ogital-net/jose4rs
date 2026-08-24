//! jose4j's "Hello World" JWE example: A128KW key management with
//! `AES_128_CBC_HMAC_SHA_256` content encryption.
//!
//! Ported from jose4j's `ExamplesTest.helloWorld`.

use jose4rs::jwa::{AlgorithmConstraints, ConstraintType};
use jose4rs::jwe::{ContentEncryptionAlgorithm, JsonWebEncryption, KeyManagementAlgorithm};
use jose4rs::jwk::{JsonWebKeyGenerator, OutputControlLevel};
use jose4rs::jwx::{HeaderParameter, JsonWebStructure};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // A random 128-bit AES key, wrapped in a JWK.
    let key = JsonWebKeyGenerator::for_encryption(KeyManagementAlgorithm::A128Kw).generate()?;
    println!("Key: {}", key.to_json(OutputControlLevel::IncludeSymmetric));

    let mut jwe = JsonWebEncryption::new();
    jwe.set_payload("Hello World!");
    jwe.set_algorithm(KeyManagementAlgorithm::A128Kw);
    jwe.set_header(
        HeaderParameter::EncryptionMethod,
        ContentEncryptionAlgorithm::Aes128CbcHmacSha256.name(),
    );
    jwe.set_key(&key);
    jwe.encrypt()?;
    let serialized_jwe = jwe.compact_serialization()?;
    println!("Serialized Encrypted JWE: {serialized_jwe}");

    // Decrypt.
    let alg_constraints =
        AlgorithmConstraints::new(ConstraintType::Permit, [KeyManagementAlgorithm::A128Kw]);
    let mut jwe = JsonWebEncryption::new();
    jwe.set_algorithm_constraints(&alg_constraints);
    jwe.set_compact_serialization(&serialized_jwe)?;
    jwe.set_key(&key);
    println!("Payload: {}", String::from_utf8_lossy(jwe.payload()?));

    Ok(())
}
