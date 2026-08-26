//! An example of signature verification using JSON Web Signature (JWS).
//!
//! Ported from jose4j's `ExamplesTest.jwsVerificationExample`. jose4j verifies
//! a fixed compact serialization from the JWS spec using bundled example keys;
//! jose4rs doesn't bundle those keys, so this example signs first and then
//! verifies the resulting compact serialization as the receiver would.

use jose4rs::jwa::{AlgorithmConstraints, ConstraintType};
use jose4rs::jwk::{JsonWebKey, JsonWebKeyGenerator, OutputControlLevel};
use jose4rs::jws::{AlgorithmIdentifier, JsonWebSignature};
use jose4rs::jwx::JsonWebStructure;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Stand in for the sender: sign some content with an ES256 key.
    let signing_jwk =
        JsonWebKeyGenerator::for_signature(AlgorithmIdentifier::EcdsaUsingP256CurveAndSha256)
            .generate()?;
    let mut signer = JsonWebSignature::new();
    signer.set_payload("This is some text that is to be signed.");
    signer.set_algorithm(AlgorithmIdentifier::EcdsaUsingP256CurveAndSha256);

    // The complete JWS representation, or compact serialization, is a string
    // consisting of three dot ('.') separated base64url-encoded parts in the
    // form Header.Payload.Signature. This is what would be received over the
    // wire.
    let compact_serialization = signer.compact_serialization(&signing_jwk)?;
    println!("JWS compact serialization: {compact_serialization}");

    // The public half of the signing key, as the receiver would obtain it
    // out-of-band (e.g. as JWK JSON from a trusted source).
    let public_jwk = JsonWebKey::from_json(signing_jwk.to_json(OutputControlLevel::PublicOnly))?;

    // Create a new JsonWebSignature.
    let mut jws = JsonWebSignature::new();

    // Set the algorithm constraints based on what is agreed upon or expected
    // from the sender.
    let constraints = AlgorithmConstraints::new(
        ConstraintType::Permit,
        [AlgorithmIdentifier::EcdsaUsingP256CurveAndSha256],
    );
    jws.set_algorithm_constraints(&constraints);

    // Set the compact serialization on the JWS.
    jws.set_compact_serialization(&compact_serialization)?;

    // Check the signature.
    let signature_verified = jws.verify_signature(&public_jwk)?;

    // Do something useful with the result of signature verification.
    println!("JWS Signature is valid: {signature_verified}");
    assert!(signature_verified);

    // Get the payload, or signed content, from the JWS.
    let payload = String::from_utf8_lossy(jws.payload(&public_jwk)?);

    // Do something useful with the content.
    println!("JWS payload: {payload}");

    Ok(())
}
