//! An example of signing using JSON Web Signature (JWS).
//!
//! Ported from jose4j's `ExamplesTest.jwsSigningExample`, except that the key
//! pair is generated here (jose4rs does not bundle the spec's example keys).

use jose4rs::jwk::{JsonWebKeyGenerator, OutputControlLevel};
use jose4rs::jws::{AlgorithmIdentifier, JsonWebSignature};
use jose4rs::jwx::JsonWebStructure;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The content that will be signed.
    let example_payload = "This is some text that is to be signed.";

    // Generate an EC key pair, which will be used for signing, wrapped in a JWK.
    // Note that your application will need to determine where/how to get the key.
    let jwk = JsonWebKeyGenerator::for_signature(AlgorithmIdentifier::EcdsaUsingP256CurveAndSha256)
        .generate()?;
    println!(
        "Signing JWK (public part): {}",
        jwk.to_json(OutputControlLevel::PublicOnly)
    );

    // Create a new JsonWebSignature.
    let mut jws = JsonWebSignature::new();

    // Set the payload, or signed content, on the JWS object.
    jws.set_payload(example_payload);

    // Set the signature algorithm on the JWS that will integrity protect the payload.
    jws.set_algorithm(AlgorithmIdentifier::EcdsaUsingP256CurveAndSha256);

    // Set the signing key on the JWS.
    jws.set_key(&jwk);

    // Sign the JWS and produce the compact serialization or complete JWS
    // representation, which is a string consisting of three dot ('.') separated
    // base64url-encoded parts in the form Header.Payload.Signature
    let jws_compact_serialization = jws.compact_serialization()?;

    // Do something useful with your JWS.
    println!("{jws_compact_serialization}");

    Ok(())
}
