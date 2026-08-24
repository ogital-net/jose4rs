//! An example of signature verification using JSON Web Signature (JWS) where
//! the verification key is selected from a JSON Web Key Set (JWKS) document.
//!
//! Ported from jose4j's `ExamplesTest.parseJwksAndVerifyJwsExample`. A JWKS
//! might be obtained from an HTTPS endpoint controlled by the signer; this
//! example presumes the JWKS JSON has already been acquired by some secure and
//! trusted means. (For fetching over HTTPS with caching, see the `jwks-https`
//! feature and the `jwks_https` example.)

use jose4rs::jwa::{AlgorithmConstraints, ConstraintType};
use jose4rs::jwk::{JsonWebKeySet, VerificationJwkSelector};
use jose4rs::jws::{AlgorithmIdentifier, JsonWebSignature};
use jose4rs::jwx::JsonWebStructure;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // A JSON Web Key (JWK) is a JSON data structure that represents a
    // cryptographic key. A JWK Set document represents one or more JWKs.
    let json_web_key_set_json = r#"{"keys":[
        {"kty":"EC","use":"sig","kid":"the key",
         "x":"amuk6RkDZi-48mKrzgBN_zUZ_9qupIwTZHJjM03qL-4",
         "y":"ZOESj6_dpPiZZR-fJ-XVszQta28Cjgti7JudooQJ0co","crv":"P-256"},
        {"kty":"EC","use":"sig","kid":"other key",
         "x":"eCNZgiEHUpLaCNgYIcvWzfyBlzlaqEaWbt7RFJ4nIBA",
         "y":"UujFME4pNk-nU4B9h4hsetIeSAzhy8DesBgWppiHKPM","crv":"P-256"}
    ]}"#;

    // The complete JWS representation, or compact serialization. Its header
    // carries kid="the key", selecting the first key in the set above.
    let compact_serialization = "eyJhbGciOiJFUzI1NiIsImtpZCI6InRoZSBrZXkifQ.\
        UEFZTE9BRCE.\
        Oq-H1lk5G0rl6oyNM3jR5S0-BZQgTlamIKMApq3RX8Hmh2d2XgB4scvsMzGvE-OlEmDY9Oy0YwNGArLpzXWyjw";

    // Parse the JWKS document. Keys that fail to parse are skipped; a missing
    // "keys" member is an error.
    let json_web_key_set = JsonWebKeySet::from_json(json_web_key_set_json)?;
    println!("JWKS has {} keys", json_web_key_set.len());

    // Create a new JsonWebSignature object and set the compact serialization.
    let mut jws = JsonWebSignature::new();

    // Set the algorithm constraints based on what is agreed upon or expected
    // from the sender.
    let constraints = AlgorithmConstraints::new(
        ConstraintType::Permit,
        [AlgorithmIdentifier::EcdsaUsingP256CurveAndSha256],
    );
    jws.set_algorithm_constraints(&constraints);
    jws.set_compact_serialization(compact_serialization)?;

    // The JWS header indicates which key was used. The VerificationJwkSelector
    // looks at the Key ID, key type (derived from alg), and designated use to
    // select the appropriate key for verification from the set.
    let selector = VerificationJwkSelector::new();
    let jwk = selector
        .select(
            jws.key_id_header_value(),
            jws.algorithm().ok_or("missing alg header")?,
            json_web_key_set.keys(),
        )
        .ok_or("no matching verification key in JWKS")?;
    println!("Selected key with kid: {:?}", jwk.key_id());

    // The verification key on the JWS is the public key from the JWK we pulled
    // from the JWK Set.
    jws.set_key(jwk);

    // Check the signature.
    let signature_verified = jws.verify_signature()?;
    println!("JWS Signature is valid: {signature_verified}");
    assert!(signature_verified);

    // Get the payload, or signed content, from the JWS.
    let payload = String::from_utf8_lossy(jws.payload()?);
    println!("JWS payload: {payload}");

    Ok(())
}
