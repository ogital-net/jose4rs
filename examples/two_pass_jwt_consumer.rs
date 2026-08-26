//! An example of "two-pass" validation of a JWT.
//!
//! In some cases you won't have enough information to set up your JWT consumer
//! without cracking open the JWT first. For example, in some contexts you
//! might not know who issued the token without looking at the "iss" claim
//! inside the JWT.
//!
//! Ported from jose4j's two-pass section of `ExamplesTest.jwtRoundTripExample`.
//! The first pass parses the JWT without verifying; the second pass is set up
//! with information from the first and does the actual validation.

use std::time::{Duration, SystemTime};

use jose4rs::jwa::{AlgorithmConstraints, ConstraintType};
use jose4rs::jwk::JsonWebKeyGenerator;
use jose4rs::jws::{AlgorithmIdentifier, JsonWebSignature};
use jose4rs::jwt::{JwtClaims, JwtConsumerBuilder};
use jose4rs::jwx::JsonWebStructure;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Produce a signed JWT to consume (same setup as jwt_round_trip).
    let rsa_json_web_key =
        JsonWebKeyGenerator::for_signature(AlgorithmIdentifier::RsaUsingSha256).generate()?;

    let mut claims = JwtClaims::new();
    claims.set_issuer("Issuer");
    claims.set_audience(vec!["Audience".to_string()]);
    claims.set_expiration_time(SystemTime::now() + Duration::from_secs(10 * 60));
    claims.set_issued_at(SystemTime::now());
    claims.set_subject("subject");

    let mut jws = JsonWebSignature::new();
    jws.set_payload(claims.to_json());
    jws.set_key_id_header_value("k1");
    jws.set_algorithm(AlgorithmIdentifier::RsaUsingSha256);
    let jwt = jws.compact_serialization(&rsa_json_web_key)?;
    println!("JWT: {jwt}");

    // --- First pass: parse without verifying ---

    // The first pass is basically just used to parse the JWT and read the
    // claims, without checking signatures or doing any validation.
    let first_pass = JsonWebSignature::from_compact_serialization(&jwt)?;
    let unverified_claims_json = String::from_utf8(first_pass.unverified_payload()?.to_vec())?;

    // From the unverified claims we can get the issuer, or whatever else we
    // might need, to lookup or figure out the kind of validation policy to
    // apply.
    let issuer = JwtClaims::parse(&unverified_claims_json)?
        .issuer()
        .map(str::to_owned)
        .ok_or("missing iss claim")?;
    println!("First pass found issuer: {issuer}");

    // Just using the same key here but you might, for example, have JWKS URIs
    // configured for each issuer, which you'd use to resolve the verification
    // key.
    let verification_key = &rsa_json_web_key;

    // Set up the allowed/expected algorithms.
    let algorithm_constraints = AlgorithmConstraints::new(
        ConstraintType::Permit,
        [
            AlgorithmIdentifier::RsaUsingSha256,
            AlgorithmIdentifier::RsaUsingSha384,
        ],
    );

    // --- Second pass: verify and validate ---

    // Using info from the first pass, verify the signature.
    let mut second_pass_jws = JsonWebSignature::new();
    second_pass_jws.set_algorithm_constraints(&algorithm_constraints);
    second_pass_jws.set_compact_serialization(&jwt)?;
    if !second_pass_jws.verify_signature(verification_key)? {
        return Err("invalid JWS signature".into());
    }
    let verified_claims_json =
        String::from_utf8(second_pass_jws.payload(verification_key)?.to_vec())?;

    // And validate the claims.
    let second_pass_consumer = JwtConsumerBuilder::new()
        .set_expected_issuer(&issuer)
        .set_require_expiration_time()
        .set_allowed_clock_skew(Duration::from_secs(30))
        .set_require_subject()
        .set_expected_audience(true, false, &["Audience"])
        .build();

    match second_pass_consumer.process_to_claims(&verified_claims_json) {
        Ok(jwt_claims) => println!("Second pass validation succeeded! {}", jwt_claims.to_json()),
        Err(e) => println!("Invalid JWT! {e}"),
    }

    Ok(())
}
