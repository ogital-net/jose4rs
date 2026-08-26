//! JSON Web Token is a compact URL-safe means of representing claims/attributes
//! to be transferred between two parties. This example demonstrates producing
//! and consuming a signed JWT.
//!
//! Ported from jose4j's `ExamplesTest.jwtRoundTripExample`. Note that the
//! jose4rs `JwtConsumer` validates claims JSON only — JWS signature
//! verification is performed with `JsonWebSignature` first (the jose4j
//! consumer does both in one shot).

use std::time::{Duration, SystemTime};

use jose4rs::jwa::{AlgorithmConstraints, ConstraintType};
use jose4rs::jwk::JsonWebKeyGenerator;
use jose4rs::jws::{AlgorithmIdentifier, JsonWebSignature};
use jose4rs::jwt::{JwtClaims, JwtConsumerBuilder};
use jose4rs::jwx::JsonWebStructure;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate an RSA key pair, which will be used for signing and
    // verification of the JWT, wrapped in a JWK.
    let rsa_json_web_key =
        JsonWebKeyGenerator::for_signature(AlgorithmIdentifier::RsaUsingSha256).generate()?;

    // Give the JWK a Key ID (kid), which is just the polite thing to do.
    // (jose4rs does not store kid on the JWK itself; keep it alongside.)
    let key_id = "k1";

    // Create the Claims, which will be the content of the JWT.
    let mut claims = JwtClaims::new();
    claims.set_issuer("Issuer"); // who creates the token and signs it
    claims.set_audience(vec!["Audience".to_string()]); // to whom the token is intended to be sent
    claims.set_expiration_time(SystemTime::now() + Duration::from_secs(10 * 60)); // 10 minutes from now
    claims.set_jwt_id(uuid_like_id()); // a unique identifier for the token
    claims.set_issued_at(SystemTime::now()); // when the token was issued/created (now)
    claims.set_not_before(SystemTime::now() - Duration::from_secs(2 * 60)); // 2 minutes ago
    claims.set_subject("subject"); // the subject/principal is whom the token is about
    claims.set_string_claim("email", "mail@example.com")?; // custom claims can be added
                                                           // Multi-valued claims work too and will end up as a JSON array.
    claims.set_string_array_claim("groups", &["group-one", "other-group", "group-three"])?;

    // A JWT is a JWS and/or a JWE with JSON claims as the payload.
    // In this example it is a JWS so we create a JsonWebSignature object.
    let mut jws = JsonWebSignature::new();

    // The payload of the JWS is JSON content of the JWT Claims.
    jws.set_payload(claims.to_json());

    // Set the Key ID (kid) header because it's just the polite thing to do.
    // We only have one key in this example but using a Key ID helps facilitate
    // a smooth key rollover process.
    jws.set_key_id_header_value(key_id);

    // Set the signature algorithm on the JWT/JWS that will integrity protect
    // the claims.
    jws.set_algorithm(AlgorithmIdentifier::RsaUsingSha256);

    // Sign the JWS and produce the compact serialization or the complete
    // JWT/JWS representation, which is a string consisting of three dot ('.')
    // separated base64url-encoded parts in the form Header.Payload.Signature
    // If you wanted to encrypt it, you can simply set this jwt as the payload
    // of a JsonWebEncryption object and set the cty (Content Type) header to
    // "jwt".
    let jwt = jws.compact_serialization(&rsa_json_web_key)?;

    // Now you can do something with the JWT. Like send it to some other party
    // over the clouds and through the interwebs.
    println!("JWT: {jwt}");

    // --- Consuming the JWT ---

    // Verify the signature first. Use AlgorithmConstraints to allow only the
    // expected signature algorithm(s) in the given context (only RS256 here).
    let constraints = AlgorithmConstraints::new(
        ConstraintType::Permit,
        [AlgorithmIdentifier::RsaUsingSha256],
    );
    let mut verifier = JsonWebSignature::new();
    verifier.set_algorithm_constraints(&constraints);
    verifier.set_compact_serialization(&jwt)?;
    if !verifier.verify_signature(&rsa_json_web_key)? {
        return Err("invalid JWS signature".into());
    }
    let verified_claims_json = String::from_utf8(verifier.payload(&rsa_json_web_key)?.to_vec())?;

    // Then validate the claims. The specific validation requirements for a JWT
    // are context dependent, however, it is typically advisable to require a
    // (reasonable) expiration time, a trusted issuer, and an audience that
    // identifies your system as the intended recipient.
    let jwt_consumer = JwtConsumerBuilder::new()
        .set_require_expiration_time() // the JWT must have an expiration time
        .set_allowed_clock_skew(Duration::from_secs(30)) // allow for clock skew
        .set_require_subject() // the JWT must have a subject claim
        .set_expected_issuer("Issuer") // whom the JWT needs to have been issued by
        .set_expected_audience(true, false, &["Audience"]) // to whom the JWT is intended for
        .build();

    match jwt_consumer.process_to_claims(&verified_claims_json) {
        Ok(jwt_claims) => println!("JWT validation succeeded! {}", jwt_claims.to_json()),
        // InvalidJwtError will be returned if the JWT failed processing or
        // validation in any way, hopefully with meaningful explanation(s)
        // about what went wrong.
        Err(e) => println!("Invalid JWT! {e}"),
    }

    Ok(())
}

/// Minimal unique-enough ID for example purposes (no external deps).
fn uuid_like_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    format!("{nanos:032x}")
}
