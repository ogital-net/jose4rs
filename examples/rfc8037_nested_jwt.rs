//! An RFC 8037 nested JWT round trip: `EdDSA` (Ed25519) signed claims nested
//! inside an X25519 `ECDH-ES` encrypted JWE.
//!
//! Ported from jose4j's `ExamplesTest.rfc8037nestedJwtRoundTripExample`.

use std::time::{Duration, SystemTime};

use jose4rs::jwa::{AlgorithmConstraints, ConstraintType};
use jose4rs::jwe::{ContentEncryptionAlgorithm, JsonWebEncryption, KeyManagementAlgorithm};
use jose4rs::jwk::{JsonWebKeyGenerator, OkpCurve};
use jose4rs::jws::{AlgorithmIdentifier, JsonWebSignature};
use jose4rs::jwt::{JwtClaims, JwtConsumerBuilder};
use jose4rs::jwx::{HeaderParameter, JsonWebStructure};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate an OKP JWK with Ed25519, which will be used for signing and
    // verification of the JWT.
    let sender_jwk = JsonWebKeyGenerator::for_signature(AlgorithmIdentifier::EdDsa).generate()?;

    // Give the JWK a Key ID (kid), which is just the polite thing to do.
    let sender_kid = "sender key";

    // Generate an OKP JWK with X25519 which will be used for encryption and
    // decryption of the JWT.
    let receiver_jwk = JsonWebKeyGenerator::for_encryption(KeyManagementAlgorithm::EcdhEs)
        .with_okp_curve(OkpCurve::X25519)
        .generate()?;

    // Give the JWK a Key ID (kid), which is just the polite thing to do.
    let receiver_kid = "receiver key";

    // Create the Claims, which will be the content of the JWT.
    let mut claims = JwtClaims::new();
    claims.set_issuer("sender"); // who creates the token and signs it
    claims.set_audience(vec!["receiver".to_string()]); // to whom the token is intended to be sent
    claims.set_expiration_time(SystemTime::now() + Duration::from_secs(10 * 60)); // 10 minutes from now
    claims.set_jwt_id(format!(
        "{}",
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_nanos()
    )); // a unique identifier for the token
    claims.set_issued_at(SystemTime::now()); // when the token was issued/created (now)
    claims.set_not_before(SystemTime::now() - Duration::from_secs(2 * 60)); // 2 minutes ago
    claims.set_subject("subject"); // the subject/principal is whom the token is about
    claims.set_string_claim("email", "mail@example.com")?; // custom claims can be added
                                                           // Multi-valued claims work too and will end up as a JSON array.
    claims.set_string_array_claim("groups", &["group-1", "other-group", "group-3"])?;

    // Complex claim values (a JSON object here) are not covered by the typed
    // string/array setters, so the "address" claim is merged in via raw JSON.
    let claims_json = claims.to_json();
    let claims_json = claims_json.trim_end_matches('}').to_string()
        + r#","address":{"street_address":"123 Main St","locality":"Anytown","region":"Anystate","country":"US"}}"#;

    // A JWT is a JWS and/or a JWE with JSON claims as the payload.
    // In this example it is a JWS nested inside a JWE.
    let mut jws = JsonWebSignature::new();

    // The payload of the JWS is JSON content of the JWT Claims.
    jws.set_payload(claims_json);

    // Set the Key ID (kid) header because it's just the polite thing to do.
    jws.set_key_id_header_value(sender_kid);

    // Set the signature algorithm on the JWT/JWS that will integrity protect
    // the claims.
    jws.set_algorithm(AlgorithmIdentifier::EdDsa);

    // Sign the JWS and produce the compact serialization, which will be the
    // inner JWT/JWS representation.
    let inner_jwt = jws.compact_serialization(&sender_jwk)?;

    // The outer JWT is a JWE.
    let mut jwe = JsonWebEncryption::new();

    // The output of the X25519 ECDH-ES key agreement and KDF will be the
    // content encryption key.
    jwe.set_algorithm(KeyManagementAlgorithm::EcdhEs);

    // The content encryption key is used to encrypt the payload with a
    // composite AES-CBC / HMAC SHA2 encryption algorithm.
    jwe.set_header(
        HeaderParameter::EncryptionMethod,
        ContentEncryptionAlgorithm::Aes128CbcHmacSha256.name(),
    );

    // We encrypt to the receiver using their public key.
    jwe.set_key_id_header_value(receiver_kid);

    // A nested JWT requires that the cty (Content Type) header be set to "JWT"
    // in the outer JWT.
    jwe.set_content_type_header_value("JWT");

    // The inner JWT is the payload of the outer JWT.
    jwe.set_payload(inner_jwt);

    // Produce the JWE compact serialization, which is the complete JWT/JWE
    // representation.
    jwe.encrypt(&receiver_jwk)?;
    let jwt = jwe.compact_serialization()?;

    // Now you can do something with the JWT. Like send it to some other party
    // over the clouds and through the interwebs.
    println!("JWT: {jwt}");

    // --- Consuming the nested JWT ---

    // It is typically good to allow only the expected algorithm(s) in the
    // given context.
    let jwe_alg_constraints =
        AlgorithmConstraints::new(ConstraintType::Permit, [KeyManagementAlgorithm::EcdhEs]);
    let jws_alg_constraints =
        AlgorithmConstraints::new(ConstraintType::Permit, [AlgorithmIdentifier::EdDsa]);

    // Decrypt the outer JWE with the receiver's private key.
    let mut decrypt_jwe = JsonWebEncryption::new();
    decrypt_jwe.set_algorithm_constraints(&jwe_alg_constraints);
    decrypt_jwe.set_compact_serialization(&jwt)?;
    let inner_jwt = String::from_utf8(decrypt_jwe.payload(&receiver_jwk)?.to_vec())?;

    // Verify the inner JWS with the sender's public key.
    let mut verify_jws = JsonWebSignature::new();
    verify_jws.set_algorithm_constraints(&jws_alg_constraints);
    verify_jws.set_compact_serialization(&inner_jwt)?;
    if !verify_jws.verify_signature(&sender_jwk)? {
        return Err("invalid JWS signature".into());
    }
    let verified_claims_json = String::from_utf8(verify_jws.payload(&sender_jwk)?.to_vec())?;

    // Validate the claims.
    let jwt_consumer = JwtConsumerBuilder::new()
        .set_require_expiration_time()
        .set_max_future_validity(Duration::from_secs(300 * 60))
        .set_require_subject()
        .set_expected_issuer("sender")
        .set_expected_audience(true, false, &["receiver"])
        .build();

    match jwt_consumer.process_to_claims(&verified_claims_json) {
        Ok(jwt_claims) => println!("JWT validation succeeded! {}", jwt_claims.to_json()),
        Err(e) => println!("Invalid JWT! {e}"),
    }

    Ok(())
}
