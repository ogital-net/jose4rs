//! A nested JWT round trip: a JWS (signed claims) nested inside a JWE.
//!
//! Ported from jose4j's `ExamplesTest.nestedJwtRoundTripExample` — EC keys,
//! ES256 signature, `ECDH-ES+A128KW` key management, `AES_128_CBC_HMAC_SHA_256`
//! content encryption.

use std::time::{Duration, SystemTime};

use jose4rs::jwa::{AlgorithmConstraints, ConstraintType};
use jose4rs::jwe::{ContentEncryptionAlgorithm, JsonWebEncryption, KeyManagementAlgorithm};
use jose4rs::jwk::JsonWebKeyGenerator;
use jose4rs::jws::{AlgorithmIdentifier, JsonWebSignature};
use jose4rs::jwt::{ErrorCode, JwtClaims, JwtConsumerBuilder};
use jose4rs::jwx::{HeaderParameter, JsonWebStructure};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate an EC key pair, which will be used for signing and verification
    // of the JWT, wrapped in a JWK.
    let sender_jwk =
        JsonWebKeyGenerator::for_signature(AlgorithmIdentifier::EcdsaUsingP256CurveAndSha256)
            .generate()?;

    // Give the JWK a Key ID (kid), which is just the polite thing to do.
    let sender_kid = "sender's key";

    // Generate an EC key pair, wrapped in a JWK, which will be used for
    // encryption and decryption of the JWT.
    let receiver_jwk =
        JsonWebKeyGenerator::for_encryption(KeyManagementAlgorithm::EcdhEsA128Kw).generate()?;

    // Give the JWK a Key ID (kid), which is just the polite thing to do.
    let receiver_kid = "receiver's key";

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

    // A JWT is a JWS and/or a JWE with JSON claims as the payload.
    // In this example it is a JWS nested inside a JWE.
    // So we first create a JsonWebSignature object.
    let mut jws = JsonWebSignature::new();

    // The payload of the JWS is JSON content of the JWT Claims.
    jws.set_payload(claims.to_json());

    // The JWT is signed using the sender's private key.
    jws.set_key(&sender_jwk);

    // Set the Key ID (kid) header because it's just the polite thing to do.
    jws.set_key_id_header_value(sender_kid);

    // Set the signature algorithm on the JWT/JWS that will integrity protect
    // the claims.
    jws.set_algorithm(AlgorithmIdentifier::EcdsaUsingP256CurveAndSha256);

    // Sign the JWS and produce the compact serialization, which will be the
    // inner JWT/JWS representation, which is a string consisting of three dot
    // ('.') separated base64url-encoded parts in the form
    // Header.Payload.Signature
    let inner_jwt = jws.compact_serialization()?;

    // The outer JWT is a JWE.
    let mut jwe = JsonWebEncryption::new();

    // The output of the ECDH-ES key agreement will encrypt a randomly
    // generated content encryption key.
    jwe.set_algorithm(KeyManagementAlgorithm::EcdhEsA128Kw);

    // The content encryption key is used to encrypt the payload with a
    // composite AES-CBC / HMAC SHA2 encryption algorithm.
    jwe.set_header(
        HeaderParameter::EncryptionMethod,
        ContentEncryptionAlgorithm::Aes128CbcHmacSha256.name(),
    );

    // We encrypt to the receiver using their public key.
    jwe.set_key(&receiver_jwk);
    jwe.set_key_id_header_value(receiver_kid);

    // A nested JWT requires that the cty (Content Type) header be set to "JWT"
    // in the outer JWT.
    jwe.set_content_type_header_value("JWT");

    // The inner JWT is the payload of the outer JWT.
    jwe.set_payload(inner_jwt);

    // Produce the JWE compact serialization, which is the complete JWT/JWE
    // representation, which is a string consisting of five dot ('.') separated
    // base64url-encoded parts in the form
    // Header.EncryptedKey.IV.Ciphertext.AuthenticationTag
    jwe.encrypt()?;
    let jwt = jwe.compact_serialization()?;

    // Now you can do something with the JWT. Like send it to some other party
    // over the clouds and through the interwebs.
    println!("JWT: {jwt}");

    // --- Consuming the nested JWT ---

    // It is typically good to allow only the expected algorithm(s) in the
    // given context.
    let jwe_alg_constraints = AlgorithmConstraints::new(
        ConstraintType::Permit,
        [KeyManagementAlgorithm::EcdhEsA128Kw],
    );
    let jws_alg_constraints = AlgorithmConstraints::new(
        ConstraintType::Permit,
        [AlgorithmIdentifier::EcdsaUsingP256CurveAndSha256],
    );

    // Decrypt the outer JWE with the receiver's private key.
    let mut decrypt_jwe = JsonWebEncryption::new();
    decrypt_jwe.set_algorithm_constraints(&jwe_alg_constraints);
    decrypt_jwe.set_compact_serialization(&jwt)?;
    decrypt_jwe.set_key(&receiver_jwk);
    let inner_jwt = String::from_utf8(decrypt_jwe.payload()?.to_vec())?;

    // Verify the inner JWS with the sender's public key.
    let mut verify_jws = JsonWebSignature::new();
    verify_jws.set_algorithm_constraints(&jws_alg_constraints);
    verify_jws.set_compact_serialization(&inner_jwt)?;
    verify_jws.set_key(&sender_jwk);
    if !verify_jws.verify_signature()? {
        return Err("invalid JWS signature".into());
    }
    let verified_claims_json = String::from_utf8(verify_jws.payload()?.to_vec())?;

    // Validate the claims. It is typically advisable to require a (reasonable)
    // expiration time, a trusted issuer, and an audience that identifies your
    // system as the intended recipient.
    let jwt_consumer = JwtConsumerBuilder::new()
        .set_require_expiration_time() // the JWT must have an expiration time
        .set_max_future_validity(Duration::from_secs(300 * 60)) // but it can't be too crazy
        .set_require_subject() // the JWT must have a subject claim
        .set_expected_issuer("sender") // whom the JWT needs to have been issued by
        .set_expected_audience(true, false, &["receiver"]) // to whom the JWT is intended for
        .build();

    match jwt_consumer.process_to_claims(&verified_claims_json) {
        Ok(jwt_claims) => println!("JWT validation succeeded! {}", jwt_claims.to_json()),
        Err(e) => {
            // Programmatic access to (some) specific reasons for JWT
            // invalidity is also possible should you want different error
            // handling behavior for certain conditions.
            if e.has_expired() {
                println!("JWT expired: {e}");
            }
            if e.has_error_code(ErrorCode::AudienceInvalid) {
                println!("JWT had wrong audience: {e}");
            }
            println!("Invalid JWT! {e}");
        }
    }

    Ok(())
}
