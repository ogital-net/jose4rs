use criterion::{criterion_group, criterion_main, Criterion};
use serde::{Deserialize, Serialize};
use std::hint::black_box;
use std::time::Duration;

// -- Shared constants & helpers ---------------------------------------------
//
// Every library validates the same logical JWT: a token carrying iss, sub,
// aud, exp, nbf, and iat.  Each consumer validates:
//   - signature (HS256 or RS256)
//   - iss == ISS
//   - aud contains AUD
//   - sub == SUB
//   - exp has not passed
//   - nbf has passed
//
// exp is set far in the future so tokens never expire during bench runs.

const ISS: &str = "https://issuer.example.com";
const SUB: &str = "user-1234";
const AUD: &str = "https://client.example.com";

// jose4rs / josekit use pre-serialized JSON.
const CLAIMS_JSON: &str = r#"{"iss":"https://issuer.example.com","sub":"user-1234","aud":"https://client.example.com","exp":1900000000,"nbf":1700000000,"iat":1700000000}"#;

// jsonwebtoken uses serde.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Claims {
    iss: String,
    sub: String,
    aud: String,
    exp: u64,
    nbf: u64,
    iat: u64,
}

// jose4rs JWT consumer -- reused across HS256/RS256 benches.
fn make_jose4rs_consumer() -> jose4rs::jwt::JwtConsumer {
    jose4rs::jwt::JwtConsumerBuilder::new()
        .set_expected_issuer(ISS)
        .set_expected_audience(true, false, &[AUD])
        .set_expected_subject(SUB)
        .set_require_expiration_time()
        .set_require_not_before()
        .set_require_issued_at()
        .set_evaluation_time_from_seconds(1_800_000_000)
        .set_allowed_clock_skew(Duration::from_secs(30))
        .build()
}

// josekit JWT validator.
fn make_josekit_validator() -> josekit::jwt::JwtPayloadValidator {
    use std::time::UNIX_EPOCH;
    let eval_time = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
    let mut v = josekit::jwt::JwtPayloadValidator::new();
    v.set_base_time(eval_time);
    v.set_issuer(ISS);
    v.set_subject(SUB);
    v.set_audience(AUD);
    v
}

// biscuit validation options.
fn make_biscuit_validation() -> biscuit::ValidationOptions {
    use biscuit::{ClaimPresenceOptions, Presence, TemporalOptions, Validation};
    use chrono::{TimeZone, Utc};
    let eval_time = Utc.timestamp_opt(1_800_000_000, 0).unwrap();
    biscuit::ValidationOptions {
        claim_presence_options: ClaimPresenceOptions {
            expiry: Presence::Required,
            not_before: Presence::Required,
            issued_at: Presence::Required,
            issuer: Presence::Required,
            audience: Presence::Required,
            subject: Presence::Required,
            ..Default::default()
        },
        temporal_options: TemporalOptions {
            now: Some(eval_time),
            epsilon: chrono::Duration::seconds(30),
        },
        expiry: Validation::Validate(()),
        not_before: Validation::Validate(()),
        issued_at: Validation::Validate(chrono::Duration::MAX),
        issuer: Validation::Validate(ISS.into()),
        audience: Validation::Validate(AUD.into()),
    }
}

// -- HS256 full JWT consume -------------------------------------------------

fn bench_hs256_jwt(c: &mut Criterion) {
    let hmac_key = [0x42u8; 32];
    let key_json = r#"{"kty":"oct","k":"QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI"}"#;

    // Pre-construct keys / signers / validators (not measured).
    let jose4rs_key = jose4rs::jwk::JsonWebKey::from_json(key_json).unwrap();
    let jose4rs_consumer = make_jose4rs_consumer();

    let jwt_dec_key = jsonwebtoken::DecodingKey::from_secret(&hmac_key);
    let jwt_validation = {
        let mut v = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
        v.set_issuer(&[ISS]);
        v.set_audience(&[AUD]);
        v.sub = Some(SUB.into());
        v.validate_nbf = true;
        v.set_required_spec_claims(&["exp", "nbf", "iss", "aud", "sub"]);
        v
    };

    let josekit_verifier = josekit::jws::HS256.verifier_from_bytes(hmac_key).unwrap();
    let josekit_validator = make_josekit_validator();

    let biscuit_secret = biscuit::jws::Secret::Bytes(hmac_key.to_vec());
    let biscuit_opts = make_biscuit_validation();

    // Sign one token with jose4rs -- all libraries verify the same bytes.
    let token = {
        use jose4rs::jws::{AlgorithmIdentifier, JsonWebSignature};
        use jose4rs::jwx::JsonWebStructure;
        let mut jws = JsonWebSignature::new();
        jws.set_payload(CLAIMS_JSON);
        jws.set_algorithm(AlgorithmIdentifier::HmacSha256);
        jws.compact_serialization(&jose4rs_key).unwrap()
    };

    let mut group = c.benchmark_group("hs256_jwt_consume");

    group.bench_function("jose4rs", |b| {
        use jose4rs::jws::JsonWebSignature;
        b.iter(|| {
            let jws = JsonWebSignature::from_compact_serialization(&token).unwrap();
            let payload = jws.payload(&jose4rs_key).unwrap();
            let payload = std::str::from_utf8(payload).unwrap();
            black_box(jose4rs_consumer.process_to_claims(payload).unwrap());
        });
    });

    group.bench_function("jsonwebtoken", |b| {
        b.iter(|| {
            black_box(
                jsonwebtoken::decode::<Claims>(&token, &jwt_dec_key, &jwt_validation).unwrap(),
            );
        });
    });

    group.bench_function("josekit", |b| {
        b.iter(|| {
            let (payload, _header) =
                josekit::jwt::decode_with_verifier(&token, &*josekit_verifier).unwrap();
            josekit_validator.validate(&payload).unwrap();
            black_box(payload);
        });
    });

    group.bench_function("biscuit", |b| {
        use biscuit::jwa::SignatureAlgorithm;
        use biscuit::Empty;
        b.iter(|| {
            let decoded = biscuit::JWT::<Empty, Empty>::new_encoded(&token)
                .into_decoded(&biscuit_secret, SignatureAlgorithm::HS256)
                .unwrap();
            decoded
                .payload()
                .unwrap()
                .registered
                .validate(biscuit_opts.clone())
                .unwrap();
            black_box(decoded);
        });
    });

    group.finish();
}

// -- RS256 full JWT consume -------------------------------------------------

fn bench_rs256_jwt(c: &mut Criterion) {
    use jose4rs::jwk::{JsonWebKeyGenerator, OutputControlLevel};
    use jose4rs::jws::{AlgorithmIdentifier, JsonWebSignature};

    // Generate one RSA 2048-bit key pair, export in multiple formats.
    let jose4rs_key = JsonWebKeyGenerator::for_signature(AlgorithmIdentifier::RsaUsingSha256)
        .generate()
        .unwrap();
    let pub_pem = jose4rs_key.to_pem(OutputControlLevel::PublicOnly).unwrap();
    let jose4rs_consumer = make_jose4rs_consumer();

    // jsonwebtoken
    let jwt_dec_key = jsonwebtoken::DecodingKey::from_rsa_pem(pub_pem.as_bytes()).unwrap();
    let jwt_validation = {
        let mut v = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        v.set_issuer(&[ISS]);
        v.set_audience(&[AUD]);
        v.sub = Some(SUB.into());
        v.validate_nbf = true;
        v.set_required_spec_claims(&["exp", "nbf", "iss", "aud", "sub"]);
        v
    };

    // josekit
    let josekit_verifier = josekit::jws::RS256
        .verifier_from_pem(pub_pem.as_bytes())
        .unwrap();
    let josekit_validator = make_josekit_validator();

    // biscuit -- construct from PKCS#8 DER via ring
    let priv_der = jose4rs_key.to_der().unwrap();
    let biscuit_verify_secret = {
        let kp = ring::signature::RsaKeyPair::from_pkcs8(&priv_der).unwrap();
        let pub_key_der = kp.public().as_ref().to_vec();
        biscuit::jws::Secret::PublicKey(pub_key_der)
    };
    let biscuit_opts = make_biscuit_validation();

    // Sign one token with jose4rs -- all libraries verify the same bytes.
    let token = {
        use jose4rs::jwx::JsonWebStructure;
        let mut jws = JsonWebSignature::new();
        jws.set_payload(CLAIMS_JSON);
        jws.set_algorithm(AlgorithmIdentifier::RsaUsingSha256);
        jws.compact_serialization(&jose4rs_key).unwrap()
    };

    let mut group = c.benchmark_group("rs256_jwt_consume");

    group.bench_function("jose4rs", |b| {
        b.iter(|| {
            let jws = JsonWebSignature::from_compact_serialization(&token).unwrap();
            let payload = jws.payload(&jose4rs_key).unwrap();
            let payload = std::str::from_utf8(payload).unwrap();
            black_box(jose4rs_consumer.process_to_claims(payload).unwrap());
        });
    });

    group.bench_function("jsonwebtoken", |b| {
        b.iter(|| {
            black_box(
                jsonwebtoken::decode::<Claims>(&token, &jwt_dec_key, &jwt_validation).unwrap(),
            );
        });
    });

    group.bench_function("josekit", |b| {
        b.iter(|| {
            let (payload, _header) =
                josekit::jwt::decode_with_verifier(&token, &*josekit_verifier).unwrap();
            josekit_validator.validate(&payload).unwrap();
            black_box(payload);
        });
    });

    group.bench_function("biscuit", |b| {
        use biscuit::jwa::SignatureAlgorithm;
        use biscuit::Empty;
        b.iter(|| {
            let decoded = biscuit::JWT::<Empty, Empty>::new_encoded(&token)
                .into_decoded(&biscuit_verify_secret, SignatureAlgorithm::RS256)
                .unwrap();
            decoded
                .payload()
                .unwrap()
                .registered
                .validate(biscuit_opts.clone())
                .unwrap();
            black_box(decoded);
        });
    });

    group.finish();
}

// -- ES256 full JWT consume -------------------------------------------------

fn bench_es256_jwt(c: &mut Criterion) {
    use jose4rs::jwk::{JsonWebKeyGenerator, OutputControlLevel};
    use jose4rs::jws::{AlgorithmIdentifier, JsonWebSignature};

    let jose4rs_key =
        JsonWebKeyGenerator::for_signature(AlgorithmIdentifier::EcdsaUsingP256CurveAndSha256)
            .generate()
            .unwrap();
    let pub_pem = jose4rs_key.to_pem(OutputControlLevel::PublicOnly).unwrap();
    let jose4rs_consumer = make_jose4rs_consumer();

    // jsonwebtoken
    let jwt_dec_key = jsonwebtoken::DecodingKey::from_ec_pem(pub_pem.as_bytes()).unwrap();
    let jwt_validation = {
        let mut v = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
        v.set_issuer(&[ISS]);
        v.set_audience(&[AUD]);
        v.sub = Some(SUB.into());
        v.validate_nbf = true;
        v.set_required_spec_claims(&["exp", "nbf", "iss", "aud", "sub"]);
        v
    };

    // josekit
    let josekit_verifier = josekit::jws::ES256
        .verifier_from_pem(pub_pem.as_bytes())
        .unwrap();
    let josekit_validator = make_josekit_validator();

    // biscuit -- EcdsaKeyPair from PKCS#8 DER via ring
    let priv_der = jose4rs_key.to_der().unwrap();
    let biscuit_verify_secret = {
        use ring::signature::KeyPair;
        let kp = ring::signature::EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &priv_der,
            &ring::rand::SystemRandom::new(),
        )
        .unwrap();
        biscuit::jws::Secret::PublicKey(kp.public_key().as_ref().to_vec())
    };
    let biscuit_opts = make_biscuit_validation();

    // Sign one token with jose4rs -- all libraries verify the same bytes.
    let token = {
        use jose4rs::jwx::JsonWebStructure;
        let mut jws = JsonWebSignature::new();
        jws.set_payload(CLAIMS_JSON);
        jws.set_algorithm(AlgorithmIdentifier::EcdsaUsingP256CurveAndSha256);
        jws.compact_serialization(&jose4rs_key).unwrap()
    };

    let mut group = c.benchmark_group("es256_jwt_consume");

    group.bench_function("jose4rs", |b| {
        b.iter(|| {
            let jws = JsonWebSignature::from_compact_serialization(&token).unwrap();
            let payload = jws.payload(&jose4rs_key).unwrap();
            let payload = std::str::from_utf8(payload).unwrap();
            black_box(jose4rs_consumer.process_to_claims(payload).unwrap());
        });
    });

    group.bench_function("jsonwebtoken", |b| {
        b.iter(|| {
            black_box(
                jsonwebtoken::decode::<Claims>(&token, &jwt_dec_key, &jwt_validation).unwrap(),
            );
        });
    });

    group.bench_function("josekit", |b| {
        b.iter(|| {
            let (payload, _header) =
                josekit::jwt::decode_with_verifier(&token, &*josekit_verifier).unwrap();
            josekit_validator.validate(&payload).unwrap();
            black_box(payload);
        });
    });

    group.bench_function("biscuit", |b| {
        use biscuit::jwa::SignatureAlgorithm;
        use biscuit::Empty;
        b.iter(|| {
            let decoded = biscuit::JWT::<Empty, Empty>::new_encoded(&token)
                .into_decoded(&biscuit_verify_secret, SignatureAlgorithm::ES256)
                .unwrap();
            decoded
                .payload()
                .unwrap()
                .registered
                .validate(biscuit_opts.clone())
                .unwrap();
            black_box(decoded);
        });
    });

    group.finish();
}

criterion_group!(benches, bench_hs256_jwt, bench_rs256_jwt, bench_es256_jwt);
criterion_main!(benches);
