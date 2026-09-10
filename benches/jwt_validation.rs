use criterion::{Criterion, criterion_group, criterion_main};
use jose4rs::jwt::{JwtClaims, JwtConsumer, JwtConsumerBuilder};
use std::hint::black_box;
use std::time::Duration;

// A representative claims blob exercising every default validator: iss, aud,
// sub, jti, and all three time claims, plus a custom claim.
const CLAIMS_JSON: &str = r#"{
    "iss":"https://issuer.example.com",
    "sub":"user-1234",
    "aud":["api://default","https://client.example.com"],
    "exp":1900000000,
    "nbf":1700000000,
    "iat":1700000000,
    "jti":"id-abc-123",
    "scope":"read write"
}"#;

fn consumer() -> JwtConsumer<'static> {
    JwtConsumerBuilder::new()
        .set_expected_issuer("https://issuer.example.com")
        .set_expected_audience(true, false, &["https://client.example.com"])
        .set_expected_subject("user-1234")
        .set_require_jwt_id()
        .set_require_expiration_time()
        .set_require_not_before()
        .set_require_issued_at()
        .set_evaluation_time_from_seconds(1_800_000_000)
        .set_allowed_clock_skew(Duration::from_secs(30))
        .build()
}

fn bench_jwt_validation(c: &mut Criterion) {
    let consumer = consumer();

    c.bench_function("jwt_validate_all_claims", |b| {
        b.iter(|| {
            let claims = consumer.process_to_claims(black_box(CLAIMS_JSON));
            black_box(claims).unwrap();
        });
    });

    let string_aud = CLAIMS_JSON.replace(
        r#"["api://default","https://client.example.com"]"#,
        r#""https://client.example.com""#,
    );
    let invalid = CLAIMS_JSON
        .replace("https://issuer.example.com", "wrong-issuer")
        .replace("https://client.example.com", "wrong-audience")
        .replace("user-1234", "wrong-subject")
        .replace("1900000000", "1600000000");

    for (name, json) in [("array_aud", CLAIMS_JSON), ("string_aud", &string_aud)] {
        c.bench_function(&format!("jwt_parse_validate/{name}"), |b| {
            b.iter(|| black_box(consumer.process_to_claims(black_box(json)).unwrap()));
        });
        let parsed = JwtClaims::parse(json).unwrap();
        c.bench_function(&format!("jwt_validate_parsed/{name}"), |b| {
            b.iter(|| consumer.validate(black_box(&parsed)).unwrap());
        });
    }

    c.bench_function("jwt_parse_validate/invalid", |b| {
        b.iter(|| black_box(consumer.process_to_claims(black_box(&invalid)).unwrap_err()));
    });
    let parsed = JwtClaims::parse(&invalid).unwrap();
    c.bench_function("jwt_validate_parsed/invalid", |b| {
        b.iter(|| black_box(consumer.validate(black_box(&parsed)).unwrap_err()));
    });

    let minimal = JwtConsumerBuilder::new().build();
    let parsed = JwtClaims::parse(r#"{"sub":"user-1234"}"#).unwrap();
    c.bench_function("jwt_validate_parsed/no_time_claims", |b| {
        b.iter(|| minimal.validate(black_box(&parsed)).unwrap());
    });

    let parsed = JwtClaims::parse(CLAIMS_JSON).unwrap();
    c.bench_function("jwt_revalidate_via_json", |b| {
        b.iter(|| {
            black_box(
                consumer
                    .process_to_claims(&black_box(&parsed).to_json())
                    .unwrap(),
            );
        });
    });
}

criterion_group!(benches, bench_jwt_validation);
criterion_main!(benches);
