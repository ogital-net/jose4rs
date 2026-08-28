use criterion::{Criterion, criterion_group, criterion_main};
use jose4rs::jwt::JwtConsumerBuilder;
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

fn bench_jwt_validation(c: &mut Criterion) {
    let consumer = JwtConsumerBuilder::new()
        .set_expected_issuer("https://issuer.example.com")
        .set_expected_audience(true, false, &["https://client.example.com"])
        .set_expected_subject("user-1234")
        .set_require_jwt_id()
        .set_require_expiration_time()
        .set_require_not_before()
        .set_require_issued_at()
        .set_evaluation_time_from_seconds(1_800_000_000)
        .set_allowed_clock_skew(Duration::from_secs(30))
        .build();

    c.bench_function("jwt_validate_all_claims", |b| {
        b.iter(|| {
            let claims = consumer.process_to_claims(black_box(CLAIMS_JSON));
            black_box(claims).unwrap();
        });
    });
}

criterion_group!(benches, bench_jwt_validation);
criterion_main!(benches);
