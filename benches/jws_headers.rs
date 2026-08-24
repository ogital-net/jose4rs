use criterion::{criterion_group, criterion_main, Criterion};
use jose4rs::jwk::JsonWebKey;
use jose4rs::jws::{AlgorithmIdentifier, JsonWebSignature};
use jose4rs::jwx::JsonWebStructure;
use std::hint::black_box;

const KEY_JSON: &str = r#"{"kty":"oct","k":"QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI"}"#;
const CLAIMS_JSON: &str = r#"{"sub":"bench","iat":1700000000,"exp":1900000000}"#;

/// Baseline for building + compact-serializing a JWS with several headers set
/// (alg, kid, plus custom string headers). This is the path #1 touches.
fn bench_jws_build_with_headers(c: &mut Criterion) {
    let key = JsonWebKey::from_json(KEY_JSON).unwrap();

    c.bench_function("jws_build_with_headers", |b| {
        b.iter(|| {
            let mut jws = JsonWebSignature::new();
            jws.set_payload(CLAIMS_JSON);
            jws.set_algorithm(AlgorithmIdentifier::HmacSha256);
            jws.set_header_name("kid", "key-1");
            jws.set_header_name("url", "https://acme.example.com/acct/1");
            jws.set_header_name("nonce", "abc123");
            jws.set_key(&key);
            black_box(jws.compact_serialization().unwrap());
        });
    });
}

/// b64=false detached flattened serialize + verify (the ACME POST pattern).
fn bench_jws_b64_detached(c: &mut Criterion) {
    let key = JsonWebKey::from_json(KEY_JSON).unwrap();
    let payload = br#"{"termsOfServiceAgreed":true}"#;

    c.bench_function("jws_b64_detached_flattened_sign", |b| {
        b.iter(|| {
            let mut jws = JsonWebSignature::new();
            jws.set_algorithm(AlgorithmIdentifier::HmacSha256);
            jws.set_header_name("url", "https://acme.example.com/new-acct");
            jws.set_header_name("nonce", "abc123");
            jws.set_key(&key);
            jws.set_b64(false);
            jws.set_detached_payload(payload);
            black_box(jws.flattened_json_serialization().unwrap());
        });
    });
}

criterion_group!(
    benches,
    bench_jws_build_with_headers,
    bench_jws_b64_detached
);
criterion_main!(benches);
