//! Allocation-profiling tests using dhat.
//!
//! Each test installs dhat's `#[global_allocator]` and exercises a hot path,
//! then prints allocation statistics.  Run with:
//!
//!     cargo test --test dhat_alloc_profiling -- --nocapture
//!
//! The dhat `testing` feature gives us `dhat::HeapStats` so we can assert
//! upper bounds on total allocations / bytes and catch regressions.

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

use jose4rs::jwa::{AlgorithmConstraints, ConstraintType};
use jose4rs::jwe::{ContentEncryptionAlgorithm, JsonWebEncryption, KeyManagementAlgorithm};
use jose4rs::jwk::{JsonWebKey, JsonWebKeyGenerator};
use jose4rs::jws::{AlgorithmIdentifier, JsonWebSignature};
use jose4rs::jwt::{JwtClaims, JwtConsumerBuilder};
use jose4rs::jwx::JsonWebStructure;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, SystemTime};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// dhat permits only one live `Profiler` per process. `cargo test` runs tests
/// on multiple threads within one process, so concurrent profiler creation
/// panics ("creating a profiler while a profiler is already running").
/// Serialize profiler lifetime across tests with a process-wide mutex: each
/// test holds the guard until it (and its profiler) is done.
static PROFILER_LOCK: Mutex<()> = Mutex::new(());

/// Builds a testing profiler while holding [`PROFILER_LOCK`]. Returns the lock
/// guard and the profiler; the guard is first in the tuple so the profiler is
/// dropped first (reverse drop order within the binding would otherwise apply
/// to locals, but returning a tuple keeps both alive for the test body). Bind
/// as `let (_lock, _profiler) = testing_profiler();`.
fn testing_profiler() -> (MutexGuard<'static, ()>, dhat::Profiler) {
    // Tolerate a poisoned lock: if one test panics while holding the guard,
    // the remaining tests should still run (the mutex still serializes access
    // to the single-profiler constraint). Unwrapping here would cascade an
    // unrelated test's panic into every other profiling test.
    let guard = PROFILER_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let profiler = dhat::Profiler::builder().testing().build();
    (guard, profiler)
}

fn print_stats(label: &str, stats: &dhat::HeapStats) {
    println!("--- dhat: {label} ---");
    println!("  total blocks : {}", stats.total_blocks);
    println!("  total bytes  : {}", stats.total_bytes);
    println!("  max blocks   : {}", stats.max_blocks);
    println!("  max bytes    : {}", stats.max_bytes);
    println!("  curr blocks  : {}", stats.curr_blocks);
    println!("  curr bytes   : {}", stats.curr_bytes);
}

// ---------------------------------------------------------------------------
// JWS – HMAC-SHA256 sign + verify round-trip
// ---------------------------------------------------------------------------

#[test]
fn profile_jws_hs256_sign_verify() {
    let (_lock, _profiler) = testing_profiler();

    // Key generation is setup cost – measure it, but don't count it against
    // the sign/verify budget.
    let key = JsonWebKeyGenerator::for_signature(AlgorithmIdentifier::HmacSha256)
        .generate()
        .unwrap();

    // --- sign ---
    let mut jws = JsonWebSignature::new();
    jws.set_payload(b"Hello DHAT profiling!");
    jws.set_algorithm(AlgorithmIdentifier::HmacSha256);
    let compact = jws.compact_serialization(&key).unwrap();

    // --- verify ---
    let constraints =
        AlgorithmConstraints::new(ConstraintType::Permit, [AlgorithmIdentifier::HmacSha256]);
    let mut verifier = JsonWebSignature::from_compact_serialization(&compact).unwrap();
    verifier.set_algorithm_constraints(&constraints);
    assert!(verifier.verify_signature(&key).unwrap());
    let payload = verifier.payload(&key).unwrap();
    assert_eq!(payload, b"Hello DHAT profiling!");

    let stats = dhat::HeapStats::get();
    print_stats("JWS HS256 sign + verify", &stats);
}

// ---------------------------------------------------------------------------
// JWS – Ed25519 verify (RFC 8037 test vector)
// ---------------------------------------------------------------------------

#[test]
fn profile_jws_ed25519_verify() {
    let (_lock, _profiler) = testing_profiler();

    let key_json =
        r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#;
    let compact = "eyJhbGciOiJFZERTQSJ9.\
        RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.\
        hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg";

    let key = JsonWebKey::from_json(key_json).unwrap();
    let constraints =
        AlgorithmConstraints::new(ConstraintType::Permit, [AlgorithmIdentifier::EdDsa]);

    let mut jws = JsonWebSignature::from_compact_serialization(compact).unwrap();
    jws.set_algorithm_constraints(&constraints);
    assert!(jws.verify_signature(&key).unwrap());
    let _ = jws.payload(&key).unwrap();

    let stats = dhat::HeapStats::get();
    print_stats("JWS Ed25519 verify", &stats);
}

// ---------------------------------------------------------------------------
// JWS – RS256 verify
// ---------------------------------------------------------------------------

#[test]
fn profile_jws_rs256_verify() {
    let (_lock, _profiler) = testing_profiler();

    let compact = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.\
        eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.\
        NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ";

    let pub_key = "-----BEGIN PUBLIC KEY-----\n\
        MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo\n\
        4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u\n\
        +qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh\n\
        kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ\n\
        0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg\n\
        cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc\n\
        mwIDAQAB\n\
        -----END PUBLIC KEY-----\n";

    let key = JsonWebKey::from_pem(pub_key).unwrap();
    let constraints = AlgorithmConstraints::new(
        ConstraintType::Permit,
        [AlgorithmIdentifier::RsaUsingSha256],
    );

    let mut jws = JsonWebSignature::from_compact_serialization(compact).unwrap();
    jws.set_algorithm_constraints(&constraints);
    assert!(jws.verify_signature(&key).unwrap());
    let _ = jws.payload(&key).unwrap();

    let stats = dhat::HeapStats::get();
    print_stats("JWS RS256 verify", &stats);
}

// ---------------------------------------------------------------------------
// JWE – direct + AES-128-GCM decrypt
// ---------------------------------------------------------------------------

#[test]
fn profile_jwe_direct_aes128gcm_decrypt() {
    let (_lock, _profiler) = testing_profiler();

    let key_json = r#"{"kty":"oct","k":"IJRDL_AZnmxvH-peVRKlqQ"}"#;
    let compact = "eyJlbmMiOiJBMTI4R0NNIiwiYWxnIjoiZGlyIn0..BSnJ5pKU_3r48H7j.AlyooSZG5J9ptIB0.5iOBvkIeRM1Eolu7IuCl-A";

    let key = JsonWebKey::from_json(key_json).unwrap();
    let mut jwe = JsonWebEncryption::from_compact_serialization(compact).unwrap();
    let payload = jwe.payload(&key).unwrap();
    assert_eq!(payload, b"Hello world!");

    let stats = dhat::HeapStats::get();
    print_stats("JWE direct AES-128-GCM decrypt", &stats);
}

// ---------------------------------------------------------------------------
// JWE – A128KW + AES-128-GCM decrypt
// ---------------------------------------------------------------------------

#[test]
fn profile_jwe_a128kw_aes128gcm_decrypt() {
    let (_lock, _profiler) = testing_profiler();

    let key_json = r#"{"kty":"oct","k":"FIGC8LqlqWb54bYvJ5SmQQ"}"#;
    let compact = "eyJlbmMiOiJBMTI4R0NNIiwiYWxnIjoiQTEyOEtXIn0.7resHW5tgwGvw55a2Oip5eh2N2aIY8LD.WZ_NOTsConezmjhY.APwSSzZtm9UFHJ2w.mU7HqwUp60rrGKUAQYk3KQ";

    let key = JsonWebKey::from_json(key_json).unwrap();
    let mut jwe = JsonWebEncryption::from_compact_serialization(compact).unwrap();
    let payload = jwe.payload(&key).unwrap();
    assert_eq!(payload, b"Hello world!");

    let stats = dhat::HeapStats::get();
    print_stats("JWE A128KW + AES-128-GCM decrypt", &stats);
}

// ---------------------------------------------------------------------------
// JWT – claims parse + validate
// ---------------------------------------------------------------------------

#[test]
fn profile_jwt_claims_parse_and_validate() {
    let (_lock, _profiler) = testing_profiler();

    // Build a realistic claims JSON with several registered + custom claims.
    let now = SystemTime::now();
    let mut claims = JwtClaims::new();
    claims.set_issuer("https://example.com");
    claims.set_audience(vec!["api.example.com".to_string()]);
    claims.set_subject("user-42");
    claims.set_expiration_time(now + Duration::from_secs(600));
    claims.set_not_before(now - Duration::from_secs(60));
    claims.set_issued_at(now);
    claims.set_jwt_id("unique-id-1234");
    claims
        .set_string_claim("email", "user@example.com")
        .unwrap();
    claims
        .set_string_array_claim("groups", &["admin", "users"])
        .unwrap();
    let json = claims.to_json();

    // Re-parse (this is the hot path in token consumption).
    let parsed = JwtClaims::parse(&json).unwrap();
    assert_eq!(parsed.issuer(), Some("https://example.com"));
    assert_eq!(parsed.subject(), Some("user-42"));

    // Run the consumer validation pipeline.
    let consumer = JwtConsumerBuilder::new()
        .set_require_expiration_time()
        .set_allowed_clock_skew(Duration::from_secs(30))
        .set_require_subject()
        .set_expected_issuer("https://example.com")
        .set_expected_audience(true, false, &["api.example.com"])
        .build();
    consumer.process_to_claims(&json).unwrap();

    let stats = dhat::HeapStats::get();
    print_stats("JWT claims parse + validate", &stats);
}

// ---------------------------------------------------------------------------
// JWT – breakdown of allocation sources
// ---------------------------------------------------------------------------

#[test]
fn profile_jwt_claims_parse_only() {
    let (_lock, _profiler) = testing_profiler();

    let json = r#"{"iss":"https://example.com","aud":["api.example.com"],"sub":"user-42","exp":1900000000,"nbf":1700000000,"iat":1700000000,"jti":"unique-id-1234","email":"user@example.com","groups":["admin","users"]}"#;

    let stats_before = dhat::HeapStats::get();
    let parsed = JwtClaims::parse(json).unwrap();
    let stats_after = dhat::HeapStats::get();

    assert_eq!(parsed.issuer(), Some("https://example.com"));
    assert_eq!(parsed.subject(), Some("user-42"));

    println!("--- dhat: JwtClaims::parse() only ---");
    println!(
        "  blocks: {} (total {} - baseline {})",
        stats_after.total_blocks - stats_before.total_blocks,
        stats_after.total_blocks,
        stats_before.total_blocks,
    );
    println!(
        "  bytes:  {} (total {} - baseline {})",
        stats_after.total_bytes - stats_before.total_bytes,
        stats_after.total_bytes,
        stats_before.total_bytes,
    );
    println!(
        "  live blocks after parse: {}",
        stats_after.curr_blocks - stats_before.curr_blocks
    );
    println!(
        "  live bytes after parse:  {}",
        stats_after.curr_bytes - stats_before.curr_bytes
    );

    drop(parsed);
    let stats_dropped = dhat::HeapStats::get();
    println!(
        "  freed by drop: {} blocks, {} bytes",
        stats_after.curr_blocks - stats_dropped.curr_blocks + stats_before.curr_blocks,
        stats_after.curr_bytes - stats_dropped.curr_bytes + stats_before.curr_bytes,
    );
}

#[test]
fn profile_jwt_audience_call() {
    let (_lock, _profiler) = testing_profiler();

    let json = r#"{"iss":"https://example.com","aud":["api.example.com","other.example.com"],"sub":"user-42","exp":1900000000}"#;
    let claims = JwtClaims::parse(json).unwrap();

    let stats_before = dhat::HeapStats::get();
    let aud = claims.audience();
    let stats_after = dhat::HeapStats::get();

    assert!(aud.is_some());
    println!("--- dhat: JwtClaims::audience() ---");
    println!(
        "  blocks: {}",
        stats_after.total_blocks - stats_before.total_blocks
    );
    println!(
        "  bytes:  {}",
        stats_after.total_bytes - stats_before.total_bytes
    );

    drop(aud);
    let stats_dropped = dhat::HeapStats::get();
    // `curr_*` is the live-allocation watermark; unrelated background allocs
    // between the two reads can push it either way, so use saturating_sub to
    // avoid a debug-build subtraction overflow in this diagnostic print.
    println!(
        "  freed by drop: {} blocks, {} bytes",
        stats_after
            .curr_blocks
            .saturating_sub(stats_dropped.curr_blocks),
        stats_after
            .curr_bytes
            .saturating_sub(stats_dropped.curr_bytes),
    );
}

#[test]
fn profile_jwt_consumer_validate() {
    let (_lock, _profiler) = testing_profiler();

    let json = r#"{"iss":"https://example.com","aud":["api.example.com"],"sub":"user-42","exp":1900000000,"nbf":1700000000,"iat":1700000000,"jti":"unique-id-1234"}"#;

    let consumer = JwtConsumerBuilder::new()
        .set_require_expiration_time()
        .set_allowed_clock_skew(Duration::from_secs(30))
        .set_require_subject()
        .set_expected_issuer("https://example.com")
        .set_expected_audience(true, false, &["api.example.com"])
        .build();

    let stats_before = dhat::HeapStats::get();
    let _claims = consumer.process_to_claims(json).unwrap();
    let stats_after = dhat::HeapStats::get();

    println!("--- dhat: JwtConsumer::process_to_claims() ---");
    println!(
        "  blocks: {}",
        stats_after.total_blocks - stats_before.total_blocks
    );
    println!(
        "  bytes:  {}",
        stats_after.total_bytes - stats_before.total_bytes
    );
}

#[test]
fn profile_jwt_to_json() {
    let (_lock, _profiler) = testing_profiler();

    let json_str = r#"{"iss":"https://example.com","aud":["api.example.com"],"sub":"user-42","exp":1900000000,"nbf":1700000000,"iat":1700000000,"jti":"unique-id-1234","email":"user@example.com","groups":["admin","users"]}"#;
    let claims = JwtClaims::parse(json_str).unwrap();

    let stats_before = dhat::HeapStats::get();
    let output = claims.to_json();
    let stats_after = dhat::HeapStats::get();

    assert!(!output.is_empty());
    println!("--- dhat: JwtClaims::to_json() ---");
    println!(
        "  blocks: {}",
        stats_after.total_blocks - stats_before.total_blocks
    );
    println!(
        "  bytes:  {}",
        stats_after.total_bytes - stats_before.total_bytes
    );
}

// ---------------------------------------------------------------------------
// Full JWT round-trip: sign → verify → validate
// ---------------------------------------------------------------------------

#[test]
fn profile_jwt_full_round_trip() {
    let (_lock, _profiler) = testing_profiler();

    let key = JsonWebKeyGenerator::for_signature(AlgorithmIdentifier::HmacSha256)
        .generate()
        .unwrap();

    // Build claims.
    let now = SystemTime::now();
    let mut claims = JwtClaims::new();
    claims.set_issuer("https://auth.example.com");
    claims.set_audience(vec!["https://api.example.com".to_string()]);
    claims.set_subject("subject-99");
    claims.set_expiration_time(now + Duration::from_secs(300));
    claims.set_not_before(now - Duration::from_secs(120));
    claims.set_issued_at(now);

    // Sign as JWS.
    let mut jws = JsonWebSignature::new();
    jws.set_payload(claims.to_json());
    jws.set_algorithm(AlgorithmIdentifier::HmacSha256);
    let jwt = jws.compact_serialization(&key).unwrap();

    // Verify signature.
    let constraints =
        AlgorithmConstraints::new(ConstraintType::Permit, [AlgorithmIdentifier::HmacSha256]);
    let mut verifier = JsonWebSignature::from_compact_serialization(&jwt).unwrap();
    verifier.set_algorithm_constraints(&constraints);
    assert!(verifier.verify_signature(&key).unwrap());
    let verified_json = String::from_utf8(verifier.payload(&key).unwrap().to_vec()).unwrap();

    // Validate claims.
    let consumer = JwtConsumerBuilder::new()
        .set_require_expiration_time()
        .set_allowed_clock_skew(Duration::from_secs(30))
        .set_require_subject()
        .set_expected_issuer("https://auth.example.com")
        .set_expected_audience(true, false, &["https://api.example.com"])
        .build();
    consumer.process_to_claims(&verified_json).unwrap();

    let stats = dhat::HeapStats::get();
    print_stats("JWT full round-trip (HS256)", &stats);
}

// ===========================================================================
// Step-by-step JWS / JWE allocation audits
// ===========================================================================

fn delta(before: &dhat::HeapStats, after: &dhat::HeapStats) -> (u64, u64) {
    (
        after.total_blocks - before.total_blocks,
        after.total_bytes - before.total_bytes,
    )
}

fn print_delta(label: &str, before: &dhat::HeapStats, after: &dhat::HeapStats) {
    let (blk, bytes) = delta(before, after);
    println!("  {label:<40} {blk:>3} blocks  {bytes:>6} bytes");
}

// ---------------------------------------------------------------------------
// JWS parse (set_compact_serialization) – step by step
// ---------------------------------------------------------------------------

#[test]
fn audit_jws_parse_steps() {
    let (_lock, _profiler) = testing_profiler();

    // Pre-build a compact JWS outside the measurement window.
    let key_json =
        r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#;
    let compact = "eyJhbGciOiJFZERTQSJ9.\
        RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.\
        hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg";

    println!("--- audit: JWS EdDSA parse steps ---");

    // 1. Key parse
    let s0 = dhat::HeapStats::get();
    let key = JsonWebKey::from_json(key_json).unwrap();
    let s1 = dhat::HeapStats::get();
    print_delta("JsonWebKey::from_json(oct/okp)", &s0, &s1);

    // 2. JWS parse
    let s2 = dhat::HeapStats::get();
    let jws = JsonWebSignature::from_compact_serialization(compact).unwrap();
    let s3 = dhat::HeapStats::get();
    print_delta("from_compact_serialization", &s2, &s3);

    // 3. (set_key removed; key is a per-call arg now)
    let s4 = dhat::HeapStats::get();
    let s5 = dhat::HeapStats::get();
    print_delta("verify_signature-prep", &s4, &s5);

    // 4. verify_signature
    let s6 = dhat::HeapStats::get();
    assert!(jws.verify_signature(&key).unwrap());
    let s7 = dhat::HeapStats::get();
    print_delta("verify_signature", &s6, &s7);

    // 5. payload (re-verifies, then returns slice)
    let s8 = dhat::HeapStats::get();
    let _ = jws.payload(&key).unwrap();
    let s9 = dhat::HeapStats::get();
    print_delta("payload()", &s8, &s9);

    println!(
        "  {:<40} {:>3} blocks  {:>6} bytes",
        "TOTAL", s9.total_blocks, s9.total_bytes
    );
}

// ---------------------------------------------------------------------------
// JWS sign (compact_serialization) – step by step
// ---------------------------------------------------------------------------

#[test]
fn audit_jws_sign_steps() {
    let (_lock, _profiler) = testing_profiler();

    println!("--- audit: JWS HS256 sign steps ---");

    // 1. Key generation
    let s0 = dhat::HeapStats::get();
    let key = JsonWebKeyGenerator::for_signature(AlgorithmIdentifier::HmacSha256)
        .generate()
        .unwrap();
    let s1 = dhat::HeapStats::get();
    print_delta("key generation", &s0, &s1);

    // 2. Build JWS struct (new + set_payload + set_algorithm)
    let s2 = dhat::HeapStats::get();
    let mut jws = JsonWebSignature::new();
    jws.set_payload(b"Hello DHAT profiling!");
    jws.set_algorithm(AlgorithmIdentifier::HmacSha256);
    let s3 = dhat::HeapStats::get();
    print_delta("new + set_payload + set_algorithm", &s2, &s3);

    // 3. compact_serialization (sign + encode)
    let s4 = dhat::HeapStats::get();
    let _compact = jws.compact_serialization(&key).unwrap();
    let s5 = dhat::HeapStats::get();
    print_delta("compact_serialization()", &s4, &s5);

    println!(
        "  {:<40} {:>3} blocks  {:>6} bytes",
        "TOTAL", s5.total_blocks, s5.total_bytes
    );
}

// ---------------------------------------------------------------------------
// JWE parse + decrypt – step by step
// ---------------------------------------------------------------------------

#[test]
fn audit_jwe_parse_decrypt_steps() {
    let (_lock, _profiler) = testing_profiler();

    let key_json = r#"{"kty":"oct","k":"IJRDL_AZnmxvH-peVRKlqQ"}"#;
    let compact = "eyJlbmMiOiJBMTI4R0NNIiwiYWxnIjoiZGlyIn0..BSnJ5pKU_3r48H7j.AlyooSZG5J9ptIB0.5iOBvkIeRM1Eolu7IuCl-A";

    println!("--- audit: JWE direct+A128GCM parse+decrypt steps ---");

    // 1. Key parse
    let s0 = dhat::HeapStats::get();
    let key = JsonWebKey::from_json(key_json).unwrap();
    let s1 = dhat::HeapStats::get();
    print_delta("JsonWebKey::from_json", &s0, &s1);

    // 2. JWE parse
    let s2 = dhat::HeapStats::get();
    let mut jwe = JsonWebEncryption::from_compact_serialization(compact).unwrap();
    let s3 = dhat::HeapStats::get();
    print_delta("from_compact_serialization", &s2, &s3);

    // 3. (set_key removed; key is a per-call arg now)
    let s4 = dhat::HeapStats::get();
    let s5 = dhat::HeapStats::get();
    print_delta("decrypt-prep", &s4, &s5);

    // 4. decrypt (payload)
    let s6 = dhat::HeapStats::get();
    let payload = jwe.payload(&key).unwrap();
    let s7 = dhat::HeapStats::get();
    print_delta("payload() [decrypt]", &s6, &s7);

    assert_eq!(payload, b"Hello world!");
    println!(
        "  {:<40} {:>3} blocks  {:>6} bytes",
        "TOTAL", s7.total_blocks, s7.total_bytes
    );
}

// ---------------------------------------------------------------------------
// JWE A128KW parse + decrypt – step by step
// ---------------------------------------------------------------------------

#[test]
fn audit_jwe_keywrap_parse_decrypt_steps() {
    let (_lock, _profiler) = testing_profiler();

    let key_json = r#"{"kty":"oct","k":"FIGC8LqlqWb54bYvJ5SmQQ"}"#;
    let compact = "eyJlbmMiOiJBMTI4R0NNIiwiYWxnIjoiQTEyOEtXIn0.7resHW5tgwGvw55a2Oip5eh2N2aIY8LD.WZ_NOTsConezmjhY.APwSSzZtm9UFHJ2w.mU7HqwUp60rrGKUAQYk3KQ";

    println!("--- audit: JWE A128KW+A128GCM parse+decrypt steps ---");

    let s0 = dhat::HeapStats::get();
    let key = JsonWebKey::from_json(key_json).unwrap();
    let s1 = dhat::HeapStats::get();
    print_delta("JsonWebKey::from_json", &s0, &s1);

    let s2 = dhat::HeapStats::get();
    let mut jwe = JsonWebEncryption::from_compact_serialization(compact).unwrap();
    let s3 = dhat::HeapStats::get();
    print_delta("from_compact_serialization", &s2, &s3);

    let s4 = dhat::HeapStats::get();
    let payload = jwe.payload(&key).unwrap();
    let s5 = dhat::HeapStats::get();
    print_delta("payload() [decrypt]", &s4, &s5);

    assert_eq!(payload, b"Hello world!");
    println!(
        "  {:<40} {:>3} blocks  {:>6} bytes",
        "TOTAL", s5.total_blocks, s5.total_bytes
    );
}

// ---------------------------------------------------------------------------
// JWE encrypt + serialize – step by step
// ---------------------------------------------------------------------------

#[test]
fn audit_jwe_encrypt_serialize_steps() {
    let (_lock, _profiler) = testing_profiler();

    let key_json = r#"{"kty":"oct","k":"FIGC8LqlqWb54bYvJ5SmQQ"}"#;

    println!("--- audit: JWE A128KW+A128GCM encrypt+serialize steps ---");

    let s0 = dhat::HeapStats::get();
    let key = JsonWebKey::from_json(key_json).unwrap();
    let s1 = dhat::HeapStats::get();
    print_delta("JsonWebKey::from_json", &s0, &s1);

    // Build JWE
    let s2 = dhat::HeapStats::get();
    let mut jwe = JsonWebEncryption::new();
    jwe.set_payload("Hello world!");
    jwe.set_algorithm(KeyManagementAlgorithm::A128Kw);
    jwe.set_encryption_method(ContentEncryptionAlgorithm::Aes128Gcm);
    let s3 = dhat::HeapStats::get();
    print_delta("new + set headers", &s2, &s3);

    // Encrypt
    let s4 = dhat::HeapStats::get();
    jwe.encrypt(&key).unwrap();
    let s5 = dhat::HeapStats::get();
    print_delta("encrypt()", &s4, &s5);

    // Serialize
    let s6 = dhat::HeapStats::get();
    let _compact = jwe.compact_serialization().unwrap();
    let s7 = dhat::HeapStats::get();
    print_delta("compact_serialization()", &s6, &s7);

    println!(
        "  {:<40} {:>3} blocks  {:>6} bytes",
        "TOTAL", s7.total_blocks, s7.total_bytes
    );
}
