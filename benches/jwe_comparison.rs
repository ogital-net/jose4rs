use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

const PLAINTEXT: &[u8] =
    br#"{"iss":"https://issuer.example.com","sub":"user-1234","exp":1900000000}"#;

// -- JWE A128KW + A128GCM ---------------------------------------------------

fn bench_jwe_a128kw(c: &mut Criterion) {
    use jose4rs::jwe::{ContentEncryptionAlgorithm, JsonWebEncryption, KeyManagementAlgorithm};
    use jose4rs::jwk::JsonWebKey;
    use jose4rs::jwx::JsonWebStructure;

    let kek = [0x42u8; 16];
    let key_json = r#"{"kty":"oct","k":"QkJCQkJCQkJCQkJCQkJCQg"}"#;

    // jose4rs setup
    let jose4rs_key = JsonWebKey::from_json(key_json).unwrap();

    // josekit setup
    let josekit_enc = josekit::jwe::A128KW.encrypter_from_bytes(kek).unwrap();
    let josekit_dec = josekit::jwe::A128KW.decrypter_from_bytes(kek).unwrap();
    let mut josekit_header = josekit::jwe::JweHeader::new();
    josekit_header.set_content_encryption("A128GCM");

    // Pre-encrypt tokens for decrypt benchmarks.
    let jose4rs_token = {
        let mut jwe = JsonWebEncryption::new();
        jwe.set_payload(PLAINTEXT);
        jwe.set_algorithm(KeyManagementAlgorithm::A128Kw);
        jwe.set_encryption_method(ContentEncryptionAlgorithm::Aes128Gcm);
        jwe.encrypt(&jose4rs_key).unwrap();
        jwe.compact_serialization().unwrap()
    };
    let josekit_token =
        josekit::jwe::serialize_compact(PLAINTEXT, &josekit_header, &*josekit_enc).unwrap();

    // -- encrypt ------------------------------------------------------------
    {
        let mut group = c.benchmark_group("jwe_a128kw_encrypt");

        group.bench_function("jose4rs", |b| {
            b.iter(|| {
                let mut jwe = JsonWebEncryption::new();
                jwe.set_payload(PLAINTEXT);
                jwe.set_algorithm(KeyManagementAlgorithm::A128Kw);
                jwe.set_encryption_method(ContentEncryptionAlgorithm::Aes128Gcm);
                jwe.encrypt(&jose4rs_key).unwrap();
                black_box(jwe.compact_serialization().unwrap());
            });
        });

        group.bench_function("josekit", |b| {
            b.iter(|| {
                black_box(
                    josekit::jwe::serialize_compact(PLAINTEXT, &josekit_header, &*josekit_enc)
                        .unwrap(),
                );
            });
        });

        group.finish();
    }

    // -- decrypt ------------------------------------------------------------
    {
        let mut group = c.benchmark_group("jwe_a128kw_decrypt");

        group.bench_function("jose4rs", |b| {
            b.iter(|| {
                let mut jwe =
                    JsonWebEncryption::from_compact_serialization(&jose4rs_token).unwrap();
                black_box(jwe.payload(&jose4rs_key).unwrap());
            });
        });

        group.bench_function("josekit", |b| {
            b.iter(|| {
                black_box(
                    josekit::jwe::deserialize_compact(&josekit_token, &*josekit_dec).unwrap(),
                );
            });
        });

        group.finish();
    }
}

// -- JWE RSA-OAEP + A256GCM -------------------------------------------------

fn bench_jwe_rsa_oaep(c: &mut Criterion) {
    use jose4rs::jwe::{ContentEncryptionAlgorithm, JsonWebEncryption, KeyManagementAlgorithm};
    use jose4rs::jwk::{JsonWebKeyGenerator, OutputControlLevel};
    use jose4rs::jwx::JsonWebStructure;

    let jose4rs_key = JsonWebKeyGenerator::for_encryption(KeyManagementAlgorithm::RsaOaep)
        .generate()
        .unwrap();
    let pub_pem = jose4rs_key.to_pem(OutputControlLevel::PublicOnly).unwrap();
    let priv_pem = jose4rs_key
        .to_pem(OutputControlLevel::IncludePrivate)
        .unwrap();

    // josekit setup
    let josekit_enc = josekit::jwe::RSA_OAEP
        .encrypter_from_pem(pub_pem.as_bytes())
        .unwrap();
    let josekit_dec = josekit::jwe::RSA_OAEP
        .decrypter_from_pem(priv_pem.as_bytes())
        .unwrap();
    let mut josekit_header = josekit::jwe::JweHeader::new();
    josekit_header.set_content_encryption("A256GCM");

    // Pre-encrypt tokens for decrypt benchmarks.
    let jose4rs_token = {
        let mut jwe = JsonWebEncryption::new();
        jwe.set_payload(PLAINTEXT);
        jwe.set_algorithm(KeyManagementAlgorithm::RsaOaep);
        jwe.set_encryption_method(ContentEncryptionAlgorithm::Aes256Gcm);
        jwe.encrypt(&jose4rs_key).unwrap();
        jwe.compact_serialization().unwrap()
    };
    let josekit_token =
        josekit::jwe::serialize_compact(PLAINTEXT, &josekit_header, &*josekit_enc).unwrap();

    // -- encrypt ------------------------------------------------------------
    {
        let mut group = c.benchmark_group("jwe_rsa_oaep_encrypt");

        group.bench_function("jose4rs", |b| {
            b.iter(|| {
                let mut jwe = JsonWebEncryption::new();
                jwe.set_payload(PLAINTEXT);
                jwe.set_algorithm(KeyManagementAlgorithm::RsaOaep);
                jwe.set_encryption_method(ContentEncryptionAlgorithm::Aes256Gcm);
                jwe.encrypt(&jose4rs_key).unwrap();
                black_box(jwe.compact_serialization().unwrap());
            });
        });

        group.bench_function("josekit", |b| {
            b.iter(|| {
                black_box(
                    josekit::jwe::serialize_compact(PLAINTEXT, &josekit_header, &*josekit_enc)
                        .unwrap(),
                );
            });
        });

        group.finish();
    }

    // -- decrypt ------------------------------------------------------------
    {
        let mut group = c.benchmark_group("jwe_rsa_oaep_decrypt");

        group.bench_function("jose4rs", |b| {
            b.iter(|| {
                let mut jwe =
                    JsonWebEncryption::from_compact_serialization(&jose4rs_token).unwrap();
                black_box(jwe.payload(&jose4rs_key).unwrap());
            });
        });

        group.bench_function("josekit", |b| {
            b.iter(|| {
                black_box(
                    josekit::jwe::deserialize_compact(&josekit_token, &*josekit_dec).unwrap(),
                );
            });
        });

        group.finish();
    }
}

criterion_group!(benches, bench_jwe_a128kw, bench_jwe_rsa_oaep);
criterion_main!(benches);
