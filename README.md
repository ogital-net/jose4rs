# jose4rs

A Rust implementation of the JOSE standards — JWS ([RFC 7515]), JWE ([RFC 7516]), JWK ([RFC 7517]), and JWT ([RFC 7519]) — ported from the Java [jose4j] library. Also implements [RFC 7797] (unencoded/detached JWS payloads), JWK thumbprints ([RFC 7638]), and JWK thumbprint URIs ([RFC 9278]).

[RFC 7515]: https://www.rfc-editor.org/rfc/rfc7515
[RFC 7516]: https://www.rfc-editor.org/rfc/rfc7516
[RFC 7517]: https://www.rfc-editor.org/rfc/rfc7517
[RFC 7519]: https://www.rfc-editor.org/rfc/rfc7519
[RFC 7797]: https://www.rfc-editor.org/rfc/rfc7797
[RFC 7638]: https://www.rfc-editor.org/rfc/rfc7638
[RFC 9278]: https://www.rfc-editor.org/rfc/rfc9278
[RFC 9864]: https://www.rfc-editor.org/rfc/rfc9864
[RFC 9964]: https://www.rfc-editor.org/rfc/rfc9964
[jose4j]: https://bitbucket.org/b_c/jose4j

## Installation

```toml
[dependencies]
jose4rs = "0.8"
```

## Status

The API is pre-1.0 and may change between minor releases. Supported algorithms and serializations are listed below.

Cryptographic primitives come from [AWS-LC] (default, via `aws-lc-sys`) or [BoringSSL] (via `boring-sys`). jose4rs handles JOSE parsing, validation, key handling, and the composition of those primitives. The crate itself has not undergone an independent security audit.

### Upgrading from 0.7

- `AlgorithmIdentifier`, `KeyManagementAlgorithm`, and `ContentEncryptionAlgorithm` are now `#[non_exhaustive]`. Downstream matches need a wildcard arm; reject unknown algorithms when matching for policy enforcement.
- The `Algorithm` trait is sealed. Downstream implementations are no longer supported; use the built-in algorithm types with `AlgorithmConstraints`.
- `Ed25519` is now a distinct JWS algorithm identifier. Existing `EdDSA` tokens still work with Ed25519 keys, but allowlists and explicit JWK `alg` values must match the identifier in use. Allow both labels only when interoperability requires both.

## What is implemented

**JWS** — compact and flattened JSON serializations; detached/unencoded payloads (`b64=false`, RFC 7797); supported signature algorithms:

| Family | Algorithms |
|--------|------------|
| HMAC | HS256, HS384, HS512 |
| RSA | RS256, RS384, RS512 |
| RSA-PSS | PS256, PS384, PS512 |
| ECDSA | ES256, ES384, ES512; ES256K (secp256k1, AWS-LC only) |
| EdDSA | `Ed25519` ([RFC 9864]), `EdDSA` (legacy, Ed25519 keys only) |
| ML-DSA (`pq-ml-dsa`, AWS-LC only) | ML-DSA-44, ML-DSA-65, ML-DSA-87 |
| Unsecured | `none` (blocked by default) |

Prefer `Ed25519` for new deployments. Both identifiers use the same signature operation, but algorithm allowlists and a JWK's `alg` restriction distinguish them.

The general (multi-signature) JSON serialization and unprotected headers are **not** supported.

**JWE** — compact serialization; supported algorithms:

| Category | Algorithms |
|----------|------------|
| Key management | RSA1_5, RSA-OAEP, RSA-OAEP-256, RSA-OAEP-384, RSA-OAEP-512, ECDH-ES, ECDH-ES+A128KW, ECDH-ES+A192KW, ECDH-ES+A256KW, A128KW, A192KW, A256KW, A128GCMKW, A192GCMKW, A256GCMKW, PBES2-HS256+A128KW, PBES2-HS384+A192KW, PBES2-HS512+A256KW, `dir` |
| Content encryption | A128CBC-HS256, A192CBC-HS384, A256CBC-HS512, A128GCM, A192GCM, A256GCM, C20P, XC20P |

C20P and XC20P are non-standard jose4j extensions (ChaCha20-Poly1305 and its extended-nonce variant), included for jose4j interoperability. The JWE JSON serialization is **not** supported. RSA1_5 and the PBES2 algorithms are blocked by default. The `zip` (DEFLATE compression) header is supported behind the optional `zip` feature (see below).

**JWK** — `RSA`, `EC`, `OKP`, and `oct` keys, plus optional `AKP` keys for ML-DSA. Includes JSON import/export, key generation via `JsonWebKeyGenerator`, JWK Sets with key-ID lookup, and thumbprints and thumbprint URIs ([RFC 7638], [RFC 9278], and [RFC 9964]). Asymmetric keys support PEM and DER (PKCS#8 private keys and SPKI public keys, plus import of legacy PKCS#1 and SEC1 private keys); `oct` keys use JWK JSON. Supported curves: P-256, P-384, P-521, secp256k1 (AWS-LC only), Ed25519, and X25519. Ed448 and X448 are not supported. X.509 helpers extract public keys from certificates; they do not validate certificate chains.

**JWT** — claims construction, parsing, and validation modeled on jose4j's `JwtConsumer`: issuer, audience, subject, and time checks (`exp`, `nbf`, `iat`), configurable clock skew, required and prohibited claims, and custom validators. `JwtConsumer` validates claims only; it does not verify signatures or decrypt tokens. Authenticate the token with the JWS or JWE API before trusting its claims. For a nested JWT (JWS inside JWE), decrypt the outer JWE, then verify the inner JWS before validating the claims.

**JWKS over HTTPS** (optional) — `HttpsJwks` and `AsyncHttpsJwks` cache keys using `Cache-Control`, `Expires`, and `Age`. By default, even responses with `no-store` or `no-cache` are reused for at least 60 seconds; set the minimum to zero to honor those directives without the floor. A key-ID miss can trigger an early refresh, subject to a 10-second cooldown. Stale-on-error reuse is opt-in. The application supplies the HTTP transport and configures a trusted endpoint; the crate does not select an issuer or endpoint from token headers.

## Design properties

- **Low-allocation hot paths.** Compact JWS and JWE parsing read directly from the input and keep token parts in a single owned buffer rather than allocating separately for each part. SIMD base64 (`base64-simd`) and `simd-json` are used by default.
- **Algorithm constraints.** Use `AlgorithmConstraints` with `ConstraintType::Permit` to pin allowed `alg` values. For JWE, check `encryption_method()` separately if your application restricts `enc`. Choose the policy from trusted application configuration, not from the token. Default constraints block `none` for JWS and RSA1_5 and PBES2 for JWE.
- **Key selection.** Use `VerificationJwkSelector::select_unique` or the cached `select_unique_verification_key` methods to reject ambiguous matches and mismatched explicit JWK `alg` values. Selection does not verify the signature or establish trust in the JWKS.

[AWS-LC]: https://github.com/aws/aws-lc
[BoringSSL]: https://github.com/google/boringssl

## Features

| Feature | Effect |
|---------|--------|
| `aws-lc` (default) | AWS-LC cryptography backend via `aws-lc-sys`. |
| `boring` | BoringSSL cryptography backend via `boring-sys`. |
| `base64-simd` (default) | SIMD-accelerated base64. |
| `base64` | Portable (non-SIMD) base64 fallback. |
| `pq-ml-dsa` | ML-DSA signatures and AKP JWKs ([RFC 9964]); implies `aws-lc`. |
| `jwks-https` | Blocking HTTPS JWKS fetching (bring your own transport). |
| `jwks-https-async` | Async HTTPS JWKS fetching; implies `jwks-https`. |
| `zip` | DEFLATE (`zip: DEF`, RFC 1951) compression of the JWE plaintext, via `flate2`. |

Enable exactly one cryptography backend and at least one base64 feature. `--all-features` is not a valid combination because it enables both crypto backends. For BoringSSL:

```toml
[dependencies]
jose4rs = { version = "0.8", default-features = false, features = ["boring", "base64-simd"] }
```

### `zip` backend selection

The `zip` feature uses `flate2` with its pure-Rust `miniz_oxide` backend. To select a different compression backend, enable the corresponding `flate2` feature in your own crate; Cargo unifies the features:

```toml
[dependencies]
jose4rs = { version = "0.8", features = ["zip"] }
flate2 = { version = "1", features = ["zlib-rs"] }  # or "zlib-ng", "zlib", ...
```

Decompression is capped (default 200 KiB, matching jose4j's `decompress-max-bytes`) to guard against zip bombs; adjust with `JsonWebEncryption::set_max_decompressed_size`.

## Performance

The Criterion benchmarks compare JWT verification and claims validation (HS256, RS256, ES256) with `jsonwebtoken`, `josekit`, and `biscuit`, and selected JWE operations with `josekit`. Results depend on the hardware, backend, token size, and validation policy.

```sh
cargo bench --bench jwt_comparison --bench jwe_comparison
```

## Testing

The suite includes unit and integration tests, the jose4j JWE test vectors, and allocation-profiling tests using `dhat`. Test the crypto backends separately:

```sh
cargo test
cargo test --features pq-ml-dsa,zip,jwks-https-async
cargo test --no-default-features --features boring,base64-simd,zip,jwks-https-async
```

With `cargo-llvm-cov` installed, use `cargo llvm-cov` in place of `cargo test` to measure Rust coverage, including the FFI wrappers. This does not measure coverage inside the native crypto libraries.

## Example

Verify a compact JWS using ES256 and a public key obtained from a trusted source:

```rust
use jose4rs::error::JoseError;
use jose4rs::jwa::{AlgorithmConstraints, ConstraintType};
use jose4rs::jwk::JsonWebKey;
use jose4rs::jws::{AlgorithmIdentifier, JsonWebSignature};
use jose4rs::jwx::JsonWebStructure;

fn verify_es256(compact: &str, trusted_jwk_json: &str) -> Result<Vec<u8>, JoseError> {
	let key = JsonWebKey::from_json(trusted_jwk_json)?;
	let constraints = AlgorithmConstraints::new(
		ConstraintType::Permit,
		[AlgorithmIdentifier::EcdsaUsingP256CurveAndSha256],
	);
	let mut jws = JsonWebSignature::new();
	jws.set_algorithm_constraints(&constraints);
	jws.set_compact_serialization(compact)?;
	let payload = jws.payload(&key)?; // verifies the signature before returning bytes
	Ok(payload.to_vec())
}
```

For runnable walkthroughs, see the [JWT round trip](examples/jwt_round_trip.rs), [JWS verification with a trusted JWKS](examples/jwks_verify_jws.rs), [nested JWT](examples/nested_jwt_round_trip.rs), and [PEM/X.509 key handling](examples/pem_x509_keys.rs). The [examples directory](examples/) also includes blocking and async HTTPS JWKS fetching.

## License

BSD-2-Clause. See [LICENSE](LICENSE).
