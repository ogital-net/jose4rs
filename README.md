# jose4rs

A Rust implementation of the JOSE standards — JWS ([RFC 7515]), JWE ([RFC 7516]), JWK ([RFC 7517]), and JWT ([RFC 7519]) — ported from the Java [jose4j] library. Also implements [RFC 7797] (unencoded/detached JWS payloads) and the JWK thumbprint ([RFC 7638]).

[RFC 7515]: https://tools.ietf.org/html/rfc7515
[RFC 7516]: https://tools.ietf.org/html/rfc7516
[RFC 7517]: https://tools.ietf.org/html/rfc7517
[RFC 7519]: https://tools.ietf.org/html/rfc7519
[RFC 7797]: https://tools.ietf.org/html/rfc7797
[RFC 7638]: https://tools.ietf.org/html/rfc7638
[RFC 9964]: https://tools.ietf.org/html/rfc9964
[jose4j]: https://bitbucket.org/b_c/jose4j

## Status

Early release (0.4.x): the API may still change between minor versions, but the implementation is complete for the standards listed below and is covered by an extensive test suite, including the jose4j test vectors.

This crate contains **no cryptographic primitives of its own**. All cryptography is delegated to [aws-lc-rs] (default) or [BoringSSL] — both widely deployed, independently maintained libraries — selected by feature flag. The crate itself has not undergone an independent security audit; the code under audit would be the parsing, validation, and key-handling logic, not the crypto.

## What is implemented

**JWS** — compact and flattened JSON serializations; detached/unencoded payloads (`b64=false`, RFC 7797); all registered signature algorithms:

| Family | Algorithms |
|--------|------------|
| HMAC | HS256, HS384, HS512 |
| RSA | RS256, RS384, RS512 |
| RSA-PSS | PS256, PS384, PS512 |
| ECDSA | ES256, ES384, ES512, ES256K (secp256k1) |
| EdDSA | Ed25519 |
| ML-DSA (optional) | ML-DSA-44, ML-DSA-65, ML-DSA-87 |
| Unsecured | `none` (blocked by default) |

The general (multi-signature) JSON serialization and unprotected headers are **not** supported.

**JWE** — compact serialization; all registered key management and content encryption algorithms:

| Category | Algorithms |
|----------|------------|
| Key management | RSA1_5, RSA-OAEP, RSA-OAEP-256/384/512, ECDH-ES, ECDH-ES+A128/192/256KW, A128/192/256KW, A128/192/256GCMKW, PBES2-HS256/384/512+A128/192/256KW, `dir` |
| Content encryption | A128/192/256CBC-HS256/384/512, A128/192/256GCM, C20P, XC20P |

C20P and XC20P are non-standard jose4j extensions (ChaCha20-Poly1305 and its extended-nonce variant), included for jose4j interoperability. The JWE JSON serialization is **not** supported. RSA1_5 and the PBES2 algorithms are blocked by default. The `zip` (DEFLATE compression) header is supported behind the optional `zip` feature (see below).

**JWK** - `RSA`, `EC`, `OKP`, and `oct` keys, plus optional `AKP` keys for ML-DSA; JSON and PEM/PKCS#8/SPKI/DER import/export; thumbprints (RFC 7638 and [RFC 9964]); key generation via `JsonWebKeyGenerator`; key sets with kid-based lookup. EC curves: P-256, P-384, P-521, secp256k1. OKP curves: Ed25519, X25519. Ed448 and X448 are **not** supported (not provided by the crypto backends).

**JWT** — claims construction/parsing and a validating consumer modeled on jose4j's `JwtConsumer`: issuer/audience/subject validation, temporal validation (`exp`, `nbf`, `iat`) with configurable clock skew, required-claim enforcement, prohibited claims, and max-future-validity. Nested JWT (JWS inside JWE) is supported.

**JWKS over HTTPS** (optional) — a caching `HttpsJwks` fetcher with `Cache-Control`/`Expires` handling and refresh-on-miss. Bring your own HTTP transport: the blocking trait is under `jwks-https`, the async trait under `jwks-https-async`. Neither pulls in an HTTP client or async runtime.

## Design properties

- **Minimal allocation on hot paths.** Parsed JOSE parts are referenced by offset into a single owned buffer rather than copied. SIMD base64 (`base64-simd`) and `simd-json` are used by default.
- **No panics on attacker-controlled input.** Malformed tokens and keys return `JoseError`; panics are reserved for internal invariants.
- **No in-tree crypto.** All cryptographic operations go through the selected backend; the public API is identical for both.
- **Algorithm constraints.** jose4j-style allow/block lists for `alg` and `enc` headers, applied at parse/decrypt/verify time. Weak algorithms (RSA1_5, PBES2, `none`) are blocked unless explicitly permitted.

[aws-lc-rs]: https://crates.io/crates/aws-lc-rs
[BoringSSL]: https://github.com/google/boringssl

## Features

| Feature | Effect |
|---------|--------|
| `aws-lc` (default) | aws-lc-rs cryptography backend. Mutually exclusive with `boring`. |
| `boring` | BoringSSL cryptography backend. Mutually exclusive with `aws-lc`. |
| `base64-simd` (default) | SIMD-accelerated base64. |
| `base64` | Portable (non-SIMD) base64 fallback. |
| `pq-ml-dsa` | ML-DSA signatures and AKP JWKs ([RFC 9964]); implies `aws-lc`. |
| `jwks-https` | Blocking HTTPS JWKS fetching (bring your own transport). |
| `jwks-https-async` | Async HTTPS JWKS fetching; implies `jwks-https`. |
| `zip` | DEFLATE (`zip: DEF`, RFC 1951) compression of the JWE plaintext, via `flate2`. |

Exactly one cryptography backend must be enabled; selecting both or neither is a compile error.

### `zip` backend selection

The `zip` feature enables `flate2`'s pure-Rust `miniz_oxide` backend (safe, no C compiler needed). To use a faster or zlib-compatible backend, depend on `flate2` in your own crate with the desired feature — Cargo unifies it onto the same `flate2` build:

```toml
[dependencies]
jose4rs = { version = "0.4", features = ["zip"] }
flate2 = { version = "1", features = ["zlib-rs"] }  # or "zlib-ng", "zlib", ...
```

Decompression is capped (default 200 KiB, matching jose4j's `decompress-max-bytes`) to guard against zip bombs; adjust with `JsonWebEncryption::set_max_decompressed_size`.

## Performance

The crate includes Criterion benchmarks comparing against `jsonwebtoken`, `josekit`, and `biscuit` for JWT validate/sign round trips (HS256, RS256, ES256), and against `josekit` for JWE (A128KW, RSA-OAEP). jose4rs is consistently the fastest in these comparisons — typically by a wide margin on JWT validation, owing to the low-allocation parse path and SIMD base64/JSON. Run them yourself:

```sh
cargo bench
```

As a rough indication from runs on an Apple M-series laptop: validating an HS256 JWT (signature + all registered claims) takes about 4 µs, and RS256 about 90 µs. Absolute numbers depend on hardware and token size; the relative ordering against the other crates is stable across runs.

## Testing

255 unit tests plus integration tests, including the jose4j JWE test-vector suite and allocation-profiling tests (`dhat`). Line coverage is approximately 90%. Run with:

```sh
cargo test
cargo llvm-cov   # coverage
```

## Example

Verify a JWS and read its payload:

```rust
use jose4rs::jws::JsonWebSignature;
use jose4rs::jwk::JsonWebKey;

# let compact = "eyJhbGc...";
# let key_json = r#"{"kty":"oct","k":"..."}"#;
let key = JsonWebKey::from_json(key_json)?;
let mut jws = JsonWebSignature::from_compact_serialization(compact)?;
let payload = jws.payload(&key)?; // verifies the signature first
# Ok::<(), jose4rs::error::JoseError>(())
```

See the [examples](examples/) directory for JWE round trips, nested JWT, JWKS fetching, PEM/X.509 key handling, and a two-pass JWT consumer. Most are direct ports of jose4j's `ExamplesTest`.

## License

BSD-2-Clause. See [LICENSE](LICENSE).
