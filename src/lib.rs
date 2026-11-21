//! # jose4rs
//!
//! A Rust implementation of the JOSE standards -- [JWS] (RFC 7515), [JWE]
//! (RFC 7516), [JWK] (RFC 7517), and [JWT] (RFC 7519) -- ported from the Java
//! [jose4j] library.
//!
//! [JWS]: https://www.rfc-editor.org/rfc/rfc7515
//! [JWE]: https://www.rfc-editor.org/rfc/rfc7516
//! [JWK]: https://www.rfc-editor.org/rfc/rfc7517
//! [JWT]: https://www.rfc-editor.org/rfc/rfc7519
//! [jose4j]: https://bitbucket.org/b_c/jose4j
//!
//! ## Modules
//!
//! - [`jwk`] -- JSON Web Keys and key sets, plus optional HTTPS JWKS fetching.
//! - [`jws`] -- JSON Web Signature creation and verification.
//! - [`jwe`] -- JSON Web Encryption encryption and decryption.
//! - [`jwt`] -- JWT claims and a validating consumer.
//! - [`jwa`] -- algorithm identifiers and algorithm constraints.
//! - [`jwx`] -- shared JOSE header parameters and structure traits.
//! - [`error`] -- the crate's error type.
//!
//! ## Verification and validation
//!
//! Parsing does not authenticate a token. Choose keys and permitted algorithms
//! from trusted application configuration. Verify a JWS or decrypt a JWE as
//! required by the token's profile before passing its claims to
//! [`jwt::JwtConsumer`], which validates claims but does not authenticate tokens.
//!
//! Compact JWS and JWE parsing store token parts in a single owned buffer.
//! Cryptographic primitives come from [AWS-LC] via `aws-lc-sys` (default) or
//! [BoringSSL] via `boring-sys`. jose4rs itself has not undergone an independent
//! security audit.
//!
//! [AWS-LC]: https://github.com/aws/aws-lc
//! [BoringSSL]: https://github.com/google/boringssl
//!
//! ## Features
//!
//! | Feature | Effect |
//! |---------|--------|
//! | `aws-lc` (default) | AWS-LC cryptography backend. Required for ES256K (secp256k1). |
//! | `boring` | BoringSSL cryptography backend. |
//! | `base64-simd` (default) | SIMD-accelerated base64. |
//! | `base64` | Portable (non-SIMD) base64 fallback. |
//! | `pq-ml-dsa` | ML-DSA signatures and AKP JWKs (RFC 9964); implies `aws-lc`. |
//! | `jwks-https` | Blocking HTTPS JWKS fetching (bring your own transport). |
//! | `jwks-https-async` | Async HTTPS JWKS fetching; implies `jwks-https`. |
//! | `zip` | DEFLATE (`zip: DEF`) compression for JWE. |
//!
//! Enable exactly one cryptography backend and at least one base64 feature.
//! To use BoringSSL, disable default features and enable `boring` and either
//! `base64-simd` or `base64`. `--all-features` is not supported because it
//! enables both cryptography backends.
//!
//! ## Example
//!
//! Sign a compact JWS, then verify it using the public key and an ES256-only
//! policy. In an application, obtain the verification key from a trusted source.
//!
//! ```
//! use jose4rs::jwa::{AlgorithmConstraints, ConstraintType};
//! use jose4rs::jwk::JsonWebKeyGenerator;
//! use jose4rs::jws::{AlgorithmIdentifier, JsonWebSignature};
//! use jose4rs::jwx::JsonWebStructure;
//!
//! let alg = AlgorithmIdentifier::EcdsaUsingP256CurveAndSha256;
//! let signing_key = JsonWebKeyGenerator::for_signature(alg).generate()?;
//! let mut signer = JsonWebSignature::new();
//! signer.set_algorithm(alg);
//! signer.set_payload(b"hello JOSE");
//! let compact = signer.compact_serialization(&signing_key)?;
//! let public_key = signing_key.into_public()?;
//!
//! let constraints = AlgorithmConstraints::new(ConstraintType::Permit, [alg]);
//! let mut verifier = JsonWebSignature::new();
//! verifier.set_algorithm_constraints(&constraints);
//! verifier.set_compact_serialization(&compact)?;
//! assert_eq!(verifier.payload(&public_key)?, b"hello JOSE");
//! # Ok::<(), jose4rs::error::JoseError>(())
//! ```

// Pedantic clippy is enabled crate-wide; the lints below are opted out because
// they are stylistic preferences or are dominated by FFI noise from the
// aws-lc / boring wrappers (C `c_int` returns, length casts, raw-pointer
// conversions), where the casts are intentional and SAFETY-documented.
#![warn(clippy::pedantic, unreachable_pub)]
#![allow(
    // Stylistic preferences we don't enforce.
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::unreadable_literal,
    clippy::too_many_lines,
    clippy::elidable_lifetime_names,
    // Per-algorithm lookup tables keep one arm per variant for clarity, even
    // when some bodies coincide; and some crypto fns return `Result` to match
    // their erroring siblings even when a given path can't fail.
    clippy::match_same_arms,
)]

// The two cryptography backends are mutually exclusive: both provide the same
// FFI symbols, so enabling both would be ambiguous (and linking them together
// is unsupported). Fail at compile time with a clear message rather than a
// confusing cascade of duplicate-symbol / missing-import errors.
#[cfg(all(feature = "aws-lc", feature = "boring"))]
compile_error!(
    "features `aws-lc` and `boring` are mutually exclusive; enable exactly one \
     cryptography backend (e.g. `--no-default-features --features boring,base64-simd`)"
);

// At least one cryptography backend is required. Without one, no EVP/AEAD/RSA
// symbols exist and the crate cannot build; say so directly.
#[cfg(not(any(feature = "aws-lc", feature = "boring")))]
compile_error!(
    "no cryptography backend selected; enable exactly one of `aws-lc` (default) \
     or `boring`"
);

mod base64;
mod crypto;
/// The crate error type, [`error::JoseError`].
pub mod error;
pub mod jwa;
pub mod jwe;
pub mod jwk;
pub mod jws;
pub mod jwt;
pub mod jwx;

/// An index pair into a per-struct backing buffer, used to reference decoded
/// JOSE parts without copying them.
///
/// A `BufferRef` owns nothing; it is only `{start_idx, end_idx}` into a buffer
/// owned elsewhere (e.g. the `buffer: Vec<u8>` on [`jwe::JsonWebEncryption`] or
/// [`jws::JsonWebSignature`]). The buffer is always passed in to [`BufferRef::get`]
/// / [`BufferRef::get_mut`].
///
/// # Usage notes
///
/// * **Zero-copy, but re-fetch after growth.** The backing `Vec` may reallocate
///   and move to a different memory block when it grows (e.g. another part is
///   appended). Any `&[u8]` / `&mut [u8]` obtained from [`get`](BufferRef::get) /
///   [`get_mut`](BufferRef::get_mut) borrows the *current* location, so it must
///   not be held across a push/`extend_from_slice`/etc. that could reallocate.
///   Re-fetch the slice after any such mutation.
/// * **Indices, not pointers.** Because the struct stores offsets rather than
///   raw pointers, the `BufferRef` itself stays valid across buffer growth -- only
///   the borrowed slice it produces does not.
/// * **`get_unchecked`.** `get`/`get_mut` use `get_unchecked` for speed; the
///   invariant is that `start_idx <= end_idx <= buffer.len()` always holds for
///   the buffer this `BufferRef` was created against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BufferRef {
    start_idx: usize,
    end_idx: usize,
}

impl BufferRef {
    pub(crate) fn new(start_idx: usize, end_idx: usize) -> Self {
        BufferRef { start_idx, end_idx }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.end_idx == 0 || self.end_idx - self.start_idx == 0
    }

    pub(crate) fn len(&self) -> usize {
        self.end_idx - self.start_idx
    }

    pub(crate) fn get<'a>(&self, s: &'a [u8]) -> &'a [u8] {
        unsafe { s.get_unchecked(self.start_idx..self.end_idx) }
    }

    pub(crate) fn get_mut<'a>(&self, s: &'a mut [u8]) -> &'a mut [u8] {
        unsafe { s.get_unchecked_mut(self.start_idx..self.end_idx) }
    }
}
