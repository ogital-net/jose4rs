//! # jose4rs
//!
//! A Rust implementation of the JOSE standards -- [JWS] (RFC 7515), [JWE]
//! (RFC 7516), [JWK] (RFC 7517), and [JWT] (RFC 7519) -- ported from the Java
//! [jose4j] library.
//!
//! [JWS]: https://tools.ietf.org/html/rfc7515
//! [JWE]: https://tools.ietf.org/html/rfc7516
//! [JWK]: https://tools.ietf.org/html/rfc7517
//! [JWT]: https://tools.ietf.org/html/rfc7519
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
//! ## Design goals
//!
//! - **Minimal allocations** on the hot parse/verify/decrypt paths. Decoded
//!   JOSE parts are referenced by offset into a single owned buffer rather
//!   than copied.
//! - **No panics on attacker-controlled input.** Malformed tokens and keys
//!   return [`error::JoseError`]; panics are reserved for internal invariants.
//! - **Backend flexibility.** Cryptography is provided by [aws-lc-rs] (default)
//!   or [BoringSSL], selected by feature flag; the public API is identical.
//!
//! [aws-lc-rs]: https://crates.io/crates/aws-lc-rs
//! [BoringSSL]: https://github.com/google/boringssl
//!
//! ## Features
//!
//! | Feature | Effect |
//! |---------|--------|
//! | `aws-lc` (default) | Use the aws-lc-rs cryptography backend. Mutually exclusive with `boring`. |
//! | `boring` | Use the `BoringSSL` cryptography backend. Mutually exclusive with `aws-lc`. |
//! | `base64-simd` (default) | SIMD-accelerated base64. |
//! | `base64` | Portable (non-SIMD) base64 fallback. |
//! | `jwks-https` | Blocking HTTPS JWKS fetching (bring your own transport). |
//! | `jwks-https-async` | Async HTTPS JWKS fetching; implies `jwks-https`. |
//!
//! Exactly one cryptography backend (`aws-lc` or `boring`) must be enabled;
//! selecting both or neither is a compile error.
//!
//! ## Example
//!
//! Verify a JWS and read its payload:
//!
//! ```no_run
//! use jose4rs::jws::JsonWebSignature;
//! use jose4rs::jwk::JsonWebKey;
//! # use jose4rs::jwx::JsonWebStructure;
//!
//! # let compact = "eyJhbGc...";
//! # let key_json = r#"{"kty":"oct","k":"..."}"#;
//! let key = JsonWebKey::from_json(key_json)?;
//! let mut jws = JsonWebSignature::from_compact_serialization(compact)?;
//! jws.set_key(&key);
//! let payload = jws.payload()?; // verifies the signature first
//! # Ok::<(), jose4rs::error::JoseError>(())
//! ```

// Pedantic clippy is enabled crate-wide; the lints below are opted out because
// they are stylistic preferences or are dominated by FFI noise from the
// aws-lc / boring wrappers (C `c_int` returns, length casts, raw-pointer
// conversions), where the casts are intentional and SAFETY-documented.
#![warn(clippy::pedantic)]
#![allow(
    // FFI-driven numeric/pointer casts in `src/crypto`; values are bounded by
    // the underlying C API contracts.
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    clippy::borrow_as_ptr,
    clippy::ptr_as_ptr,
    clippy::ptr_cast_constness,
    clippy::ref_as_ptr,
    // Stylistic preferences we don't enforce.
    clippy::must_use_candidate,
    clippy::return_self_not_must_use,
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::unreadable_literal,
    clippy::too_many_lines,
    clippy::struct_excessive_bools,
    clippy::match_wildcard_for_single_variants,
    clippy::trivially_copy_pass_by_ref,
    clippy::needless_pass_by_value,
    clippy::unused_self,
    clippy::items_after_statements,
    clippy::module_name_repetitions,
    clippy::elidable_lifetime_names,
    // Per-algorithm lookup tables keep one arm per variant for clarity, even
    // when some bodies coincide; and some crypto fns return `Result` to match
    // their erroring siblings even when a given path can't fail.
    clippy::match_same_arms,
    clippy::unnecessary_wraps
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
/// JOSE algorithms: identifiers and algorithm-constraint enforcement.
pub mod jwa;
/// JSON Web Encryption (JWE, RFC 7516) creation and decryption.
pub mod jwe;
/// JSON Web Keys (JWK, RFC 7517) and key sets (JWKS).
pub mod jwk;
/// JSON Web Signature (JWS, RFC 7515) creation and verification.
pub mod jws;
/// JSON Web Token (JWT, RFC 7519) claims and a validating consumer.
pub mod jwt;
/// Shared JOSE header parameters and the common structure trait.
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
    pub fn new(start_idx: usize, end_idx: usize) -> Self {
        BufferRef { start_idx, end_idx }
    }

    pub fn is_empty(&self) -> bool {
        self.end_idx == 0 || self.end_idx - self.start_idx == 0
    }

    pub fn len(&self) -> usize {
        self.end_idx - self.start_idx
    }

    pub fn get<'a>(&self, s: &'a [u8]) -> &'a [u8] {
        unsafe { s.get_unchecked(self.start_idx..self.end_idx) }
    }

    pub fn get_mut<'a>(&self, s: &'a mut [u8]) -> &'a mut [u8] {
        unsafe { s.get_unchecked_mut(self.start_idx..self.end_idx) }
    }
}
