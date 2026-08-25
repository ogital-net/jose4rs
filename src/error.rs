use std::fmt;

use crate::base64;

// Construction style:
//
// All variants are constructed directly via their variant name (matching
// the `thiserror` convention and Rust stdlib patterns for non-wrapper
// errors):
//
//     return Err(JoseError::InvalidKey("malformed RSA modulus".into()));
//     return Err(JoseError::InvalidKey(format!("missing '{n}' field")));
//     return Err(JoseError::NoMatchingJwk);
//
// There are no per-variant helper methods (`invalid_key(msg)`, etc.).
// `JoseError::new(msg)` exists as a shortcut for `JoseError::General(msg)`.
// `JoseError::new_with_cause(msg, err)` wraps a source error.
// `JoseError::json(err)` is an internal helper for simd_json errors.
//
// Variant policy (read me before adding new variants):
//
// `General` is the deliberate catch-all for *programmer-error* conditions --
// e.g. a `JsonWebEncryption` was decrypted without ever having a key set, or
// an `Okp` key was supplied where the algorithm requires `Ec`. These are
// internal invariants the library surfaces as errors rather than panicking.
// They are NOT security-relevant and downstream consumers can't meaningfully
// act on them. Don't route new variants here.
//
// The security-relevant / externally-observable failure modes each have a
// dedicated variant:
//   * `InvalidKey`       -- malformed or wrong-type key
//   * `InvalidAlgorithm` -- algorithm parameter out of contract (unsupported
//                            alg, PBES2 iteration count out of range, ...)
//   * `InvalidJson`      -- structurally malformed JSON / wrong type where
//                            JSON is expected
//   * `InvalidHeader`    -- JOSE/JWE/JWS protected header missing required
//                            field, has the wrong type, or a critical
//                            extension is unsupported
//   * `MalformedToken`   -- the JOSE compact-serialization wire format is
//                            wrong (wrong number of `.`-separated parts,
//                            missing required JSON member, ...). Use this for
//                            shape/structure errors; use `InvalidHeader` for
//                            content errors *inside* an otherwise well-shaped
//                            header.
//   * `IntegrityError`   -- JWS signature verification failed, or any
//                            cryptographic integrity check at decrypt time
//                            (JWE AEAD tag, AES key unwrap, RSA-OAEP padding,
//                            AEAD open). Use this for any "the bytes checked
//                            out cryptographically" failure.
//   * `JwksFetch`        -- JWKS transport failure (network error,
//                            non-success HTTP status, DNS failure, ...).
//                            Distinguishable from `InvalidJson`, which covers
//                            a JWKS that was fetched but had a malformed body.
//   * `NoMatchingJwk`    -- JWKS was fetched and parsed successfully, but no
//                            key matched the requested kid
//
// `WithCause` exists for wrapping the underlying source error (used for
// base64 and simd_json errors) so that `Error::source()` returns it.

/// Represents errors related to JOSE (JSON Object Signing and Encryption).
#[derive(Debug)]
#[non_exhaustive]
pub enum JoseError {
    /// A general error with a message. Reserved for programmer-error
    /// preconditions (missing struct fields, internal invariant violations);
    /// see the variant policy at the top of this file.
    General(String),

    /// JSON parse error with a message.
    InvalidJson(String),

    /// An invalid key error with a message.
    InvalidKey(String),

    /// An invalid algorithm error with a message.
    InvalidAlgorithm(String),

    /// Invalid JOSE/JWE/JWS header: a required header parameter is missing,
    /// has the wrong type, or a critical extension is unsupported.
    InvalidHeader(String),

    /// The JOSE compact-serialization wire format is malformed (wrong number
    /// of `.`-separated parts, missing required JSON member, malformed
    /// signing input, ...). Distinct from [`InvalidHeader`](JoseError::InvalidHeader) (header content
    /// inside an otherwise well-shaped token) and [`InvalidJson`](JoseError::InvalidJson) (the JSON
    /// itself didn't parse).
    MalformedToken(String),

    /// An integrity / authentication check failed (JWS signature, JWE AEAD
    /// tag, ...).
    IntegrityError(String),

    /// A JWKS fetch failed at the transport layer (network error, non-2xx
    /// HTTP status, DNS failure, ...). Distinguishable from [`InvalidJson`](JoseError::InvalidJson),
    /// which covers a JWKS that was fetched but had a malformed body.
    JwksFetch(String),

    /// The JWKS was fetched and parsed successfully but contained no key
    /// matching the requested `kid`. Unit variant -- the variant name is
    /// the message.
    NoMatchingJwk,

    /// An error with a message and a cause.
    WithCause {
        /// A human-readable description of what went wrong.
        message: String,
        /// The underlying error that caused this one.
        source: Box<dyn std::error::Error + Send + Sync>,
    },
}

impl fmt::Display for JoseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::General(msg)
            | Self::InvalidJson(msg)
            | Self::InvalidKey(msg)
            | Self::InvalidAlgorithm(msg)
            | Self::InvalidHeader(msg)
            | Self::MalformedToken(msg)
            | Self::IntegrityError(msg)
            | Self::JwksFetch(msg) => f.write_str(msg),
            Self::NoMatchingJwk => f.write_str("no JWK matches the requested 'kid'"),
            Self::WithCause { message, source } => write!(f, "{message}: {source}"),
        }
    }
}

impl std::error::Error for JoseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::WithCause { source, .. } => Some(&**source),
            _ => None,
        }
    }
}

impl JoseError {
    /// Creates a new `JoseError::General` with a message. Prefer a more
    /// specific variant (`InvalidKey`, `IntegrityError`, ...) when the
    /// failure mode is identifiable; this is for programmer-error preconditions
    /// -- internal invariants the library surfaces as errors rather than
    /// panicking, and that downstream consumers can't meaningfully act on.
    pub fn new(message: impl Into<String>) -> Self {
        JoseError::General(message.into())
    }

    /// Creates a new `JoseError` with a message and a cause.
    pub fn new_with_cause<E>(message: &str, cause: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        JoseError::WithCause {
            message: message.to_string(),
            source: Box::new(cause),
        }
    }
}

impl From<base64::Error> for JoseError {
    fn from(value: base64::Error) -> Self {
        // Convert base64 error into a JoseError
        JoseError::new_with_cause("base64 encoding/decoding error", value)
    }
}

impl JoseError {
    /// Maps a JSON parse error into a `JoseError`. Internal helper so the
    /// `simd_json` dependency stays out of the public API surface.
    pub(crate) fn json(err: impl std::fmt::Display) -> Self {
        Self::InvalidJson(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn display_for_message_variants() {
        let cases: [(JoseError, &str); 7] = [
            (JoseError::General("g".into()), "g"),
            (JoseError::InvalidJson("j".into()), "j"),
            (JoseError::InvalidKey("k".into()), "k"),
            (JoseError::InvalidAlgorithm("a".into()), "a"),
            (JoseError::InvalidHeader("h".into()), "h"),
            (JoseError::MalformedToken("m".into()), "m"),
            (JoseError::IntegrityError("i".into()), "i"),
        ];
        for (err, expected) in cases {
            assert_eq!(err.to_string(), expected, "for {err:?}");
            assert!(err.source().is_none());
        }
    }

    #[test]
    fn display_for_jwks_variants() {
        let fetch = JoseError::JwksFetch("HTTP 503".into());
        assert_eq!(fetch.to_string(), "HTTP 503");
        assert!(matches!(fetch, JoseError::JwksFetch(_)));

        let no_match = JoseError::NoMatchingJwk;
        assert_eq!(no_match.to_string(), "no JWK matches the requested 'kid'");
        assert!(matches!(no_match, JoseError::NoMatchingJwk));
        assert!(no_match.source().is_none());
    }

    #[test]
    fn with_cause_exposes_source() {
        let inner = std::io::Error::other("boom");
        let err = JoseError::new_with_cause("operation failed", inner);
        assert_eq!(err.to_string(), "operation failed: boom");
        assert!(err.source().is_some());
    }

    #[test]
    fn non_exhaustive_is_open() {
        // If `#[non_exhaustive]` is ever dropped the wildcard arm becomes
        // redundant (no compile error); this test pins down the exhaustive
        // shape we promise today.
        let _ = |e: &JoseError| match e {
            JoseError::General(_)
            | JoseError::InvalidJson(_)
            | JoseError::InvalidKey(_)
            | JoseError::InvalidAlgorithm(_)
            | JoseError::InvalidHeader(_)
            | JoseError::MalformedToken(_)
            | JoseError::IntegrityError(_)
            | JoseError::JwksFetch(_)
            | JoseError::NoMatchingJwk
            | JoseError::WithCause { .. } => {}
        };
    }
}
