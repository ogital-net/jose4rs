use std::fmt;

use crate::base64;

/// Represents errors related to JOSE (JSON Object Signing and Encryption).
#[derive(Debug)]
#[non_exhaustive]
pub enum JoseError {
    /// A general error with a message.
    General(String),

    /// JSON parse error with a message.
    InvalidJson(String),

    /// An invalid key error with a message.
    InvalidKey(String),

    /// An invalid algorithm error with a message.
    InvalidAlgorithm(String),

    /// Invalid signature error with a message.
    IntegrityError(String),

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
            | Self::IntegrityError(msg) => f.write_str(msg),
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
    /// Creates a new `JoseError` with a message.
    pub fn new(message: impl Into<String>) -> Self {
        JoseError::General(message.into())
    }

    /// Creates a new `JoseError::InvalidKey` with a message.
    pub fn invalid_key(message: impl Into<String>) -> Self {
        JoseError::InvalidKey(message.into())
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
