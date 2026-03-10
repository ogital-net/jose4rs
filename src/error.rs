use thiserror::Error;

use crate::base64;

/// Represents errors related to JOSE (JSON Object Signing and Encryption).
#[derive(Debug, Error)]
pub enum JoseError {
    /// A general error with a message.
    #[error("{0}")]
    General(String),

    /// JSON parse error with a message.
    #[error("{0}")]
    InvalidJson(String),

    /// An invalid key error with a message.
    #[error("{0}")]
    InvalidKey(String),

    /// An invalid algorithm error with a message.
    #[error("{0}")]
    InvalidAlgorithm(String),

    /// Invalid signature error with a message.
    #[error("{0}")]
    IntegrityError(String),

    /// An error with a message and a cause.
    #[error("{message}: {source}")]
    WithCause {
        message: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
}

impl JoseError {
    /// Creates a new `JoseError` with a message.
    pub fn new(message: impl Into<String>) -> Self {
        JoseError::General(message.into())
    }

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
        JoseError::new_with_cause("Base64 encoding/decoding error", value)
    }
}

impl From<simd_json::Error> for JoseError {
    fn from(value: simd_json::Error) -> Self {
        Self::InvalidJson(format!("{value}"))
    }
}
