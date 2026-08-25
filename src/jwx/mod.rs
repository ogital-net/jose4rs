use crate::{error::JoseError, jwa::AlgorithmConstraints, jwk::JsonWebKey};
use simd_json::{
    base::{ValueAsArray as _, ValueAsScalar as _},
    prelude::ValueObjectAccess,
};

mod header_param;

pub use header_param::HeaderParameter;

/// The operations common to a JOSE object ([`crate::jws::JsonWebSignature`] and
/// [`crate::jwe::JsonWebEncryption`]).
///
/// The trait is generic over the algorithm type `A` used for algorithm
/// constraints ([`crate::jws::AlgorithmIdentifier`] for JWS,
/// [`crate::jwe::KeyManagementAlgorithm`] for JWE), and parameterized by the
/// lifetime `'a` of the borrowed key and constraints.
pub trait JsonWebStructure<'a, A> {
    /// Parses and replaces the structure's contents from a compact serialization.
    ///
    /// # Errors
    /// Returns an error if the serialization is malformed.
    fn set_compact_serialization(
        &mut self,
        compact_serialization: &'a (impl AsRef<[u8]> + ?Sized),
    ) -> Result<(), JoseError>;

    /// Produces the compact serialization of the structure.
    ///
    /// For a JWS this signs the payload; for a JWE it encrypts it.
    ///
    /// # Errors
    /// Returns an error if the structure is incomplete or signing/encryption fails.
    fn compact_serialization(&self) -> Result<String, JoseError>;

    /// Sets the payload to be signed or encrypted.
    fn set_payload(&mut self, payload: impl AsRef<[u8]>);

    /// Returns the payload.
    ///
    /// For a JWS this verifies the signature first; for a JWE it decrypts first.
    ///
    /// # Errors
    /// Returns an error if verification/decryption fails or the payload is absent.
    fn payload(&mut self) -> Result<&[u8], JoseError>;

    /// Sets a typed header parameter to a string value.
    fn set_header(&mut self, param: HeaderParameter, value: impl Into<String>) {
        self.set_header_name(param.name(), value);
    }

    /// Returns the value of a typed header parameter, if present.
    fn header(&self, param: HeaderParameter) -> Option<&str> {
        self.header_name(param.name())
    }

    /// Sets an arbitrary header parameter by name.
    fn set_header_name(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.set_header_value(name, simd_json::owned::Value::from(value.into()));
    }

    /// Sets an arbitrary header parameter by name to a raw JSON value.
    ///
    /// Unlike [`set_header_name`](Self::set_header_name) -- which always stores
    /// the value as a JSON string -- this inserts the value as-is, so an object
    /// (e.g. an embedded `jwk`) or an array stays a structured JSON value.
    fn set_header_value(&mut self, name: impl Into<String>, value: simd_json::owned::Value);

    /// Returns the value of an arbitrary header parameter by name, if present.
    fn header_name(&self, name: impl AsRef<str>) -> Option<&str>;

    /// Embeds a public JWK in the `jwk` header parameter (RFC 7515 Section 4.1.3),
    /// as a JSON object -- the form ACME's `new-account` requires.
    ///
    /// The key is serialized at the public output level, so no private
    /// material is embedded.
    fn set_jwk_header(&mut self, key: &crate::jwk::JsonWebKey) {
        use crate::jwk::OutputControlLevel;
        let json = key.to_json(OutputControlLevel::PublicOnly);
        // A JWK serialization is always a JSON object.
        let value =
            simd_json::to_owned_value(&mut json.into_bytes()).expect("JWK JSON is an object");
        self.set_header_value(crate::jwx::HeaderParameter::Jwk.name(), value);
    }

    /// Sets the `alg` header parameter.
    fn set_algorithm_header_value(&mut self, alg: impl Into<String>) {
        self.set_header(HeaderParameter::Algorithm, alg);
    }

    /// Returns the `alg` header parameter value, if present.
    fn algorithm_header_value(&self) -> Option<&str> {
        self.header(HeaderParameter::Algorithm)
    }

    /// Sets the `cty` (content type) header parameter.
    fn set_content_type_header_value(&mut self, cty: impl Into<String>) {
        self.set_header(HeaderParameter::ContentType, cty);
    }

    /// Returns the `cty` (content type) header parameter value, if present.
    fn content_type_header_value(&self) -> Option<&str> {
        self.header(HeaderParameter::ContentType)
    }

    /// Sets the `kid` (key ID) header parameter.
    fn set_key_id_header_value(&mut self, kid: impl Into<String>) {
        self.set_header(HeaderParameter::KeyId, kid);
    }

    /// Returns the `kid` (key ID) header parameter value, if present.
    fn key_id_header_value(&self) -> Option<&str> {
        self.header(HeaderParameter::KeyId)
    }

    /// Sets the key used to verify/decrypt or sign/encrypt.
    fn set_key(&mut self, key: &'a JsonWebKey);

    /// Returns the currently configured key, if any.
    fn key(&self) -> Option<&'a JsonWebKey>;

    /// Restricts which algorithms this structure will accept.
    fn set_algorithm_constraints(&mut self, algorithm_constraints: &'a AlgorithmConstraints<A>);
}

/// Enforces RFC 7515 Section 4.1.11 / RFC 7516 Section 4.1.11: every name listed in the
/// `crit` header parameter must be understood and supported. `supported` lists
/// the extension names this implementation handles (e.g. `"b64"` for RFC 7797
/// in JWS). Any other name in `crit` causes rejection.
///
/// A missing `crit` is fine. A `crit` that is present but not a non-empty
/// array of strings is malformed and rejected.
pub(crate) fn check_crit(
    header: &simd_json::owned::Value,
    supported: &[&str],
) -> Result<(), JoseError> {
    let Some(crit) = header.get("crit") else {
        return Ok(());
    };
    let arr = crit.as_array().ok_or_else(|| {
        JoseError::InvalidHeader("JOSE 'crit' header parameter must be an array".into())
    })?;
    if arr.is_empty() {
        return Err(JoseError::InvalidHeader(
            "JOSE 'crit' header parameter must not be empty".into(),
        ));
    }
    for name in arr {
        let name = name.as_str().ok_or_else(|| {
            JoseError::InvalidHeader("JOSE 'crit' entries must be strings".into())
        })?;
        if !supported.contains(&name) {
            return Err(JoseError::InvalidHeader(format!(
                "unsupported critical header extension '{name}' listed in 'crit'"
            )));
        }
    }
    Ok(())
}
