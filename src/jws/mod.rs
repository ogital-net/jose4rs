//! JSON Web Signature (JWS) implementation.
//!
//! This module provides support for creating and verifying JSON Web Signatures
//! as defined in [RFC 7515](https://tools.ietf.org/html/rfc7515).
//!
//! JWS represents digitally signed or MACed content using JSON data structures.
//! It supports both compact serialization (URL-safe) and JSON serialization formats.

mod algorithm_identifier;

pub use algorithm_identifier::AlgorithmIdentifier;
use simd_json::{
    base::{ValueAsArray as _, ValueAsScalar as _},
    derived::{MutableObject, TypedObjectValue as _, ValueObjectAccessAsScalar as _},
    prelude::{ValueObjectAccess, Writable as _},
    ValueBuilder,
};

use crate::{
    base64,
    crypto::DigestAlgorithm,
    error::JoseError,
    jwa::{AlgorithmConstraints, BLOCK_NONE},
    jwk::JsonWebKey,
    jwx::{HeaderParameter, JsonWebStructure},
    BufferRef,
};

const MIN_RSA_KEY_BITS: usize = 2048;

/// Reads the RFC 7797 `b64` flag from a parsed protected header.
///
/// Returns `Ok(true)` when `b64` is absent (the default JWS behavior). When
/// `b64:false` is present, RFC 7797 requires `crit` to list `b64`; otherwise
/// the JWS is rejected.
fn header_b64_flag(header: &simd_json::owned::Value) -> Result<bool, JoseError> {
    let b64 = match header.get("b64") {
        None => return Ok(true),
        Some(v) => v.as_bool().ok_or_else(|| {
            JoseError::InvalidHeader("JWS 'b64' header parameter must be a boolean".into())
        })?,
    };
    if b64 {
        return Ok(true);
    }
    // b64 == false requires crit to contain "b64".
    let crit_ok = header
        .get("crit")
        .and_then(|c| c.as_array())
        .is_some_and(|arr| arr.iter().any(|e| e.as_str() == Some("b64")));
    if crit_ok {
        Ok(false)
    } else {
        Err(JoseError::InvalidHeader(
            "JWS 'b64=false' requires 'crit' to list \"b64\" (RFC 7797)".into(),
        ))
    }
}

/// A JSON Web Signature (JWS) structure.
///
/// Represents a JWS object that can be serialized in either compact or JSON format.
/// The structure maintains the signature, payload, and protected header, and provides
/// methods for signing and verification.
///
/// # Formats
///
/// - **Compact Serialization**: URL-safe format suitable for HTTP headers
///   (e.g., `header.payload.signature`)
/// - **JSON Serialization**: JSON object format with separate fields for header,
///   payload, and signature
pub struct JsonWebSignature<'a> {
    buffer: Vec<u8>,
    key: Option<&'a JsonWebKey>,
    verification_input: Option<BufferRef>,
    header: Option<simd_json::owned::Value>,
    payload: Option<BufferRef>,
    signature: Option<BufferRef>,
    algorithm_constraints: &'a AlgorithmConstraints<AlgorithmIdentifier>,
    /// Whether the payload is base64url-encoded in the signing input (RFC 7797
    /// `b64`). `true` (the default) is the standard JWS behavior. `false`
    /// means the raw payload bytes go into the signing input and the payload
    /// may be omitted (detached) from the serialization.
    payload_is_b64: bool,
    /// Caller-supplied raw payload for a detached (`b64=false`) JWS, used when
    /// the payload is not carried in the serialization.
    detached_payload: Option<Vec<u8>>,
}

// Redacted Debug: shows the algorithm and which parts are populated, never the
// payload, signature, or key material.
impl std::fmt::Debug for JsonWebSignature<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JsonWebSignature")
            .field("alg", &self.algorithm())
            .field("has_key", &self.key.is_some())
            .field("has_header", &self.header.is_some())
            .field("has_payload", &self.payload.is_some())
            .field("has_signature", &self.signature.is_some())
            .finish()
    }
}

impl<'a> JsonWebSignature<'a> {
    /// Create an empty JWS. Set a payload and/or compact serialization, then
    /// sign or verify.
    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
            key: None,
            verification_input: None,
            header: None,
            payload: None,
            signature: None,
            algorithm_constraints: &BLOCK_NONE,
            payload_is_b64: true,
            detached_payload: None,
        }
    }

    /// Creates a new JWS from a compact serialization string.
    ///
    /// The compact serialization format is `BASE64URL(UTF8(JWS Protected Header)) || '.' ||
    /// BASE64URL(JWS Payload) || '.' || BASE64URL(JWS Signature)`.
    ///
    /// # Arguments
    ///
    /// * `compact_serialization` - A JWS compact serialization string
    ///
    /// # Errors
    ///
    /// Returns an error if the serialization is malformed or cannot be parsed.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use jose4rs::jws::JsonWebSignature;
    /// let jws = JsonWebSignature::from_compact_serialization(
    ///     "eyJhbGc..."
    /// ).unwrap();
    /// ```
    pub fn from_compact_serialization(
        compact_serialization: &'a (impl AsRef<[u8]> + ?Sized),
    ) -> Result<Self, JoseError> {
        let mut jws = JsonWebSignature::new();
        jws.set_compact_serialization(compact_serialization)?;
        Ok(jws)
    }

    /// Creates a new JWS from a flattened JSON serialization.
    ///
    /// The flattened JSON serialization uses a JSON object with fields:
    /// `protected`, `payload`, and `signature`.
    ///
    /// # Arguments
    ///
    /// * `compact_serialization` - A JWS flattened JSON serialization string
    ///
    /// # Errors
    ///
    /// Returns an error if the JSON is malformed, missing required fields,
    /// or contains unsupported features (e.g., unprotected headers).
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use jose4rs::jws::JsonWebSignature;
    /// let json = r#"{"protected":"eyJhbGc...","payload":"...","signature":"..."}"#;
    /// let jws = JsonWebSignature::from_flattened_json_serialization(json).unwrap();
    /// ```
    pub fn from_flattened_json_serialization(
        compact_serialization: &(impl AsRef<[u8]> + ?Sized),
    ) -> Result<Self, JoseError> {
        let mut jws = JsonWebSignature::new();
        jws.set_flattened_json_serialization(compact_serialization)?;
        Ok(jws)
    }

    /// Verifies the signature of the JWS.
    ///
    /// Validates that the signature matches the protected header and payload using
    /// the configured key and algorithm. Supports HMAC, RSA, ECDSA, `EdDSA`, and RSA-PSS algorithms.
    ///
    /// # Returns
    ///
    /// * `Ok(true)` - The signature is valid
    /// * `Ok(false)` - The signature is invalid
    /// * `Err` - There is a problem with the key, algorithm, or JWS structure
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The key is missing or incompatible with the algorithm
    /// - The algorithm is not allowed by constraints
    /// - The signature or verification input is missing
    /// - The RSA key is too small (< 2048 bits)
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use jose4rs::jws::JsonWebSignature;
    /// # use jose4rs::jwk::JsonWebKey;
    /// # use jose4rs::jwx::JsonWebStructure;
    /// # let mut jws = JsonWebSignature::from_compact_serialization("...").unwrap();
    /// # let key = JsonWebKey::from_pem("...").unwrap();
    /// jws.set_key(&key);
    /// if jws.verify_signature()? {
    ///     println!("Signature is valid");
    /// }
    /// # Ok::<(), jose4rs::error::JoseError>(())
    /// ```
    pub fn verify_signature(&self) -> Result<bool, JoseError> {
        // check algorithm constraints
        let alg = self.get_algorithm(true)?;

        // handle 'none' algorithm
        if alg == AlgorithmIdentifier::None {
            if self.key.is_some() {
                return Err(JoseError::InvalidKey(format!(
                    "JWS Plaintext (alg={alg}) must not use a key."
                )));
            }
            let is_valid = match self.signature {
                Some(ref signature) => signature.is_empty(),
                None => false,
            };
            return Ok(is_valid);
        }

        // key preflight checks
        let key = self.get_key_with_validation(alg)?;

        let signature = self
            .signature
            .as_ref()
            .ok_or_else(|| JoseError::new("missing signature, cannot verify JWS"))?;
        let verification_input = self
            .verification_input
            .ok_or_else(|| JoseError::new("missing verification input, cannot verify JWS"))?;

        // For b64=false the stored verification_input was built from the
        // serialized (base64) form; rebuild it as `BASE64URL(protected) || '.'
        // || <raw payload>`. The common b64=true path uses the stored input
        // directly with no extra work.
        let rebuilt: Vec<u8>;
        let verification_input: &[u8] = if self.payload_is_b64 {
            verification_input.get(&self.buffer)
        } else {
            rebuilt = self.build_unencoded_signing_input()?;
            &rebuilt
        };

        match alg {
            AlgorithmIdentifier::HmacSha256 => match key {
                JsonWebKey::Oct(hmac_key) => Ok(hmac_key.verify(
                    verification_input,
                    DigestAlgorithm::Sha256,
                    signature.get(&self.buffer),
                )),
                _ => Err(JoseError::InvalidKey(format!(
                    "invalid key type {}",
                    key.key_type()
                ))),
            },
            AlgorithmIdentifier::HmacSha384 => match key {
                JsonWebKey::Oct(hmac_key) => Ok(hmac_key.verify(
                    verification_input,
                    DigestAlgorithm::Sha384,
                    signature.get(&self.buffer),
                )),
                _ => Err(JoseError::InvalidKey(format!(
                    "invalid key type {}",
                    key.key_type()
                ))),
            },
            AlgorithmIdentifier::HmacSha512 => match key {
                JsonWebKey::Oct(hmac_key) => Ok(hmac_key.verify(
                    verification_input,
                    DigestAlgorithm::Sha512,
                    signature.get(&self.buffer),
                )),
                _ => Err(JoseError::InvalidKey(format!(
                    "invalid key type {}",
                    key.key_type()
                ))),
            },
            AlgorithmIdentifier::RsaUsingSha256 => match key {
                JsonWebKey::Rsa(rsa_key) => Ok(rsa_key.verify(
                    verification_input,
                    DigestAlgorithm::Sha256,
                    signature.get(&self.buffer),
                )),
                _ => Err(JoseError::InvalidKey(format!(
                    "invalid key type {}",
                    key.key_type()
                ))),
            },
            AlgorithmIdentifier::RsaUsingSha384 => match key {
                JsonWebKey::Rsa(rsa_key) => Ok(rsa_key.verify(
                    verification_input,
                    DigestAlgorithm::Sha384,
                    signature.get(&self.buffer),
                )),
                _ => Err(JoseError::InvalidKey(format!(
                    "invalid key type {}",
                    key.key_type()
                ))),
            },
            AlgorithmIdentifier::RsaUsingSha512 => match key {
                JsonWebKey::Rsa(rsa_key) => Ok(rsa_key.verify(
                    verification_input,
                    DigestAlgorithm::Sha512,
                    signature.get(&self.buffer),
                )),
                _ => Err(JoseError::InvalidKey(format!(
                    "invalid key type {}",
                    key.key_type()
                ))),
            },
            AlgorithmIdentifier::EcdsaUsingP256CurveAndSha256 => match key {
                JsonWebKey::EllipticCurve(ec_key) => Ok(ec_key.verify(
                    verification_input,
                    DigestAlgorithm::Sha256,
                    signature.get(&self.buffer),
                )),
                _ => Err(JoseError::InvalidKey(format!(
                    "invalid key type {}",
                    key.key_type()
                ))),
            },
            AlgorithmIdentifier::EcdsaUsingP384CurveAndSha384 => match key {
                JsonWebKey::EllipticCurve(ec_key) => Ok(ec_key.verify(
                    verification_input,
                    DigestAlgorithm::Sha384,
                    signature.get(&self.buffer),
                )),
                _ => Err(JoseError::InvalidKey(format!(
                    "invalid key type {}",
                    key.key_type()
                ))),
            },
            AlgorithmIdentifier::EcdsaUsingP521CurveAndSha512 => match key {
                JsonWebKey::EllipticCurve(ec_key) => Ok(ec_key.verify(
                    verification_input,
                    DigestAlgorithm::Sha512,
                    signature.get(&self.buffer),
                )),
                _ => Err(JoseError::InvalidKey(format!(
                    "invalid key type {}",
                    key.key_type()
                ))),
            },
            #[cfg(not(feature = "boring"))]
            AlgorithmIdentifier::EcdsaUsingSecp256k1CurveAndSha256 => match key {
                JsonWebKey::EllipticCurve(ec_key) => Ok(ec_key.verify(
                    verification_input,
                    DigestAlgorithm::Sha256,
                    signature.get(&self.buffer),
                )),
                _ => Err(JoseError::InvalidKey(format!(
                    "invalid key type {}",
                    key.key_type()
                ))),
            },
            AlgorithmIdentifier::EdDsa => match key {
                JsonWebKey::OctetKeyPair(okp) => {
                    Ok(okp.verify(verification_input, signature.get(&self.buffer)))
                }
                _ => Err(JoseError::InvalidKey(format!(
                    "invalid key type {}",
                    key.key_type()
                ))),
            },
            AlgorithmIdentifier::RsaPssUsingSha256 => match key {
                JsonWebKey::Rsa(rsa_key) => Ok(rsa_key.verify_rsa_pss(
                    verification_input,
                    DigestAlgorithm::Sha256,
                    signature.get(&self.buffer),
                )),
                _ => Err(JoseError::InvalidKey(format!(
                    "invalid key type {}",
                    key.key_type()
                ))),
            },
            AlgorithmIdentifier::RsaPssUsingSha384 => match key {
                JsonWebKey::Rsa(rsa_key) => Ok(rsa_key.verify_rsa_pss(
                    verification_input,
                    DigestAlgorithm::Sha384,
                    signature.get(&self.buffer),
                )),
                _ => Err(JoseError::InvalidKey(format!(
                    "invalid key type {}",
                    key.key_type()
                ))),
            },
            AlgorithmIdentifier::RsaPssUsingSha512 => match key {
                JsonWebKey::Rsa(rsa_key) => Ok(rsa_key.verify_rsa_pss(
                    verification_input,
                    DigestAlgorithm::Sha512,
                    signature.get(&self.buffer),
                )),
                _ => Err(JoseError::InvalidKey(format!(
                    "invalid key type {}",
                    key.key_type()
                ))),
            },
            _ => unreachable!("unsupported algorithm"),
        }
    }

    /// Returns `true` if the JWS signature is valid.
    ///
    /// Idiomatic alias for [`JsonWebSignature::verify_signature`].
    ///
    /// # Errors
    ///
    /// Returns an error if verification cannot be performed (missing key,
    /// disallowed algorithm, malformed structure, etc.).
    pub fn verify(&self) -> Result<bool, JoseError> {
        self.verify_signature()
    }

    /// Returns the signature algorithm (`alg`) header value, if set.
    pub fn algorithm(&self) -> Option<&str> {
        self.algorithm_header_value()
    }

    /// Returns the payload **without** verifying the signature.
    ///
    /// # Warning
    ///
    /// This method returns the payload **without** verifying the signature.
    /// Only use this when you trust the source or plan to verify the signature separately.
    /// For most use cases, prefer using [`JsonWebStructure::payload`] which verifies the signature first.
    ///
    /// # Errors
    ///
    /// Returns an error if the payload is missing.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use jose4rs::jws::JsonWebSignature;
    /// # let jws = JsonWebSignature::from_compact_serialization("...").unwrap();
    /// // WARNING: This does not verify the signature!
    /// let payload = jws.unverified_payload()?;
    /// # Ok::<(), jose4rs::error::JoseError>(())
    /// ```
    pub fn unverified_payload(&self) -> Result<&[u8], JoseError> {
        let payload = self
            .payload
            .as_ref()
            .ok_or_else(|| JoseError::new("missing payload"))?;
        Ok(payload.get(&self.buffer))
    }

    fn sign(&self, alg: AlgorithmIdentifier, input: &[u8]) -> Result<Option<Box<[u8]>>, JoseError> {
        // handle 'none' algorithm
        if alg == AlgorithmIdentifier::None {
            if self.key.is_some() {
                return Err(JoseError::InvalidKey(format!(
                    "JWS plaintext (alg={alg}) must not use a key"
                )));
            }
            return Ok(None);
        }

        // key preflight checks
        let key = self.get_key_with_validation(alg)?;

        let sig = match alg {
            AlgorithmIdentifier::HmacSha256 => match key {
                JsonWebKey::Oct(hmac_key) => Some(hmac_key.sign(input, DigestAlgorithm::Sha256)?),
                _ => {
                    return Err(JoseError::InvalidKey(format!(
                        "invalid key type {}",
                        key.key_type()
                    )))
                }
            },
            AlgorithmIdentifier::HmacSha384 => match key {
                JsonWebKey::Oct(hmac_key) => Some(hmac_key.sign(input, DigestAlgorithm::Sha384)?),
                _ => {
                    return Err(JoseError::InvalidKey(format!(
                        "invalid key type {}",
                        key.key_type()
                    )))
                }
            },
            AlgorithmIdentifier::HmacSha512 => match key {
                JsonWebKey::Oct(hmac_key) => Some(hmac_key.sign(input, DigestAlgorithm::Sha512)?),
                _ => {
                    return Err(JoseError::InvalidKey(format!(
                        "invalid key type {}",
                        key.key_type()
                    )))
                }
            },
            AlgorithmIdentifier::RsaUsingSha256 => match key {
                JsonWebKey::Rsa(rsa_key) => Some(rsa_key.sign(input, DigestAlgorithm::Sha256)),
                _ => {
                    return Err(JoseError::InvalidKey(format!(
                        "invalid key type {}",
                        key.key_type()
                    )))
                }
            },
            AlgorithmIdentifier::RsaUsingSha384 => match key {
                JsonWebKey::Rsa(rsa_key) => Some(rsa_key.sign(input, DigestAlgorithm::Sha384)),
                _ => {
                    return Err(JoseError::InvalidKey(format!(
                        "invalid key type {}",
                        key.key_type()
                    )))
                }
            },
            AlgorithmIdentifier::RsaUsingSha512 => match key {
                JsonWebKey::Rsa(rsa_key) => Some(rsa_key.sign(input, DigestAlgorithm::Sha512)),
                _ => {
                    return Err(JoseError::InvalidKey(format!(
                        "invalid key type {}",
                        key.key_type()
                    )))
                }
            },
            AlgorithmIdentifier::EcdsaUsingP256CurveAndSha256 => match key {
                JsonWebKey::EllipticCurve(ec_key) => {
                    Some(ec_key.sign(input, DigestAlgorithm::Sha256))
                }
                _ => {
                    return Err(JoseError::InvalidKey(format!(
                        "invalid key type {}",
                        key.key_type()
                    )))
                }
            },
            AlgorithmIdentifier::EcdsaUsingP384CurveAndSha384 => match key {
                JsonWebKey::EllipticCurve(ec_key) => {
                    Some(ec_key.sign(input, DigestAlgorithm::Sha384))
                }
                _ => {
                    return Err(JoseError::InvalidKey(format!(
                        "invalid key type {}",
                        key.key_type()
                    )))
                }
            },
            AlgorithmIdentifier::EcdsaUsingP521CurveAndSha512 => match key {
                JsonWebKey::EllipticCurve(ec_key) => {
                    Some(ec_key.sign(input, DigestAlgorithm::Sha512))
                }
                _ => {
                    return Err(JoseError::InvalidKey(format!(
                        "invalid key type {}",
                        key.key_type()
                    )))
                }
            },
            #[cfg(not(feature = "boring"))]
            AlgorithmIdentifier::EcdsaUsingSecp256k1CurveAndSha256 => match key {
                JsonWebKey::EllipticCurve(ec_key) => {
                    Some(ec_key.sign(input, DigestAlgorithm::Sha256))
                }
                _ => {
                    return Err(JoseError::InvalidKey(format!(
                        "invalid key type {}",
                        key.key_type()
                    )))
                }
            },
            AlgorithmIdentifier::EdDsa => match key {
                JsonWebKey::OctetKeyPair(okp) => Some(okp.sign(input)?),
                _ => {
                    return Err(JoseError::InvalidKey(format!(
                        "invalid key type {}",
                        key.key_type()
                    )))
                }
            },
            AlgorithmIdentifier::RsaPssUsingSha256 => match key {
                JsonWebKey::Rsa(rsa_key) => {
                    Some(rsa_key.sign_rsa_pss(input, DigestAlgorithm::Sha256))
                }
                _ => {
                    return Err(JoseError::InvalidKey(format!(
                        "invalid key type {}",
                        key.key_type()
                    )))
                }
            },
            AlgorithmIdentifier::RsaPssUsingSha384 => match key {
                JsonWebKey::Rsa(rsa_key) => {
                    Some(rsa_key.sign_rsa_pss(input, DigestAlgorithm::Sha384))
                }
                _ => {
                    return Err(JoseError::InvalidKey(format!(
                        "invalid key type {}",
                        key.key_type()
                    )))
                }
            },
            AlgorithmIdentifier::RsaPssUsingSha512 => match key {
                JsonWebKey::Rsa(rsa_key) => {
                    Some(rsa_key.sign_rsa_pss(input, DigestAlgorithm::Sha512))
                }
                _ => {
                    return Err(JoseError::InvalidKey(format!(
                        "invalid key type {}",
                        key.key_type()
                    )))
                }
            },
            _ => unreachable!("unsupported algorithm"),
        };
        Ok(sig)
    }

    fn get_algorithm(&self, check_constraints: bool) -> Result<AlgorithmIdentifier, JoseError> {
        let alg = self
            .header(HeaderParameter::Algorithm)
            .ok_or_else(|| JoseError::InvalidHeader("missing algorithm in header".into()))?;
        let alg = AlgorithmIdentifier::try_from(alg)?;
        if check_constraints {
            self.algorithm_constraints.check_constraint(alg)?;
        }
        Ok(alg)
    }

    fn get_key_with_validation(
        &self,
        alg: AlgorithmIdentifier,
    ) -> Result<&'a JsonWebKey, JoseError> {
        match self.key {
            Some(key) => {
                // RFC 7517 Section 4.4: a key with an `alg` member is intended only
                // for that algorithm. Reject same-family algorithm drift (e.g.
                // a key tagged HS256 verifying HS384).
                if let Some(key_alg) = key.algorithm() {
                    if key_alg != alg.name() {
                        return Err(JoseError::InvalidKey(format!(
                            "key is restricted to algorithm '{key_alg}' but the JWS uses '{alg}'"
                        )));
                    }
                }
                match key {
                    JsonWebKey::Rsa(rsa_key) => {
                        if rsa_key.key_size_bits() < MIN_RSA_KEY_BITS {
                            return Err(JoseError::InvalidKey(format!(
                                "an RSA key of size {MIN_RSA_KEY_BITS} bits or larger MUST be used with the all JOSE \
                                RSA algorithms (given key was only {} bits)",
                                rsa_key.key_size_bits()
                            )));
                        }
                        Ok(key)
                    }
                    JsonWebKey::Oct(oct_key) => {
                        // RFC 7518 Section 3.2: an HMAC key of the same size as the hash
                        // output or larger MUST be used. jose4j enforces the same
                        // minimum in validateKey().
                        let min_bits = match alg {
                            AlgorithmIdentifier::HmacSha256 => 256,
                            AlgorithmIdentifier::HmacSha384 => 384,
                            AlgorithmIdentifier::HmacSha512 => 512,
                            _ => 0, // not an HMAC algorithm; no symmetric minimum
                        };
                        if oct_key.key_size_bits() < min_bits {
                            return Err(JoseError::InvalidKey(format!(
                            "a key of the same size as the hash output (i.e. {min_bits} bits for \
                            {alg}) or larger MUST be used with the HMAC SHA algorithms but this \
                            key is only {} bits",
                            oct_key.key_size_bits()
                        )));
                        }
                        Ok(key)
                    }
                    JsonWebKey::EllipticCurve(ec_key) => {
                        // RFC 7518 Section 3.4: each ECDSA algorithm pins a
                        // specific curve. Reject a key whose curve doesn't match
                        // (e.g. a P-384 key used with ES256), as jose4j's
                        // EcdsaUsingShaAlgorithm.validateKeySpec() does.
                        if let Some(required_curve) = alg.ec_curve() {
                            if ec_key.curve_name() != required_curve {
                                return Err(JoseError::InvalidKey(format!(
                                    "key curve '{}' does not match the curve '{required_curve}' required by {alg}",
                                    ec_key.curve_name()
                                )));
                            }
                        }
                        Ok(key)
                    }
                    JsonWebKey::OctetKeyPair(okp_key) => {
                        // EdDSA signs and verifies with an Edwards-curve key
                        // (Ed25519 here). An X25519 key is for ECDH key
                        // agreement only and cannot sign/verify; reject it up
                        // front with a descriptive error rather than letting it
                        // reach the signing/verification primitive, where it
                        // would fail to initialize.
                        if alg == AlgorithmIdentifier::EdDsa && okp_key.curve_name() != "Ed25519" {
                            return Err(JoseError::InvalidKey(format!(
                                "key curve '{}' cannot be used with {alg}; an Ed25519 key is required",
                                okp_key.curve_name()
                            )));
                        }
                        Ok(key)
                    }
                }
            }
            None => Err(JoseError::new("missing key")),
        }
    }

    /// Sets the signature algorithm in the JWS header.
    ///
    /// # Arguments
    ///
    /// * `alg` - The signature algorithm to use
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use jose4rs::jws::{JsonWebSignature, AlgorithmIdentifier};
    /// # let mut jws = JsonWebSignature::from_compact_serialization("...").unwrap();
    /// jws.set_algorithm(AlgorithmIdentifier::RsaUsingSha256);
    /// ```
    pub fn set_algorithm(&mut self, alg: AlgorithmIdentifier) {
        self.set_algorithm_header_value(alg.name());
    }

    #[inline]
    fn set_parts(
        &mut self,
        protected_header: &[u8],
        encoded_payload: &[u8],
        encoded_signature: &[u8],
        verification_input: BufferRef,
    ) -> Result<(), JoseError> {
        let header = {
            let len = self.buffer.len();
            let h = base64::url_decode_append(protected_header, &mut self.buffer)?;
            let h =
                simd_json::to_owned_value(h.get_mut(&mut self.buffer)).map_err(JoseError::json)?;
            self.buffer.truncate(len);
            h
        };
        // A JWS protected header must be a JSON object; rejecting anything else
        // here keeps `set_header_name` (which inserts into the map) infallible.
        if !header.is_object() {
            return Err(JoseError::InvalidHeader(
                "JWS protected header is not a JSON object".into(),
            ));
        }

        // RFC 7515 Section 4.1.11: reject unsupported critical extensions. The only
        // critical extension this implementation understands is RFC 7797 `b64`.
        crate::jwx::check_crit(&header, &["b64"])?;

        // RFC 7797: read `b64`. The serialized "payload" member is ALWAYS
        // base64url-encoded regardless of `b64`; `b64=false` only changes what
        // feeds the signing input (raw payload instead of the encoded form).
        // `crit` must list `b64` when it is false.
        let payload_is_b64 = header_b64_flag(&header)?;
        let payload = base64::url_decode_append(encoded_payload, &mut self.buffer)?;
        let signature = base64::url_decode_append(encoded_signature, &mut self.buffer)?;

        self.payload_is_b64 = payload_is_b64;
        self.verification_input = Some(verification_input);
        self.header = Some(header);
        self.payload = Some(payload);
        self.signature = Some(signature);
        // A fresh parse installs a new payload; drop any detached payload a
        // caller may have set on a prior token so it can't leak into this one.
        // Callers that need a detached payload must re-set it after parsing.
        self.detached_payload = None;
        Ok(())
    }

    /// Sets whether the payload is base64url-encoded in the signing input
    /// (RFC 7797 `b64` header parameter).
    ///
    /// Setting `false` records `b64:false` in the protected header and adds
    /// `b64` to `crit`. Call before serializing. Use together with
    /// [`set_detached_payload`](Self::set_detached_payload) to omit the payload
    /// from the serialization (the ACME POST pattern).
    pub fn set_b64(&mut self, b64: bool) {
        self.payload_is_b64 = b64;
        if b64 {
            // A `crit` listing `b64` with no `b64` field is rejected by
            // recipients (RFC 7515 Section 4.1.11), so both must go.
            if let Some(ref mut header) = self.header {
                let _ = header.remove("b64");
                let _ = header.remove("crit");
            }
        } else {
            self.set_header_value("b64", simd_json::owned::Value::from(false));
            // crit must list b64.
            let crit = simd_json::owned::Value::from(vec![simd_json::owned::Value::from("b64")]);
            self.set_header_value("crit", crit);
        }
    }

    /// Supplies the raw payload for a detached (`b64=false`) JWS.
    ///
    /// When set, the payload is omitted from the serialized JWS but these
    /// bytes are used in the signing input / verification. This is the ACME
    /// `POST` body pattern, where the payload travels in the HTTP body, not
    /// inside the JWS.
    pub fn set_detached_payload(&mut self, payload: impl AsRef<[u8]>) {
        self.detached_payload = Some(payload.as_ref().to_vec());
    }

    /// Builds the signing input for a `b64=false` JWS:
    /// `BASE64URL(protected) || '.' || <raw payload>`.
    ///
    /// The raw payload comes from the detached payload if present, else the
    /// embedded (unencoded) payload buffer.
    ///
    /// When verifying a parsed JWS, the protected header must be the *original*
    /// serialized bytes (re-encoding could reorder keys and change the input),
    /// so we reuse the protected prefix stored in `verification_input`. When
    /// signing there is no stored input yet, so we encode the in-memory header.
    fn build_unencoded_signing_input(&self) -> Result<Vec<u8>, JoseError> {
        let mut out = Vec::new();
        if let Some(ref vi) = self.verification_input {
            // Original protected header = bytes up to the first '.'.
            let stored = vi.get(&self.buffer);
            let dot = stored
                .iter()
                .position(|&b| b == b'.')
                .ok_or_else(|| JoseError::MalformedToken("malformed verification input".into()))?;
            out.extend_from_slice(&stored[..dot]);
        } else {
            let header = self
                .header
                .as_ref()
                .ok_or_else(|| JoseError::new("missing header"))?;
            base64::url_encode_append(header.encode(), &mut out);
        }
        out.push(b'.');
        if let Some(ref detached) = self.detached_payload {
            out.extend_from_slice(detached);
        } else if let Some(ref payload) = self.payload {
            out.extend_from_slice(payload.get(&self.buffer));
        }
        Ok(out)
    }

    /// Parses and sets the JWS from a flattened JSON serialization.
    ///
    /// This method parses the JSON object and extracts the protected header,
    /// payload, and signature fields.
    ///
    /// # Arguments
    ///
    /// * `json_serialization` - A JSON string containing the JWS serialization
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The JSON is malformed
    /// - Required fields (`protected`, `payload`, `signature`) are missing
    /// - Unprotected headers are present (not supported)
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use jose4rs::jws::JsonWebSignature;
    /// let json = r#"{"protected":"eyJhbGc...","payload":"...","signature":"..."}"#;
    /// # let mut jws = JsonWebSignature::from_compact_serialization("...").unwrap();
    /// jws.set_flattened_json_serialization(json)?;
    /// # Ok::<(), jose4rs::error::JoseError>(())
    /// ```
    pub fn set_flattened_json_serialization(
        &mut self,
        json_serialization: &(impl AsRef<[u8]> + ?Sized),
    ) -> Result<(), JoseError> {
        let mut json: Box<[u8]> = Box::from(json_serialization.as_ref());
        let value = simd_json::to_borrowed_value(&mut json).map_err(JoseError::json)?;
        if value.contains_key("header") {
            return Err(JoseError::InvalidHeader(
                "unprotected header not supported".into(),
            ));
        }
        let protected_header = value.get_str("protected").map_or_else(
            || {
                Err(JoseError::MalformedToken(
                    "invalid JWS, no 'protected' member".into(),
                ))
            },
            |s| Ok(s.as_bytes()),
        )?;
        // The payload member is required for a normal (b64) JWS. It may be
        // omitted only by a detached b64=false JWS (RFC 7797), whose raw
        // payload the caller supplies via `set_detached_payload`.
        let encoded_payload: Option<&[u8]> = value.get_str("payload").map(str::as_bytes);
        let encoded_signature = value.get_str("signature").map_or_else(
            || {
                Err(JoseError::MalformedToken(
                    "invalid JWS, no 'signature' member".into(),
                ))
            },
            |s| Ok(s.as_bytes()),
        )?;

        // Decode the protected header to learn the b64 flag before deciding
        // whether an absent payload is acceptable.
        let payload_is_b64 = {
            let mut hdr_bytes = base64::url_decode(protected_header)?;
            let hdr = simd_json::to_owned_value(hdr_bytes.as_mut()).map_err(JoseError::json)?;
            header_b64_flag(&hdr)?
        };

        let encoded_payload: &[u8] = match (encoded_payload, payload_is_b64) {
            (Some(p), _) => p,
            (None, false) => b"", // detached payload
            (None, true) => {
                return Err(JoseError::MalformedToken(
                    "invalid JWS, no 'payload' member".into(),
                ));
            }
        };

        let start = self.buffer.len();
        self.buffer.extend_from_slice(protected_header);
        self.buffer.push(b'.');
        self.buffer.extend_from_slice(encoded_payload);
        let verification_input = BufferRef::new(start, self.buffer.len());

        self.set_parts(
            protected_header,
            encoded_payload,
            encoded_signature,
            verification_input,
        )
    }

    /// Serializes the JWS to flattened JSON format.
    ///
    /// Creates a JSON object with `protected`, `payload`, and `signature` fields.
    /// This method will sign the JWS using the configured key and algorithm.
    ///
    /// # Returns
    ///
    /// A JSON string representing the JWS in flattened JSON serialization format.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The header is missing
    /// - The algorithm is not set or not allowed by constraints
    /// - Signing fails
    ///
    /// # Panics
    ///
    /// Panics if the JSON value store is not an object (only possible if it
    /// was parsed from a non-object document).
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use jose4rs::jws::{JsonWebSignature, AlgorithmIdentifier};
    /// # use jose4rs::jwk::JsonWebKey;
    /// # use jose4rs::jwx::JsonWebStructure;
    /// # let mut jws = JsonWebSignature::from_compact_serialization("...").unwrap();
    /// # let key = JsonWebKey::from_pem("...").unwrap();
    /// jws.set_key(&key);
    /// jws.set_algorithm(AlgorithmIdentifier::RsaUsingSha256);
    /// let json = jws.flattened_json_serialization()?;
    /// # Ok::<(), jose4rs::error::JoseError>(())
    /// ```
    pub fn flattened_json_serialization(&self) -> Result<String, JoseError> {
        // check algorithm constraints
        let alg = self.get_algorithm(true)?;

        let header = self
            .header
            .as_ref()
            .ok_or_else(|| JoseError::new("missing header"))?;

        let header_json = header.encode();

        // {
        //     "payload":"<payload contents>",
        //     "protected":"<integrity-protected header contents>",
        //     "signature":"<signature contents>"
        // }

        let mut out = simd_json::owned::Value::object_with_capacity(3);
        let mut out_buffer = Vec::new();
        let protected = base64::url_encode_append(header_json, &mut out_buffer);
        out_buffer.push(b'.');

        // SAFETY: base64 is always valid UTF-8
        out.insert("protected", unsafe {
            std::str::from_utf8_unchecked(protected.get(&out_buffer))
        })
        .unwrap();

        // Determine the signing input and the serialized "payload" member.
        // b64=true (default): signing input is protected || '.' || b64(payload)
        // and that same buffer suffix is serialized. b64=false: the signing
        // input uses the RAW payload, and the payload may be detached.
        let signing_input = if self.payload_is_b64 {
            match self.payload {
                Some(ref payload) => {
                    let p = base64::url_encode_append(payload.get(&self.buffer), &mut out_buffer);
                    out.insert("payload", unsafe {
                        std::str::from_utf8_unchecked(p.get(&out_buffer))
                    })
                    .unwrap();
                }
                None => {
                    out.insert("payload", "").unwrap();
                }
            }
            out_buffer.clone()
        } else {
            // b64=false: serialize the payload base64url-encoded UNLESS it is
            // detached (then omit it). The signing input uses the raw bytes.
            if self.detached_payload.is_none() {
                match self.payload {
                    Some(ref payload) => {
                        let p =
                            base64::url_encode_append(payload.get(&self.buffer), &mut out_buffer);
                        out.insert("payload", unsafe {
                            std::str::from_utf8_unchecked(p.get(&out_buffer))
                        })
                        .unwrap();
                    }
                    None => {
                        out.insert("payload", "").unwrap();
                    }
                }
            }
            self.build_unencoded_signing_input()?
        };

        let sig = self.sign(alg, &signing_input)?;
        match sig {
            Some(sig) => {
                let s = base64::url_encode_append(sig, &mut out_buffer);
                out.insert("signature", unsafe {
                    std::str::from_utf8_unchecked(s.get(&out_buffer))
                })
                .unwrap();
            }
            None => {
                out.insert("signature", "").unwrap();
            }
        }

        Ok(out.encode())
    }
}

impl<'a> JsonWebStructure<'a, AlgorithmIdentifier> for JsonWebSignature<'a> {
    fn set_compact_serialization(
        &mut self,
        compact_serialization: &'a (impl AsRef<[u8]> + ?Sized),
    ) -> Result<(), JoseError> {
        let compact_serialization = compact_serialization.as_ref();

        let delimeter_indexes = {
            let mut iter = memchr::memchr_iter(b'.', compact_serialization);

            let mut indexes = [0usize; 2];
            for idx in &mut indexes {
                match iter.next() {
                    Some(i) => *idx = i,
                    None => return Err(JoseError::MalformedToken("not enough parts".into())),
                }
            }
            if iter.next().is_some() {
                return Err(JoseError::MalformedToken("too many parts".into()));
            }
            indexes
        };

        let (protected_header, encoded_payload, encoded_signature, verification_input) =
            // SAFETY: these indexes are checked above
            unsafe {
                (compact_serialization.get_unchecked(..delimeter_indexes[0]),
                compact_serialization.get_unchecked((delimeter_indexes[0] + 1)..delimeter_indexes[1]),
                compact_serialization.get_unchecked((delimeter_indexes[1] + 1)..),
                compact_serialization.get_unchecked(..delimeter_indexes[1]))
            };
        let need = std::cmp::max(
            base64::url_decode_size(protected_header.len()),
            verification_input.len()
                + base64::url_decode_size(encoded_payload.len())
                + base64::url_decode_size(encoded_signature.len()),
        );
        self.buffer.reserve_exact(need);

        let start = self.buffer.len();
        self.buffer.extend_from_slice(verification_input);
        let verification_input = BufferRef::new(start, self.buffer.len());

        self.set_parts(
            protected_header,
            encoded_payload,
            encoded_signature,
            verification_input,
        )
    }

    fn compact_serialization(&self) -> Result<String, JoseError> {
        // check algorithm constraints
        let alg = self.get_algorithm(true)?;

        if !self.payload_is_b64 {
            // RFC 7797 Section 8: an unencoded payload can contain '.', which is not
            // representable in compact serialization. ACME uses flattened JSON.
            return Err(JoseError::InvalidHeader(
                "b64=false is not supported in compact serialization; use flattened JSON".into(),
            ));
        }

        let header = self
            .header
            .as_ref()
            .ok_or_else(|| JoseError::new("missing header"))?;

        let header_json = header.encode();

        // buffer size
        let mut need = base64::url_encode_size(header_json.len());
        need += 1; // '.'
        need += base64::url_encode_size(self.payload.as_ref().map_or(0, super::BufferRef::len));
        need += 1; // '.'

        match alg {
            AlgorithmIdentifier::None => {}
            AlgorithmIdentifier::HmacSha256 => need += base64::url_encode_size(32),
            AlgorithmIdentifier::HmacSha384 => need += base64::url_encode_size(48),
            AlgorithmIdentifier::HmacSha512 => need += base64::url_encode_size(64),
            AlgorithmIdentifier::EcdsaUsingP256CurveAndSha256 => {
                need += base64::url_encode_size(64);
            }
            AlgorithmIdentifier::EcdsaUsingP384CurveAndSha384 => {
                need += base64::url_encode_size(96);
            }
            AlgorithmIdentifier::EcdsaUsingP521CurveAndSha512 => {
                need += base64::url_encode_size(132);
            }
            #[cfg(not(feature = "boring"))]
            AlgorithmIdentifier::EcdsaUsingSecp256k1CurveAndSha256 => {
                need += base64::url_encode_size(64);
            }
            AlgorithmIdentifier::EdDsa => need += base64::url_encode_size(64),
            AlgorithmIdentifier::RsaUsingSha256
            | AlgorithmIdentifier::RsaUsingSha384
            | AlgorithmIdentifier::RsaUsingSha512
            | AlgorithmIdentifier::RsaPssUsingSha256
            | AlgorithmIdentifier::RsaPssUsingSha384
            | AlgorithmIdentifier::RsaPssUsingSha512 => {
                if let Some(JsonWebKey::Rsa(rsa)) = self.key {
                    need += base64::url_encode_size(rsa.key_size_bits() / 8);
                }
            }
        }

        let mut out = Vec::with_capacity(need);
        base64::url_encode_append(header_json, &mut out);
        out.push(b'.');
        if let Some(payload) = self.payload.as_ref() {
            base64::url_encode_append(payload.get(&self.buffer), &mut out);
        }

        let sig = self.sign(alg, &out)?;
        out.push(b'.');

        if let Some(sig) = sig {
            base64::url_encode_append(sig, &mut out);
        }

        // SAFETY: base64 encoding is valid UTF-8
        unsafe { Ok(String::from_utf8_unchecked(out)) }
    }

    fn set_payload(&mut self, payload: impl AsRef<[u8]>) {
        let start = self.buffer.len();
        self.buffer.extend_from_slice(payload.as_ref());
        self.payload = Some(BufferRef::new(start, self.buffer.len()));
    }

    fn payload(&mut self) -> Result<&[u8], JoseError> {
        if !self.verify_signature()? {
            return Err(JoseError::IntegrityError("JWS signature is invalid".into()));
        }
        let payload = self
            .payload
            .as_ref()
            .ok_or_else(|| JoseError::new("missing payload"))?;
        Ok(payload.get(&self.buffer))
    }

    fn set_header_value(&mut self, name: impl Into<String>, value: simd_json::owned::Value) {
        if let Some(ref mut header) = self.header {
            header.insert(name.into(), value).unwrap();
        } else {
            let mut header = simd_json::owned::Value::object();
            header.insert(name.into(), value).unwrap();
            self.header = Some(header);
        }
    }

    fn header_name(&self, name: impl AsRef<str>) -> Option<&str> {
        match self.header {
            Some(ref header) => header.get_str(name.as_ref()),
            None => None,
        }
    }

    fn set_key(&mut self, key: &'a JsonWebKey) {
        self.key = Some(key);
    }

    fn key(&self) -> Option<&'a JsonWebKey> {
        self.key
    }

    fn set_algorithm_constraints(
        &mut self,
        algorithm_constraints: &'a AlgorithmConstraints<AlgorithmIdentifier>,
    ) {
        self.algorithm_constraints = algorithm_constraints;
    }
}

impl<'a> Default for JsonWebSignature<'a> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use crate::jwa::ConstraintType;
    use crate::jwk::JsonWebKeyGenerator;

    use super::*;

    #[test]
    fn test_set_compact_serialization() {
        let mut jws = JsonWebSignature::new();
        let compact_serialization = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.\
            eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.\
            NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ";

        jws.set_compact_serialization(compact_serialization)
            .unwrap();
        assert_eq!(jws.algorithm_header_value().unwrap(), "RS256");
    }

    #[test]
    fn test_get_compact_serialization() {}

    #[test]
    fn test_verify_signature_rs256() {
        let mut jws = JsonWebSignature::new();
        let compact_serialization = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.\
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
        let jwk = JsonWebKey::from_pem(pub_key).unwrap();

        jws.set_compact_serialization(compact_serialization)
            .unwrap();
        jws.set_key(&jwk);
        assert!(jws.verify_signature().unwrap());
    }

    #[test]
    fn test_verify_signature_ps256() {
        let mut jws = JsonWebSignature::new();
        let compact_serialization = "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.\
            eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.\
            iOeNU4dAFFeBwNj6qdhdvm-IvDQrTa6R22lQVJVuWJxorJfeQww5Nwsra0PjaOYhAMj9jNMO5YLmud8U7iQ5gJK2zYyepeSuXhfSi8yjFZfRiSkelqSkU19I-Ja8aQBDbqXf2SAWA8mHF8VS3F08rgEaLCyv98fLLH4vSvsJGf6ueZSLKDVXz24rZRXGWtYYk_OYYTVgR1cg0BLCsuCvqZvHleImJKiWmtS0-CymMO4MMjCy_FIl6I56NqLE9C87tUVpo1mT-kbg5cHDD8I7MjCW5Iii5dethB4Vid3mZ6emKjVYgXrtkOQ-JyGMh6fnQxEFN1ft33GX2eRHluK9eg";

        let pub_key = "-----BEGIN PUBLIC KEY-----\n\
            MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo\n\
            4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u\n\
            +qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh\n\
            kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ\n\
            0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg\n\
            cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc\n\
            mwIDAQAB\n\
            -----END PUBLIC KEY-----\n";
        let jwk = JsonWebKey::from_pem(pub_key).unwrap();

        jws.set_compact_serialization(compact_serialization)
            .unwrap();
        jws.set_key(&jwk);
        assert!(jws.verify_signature().unwrap());
    }

    #[test]
    fn test_verify_signature_es256() {
        let mut jws = JsonWebSignature::new();
        let compact_serialization = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.\
            eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTc0NTA5MjgwMCwiZXhwIjoxNzQ1MDk2NDAwfQ.\
            N0bI7WwFbnB9IQoR-PXpJ2voDNCoQwyBuISXVfgLbVDyVh0xwKPYnx7jITw7DTXWDxwZsxVwGgPAeAENF87DeQ";

        let pub_key = "-----BEGIN PUBLIC KEY-----\n\
            MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAERqVXn+o+6zEOpWEsGw5CsB+wd8zO\n\
            jxu0uASGpiGP+wYfcc1unyMxcStbDzUjRuObY8DalaCJ9/J6UrkQkZBtZw==\n\
            -----END PUBLIC KEY-----\n";
        let jwk = JsonWebKey::from_pem(pub_key).unwrap();

        jws.set_compact_serialization(compact_serialization)
            .unwrap();
        jws.set_key(&jwk);

        assert!(jws.verify_signature().unwrap());
    }

    #[test]
    fn test_verify_signature_es512() {
        let mut jws = JsonWebSignature::new();
        let compact_serialization = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzUxMiJ9.\
            eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTc0NTM5MjY0MSwiZXhwIjoxNzQ1Mzk2MjQxfQ.\
            ADztEUbN6APNOkpPH9R8JJY9wcLKfZfVg9LFL6bsQDue6br37wnPXIBeZFzgZzsPkVd-jggeDWjMYSBBNfXKqe6fAGa9pb6R403K2IdQ318v0DszIgLLjIwoKcHxo8B9TebxJXJPPgDMOFF6CHJaqrNuymd_wNef7kM86B9LoTWImTJz";

        let pub_key = "-----BEGIN PUBLIC KEY-----\n\
            MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBh4Cv4rcExpKWeuOazO4l05gGy0Yl\n\
            /SK0zZNMbCxo7T5wZxeivx/Qs9dsH0H+AsrubS2HeiRfPKkiur6qBMywyKAAYt2/\n\
            3ZoBGbp597+wQnJEn6fggHGExFObrAh7wBmGWR0tbHMTJ+6yJctkeifU2C39Dx38\n\
            9hZitslVZLtWucrTlsk=\n\
            -----END PUBLIC KEY-----\n";
        let jwk = JsonWebKey::from_pem(pub_key).unwrap();

        jws.set_compact_serialization(compact_serialization)
            .unwrap();
        jws.set_key(&jwk);

        assert!(jws.verify_signature().unwrap());
    }

    #[test]
    fn test_verify_signature_ed25519() {
        let json =
            r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#;
        let jwk = JsonWebKey::from_json(json).unwrap();

        let compact_serialization = "eyJhbGciOiJFZERTQSJ9.\
            RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.\
            hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg";
        let mut jws = JsonWebSignature::new();

        jws.set_compact_serialization(compact_serialization)
            .unwrap();
        jws.set_key(&jwk);
        assert!(jws.verify_signature().unwrap());
    }

    #[test]
    fn test_set_jwk_header_embeds_object() {
        // The `jwk` header must be a nested JSON object (ACME new-account),
        // not a string-encoded JWK.
        let key = JsonWebKeyGenerator::for_signature(AlgorithmIdentifier::HmacSha256)
            .generate()
            .unwrap();
        let mut jws = JsonWebSignature::new();
        jws.set_payload(b"hello");
        jws.set_algorithm(AlgorithmIdentifier::HmacSha256);
        jws.set_key(&key);
        jws.set_jwk_header(&key);

        // Inspect the in-memory protected header directly.
        let header = jws.header.as_ref().unwrap();
        let jwk_val = header.get("jwk").unwrap();
        assert!(jwk_val.is_object(), "jwk header must be a JSON object");
        assert_eq!(jwk_val.get_str("kty"), Some("oct"));

        // And it must survive a flattened serialize/parse round-trip.
        let json = jws.flattened_json_serialization().unwrap();
        let parsed = JsonWebSignature::from_flattened_json_serialization(&json).unwrap();
        let header = parsed.header.as_ref().unwrap();
        assert!(header.get("jwk").unwrap().is_object());
    }

    // -- RFC 7797 (b64=false / unencoded / detached payload) -----------------

    /// RFC 7797 Appendix A worked example: HS256 over the unencoded payload
    /// `$.02` with `b64:false, crit:["b64"]`. The signature is a known answer.
    #[test]
    fn test_rfc7797_appendix_a_vector() {
        // Symmetric key from RFC 7797 Appendix A.
        let key_json = r#"{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}"#;
        let key = JsonWebKey::from_json(key_json).unwrap();

        // Protected header: {"alg":"HS256","b64":false,"crit":["b64"]}
        let protected = "eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19";
        let expected_sig = "A5dxf2s96_n5FLueVuW1Z_vh161FwXZC4YLPff6dmDY";

        // Build the flattened serialization with the RAW payload $.02 embedded
        // (base64url of the payload for the "payload" member is "JC4wMg").
        let flattened = format!(
            r#"{{"protected":"{protected}","payload":"JC4wMg","signature":"{expected_sig}"}}"#
        );

        let mut jws = JsonWebSignature::from_flattened_json_serialization(&flattened).unwrap();
        jws.set_key(&key);
        assert!(
            jws.verify_signature().unwrap(),
            "RFC 7797 Appendix A signature must verify"
        );
        // The payload round-trips as the raw bytes $.02.
        assert_eq!(jws.unverified_payload().unwrap(), b"$.02");
    }

    /// Sign with b64=false and confirm the signature uses the raw payload, then
    /// verify it back. Also confirm the serialized payload stays embedded.
    #[test]
    fn test_b64_false_sign_verify_round_trip() {
        let key = JsonWebKeyGenerator::for_signature(AlgorithmIdentifier::HmacSha256)
            .generate()
            .unwrap();

        let mut jws = JsonWebSignature::new();
        jws.set_payload(b"$.02");
        jws.set_algorithm(AlgorithmIdentifier::HmacSha256);
        jws.set_key(&key);
        jws.set_b64(false);

        let json = jws.flattened_json_serialization().unwrap();

        // The protected header must carry b64:false + crit:["b64"].
        let parsed = JsonWebSignature::from_flattened_json_serialization(&json).unwrap();
        let header = parsed.header.as_ref().unwrap();
        assert_eq!(header.get("b64").unwrap().as_bool(), Some(false));

        let mut parsed = parsed;
        parsed.set_key(&key);
        assert!(parsed.verify_signature().unwrap());
        assert_eq!(parsed.unverified_payload().unwrap(), b"$.02");
    }

    /// Detached payload: the payload is omitted from the serialization but
    /// supplied out-of-band for signing and verification (the ACME POST form).
    #[test]
    fn test_b64_false_detached_payload() {
        let key = JsonWebKeyGenerator::for_signature(AlgorithmIdentifier::HmacSha256)
            .generate()
            .unwrap();

        let mut jws = JsonWebSignature::new();
        jws.set_algorithm(AlgorithmIdentifier::HmacSha256);
        jws.set_key(&key);
        jws.set_b64(false);
        jws.set_detached_payload(b"$.02");

        let json = jws.flattened_json_serialization().unwrap();
        // Detached => no "payload" member in the JSON.
        assert!(
            !json.contains("\"payload\""),
            "detached JWS must omit payload: {json}"
        );

        // Verify: parse, re-attach the payload, then verify.
        let mut parsed = JsonWebSignature::from_flattened_json_serialization(&json).unwrap();
        parsed.set_b64(false); // parse records b64=false from the header already
        parsed.set_detached_payload(b"$.02");
        parsed.set_key(&key);
        assert!(parsed.verify_signature().unwrap());

        // A tampered payload must fail.
        let mut bad = JsonWebSignature::from_flattened_json_serialization(&json).unwrap();
        bad.set_detached_payload(b"$.03");
        bad.set_key(&key);
        assert!(!bad.verify_signature().unwrap());
    }

    /// b64=false without crit listing b64 must be rejected (RFC 7797 Section 3).
    #[test]
    fn test_b64_false_without_crit_rejected() {
        // {"alg":"HS256","b64":false}  -- no crit
        let protected = "eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2V9";
        let flattened =
            format!(r#"{{"protected":"{protected}","payload":"JC4wMg","signature":"AA"}}"#);
        assert!(JsonWebSignature::from_flattened_json_serialization(&flattened).is_err());
    }

    /// An unknown extension listed in `crit` must be rejected
    /// (RFC 7515 Section 4.1.11), even though it is otherwise ignored.
    #[test]
    fn test_unknown_crit_extension_rejected() {
        // {"alg":"HS256","crit":["exp-ext"],"exp-ext":true}
        let protected = "eyJhbGciOiJIUzI1NiIsImNyaXQiOlsiZXhwLWV4dCJdLCJleHAtZXh0Ijp0cnVlfQ";
        let flattened =
            format!(r#"{{"protected":"{protected}","payload":"JC4wMg","signature":"AA"}}"#);
        let err = JsonWebSignature::from_flattened_json_serialization(&flattened).unwrap_err();
        assert!(err.to_string().contains("critical"), "{err}");

        // A crit that is not an array is also malformed.
        // {"alg":"HS256","crit":"b64"}
        let protected = "eyJhbGciOiJIUzI1NiIsImNyaXQiOiJiNjQifQ";
        let flattened =
            format!(r#"{{"protected":"{protected}","payload":"JC4wMg","signature":"AA"}}"#);
        assert!(JsonWebSignature::from_flattened_json_serialization(&flattened).is_err());
    }

    /// b64=false is not representable in compact serialization.
    #[test]
    fn test_b64_false_compact_rejected() {
        let key = JsonWebKeyGenerator::for_signature(AlgorithmIdentifier::HmacSha256)
            .generate()
            .unwrap();
        let mut jws = JsonWebSignature::new();
        jws.set_payload(b"hello");
        jws.set_algorithm(AlgorithmIdentifier::HmacSha256);
        jws.set_key(&key);
        jws.set_b64(false);
        assert!(jws.compact_serialization().is_err());
    }

    #[test]
    fn test_compact_sign_verify_round_trip() {
        for alg in [
            AlgorithmIdentifier::HmacSha256,
            AlgorithmIdentifier::HmacSha384,
            AlgorithmIdentifier::HmacSha512,
            AlgorithmIdentifier::RsaUsingSha256,
            AlgorithmIdentifier::RsaUsingSha384,
            AlgorithmIdentifier::RsaUsingSha512,
            AlgorithmIdentifier::RsaPssUsingSha256,
            AlgorithmIdentifier::RsaPssUsingSha384,
            AlgorithmIdentifier::RsaPssUsingSha512,
            AlgorithmIdentifier::EdDsa,
            AlgorithmIdentifier::EcdsaUsingP256CurveAndSha256,
            AlgorithmIdentifier::EcdsaUsingP384CurveAndSha384,
            AlgorithmIdentifier::EcdsaUsingP521CurveAndSha512,
            #[cfg(not(feature = "boring"))]
            AlgorithmIdentifier::EcdsaUsingSecp256k1CurveAndSha256,
        ] {
            let key = JsonWebKeyGenerator::for_signature(alg).generate().unwrap();
            let mut jws = JsonWebSignature::new();
            let payload = b"hello world";
            jws.set_payload(payload);
            jws.set_algorithm(alg);
            jws.set_key(&key);

            let compact_serialization = jws.compact_serialization().unwrap();
            let mut jws =
                JsonWebSignature::from_compact_serialization(&compact_serialization).unwrap();
            jws.set_key(&key);
            assert_eq!(jws.payload().unwrap(), payload);
        }
    }

    #[test]
    fn test_json_sign_verify_round_trip() {
        for alg in [
            AlgorithmIdentifier::HmacSha256,
            AlgorithmIdentifier::HmacSha384,
            AlgorithmIdentifier::HmacSha512,
            AlgorithmIdentifier::RsaUsingSha256,
            AlgorithmIdentifier::RsaUsingSha384,
            AlgorithmIdentifier::RsaUsingSha512,
            AlgorithmIdentifier::RsaPssUsingSha256,
            AlgorithmIdentifier::RsaPssUsingSha384,
            AlgorithmIdentifier::RsaPssUsingSha512,
            AlgorithmIdentifier::EdDsa,
            AlgorithmIdentifier::EcdsaUsingP256CurveAndSha256,
            AlgorithmIdentifier::EcdsaUsingP384CurveAndSha384,
            AlgorithmIdentifier::EcdsaUsingP521CurveAndSha512,
            #[cfg(not(feature = "boring"))]
            AlgorithmIdentifier::EcdsaUsingSecp256k1CurveAndSha256,
        ] {
            let key = JsonWebKeyGenerator::for_signature(alg).generate().unwrap();
            let mut jws = JsonWebSignature::new();
            let payload = b"hello world";
            jws.set_payload(payload);
            jws.set_algorithm(alg);
            jws.set_key(&key);

            let json_serialization = jws.flattened_json_serialization().unwrap();
            let mut jws =
                JsonWebSignature::from_flattened_json_serialization(&json_serialization).unwrap();
            jws.set_key(&key);
            assert_eq!(jws.payload().unwrap(), payload);
        }
    }

    #[test]
    fn test_short_hmac_key_errors_not_panics() {
        // RFC 7518 Section 3.2 requires an HMAC key at least as large as the hash
        // output. A too-short oct key is attacker-controlled input, so verify
        // must return Err rather than panic. First sign with a valid key.
        let good_key = JsonWebKeyGenerator::for_signature(AlgorithmIdentifier::HmacSha256)
            .generate()
            .unwrap();
        let mut jws = JsonWebSignature::new();
        jws.set_payload(b"hello");
        jws.set_algorithm(AlgorithmIdentifier::HmacSha256);
        jws.set_key(&good_key);
        let compact = jws.compact_serialization().unwrap();

        // An oct JWK whose `k` decodes to fewer than 32 bytes (HS256 minimum).
        let short_key =
            JsonWebKey::from_json(r#"{"kty":"oct","alg":"HS256","k":"c2hvcnQ"}"#).unwrap();
        let mut jws = JsonWebSignature::from_compact_serialization(&compact).unwrap();
        jws.set_key(&short_key);
        let result = jws.verify_signature();
        assert!(
            matches!(result, Err(JoseError::InvalidKey(_))),
            "{result:?}"
        );

        // Signing with a too-short key errors too (no panic).
        let mut jws = JsonWebSignature::new();
        jws.set_payload(b"hello");
        jws.set_algorithm(AlgorithmIdentifier::HmacSha256);
        jws.set_key(&short_key);
        let result = jws.compact_serialization();
        assert!(
            matches!(result, Err(JoseError::InvalidKey(_))),
            "{result:?}"
        );
    }

    /// An EC key on the wrong curve for the algorithm must be
    /// rejected (RFC 7518 Section 3.4). A P-384 key used with ES256, etc.
    #[test]
    fn test_ec_curve_mismatch_rejected() {
        // Sign with ES256 (P-256) but hand the verifier a P-384 key.
        let p256_key =
            JsonWebKeyGenerator::for_signature(AlgorithmIdentifier::EcdsaUsingP256CurveAndSha256)
                .generate()
                .unwrap();
        let p384_key =
            JsonWebKeyGenerator::for_signature(AlgorithmIdentifier::EcdsaUsingP384CurveAndSha384)
                .generate()
                .unwrap();

        let mut jws = JsonWebSignature::new();
        jws.set_payload(b"hello");
        jws.set_algorithm(AlgorithmIdentifier::EcdsaUsingP256CurveAndSha256);
        jws.set_key(&p256_key);
        let compact = jws.compact_serialization().unwrap();

        // Verify with the wrong-curve (P-384) key: must error, not just fail.
        let mut parsed = JsonWebSignature::from_compact_serialization(&compact).unwrap();
        parsed.set_key(&p384_key);
        let result = parsed.verify_signature();
        assert!(
            matches!(result, Err(JoseError::InvalidKey(_))),
            "expected InvalidKey, got {result:?}"
        );

        // Signing with a wrong-curve key must also error (no panic).
        let mut bad = JsonWebSignature::new();
        bad.set_payload(b"hello");
        bad.set_algorithm(AlgorithmIdentifier::EcdsaUsingP256CurveAndSha256);
        bad.set_key(&p384_key);
        let result = bad.compact_serialization();
        assert!(
            matches!(result, Err(JoseError::InvalidKey(_))),
            "expected InvalidKey on sign, got {result:?}"
        );
    }

    /// `set_b64(true)` must remove both `crit` and `b64`, so the serialized
    /// header doesn't reference an absent extension.
    #[test]
    fn test_set_b64_true_clears_crit() {
        let key = JsonWebKeyGenerator::for_signature(AlgorithmIdentifier::HmacSha256)
            .generate()
            .unwrap();
        let mut jws = JsonWebSignature::new();
        jws.set_payload(b"hello");
        jws.set_algorithm(AlgorithmIdentifier::HmacSha256);
        jws.set_key(&key);
        jws.set_b64(false);
        jws.set_detached_payload(b"hello");
        // Now flip back to the default encoded form.
        jws.set_b64(true);

        let json = jws.flattened_json_serialization().unwrap();
        // The header must not carry a `crit` referencing a now-absent `b64`.
        assert!(
            !json.contains("\"crit\""),
            "crit header should be removed: {json}"
        );
        assert!(
            !json.contains("\"b64\""),
            "b64 header should be removed: {json}"
        );
        // And it must verify cleanly with the attached payload.
        let mut parsed = JsonWebSignature::from_flattened_json_serialization(&json).unwrap();
        parsed.set_key(&key);
        assert!(parsed.verify_signature().unwrap());
    }

    #[test]
    fn test_non_object_protected_header_rejected() {
        // A JWS protected header that decodes to valid JSON but is not an object
        // must be rejected at parse time (so set_header_name can never panic).
        // BASE64URL(`[1,2,3]`) below is a JSON array, not an object.
        let enc = |b: &[u8]| String::from_utf8(base64::url_encode(b).into_vec()).unwrap();
        let compact = format!("{}.{}.{}", enc(b"[1,2,3]"), enc(b"payload"), enc(b"sig"));
        assert!(JsonWebSignature::from_compact_serialization(&compact).is_err());
    }

    // -- alg=none (unsecured JWS) ----------------------------------------

    #[test]
    fn test_none_sign_verify_round_trip() {
        let permit_none =
            AlgorithmConstraints::new(ConstraintType::Permit, [AlgorithmIdentifier::None]);
        let mut jws = JsonWebSignature::new();
        jws.set_payload(b"unsecured payload");
        jws.set_algorithm(AlgorithmIdentifier::None);
        jws.set_algorithm_constraints(&permit_none);
        let compact = jws.compact_serialization().unwrap();

        assert!(compact.ends_with('.'));

        let mut jws = JsonWebSignature::from_compact_serialization(&compact).unwrap();
        jws.set_algorithm_constraints(&permit_none);
        assert!(jws.verify_signature().unwrap());
        assert_eq!(jws.payload().unwrap(), b"unsecured payload");
    }

    #[test]
    fn test_none_verify_rejects_key() {
        let permit_none =
            AlgorithmConstraints::new(ConstraintType::Permit, [AlgorithmIdentifier::None]);
        let mut jws = JsonWebSignature::new();
        jws.set_payload(b"payload");
        jws.set_algorithm(AlgorithmIdentifier::None);
        jws.set_algorithm_constraints(&permit_none);
        let compact = jws.compact_serialization().unwrap();

        let key = JsonWebKeyGenerator::for_signature(AlgorithmIdentifier::HmacSha256)
            .generate()
            .unwrap();
        let mut jws = JsonWebSignature::from_compact_serialization(&compact).unwrap();
        jws.set_algorithm_constraints(&permit_none);
        jws.set_key(&key);
        assert!(matches!(
            jws.verify_signature(),
            Err(JoseError::InvalidKey(_))
        ));
    }

    #[test]
    fn test_none_sign_rejects_key() {
        let permit_none =
            AlgorithmConstraints::new(ConstraintType::Permit, [AlgorithmIdentifier::None]);
        let key = JsonWebKeyGenerator::for_signature(AlgorithmIdentifier::HmacSha256)
            .generate()
            .unwrap();
        let mut jws = JsonWebSignature::new();
        jws.set_payload(b"payload");
        jws.set_algorithm(AlgorithmIdentifier::None);
        jws.set_algorithm_constraints(&permit_none);
        jws.set_key(&key);
        assert!(matches!(
            jws.compact_serialization(),
            Err(JoseError::InvalidKey(_))
        ));
    }

    #[test]
    fn test_none_verify_rejects_nonempty_signature() {
        let permit_none =
            AlgorithmConstraints::new(ConstraintType::Permit, [AlgorithmIdentifier::None]);
        let enc = |b: &[u8]| String::from_utf8(base64::url_encode(b).into_vec()).unwrap();
        let compact = format!(
            "{}.{}.{}",
            enc(br#"{"alg":"none"}"#),
            enc(b"payload"),
            enc(b"fake-signature")
        );
        let mut jws = JsonWebSignature::from_compact_serialization(&compact).unwrap();
        jws.set_algorithm_constraints(&permit_none);
        assert!(!jws.verify_signature().unwrap());
    }

    // -- flattened JSON error paths --------------------------------------

    #[test]
    fn test_flattened_json_missing_protected() {
        let json = r#"{"payload":"cGF5bG9hZA","signature":"c2ln"}"#;
        assert!(JsonWebSignature::from_flattened_json_serialization(json).is_err());
    }

    #[test]
    fn test_flattened_json_missing_payload() {
        let json = r#"{"protected":"eyJhbGciOiJub25lIn0","signature":"c2ln"}"#;
        assert!(JsonWebSignature::from_flattened_json_serialization(json).is_err());
    }

    #[test]
    fn test_flattened_json_missing_signature() {
        let json = r#"{"protected":"eyJhbGciOiJub25lIn0","payload":"cGF5bG9hZA"}"#;
        assert!(JsonWebSignature::from_flattened_json_serialization(json).is_err());
    }

    #[test]
    fn test_flattened_json_unprotected_header_rejected() {
        let json = r#"{"protected":"eyJhbGciOiJub25lIn0","header":{},"payload":"cGF5bG9hZA","signature":""}"#;
        assert!(JsonWebSignature::from_flattened_json_serialization(json).is_err());
    }
}
