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
    derived::{MutableObject, ValueObjectAccessAsScalar as _},
    prelude::{ValueObjectAccess, Writable as _},
    ValueBuilder,
};

use crate::{
    base64,
    crypto::DigestAlgorithm,
    error::JoseError,
    jwa::{AlgorithmConstraints, BLOCK_NONE},
    jwk::JsonWebKey,
    jwx::{HeaderParameter, JsonWebStructure, Memchr},
    BufferRef,
};

const MIN_RSA_KEY_BITS: usize = 2048;

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
}

impl<'a> JsonWebSignature<'a> {
    fn new() -> Self {
        Self {
            buffer: Vec::new(),
            key: None,
            verification_input: None,
            header: None,
            payload: None,
            signature: None,
            algorithm_constraints: &BLOCK_NONE,
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
    /// the configured key and algorithm. Supports HMAC, RSA, ECDSA, EdDSA, and RSA-PSS algorithms.
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
        };

        // key preflight checks
        let key = self.get_key_with_validation()?;

        let signature = self
            .signature
            .as_ref()
            .ok_or_else(|| JoseError::new("missing signature, cannot verify JWS"))?;
        let verification_input = self
            .verification_input
            .ok_or_else(|| JoseError::new("missing verification input, cannot verify JWS"))?;

        match alg {
            AlgorithmIdentifier::HmacSha256 => match key {
                JsonWebKey::Oct(hmac_key) => Ok(hmac_key.verify(
                    verification_input.get(&self.buffer),
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
                    verification_input.get(&self.buffer),
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
                    verification_input.get(&self.buffer),
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
                    verification_input.get(&self.buffer),
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
                    verification_input.get(&self.buffer),
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
                    verification_input.get(&self.buffer),
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
                    verification_input.get(&self.buffer),
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
                    verification_input.get(&self.buffer),
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
                    verification_input.get(&self.buffer),
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
                    verification_input.get(&self.buffer),
                    DigestAlgorithm::Sha256,
                    signature.get(&self.buffer),
                )),
                _ => Err(JoseError::InvalidKey(format!(
                    "invalid key type {}",
                    key.key_type()
                ))),
            },
            AlgorithmIdentifier::EdDsa => match key {
                JsonWebKey::OctetKeyPair(okp) => Ok(okp.verify(
                    verification_input.get(&self.buffer),
                    signature.get(&self.buffer),
                )),
                _ => Err(JoseError::InvalidKey(format!(
                    "invalid key type {}",
                    key.key_type()
                ))),
            },
            AlgorithmIdentifier::RsaPssUsingSha256 => match key {
                JsonWebKey::Rsa(rsa_key) => Ok(rsa_key.verify_rsa_pss(
                    verification_input.get(&self.buffer),
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
                    verification_input.get(&self.buffer),
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
                    verification_input.get(&self.buffer),
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

    /// Gets the payload without verifying the signature.
    ///
    /// # Warning
    ///
    /// This method returns the payload **without** verifying the signature.
    /// Only use this when you trust the source or plan to verify the signature separately.
    /// For most use cases, prefer using `get_payload()` which verifies the signature first.
    ///
    /// # Returns
    ///
    /// The payload bytes if present.
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
    /// let payload = jws.get_unverified_payload()?;
    /// # Ok::<(), jose4rs::error::JoseError>(())
    /// ```
    pub fn get_unverified_payload(&self) -> Result<&[u8], JoseError> {
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
                    "JWS Plaintext (alg={alg}) must not use a key."
                )));
            }
            return Ok(None);
        };

        // key preflight checks
        let key = self.get_key_with_validation()?;

        let sig = match alg {
            AlgorithmIdentifier::HmacSha256 => match key {
                JsonWebKey::Oct(hmac_key) => Some(hmac_key.sign(input, DigestAlgorithm::Sha256)),
                _ => {
                    return Err(JoseError::InvalidKey(format!(
                        "invalid key type {}",
                        key.key_type()
                    )))
                }
            },
            AlgorithmIdentifier::HmacSha384 => match key {
                JsonWebKey::Oct(hmac_key) => Some(hmac_key.sign(input, DigestAlgorithm::Sha384)),
                _ => {
                    return Err(JoseError::InvalidKey(format!(
                        "invalid key type {}",
                        key.key_type()
                    )))
                }
            },
            AlgorithmIdentifier::HmacSha512 => match key {
                JsonWebKey::Oct(hmac_key) => Some(hmac_key.sign(input, DigestAlgorithm::Sha512)),
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
                JsonWebKey::OctetKeyPair(okp) => Some(okp.sign(input)),
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
            .get_header(HeaderParameter::Algorithm)
            .ok_or_else(|| JoseError::new("missing algorithm in header"))?;
        let alg = AlgorithmIdentifier::try_from(alg)?;
        if check_constraints {
            self.algorithm_constraints.check_constraint(alg)?;
        }
        Ok(alg)
    }

    fn get_key_with_validation(&self) -> Result<&'a JsonWebKey, JoseError> {
        match self.key {
            Some(key) => match key {
                JsonWebKey::Rsa(rsa_key) => {
                    if rsa_key.key_size_bits() < MIN_RSA_KEY_BITS {
                        return Err(JoseError::InvalidKey(format!(
                                "An RSA key of size {MIN_RSA_KEY_BITS} bits or larger MUST be used with the all JOSE \
                                RSA algorithms (given key was only {} bits).",
                                rsa_key.key_size_bits()
                            )));
                    }
                    Ok(key)
                }
                _ => Ok(key),
            },
            None => Err(JoseError::new("missing key")),
        }
    }

    pub(crate) fn get_payload_mut(&mut self) -> Result<&mut [u8], JoseError> {
        if !self.verify_signature()? {
            return Err(JoseError::IntegrityError("JWS signature is invalid".into()));
        }
        let payload = self
            .payload
            .as_ref()
            .ok_or_else(|| JoseError::new("missing payload"))?;
        Ok(payload.get_mut(&mut self.buffer))
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
            let h = simd_json::to_owned_value(h.get_mut(&mut self.buffer))?;
            self.buffer.truncate(len);
            h
        };
        let payload = base64::url_decode_append(encoded_payload, &mut self.buffer)?;
        let signature = base64::url_decode_append(encoded_signature, &mut self.buffer)?;

        self.verification_input = Some(verification_input);
        self.header = Some(header);
        self.payload = Some(payload);
        self.signature = Some(signature);
        Ok(())
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
        let value = simd_json::to_borrowed_value(&mut json)?;
        if value.contains_key("header") {
            return Err(JoseError::new("unprotected header not supported"));
        }
        let protected_header = value.get_str("protected").map_or_else(
            || Err(JoseError::new("invalid JWS, no 'protected' member")),
            |s| Ok(s.as_bytes()),
        )?;
        let encoded_payload = value.get_str("payload").map_or_else(
            || Err(JoseError::new("invalid JWS, no 'payload' member")),
            |s| Ok(s.as_bytes()),
        )?;
        let encoded_signature = value.get_str("signature").map_or_else(
            || Err(JoseError::new("invalid JWS, no 'signature' member")),
            |s| Ok(s.as_bytes()),
        )?;

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
    /// # Example
    ///
    /// ```no_run
    /// # use jose4rs::jws::{JsonWebSignature, AlgorithmIdentifier};
    /// # use jose4rs::jwk::JsonWebKey;
    /// # let mut jws = JsonWebSignature::from_compact_serialization("...").unwrap();
    /// # let key = JsonWebKey::from_pem("...").unwrap();
    /// jws.set_key(&key);
    /// jws.set_algorithm(AlgorithmIdentifier::RsaUsingSha256);
    /// let json = jws.get_flattened_json_serialization()?;
    /// # Ok::<(), jose4rs::error::JoseError>(())
    /// ```
    pub fn get_flattened_json_serialization(&self) -> Result<String, JoseError> {
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

        let sig = self.sign(alg, &out_buffer)?;
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
            let mut iter = Memchr::new(b'.', compact_serialization);

            let mut indexes = [0usize; 2];
            for idx in &mut indexes {
                match iter.next() {
                    Some(i) => *idx = i,
                    None => return Err(JoseError::new("not enough parts")),
                }
            }
            if iter.next().is_some() {
                return Err(JoseError::new("too many parts"));
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

    fn get_compact_serialization(&self) -> Result<String, JoseError> {
        // check algorithm constraints
        let alg = self.get_algorithm(true)?;

        let header = self
            .header
            .as_ref()
            .ok_or_else(|| JoseError::new("missing header"))?;

        let header_json = header.encode();

        // buffer size
        let mut need = base64::url_encode_size(header_json.len());
        need += 1; // '.'
        need += base64::url_encode_size(self.payload.as_ref().map_or(0, |p| p.len()));
        need += 1; // '.'

        match alg {
            AlgorithmIdentifier::None => {}
            AlgorithmIdentifier::HmacSha256 => need += base64::url_encode_size(32),
            AlgorithmIdentifier::HmacSha384 => need += base64::url_encode_size(48),
            AlgorithmIdentifier::HmacSha512 => need += base64::url_encode_size(64),
            AlgorithmIdentifier::EcdsaUsingP256CurveAndSha256 => {
                need += base64::url_encode_size(64)
            }
            AlgorithmIdentifier::EcdsaUsingP384CurveAndSha384 => {
                need += base64::url_encode_size(96)
            }
            AlgorithmIdentifier::EcdsaUsingP521CurveAndSha512 => {
                need += base64::url_encode_size(132)
            }
            #[cfg(not(feature = "boring"))]
            AlgorithmIdentifier::EcdsaUsingSecp256k1CurveAndSha256 => {
                need += base64::url_encode_size(64)
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

    fn get_payload(&mut self) -> Result<&[u8], JoseError> {
        if !self.verify_signature()? {
            return Err(JoseError::IntegrityError("JWS signature is invalid".into()));
        }
        let payload = self
            .payload
            .as_ref()
            .ok_or_else(|| JoseError::new("missing payload"))?;
        Ok(payload.get(&self.buffer))
    }

    fn set_header_name(&mut self, name: impl Into<String>, value: impl Into<String>) {
        match self.header {
            Some(ref mut header) => {
                header.insert(name.into(), value.into()).unwrap();
            }
            None => {
                let mut header = simd_json::owned::Value::object();
                header.insert(name.into(), value.into()).unwrap();
                self.header = Some(header);
            }
        };
    }

    fn get_header_name(&self, name: impl AsRef<str>) -> Option<&str> {
        match self.header {
            Some(ref header) => header.get_str(name.as_ref()),
            None => None,
        }
    }

    fn set_key(&mut self, key: &'a JsonWebKey) {
        self.key = Some(key);
    }

    fn get_key(&mut self) -> Option<&'a JsonWebKey> {
        self.key
    }

    fn set_algorithm_constraints(
        &mut self,
        algorithm_constraints: &'a AlgorithmConstraints<AlgorithmIdentifier>,
    ) {
        self.algorithm_constraints = algorithm_constraints;
    }
}

#[cfg(test)]
mod tests {
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
        assert_eq!(jws.get_algorithm_header_value().unwrap(), "RS256");
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

            let compact_serialization = jws.get_compact_serialization().unwrap();
            let mut jws =
                JsonWebSignature::from_compact_serialization(&compact_serialization).unwrap();
            jws.set_key(&key);
            assert_eq!(jws.get_payload().unwrap(), payload);
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

            let json_serialization = jws.get_flattened_json_serialization().unwrap();
            let mut jws =
                JsonWebSignature::from_flattened_json_serialization(&json_serialization).unwrap();
            jws.set_key(&key);
            assert_eq!(jws.get_payload().unwrap(), payload);
        }
    }
}
