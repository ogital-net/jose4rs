use std::collections::BTreeMap;

use crate::{
    base64,
    crypto::{hmac, mem::crypto_memcmp, DigestAlgorithm},
    error::JoseError,
    jws::AlgorithmIdentifier,
};

use super::GetStr;

#[derive(Clone)]
/// A symmetric (shared-secret) JSON Web Key (`kty: "oct"`), used for HMAC
/// signatures and symmetric JWE key management / direct encryption.
pub struct OctetSequenceJsonWebKey {
    oct_key: Box<[u8]>,
    alg: Option<AlgorithmIdentifier>,
    key_use: Option<super::KeyUse>,
    key_id: Option<String>,
}

// Redacted Debug: shows key metadata but never the symmetric key material.
impl std::fmt::Debug for OctetSequenceJsonWebKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OctetSequenceJsonWebKey")
            .field("kty", &self.key_type())
            .field("size_bits", &self.key_size_bits())
            .field("alg", &self.alg())
            .field("use", &self.key_use())
            .field("kid", &self.key_id())
            .finish()
    }
}

impl OctetSequenceJsonWebKey {
    pub(super) fn new(oct_key: Box<[u8]>, alg: Option<AlgorithmIdentifier>) -> Self {
        Self {
            oct_key,
            alg,
            key_use: None,
            key_id: None,
        }
    }

    /// The key ID (`kid`), if set.
    pub fn key_id(&self) -> Option<&str> {
        self.key_id.as_deref()
    }

    /// Sets the key ID (`kid`).
    pub fn set_key_id(&mut self, key_id: impl Into<String>) {
        self.key_id = Some(key_id.into());
    }

    /// The key usage (`use`), if set.
    pub fn key_use(&self) -> Option<super::KeyUse> {
        self.key_use
    }

    /// Sets the key usage (`use`).
    pub fn set_key_use(&mut self, key_use: super::KeyUse) {
        self.key_use = Some(key_use);
    }

    /// The algorithm (`alg`) designated for this key, if set.
    pub fn alg(&self) -> Option<&'static str> {
        self.alg.map(|a| a.name())
    }

    /// Serializes the key to its JWK JSON form, honoring the given output level.
    ///
    /// The symmetric `k` value is only included for
    /// [`super::OutputControlLevel::IncludePrivate`] or
    /// [`super::OutputControlLevel::IncludeSymmetric`].
    pub fn to_json(&self, level: super::OutputControlLevel) -> String {
        use super::OutputControlLevel;

        // {"kty":"oct"} plus optional ,"alg":"<alg>", ,"use":"<use>",
        // ,"kid":"<id>" and ,"k":"<b64>"
        let alg_len = self.alg.map_or(0, |a| 9 + a.name().len());
        let use_len = self.key_use.map_or(0, |u| 8 + u.as_str().len());
        let kid_len = self.key_id.as_ref().map_or(0, |v| 8 + v.len());
        let k_len = match level {
            OutputControlLevel::IncludePrivate | OutputControlLevel::IncludeSymmetric => {
                6 + base64::url_encode_size(self.oct_key.len())
            }
            OutputControlLevel::PublicOnly => 0,
        };
        let mut out = String::with_capacity(13 + alg_len + use_len + kid_len + k_len);

        out.push_str("{\"kty\":\"oct\"");
        if let Some(alg) = self.alg {
            out.push_str(",\"alg\":\"");
            out.push_str(alg.name());
            out.push('"');
        }
        if let Some(key_use) = self.key_use {
            out.push_str(",\"use\":\"");
            out.push_str(key_use.as_str());
            out.push('"');
        }
        if let Some(key_id) = &self.key_id {
            out.push_str(",\"kid\":\"");
            out.push_str(key_id);
            out.push('"');
        }
        match level {
            OutputControlLevel::IncludePrivate | OutputControlLevel::IncludeSymmetric => {
                out.push_str(",\"k\":\"");
                // SAFETY: base64url output is pure ASCII, always valid UTF-8.
                // Bind to a local so the temporary lives for the duration of
                // push_str (edition 2024 enforces this for `&` of owned
                // temporaries).
                let k_b64 = base64::url_encode(&self.oct_key);
                out.push_str(unsafe { std::str::from_utf8_unchecked(&k_b64) });
                out.push('"');
            }
            OutputControlLevel::PublicOnly => {}
        }
        out.push('}');
        out
    }

    /// The JWK key type: always `"oct"`.
    pub fn key_type(&self) -> &'static str {
        "oct"
    }

    /// The size of the symmetric key, in bits.
    pub fn key_size_bits(&self) -> usize {
        self.oct_key.len() * 8
    }

    /// The raw symmetric key bytes.
    pub fn key_bytes(&self) -> &[u8] {
        &self.oct_key
    }

    /// Computes an HMAC over a message using the given digest.
    ///
    /// # Errors
    /// Returns an error if the key is too short for the digest (the JWS layer
    /// enforces the RFC 7518 minimum up front, so this is defense in depth for
    /// direct callers).
    pub fn sign(&self, message: &[u8], digest: DigestAlgorithm) -> Result<Box<[u8]>, JoseError> {
        hmac::hmac(digest, &self.oct_key, message)
    }

    /// Verifies an HMAC over a message in constant time.
    pub fn verify(&self, message: &[u8], digest: DigestAlgorithm, signature: &[u8]) -> bool {
        // An unusable (e.g. too-short) key can never produce a valid
        // signature, so verification simply fails rather than panicking. The
        // JWS layer enforces the RFC 7518 minimum key length up front, so this
        // is defense in depth for direct callers.
        let Ok(expected) = hmac::hmac(digest, &self.oct_key, message) else {
            return false;
        };
        crypto_memcmp(&expected, signature)
    }

    pub(super) fn from_map(value: impl GetStr) -> Result<Self, JoseError> {
        let alg = match value.get("alg") {
            Some(alg) => match alg {
                "HS256" => Some(AlgorithmIdentifier::HmacSha256),
                "HS384" => Some(AlgorithmIdentifier::HmacSha384),
                "HS512" => Some(AlgorithmIdentifier::HmacSha512),
                _ => return Err(JoseError::InvalidKey(format!("invalid 'alg' {alg}"))),
            },
            None => None,
        };

        let k = match value.get("k") {
            Some(k) => base64::url_decode(k)?,
            None => return Err(JoseError::InvalidKey("missing 'k' parameter".into())),
        };
        let mut jwk = Self::new(k, alg);
        jwk.key_id = value.get("kid").map(str::to_string);
        jwk.key_use = value.get("use").map(str::parse).transpose()?;
        Ok(jwk)
    }
}

impl TryFrom<BTreeMap<String, String>> for OctetSequenceJsonWebKey {
    type Error = JoseError;

    fn try_from(value: BTreeMap<String, String>) -> Result<Self, Self::Error> {
        OctetSequenceJsonWebKey::from_map(value)
    }
}
