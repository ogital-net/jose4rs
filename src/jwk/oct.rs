use std::collections::BTreeMap;

use crate::{
    base64,
    crypto::{hmac, mem::crypto_memcmp, DigestAlgorithm},
    error::JoseError,
    jws::AlgorithmIdentifier,
};

use super::GetStr;

pub struct OctetSequenceJsonWebKey {
    oct_key: Box<[u8]>,
    alg: Option<AlgorithmIdentifier>,
}

impl OctetSequenceJsonWebKey {
    pub(super) fn new(oct_key: Box<[u8]>, alg: Option<AlgorithmIdentifier>) -> Self {
        Self { oct_key, alg }
    }

    pub fn to_json(&self, level: super::OutputControlLevel) -> String {
        todo!()
    }

    pub fn key_type(&self) -> &'static str {
        "oct"
    }

    pub fn key_size_bits(&self) -> usize {
        self.oct_key.len() * 8
    }

    pub fn key_bytes(&self) -> &[u8] {
        &self.oct_key
    }

    pub fn sign(&self, message: &[u8], digest: DigestAlgorithm) -> Box<[u8]> {
        hmac::hmac(digest, &self.oct_key, message).unwrap()
    }

    pub fn verify(&self, message: &[u8], digest: DigestAlgorithm, signature: &[u8]) -> bool {
        let expected = hmac::hmac(digest, &self.oct_key, message).unwrap();
        crypto_memcmp(&expected, signature)
    }

    pub(super) fn from_map(value: impl GetStr) -> Result<Self, JoseError> {
        let alg = match value.get("alg") {
            Some(alg) => match alg {
                "HS256" => Some(AlgorithmIdentifier::HmacSha256),
                "HS384" => Some(AlgorithmIdentifier::HmacSha384),
                "HS512" => Some(AlgorithmIdentifier::HmacSha512),
                _ => return Err(JoseError::invalid_key(format!("invalid 'alg' {alg}"))),
            },
            None => None,
        };

        let k = match value.get("k") {
            Some(k) => base64::url_decode(k)?,
            None => return Err(JoseError::invalid_key("missing 'k' parameter")),
        };
        Ok(Self::new(k, alg))
    }
}

impl TryFrom<BTreeMap<String, String>> for OctetSequenceJsonWebKey {
    type Error = JoseError;

    fn try_from(value: BTreeMap<String, String>) -> Result<Self, Self::Error> {
        OctetSequenceJsonWebKey::from_map(value)
    }
}

impl TryFrom<simd_json::BorrowedValue<'_>> for OctetSequenceJsonWebKey {
    type Error = JoseError;

    fn try_from(value: simd_json::BorrowedValue<'_>) -> Result<Self, Self::Error> {
        OctetSequenceJsonWebKey::from_map(value)
    }
}

impl TryFrom<&simd_json::OwnedValue> for OctetSequenceJsonWebKey {
    type Error = JoseError;

    fn try_from(value: &simd_json::OwnedValue) -> Result<Self, Self::Error> {
        OctetSequenceJsonWebKey::from_map(value)
    }
}
