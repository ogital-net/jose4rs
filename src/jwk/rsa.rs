use std::collections::BTreeMap;

use crate::{
    crypto::{BigNum, DigestAlgorithm, EvpPkey, Rsa, RsaPadding},
    error::JoseError,
    jws::AlgorithmIdentifier,
};

use super::GetStr;

pub struct RsaJsonWebKey {
    evp_pkey: EvpPkey,
    alg: Option<AlgorithmIdentifier>,
    key_use: Option<super::KeyUse>,
}

impl RsaJsonWebKey {
    pub(super) fn new(evp_pkey: EvpPkey, alg: Option<AlgorithmIdentifier>) -> Self {
        Self {
            evp_pkey,
            alg,
            key_use: None,
        }
    }

    pub(super) fn from_evp_pkey(evp_pkey: EvpPkey) -> Self {
        Self {
            evp_pkey,
            alg: None,
            key_use: None,
        }
    }

    pub fn to_der(&self) -> Box<[u8]> {
        if self.evp_pkey.rsa().unwrap().is_private() {
            self.evp_pkey.private_key_to_der().unwrap()
        } else {
            self.evp_pkey.public_key_to_der().unwrap()
        }
    }

    pub fn to_json(&self, level: super::OutputControlLevel) -> String {
        todo!()
    }

    pub fn key_type(&self) -> &'static str {
        "RSA"
    }

    pub fn key_size_bits(&self) -> usize {
        self.evp_pkey.key_size_bits()
    }

    pub fn sign(&self, message: &[u8], digest: DigestAlgorithm) -> Box<[u8]> {
        self.evp_pkey.sign(message, digest)
    }

    pub fn sign_rsa_pss(&self, message: &[u8], digest: DigestAlgorithm) -> Box<[u8]> {
        self.evp_pkey.sign_rsa_pss(message, digest)
    }

    pub fn verify(&self, message: &[u8], digest: DigestAlgorithm, signature: &[u8]) -> bool {
        self.evp_pkey.verify(message, digest, signature)
    }

    pub fn verify_rsa_pss(
        &self,
        message: &[u8],
        digest: DigestAlgorithm,
        signature: &[u8],
    ) -> bool {
        self.evp_pkey.verify_rsa_pss(message, digest, signature)
    }

    pub fn encrypt_pcks1_1_5(&self, plaintext: &[u8]) -> Box<[u8]> {
        self.evp_pkey
            .rsa_encrypt(RsaPadding::Pkcs1, DigestAlgorithm::Sha1, plaintext)
    }

    pub fn decrypt_pcks1_1_5(&self, plaintext: &[u8]) -> Result<Box<[u8]>, JoseError> {
        self.evp_pkey
            .rsa_decrypt(RsaPadding::Pkcs1, DigestAlgorithm::Sha1, plaintext)
    }

    pub fn encrypt_oaep(&self, plaintext: &[u8], digest_alg: DigestAlgorithm) -> Box<[u8]> {
        self.evp_pkey
            .rsa_encrypt(RsaPadding::Pkcs1Oaep, digest_alg, plaintext)
    }

    pub fn decrypt_oaep(
        &self,
        plaintext: &[u8],
        digest_alg: DigestAlgorithm,
    ) -> Result<Box<[u8]>, JoseError> {
        self.evp_pkey
            .rsa_decrypt(RsaPadding::Pkcs1Oaep, digest_alg, plaintext)
    }

    pub(super) fn from_map(value: impl GetStr) -> Result<Self, JoseError> {
        let n = value.get("n").map(BigNum::from_b64).transpose()?;
        let e = value.get("e").map(BigNum::from_b64).transpose()?;
        let d = value.get("d").map(BigNum::from_b64).transpose()?;
        let p = value.get("p").map(BigNum::from_b64).transpose()?;
        let q = value.get("q").map(BigNum::from_b64).transpose()?;
        let dp = value.get("dp").map(BigNum::from_b64).transpose()?;
        let dq = value.get("dq").map(BigNum::from_b64).transpose()?;
        let qi = value.get("qi").map(BigNum::from_b64).transpose()?;

        let mut rsa = Rsa::new();
        if n.is_none() {
            return Err(JoseError::InvalidKey("Missing 'n' parameter".to_string()));
        }
        if e.is_none() {
            return Err(JoseError::InvalidKey("Missing 'e' parameter".to_string()));
        }
        let private = d.is_some();
        rsa.set_key(n.unwrap(), e.unwrap(), d);

        #[allow(clippy::unnecessary_unwrap)]
        if private && p.is_some() && q.is_some() {
            rsa.set_factors(p.unwrap(), q.unwrap());

            if dp.is_some() && dq.is_some() && qi.is_some() {
                rsa.set_crt_params(dp.unwrap(), dq.unwrap(), qi.unwrap());
            }
        }

        let alg = match value.get("alg") {
            Some(alg) => match alg {
                "RS256" => Some(AlgorithmIdentifier::RsaUsingSha256),
                "RS384" => Some(AlgorithmIdentifier::RsaUsingSha384),
                "RS512" => Some(AlgorithmIdentifier::RsaUsingSha512),
                "PS256" => Some(AlgorithmIdentifier::RsaPssUsingSha256),
                "PS384" => Some(AlgorithmIdentifier::RsaPssUsingSha384),
                "PS512" => Some(AlgorithmIdentifier::RsaPssUsingSha512),
                _ => return Err(JoseError::InvalidAlgorithm(format!("invalid 'alg' {alg}"))),
            },
            None => None,
        };

        Ok(Self::new(EvpPkey::from_rsa(rsa), alg))
    }

    pub(crate) fn evp_pkey(&self) -> &EvpPkey {
        &self.evp_pkey
    }
}

impl TryFrom<BTreeMap<String, String>> for RsaJsonWebKey {
    type Error = JoseError;

    fn try_from(value: BTreeMap<String, String>) -> Result<Self, Self::Error> {
        RsaJsonWebKey::from_map(value)
    }
}

impl TryFrom<simd_json::BorrowedValue<'_>> for RsaJsonWebKey {
    type Error = JoseError;

    fn try_from(value: simd_json::BorrowedValue) -> Result<Self, Self::Error> {
        RsaJsonWebKey::from_map(value)
    }
}

impl TryFrom<&simd_json::OwnedValue> for RsaJsonWebKey {
    type Error = JoseError;

    fn try_from(value: &simd_json::OwnedValue) -> Result<Self, Self::Error> {
        RsaJsonWebKey::from_map(value)
    }
}
