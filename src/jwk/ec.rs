use std::collections::BTreeMap;

use crate::{
    crypto::{BigNum, DigestAlgorithm, EcCurve, EcKey, EvpPkey},
    error::JoseError,
    jws::AlgorithmIdentifier,
};

use super::GetStr;

pub struct ECJsonWebKey {
    evp_pkey: EvpPkey,
    alg: Option<AlgorithmIdentifier>,
}

impl ECJsonWebKey {
    pub(super) fn new(evp_pkey: EvpPkey, alg: Option<AlgorithmIdentifier>) -> Self {
        Self { evp_pkey, alg }
    }

    pub(super) fn from_evp_pkey(evp_pkey: EvpPkey) -> Self {
        Self {
            evp_pkey,
            alg: None,
        }
    }

    pub fn to_der(&self) -> Box<[u8]> {
        if self.evp_pkey.ec().unwrap().is_private() {
            self.evp_pkey.private_key_to_der().unwrap()
        } else {
            self.evp_pkey.public_key_to_der().unwrap()
        }
    }

    pub fn to_json(&self, level: super::OutputControlLevel) -> String {
        todo!()
    }

    pub fn key_type(&self) -> &'static str {
        "EC"
    }

    pub fn sign(&self, message: &[u8], digest_alg: DigestAlgorithm) -> Box<[u8]> {
        let ec = self.evp_pkey.ec().unwrap();
        ec.sign_concatenated(message, digest_alg)
    }

    pub fn verify(&self, message: &[u8], digest_alg: DigestAlgorithm, signature: &[u8]) -> bool {
        let expected_len = match digest_alg {
            DigestAlgorithm::Sha256 => 64,
            DigestAlgorithm::Sha384 => 96,
            DigestAlgorithm::Sha512 => 132,
            _ => 0,
        };
        if signature.len() != expected_len {
            return false;
        }

        let ec = self.evp_pkey.ec().unwrap();
        ec.verify_concatenated(message, digest_alg, signature)
    }

    pub(super) fn from_map(value: impl GetStr) -> Result<Self, JoseError> {
        let x = value.get("x").map(BigNum::from_b64).transpose()?;
        let y = value.get("y").map(BigNum::from_b64).transpose()?;
        let d = value.get("d").map(BigNum::from_b64).transpose()?;

        let curve = value
            .get("crv")
            .ok_or_else(|| JoseError::InvalidKey("Missing 'crv' parameter".to_string()))?;
        let curve = curve.try_into()?;

        let mut ec_key = EcKey::new(curve);
        if x.is_none() {
            return Err(JoseError::InvalidKey("Missing 'x' parameter".to_string()));
        }
        if y.is_none() {
            return Err(JoseError::InvalidKey("Missing 'y' parameter".to_string()));
        }
        let private = d.is_some();
        ec_key.set_pub_key(x.unwrap(), y.unwrap());
        if private {
            ec_key.set_priv_key(d.unwrap());
        }
        ec_key.check_key()?;

        let alg = match value.get("alg") {
            Some(alg) => match alg {
                "ES256" => Some(AlgorithmIdentifier::EcdsaUsingP256CurveAndSha256),
                "ES384" => Some(AlgorithmIdentifier::EcdsaUsingP384CurveAndSha384),
                "ES512" => Some(AlgorithmIdentifier::EcdsaUsingP521CurveAndSha512),
                #[cfg(not(feature = "boring"))]
                "ES256K" => Some(AlgorithmIdentifier::EcdsaUsingSecp256k1CurveAndSha256),
                _ => return Err(JoseError::InvalidAlgorithm(format!("invalid 'alg' {alg}"))),
            },
            None => None,
        };

        Ok(Self::new(EvpPkey::from_ec_key(ec_key), alg))
    }

    pub(crate) fn evp_pkey(&self) -> &EvpPkey {
        &self.evp_pkey
    }

    pub(crate) fn get_curve(&self) -> EcCurve {
        self.evp_pkey.get_ec_curve().unwrap()
    }
}

impl TryFrom<BTreeMap<String, String>> for ECJsonWebKey {
    type Error = JoseError;

    fn try_from(value: BTreeMap<String, String>) -> Result<Self, Self::Error> {
        ECJsonWebKey::from_map(value)
    }
}

impl TryFrom<simd_json::BorrowedValue<'_>> for ECJsonWebKey {
    type Error = JoseError;

    fn try_from(value: simd_json::BorrowedValue) -> Result<Self, Self::Error> {
        ECJsonWebKey::from_map(value)
    }
}

impl TryFrom<&simd_json::OwnedValue> for ECJsonWebKey {
    type Error = JoseError;

    fn try_from(value: &simd_json::OwnedValue) -> Result<Self, Self::Error> {
        ECJsonWebKey::from_map(value)
    }
}
