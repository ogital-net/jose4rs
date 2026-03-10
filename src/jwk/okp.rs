use std::collections::BTreeMap;

use crate::{
    base64,
    crypto::{curve25519::ed25519_pubkey_is_valid_for_private_key, EvpPkey, EvpPkeyType},
    error::JoseError,
    jws::AlgorithmIdentifier,
};

use super::GetStr;

pub struct OkpJsonWebKey {
    evp_pkey: EvpPkey,
    alg: Option<AlgorithmIdentifier>,
}

impl OkpJsonWebKey {
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
        match self.evp_pkey.private_key_to_der() {
            Ok(der) => der,
            Err(_) => self.evp_pkey.public_key_to_der().unwrap(),
        }
    }

    pub fn to_json(&self, level: super::OutputControlLevel) -> String {
        todo!()
    }

    pub fn key_type(&self) -> &'static str {
        "OKP"
    }

    pub fn sign(&self, message: &[u8]) -> Box<[u8]> {
        self.evp_pkey.sign_eddsa(message)
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        self.evp_pkey.verify_eddsa(message, signature)
    }

    pub(super) fn from_map(value: impl GetStr) -> Result<Self, JoseError> {
        let mut x = value.get("x").map_or_else(
            || Err(JoseError::InvalidKey("Missing 'x' parameter".to_string())),
            |v| Ok(base64::url_decode(v)?),
        )?;

        let d = value.get("d").map(base64::url_decode).transpose()?;

        let alg = match value.get("alg") {
            Some(alg) => match alg {
                "EdDSA" => Some(AlgorithmIdentifier::EdDsa),
                _ => return Err(JoseError::InvalidAlgorithm(format!("invalid 'alg' {alg}"))),
            },
            None => None,
        };

        match value.get("crv") {
            Some("Ed25519") => {
                if let Some(mut private) = d {
                    if private.len() != 32 {
                        return Err(JoseError::InvalidKey(
                            "Invalid 'd' parameter length for Ed25519".to_string(),
                        ));
                    }
                    if !ed25519_pubkey_is_valid_for_private_key(&private, &x) {
                        return Err(JoseError::InvalidKey(
                            "Invalid 'x' parameter for Ed25519".to_string(),
                        ));
                    }
                    Ok(OkpJsonWebKey::new(
                        EvpPkey::new_raw_private_key(EvpPkeyType::Ed25519, &mut private),
                        alg,
                    ))
                } else {
                    if x.len() != 32 {
                        return Err(JoseError::InvalidKey(
                            "Invalid 'x' parameter length for Ed25519".to_string(),
                        ));
                    }
                    Ok(OkpJsonWebKey::new(
                        EvpPkey::new_raw_public_key(EvpPkeyType::Ed25519, &mut x),
                        alg,
                    ))
                }
            }
            Some("X25519") => {
                if let Some(mut private) = d {
                    if private.len() != 32 {
                        return Err(JoseError::InvalidKey(
                            "Invalid 'd' parameter length for X25519".to_string(),
                        ));
                    }
                    Ok(OkpJsonWebKey::new(
                        EvpPkey::new_raw_private_key(EvpPkeyType::X25519, &mut private),
                        alg,
                    ))
                } else {
                    if x.len() != 32 {
                        return Err(JoseError::InvalidKey(
                            "Invalid 'x' parameter length for X25519".to_string(),
                        ));
                    }
                    Ok(OkpJsonWebKey::new(
                        EvpPkey::new_raw_public_key(EvpPkeyType::X25519, &mut x),
                        alg,
                    ))
                }
            }
            Some(crv) => Err(JoseError::InvalidKey(format!("unsupported curve '{crv}'"))),
            None => Err(JoseError::InvalidKey("Missing 'crv' parameter".to_string())),
        }
    }

    pub(crate) fn evp_pkey(&self) -> &EvpPkey {
        &self.evp_pkey
    }
}

impl TryFrom<BTreeMap<String, String>> for OkpJsonWebKey {
    type Error = JoseError;

    fn try_from(value: BTreeMap<String, String>) -> Result<Self, Self::Error> {
        OkpJsonWebKey::from_map(value)
    }
}

impl TryFrom<simd_json::BorrowedValue<'_>> for OkpJsonWebKey {
    type Error = JoseError;

    fn try_from(value: simd_json::BorrowedValue) -> Result<Self, Self::Error> {
        OkpJsonWebKey::from_map(value)
    }
}

impl TryFrom<&simd_json::OwnedValue> for OkpJsonWebKey {
    type Error = JoseError;

    fn try_from(value: &simd_json::OwnedValue) -> Result<Self, Self::Error> {
        OkpJsonWebKey::from_map(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_map() {
        let mut map: BTreeMap<String, String> = BTreeMap::new();
        map.insert("kty".to_string(), "OKP".to_string());
        map.insert("crv".to_string(), "Ed25519".to_string());
        map.insert(
            "d".to_string(),
            "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A".to_string(),
        );
        map.insert(
            "x".to_string(),
            "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo".to_string(),
        );

        let jwk = OkpJsonWebKey::try_from(map).unwrap();
        assert_eq!(jwk.key_type(), "OKP");
        assert_eq!(jwk.evp_pkey.key_type(), EvpPkeyType::Ed25519);
    }
}
