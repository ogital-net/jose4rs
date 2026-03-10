use std::fmt;

use crate::{
    base64,
    crypto::{aead, aes, DigestAlgorithm},
    error::JoseError,
    jwe::{kdf, ContentEncryptionAlgorithm, ContentEncryptionKeys},
    jwk::JsonWebKey,
    jwx::HeaderParameter,
};
use simd_json::derived::{ValueObjectAccess, ValueObjectAccessAsScalar as _};

/// Represents the key management algorithm identifiers for JWE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyManagementAlgorithm {
    Rsa15,
    RsaOaep,
    RsaOaep256,
    RsaOaep384,
    RsaOaep512,
    EcdhEs,
    EcdhEsA128Kw,
    EcdhEsA192Kw,
    EcdhEsA256Kw,
    A128Kw,
    A192Kw,
    A256Kw,
    A128GcmKw,
    A192GcmKw,
    A256GcmKw,
    Pbes2Hs256A128Kw,
    Pbes2Hs384A192Kw,
    Pbes2Hs512A256Kw,
    Direct,
}

impl KeyManagementAlgorithm {
    fn try_from_str(alg: impl AsRef<str>) -> Result<Self, JoseError> {
        match alg.as_ref() {
            "RSA1_5" => Ok(KeyManagementAlgorithm::Rsa15),
            "RSA-OAEP" => Ok(KeyManagementAlgorithm::RsaOaep),
            "RSA-OAEP-256" => Ok(KeyManagementAlgorithm::RsaOaep256),
            "RSA-OAEP-384" => Ok(KeyManagementAlgorithm::RsaOaep384),
            "RSA-OAEP-512" => Ok(KeyManagementAlgorithm::RsaOaep512),
            "ECDH-ES" => Ok(KeyManagementAlgorithm::EcdhEs),
            "ECDH-ES+A128KW" => Ok(KeyManagementAlgorithm::EcdhEsA128Kw),
            "ECDH-ES+A192KW" => Ok(KeyManagementAlgorithm::EcdhEsA192Kw),
            "ECDH-ES+A256KW" => Ok(KeyManagementAlgorithm::EcdhEsA256Kw),
            "A128KW" => Ok(KeyManagementAlgorithm::A128Kw),
            "A192KW" => Ok(KeyManagementAlgorithm::A192Kw),
            "A256KW" => Ok(KeyManagementAlgorithm::A256Kw),
            "A128GCMKW" => Ok(KeyManagementAlgorithm::A128GcmKw),
            "A192GCMKW" => Ok(KeyManagementAlgorithm::A192GcmKw),
            "A256GCMKW" => Ok(KeyManagementAlgorithm::A256GcmKw),
            "PBES2-HS256+A128KW" => Ok(KeyManagementAlgorithm::Pbes2Hs256A128Kw),
            "PBES2-HS384+A192KW" => Ok(KeyManagementAlgorithm::Pbes2Hs384A192Kw),
            "PBES2-HS512+A256KW" => Ok(KeyManagementAlgorithm::Pbes2Hs512A256Kw),
            "dir" => Ok(KeyManagementAlgorithm::Direct),
            alg => Err(JoseError::InvalidAlgorithm(format!(
                "unsupported key management algorithm: {alg}"
            ))),
        }
    }

    /// Returns the string representation of the key management algorithm.
    pub fn name(&self) -> &'static str {
        match self {
            KeyManagementAlgorithm::Rsa15 => "RSA1_5",
            KeyManagementAlgorithm::RsaOaep => "RSA-OAEP",
            KeyManagementAlgorithm::RsaOaep256 => "RSA-OAEP-256",
            KeyManagementAlgorithm::RsaOaep384 => "RSA-OAEP-384",
            KeyManagementAlgorithm::RsaOaep512 => "RSA-OAEP-512",
            KeyManagementAlgorithm::EcdhEs => "ECDH-ES",
            KeyManagementAlgorithm::EcdhEsA128Kw => "ECDH-ES+A128KW",
            KeyManagementAlgorithm::EcdhEsA192Kw => "ECDH-ES+A192KW",
            KeyManagementAlgorithm::EcdhEsA256Kw => "ECDH-ES+A256KW",
            KeyManagementAlgorithm::A128Kw => "A128KW",
            KeyManagementAlgorithm::A192Kw => "A192KW",
            KeyManagementAlgorithm::A256Kw => "A256KW",
            KeyManagementAlgorithm::A128GcmKw => "A128GCMKW",
            KeyManagementAlgorithm::A192GcmKw => "A192GCMKW",
            KeyManagementAlgorithm::A256GcmKw => "A256GCMKW",
            KeyManagementAlgorithm::Pbes2Hs256A128Kw => "PBES2-HS256+A128KW",
            KeyManagementAlgorithm::Pbes2Hs384A192Kw => "PBES2-HS384+A192KW",
            KeyManagementAlgorithm::Pbes2Hs512A256Kw => "PBES2-HS512+A256KW",
            KeyManagementAlgorithm::Direct => "dir",
        }
    }

    pub(super) fn manage_encrypt(
        &self,
        management_key: impl Into<Box<[u8]>>,
        headers: &simd_json::owned::Value,
    ) -> Result<ContentEncryptionKeys, JoseError> {
        match self {
            KeyManagementAlgorithm::Rsa15 => todo!(),
            KeyManagementAlgorithm::RsaOaep => todo!(),
            KeyManagementAlgorithm::RsaOaep256 => todo!(),
            KeyManagementAlgorithm::RsaOaep384 => todo!(),
            KeyManagementAlgorithm::RsaOaep512 => todo!(),
            KeyManagementAlgorithm::EcdhEs => todo!(),
            KeyManagementAlgorithm::EcdhEsA128Kw => todo!(),
            KeyManagementAlgorithm::EcdhEsA192Kw => todo!(),
            KeyManagementAlgorithm::EcdhEsA256Kw => todo!(),
            KeyManagementAlgorithm::A128Kw => todo!(),
            KeyManagementAlgorithm::A192Kw => todo!(),
            KeyManagementAlgorithm::A256Kw => todo!(),
            KeyManagementAlgorithm::A128GcmKw => todo!(),
            KeyManagementAlgorithm::A192GcmKw => todo!(),
            KeyManagementAlgorithm::A256GcmKw => todo!(),
            KeyManagementAlgorithm::Pbes2Hs256A128Kw => todo!(),
            KeyManagementAlgorithm::Pbes2Hs384A192Kw => todo!(),
            KeyManagementAlgorithm::Pbes2Hs512A256Kw => todo!(),
            KeyManagementAlgorithm::Direct => Ok(ContentEncryptionKeys::direct(management_key)),
        }
    }

    pub(super) fn manage_decrypt(
        &self,
        management_key: &JsonWebKey,
        encrypted_key: &[u8],
        headers: &simd_json::owned::Value,
    ) -> Result<Box<[u8]>, JoseError> {
        match self {
            KeyManagementAlgorithm::Rsa15 => match management_key {
                JsonWebKey::Rsa(rsa_key) => rsa_key.decrypt_pcks1_1_5(encrypted_key),
                _ => Err(JoseError::InvalidKey("Invalid key type".into())),
            },
            KeyManagementAlgorithm::RsaOaep => match management_key {
                JsonWebKey::Rsa(rsa_key) => {
                    rsa_key.decrypt_oaep(encrypted_key, DigestAlgorithm::Sha1)
                }
                _ => Err(JoseError::InvalidKey("Invalid key type".into())),
            },
            KeyManagementAlgorithm::RsaOaep256 => match management_key {
                JsonWebKey::Rsa(rsa_key) => {
                    rsa_key.decrypt_oaep(encrypted_key, DigestAlgorithm::Sha256)
                }
                _ => Err(JoseError::InvalidKey("Invalid key type".into())),
            },
            KeyManagementAlgorithm::RsaOaep384 => match management_key {
                JsonWebKey::Rsa(rsa_key) => {
                    rsa_key.decrypt_oaep(encrypted_key, DigestAlgorithm::Sha384)
                }
                _ => Err(JoseError::InvalidKey("Invalid key type".into())),
            },
            KeyManagementAlgorithm::RsaOaep512 => match management_key {
                JsonWebKey::Rsa(rsa_key) => {
                    rsa_key.decrypt_oaep(encrypted_key, DigestAlgorithm::Sha512)
                }
                _ => Err(JoseError::InvalidKey("Invalid key type".into())),
            },
            KeyManagementAlgorithm::EcdhEs => {
                let epk = headers
                    .get(HeaderParameter::EphemeralPublicKey.name())
                    .ok_or(JoseError::new("Missing 'epk' header parameter"))?;
                let epk = JsonWebKey::from_value(epk)?;

                let private_key = match management_key {
                    JsonWebKey::EllipticCurve(ec) => ec.evp_pkey(),
                    JsonWebKey::OctetKeyPair(okp) => okp.evp_pkey(),
                    _ => return Err(JoseError::InvalidKey("Invalid key type".into())),
                };
                let public_key = match &epk {
                    JsonWebKey::EllipticCurve(ec) => ec.evp_pkey(),
                    JsonWebKey::OctetKeyPair(okp) => okp.evp_pkey(),
                    _ => return Err(JoseError::InvalidKey("Invalid key type".into())),
                };
                // derive() handles curve and parameter validation
                let shared_secret = private_key.derive(public_key)?;
                let content_enc_alg = ContentEncryptionAlgorithm::try_from_str(
                    headers
                        .get_str(HeaderParameter::EncryptionMethod.name())
                        .ok_or(JoseError::new("missing 'enc' header parameter"))?,
                )?;
                let party_u_info = headers
                    .get_str(HeaderParameter::AgreementPartyUInfo.name())
                    .unwrap_or("");
                let party_v_info = headers
                    .get_str(HeaderParameter::AgreementPartyVInfo.name())
                    .unwrap_or("");
                let concat_kdf = kdf::ConcatKDF::init(DigestAlgorithm::Sha256);
                Ok(concat_kdf
                    .kdf(
                        &shared_secret,
                        content_enc_alg.key_len() * 8,
                        content_enc_alg.name(),
                        party_u_info,
                        party_v_info,
                    )
                    .into_boxed_slice())
            }
            KeyManagementAlgorithm::EcdhEsA128Kw => {
                let epk = headers
                    .get(HeaderParameter::EphemeralPublicKey.name())
                    .ok_or(JoseError::new("Missing 'epk' header parameter"))?;
                let epk = JsonWebKey::from_value(epk)?;

                let private_key = match management_key {
                    JsonWebKey::EllipticCurve(ec) => ec.evp_pkey(),
                    JsonWebKey::OctetKeyPair(okp) => okp.evp_pkey(),
                    _ => return Err(JoseError::InvalidKey("Invalid key type".into())),
                };
                let public_key = match &epk {
                    JsonWebKey::EllipticCurve(ec) => ec.evp_pkey(),
                    JsonWebKey::OctetKeyPair(okp) => okp.evp_pkey(),
                    _ => return Err(JoseError::InvalidKey("Invalid key type".into())),
                };
                // derive() handles curve and parameter validation
                let shared_secret = private_key.derive(public_key)?;
                let party_u_info = headers
                    .get_str(HeaderParameter::AgreementPartyUInfo.name())
                    .unwrap_or("");
                let party_v_info = headers
                    .get_str(HeaderParameter::AgreementPartyVInfo.name())
                    .unwrap_or("");
                let concat_kdf = kdf::ConcatKDF::init(DigestAlgorithm::Sha256);
                let aeskw_key =
                    concat_kdf.kdf(&shared_secret, 128, self.name(), party_u_info, party_v_info);
                Ok(aes::unwrap_key(&aeskw_key, None, encrypted_key))
            }
            KeyManagementAlgorithm::EcdhEsA192Kw => {
                let epk = headers
                    .get(HeaderParameter::EphemeralPublicKey.name())
                    .ok_or(JoseError::new("Missing 'epk' header parameter"))?;
                let epk = JsonWebKey::from_value(epk)?;

                let private_key = match management_key {
                    JsonWebKey::EllipticCurve(ec) => ec.evp_pkey(),
                    JsonWebKey::OctetKeyPair(okp) => okp.evp_pkey(),
                    _ => return Err(JoseError::InvalidKey("Invalid key type".into())),
                };
                let public_key = match &epk {
                    JsonWebKey::EllipticCurve(ec) => ec.evp_pkey(),
                    JsonWebKey::OctetKeyPair(okp) => okp.evp_pkey(),
                    _ => return Err(JoseError::InvalidKey("Invalid key type".into())),
                };
                // derive() handles curve and parameter validation
                let shared_secret = private_key.derive(public_key)?;
                let party_u_info = headers
                    .get_str(HeaderParameter::AgreementPartyUInfo.name())
                    .unwrap_or("");
                let party_v_info = headers
                    .get_str(HeaderParameter::AgreementPartyVInfo.name())
                    .unwrap_or("");
                let concat_kdf = kdf::ConcatKDF::init(DigestAlgorithm::Sha256);
                let aeskw_key =
                    concat_kdf.kdf(&shared_secret, 192, self.name(), party_u_info, party_v_info);
                Ok(aes::unwrap_key(&aeskw_key, None, encrypted_key))
            }
            KeyManagementAlgorithm::EcdhEsA256Kw => {
                let epk = headers
                    .get(HeaderParameter::EphemeralPublicKey.name())
                    .ok_or(JoseError::new("Missing 'epk' header parameter"))?;
                let epk = JsonWebKey::from_value(epk)?;

                let private_key = match management_key {
                    JsonWebKey::EllipticCurve(ec) => ec.evp_pkey(),
                    JsonWebKey::OctetKeyPair(okp) => okp.evp_pkey(),
                    _ => return Err(JoseError::InvalidKey("Invalid key type".into())),
                };
                let public_key = match &epk {
                    JsonWebKey::EllipticCurve(ec) => ec.evp_pkey(),
                    JsonWebKey::OctetKeyPair(okp) => okp.evp_pkey(),
                    _ => return Err(JoseError::InvalidKey("Invalid key type".into())),
                };
                // derive() handles curve and parameter validation
                let shared_secret = private_key.derive(public_key)?;
                let party_u_info = headers
                    .get_str(HeaderParameter::AgreementPartyUInfo.name())
                    .unwrap_or("");
                let party_v_info = headers
                    .get_str(HeaderParameter::AgreementPartyVInfo.name())
                    .unwrap_or("");
                let concat_kdf = kdf::ConcatKDF::init(DigestAlgorithm::Sha256);
                let aeskw_key =
                    concat_kdf.kdf(&shared_secret, 256, self.name(), party_u_info, party_v_info);
                Ok(aes::unwrap_key(&aeskw_key, None, encrypted_key))
            }
            KeyManagementAlgorithm::A128Kw => {
                let key_bytes = management_key
                    .key_bytes()
                    .ok_or(JoseError::InvalidKey("Invalid key type".into()))?;
                if key_bytes.len() != 16 {
                    return Err(JoseError::InvalidKey("Invalid key length".into()));
                }
                if encrypted_key.len() != 24 {
                    return Err(JoseError::InvalidKey("Invalid encrypted key".into()));
                }
                Ok(aes::unwrap_key(key_bytes, None, encrypted_key))
            }
            KeyManagementAlgorithm::A192Kw => {
                let key_bytes = management_key
                    .key_bytes()
                    .ok_or(JoseError::InvalidKey("Invalid key type".into()))?;
                if key_bytes.len() != 24 {
                    return Err(JoseError::InvalidKey("Invalid key length".into()));
                }
                if encrypted_key.len() != 32 {
                    return Err(JoseError::InvalidKey("Invalid encrypted key".into()));
                }
                Ok(aes::unwrap_key(key_bytes, None, encrypted_key))
            }
            KeyManagementAlgorithm::A256Kw => {
                let key_bytes = management_key
                    .key_bytes()
                    .ok_or(JoseError::InvalidKey("Invalid key type".into()))?;
                if key_bytes.len() != 32 {
                    return Err(JoseError::InvalidKey("Invalid key length".into()));
                }
                if encrypted_key.len() != 40 {
                    return Err(JoseError::InvalidKey("Invalid encrypted key".into()));
                }
                Ok(aes::unwrap_key(key_bytes, None, encrypted_key))
            }
            KeyManagementAlgorithm::A128GcmKw => {
                let key_bytes = management_key
                    .key_bytes()
                    .ok_or(JoseError::InvalidKey("Invalid key type".into()))?;
                let encoded_iv = headers
                    .get_str(HeaderParameter::InitializationVector.name())
                    .ok_or(JoseError::new("Missing IV header param"))?;
                let encoded_tag = headers
                    .get_str(HeaderParameter::AuthenticationTag.name())
                    .ok_or(JoseError::new("Missing authentication tag header param"))?;
                let iv = base64::url_decode(encoded_iv)?;
                let tag = base64::url_decode(encoded_tag)?;

                let alg = aead::Algorithm::Aes128Gcm;
                if key_bytes.len() != alg.key_len() {
                    return Err(JoseError::InvalidKey("Invalid key length".into()));
                }
                if iv.len() != alg.iv_len() {
                    return Err(JoseError::InvalidKey("Invalid IV length".into()));
                }
                let mut out: Box<[u8]> = Box::from(encrypted_key);
                let ctx = aead::EvpAeadCtx::init(alg, key_bytes);
                ctx.decrypt(&iv, &[], &mut out, &tag)?;
                Ok(out)
            }
            KeyManagementAlgorithm::A192GcmKw => {
                let key_bytes = management_key
                    .key_bytes()
                    .ok_or(JoseError::InvalidKey("Invalid key type".into()))?;
                let encoded_iv = headers
                    .get_str(HeaderParameter::InitializationVector.name())
                    .ok_or(JoseError::new("Missing IV header param"))?;
                let encoded_tag = headers
                    .get_str(HeaderParameter::AuthenticationTag.name())
                    .ok_or(JoseError::new("Missing authentication tag header param"))?;
                let iv = base64::url_decode(encoded_iv)?;
                let tag = base64::url_decode(encoded_tag)?;

                let alg = aead::Algorithm::Aes192Gcm;
                if key_bytes.len() != alg.key_len() {
                    return Err(JoseError::InvalidKey("Invalid key length".into()));
                }
                if iv.len() != alg.iv_len() {
                    return Err(JoseError::InvalidKey("Invalid IV length".into()));
                }
                let mut out: Box<[u8]> = Box::from(encrypted_key);
                let ctx = aead::EvpAeadCtx::init(alg, key_bytes);
                ctx.decrypt(&iv, &[], &mut out, &tag)?;
                Ok(out)
            }
            KeyManagementAlgorithm::A256GcmKw => {
                let key_bytes = management_key
                    .key_bytes()
                    .ok_or(JoseError::InvalidKey("Invalid key type".into()))?;
                let encoded_iv = headers
                    .get_str(HeaderParameter::InitializationVector.name())
                    .ok_or(JoseError::new("Missing IV header param"))?;
                let encoded_tag = headers
                    .get_str(HeaderParameter::AuthenticationTag.name())
                    .ok_or(JoseError::new("Missing authentication tag header param"))?;
                let iv = base64::url_decode(encoded_iv)?;
                let tag = base64::url_decode(encoded_tag)?;

                let alg = aead::Algorithm::Aes256Gcm;
                if key_bytes.len() != alg.key_len() {
                    return Err(JoseError::InvalidKey("Invalid key length".into()));
                }
                if iv.len() != alg.iv_len() {
                    return Err(JoseError::InvalidKey("Invalid IV length".into()));
                }
                let mut out: Box<[u8]> = Box::from(encrypted_key);
                let ctx = aead::EvpAeadCtx::init(alg, key_bytes);
                ctx.decrypt(&iv, &[], &mut out, &tag)?;
                Ok(out)
            }
            KeyManagementAlgorithm::Pbes2Hs256A128Kw => todo!(),
            KeyManagementAlgorithm::Pbes2Hs384A192Kw => todo!(),
            KeyManagementAlgorithm::Pbes2Hs512A256Kw => todo!(),
            KeyManagementAlgorithm::Direct => {
                if !encrypted_key.is_empty() {
                    return Err(JoseError::InvalidKey(
                        "No encrypted key is to be used when utilizing direct encryption".into(),
                    ));
                }
                let key_bytes = management_key
                    .key_bytes()
                    .ok_or(JoseError::InvalidKey("Invalid key type".into()))?;
                Ok(Box::from(key_bytes))
            }
        }
    }
}

impl TryFrom<&str> for KeyManagementAlgorithm {
    type Error = JoseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::try_from_str(value)
    }
}

impl TryFrom<String> for KeyManagementAlgorithm {
    type Error = JoseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from_str(value)
    }
}

impl TryFrom<&String> for KeyManagementAlgorithm {
    type Error = JoseError;

    fn try_from(value: &String) -> Result<Self, Self::Error> {
        Self::try_from_str(value)
    }
}

impl fmt::Display for KeyManagementAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}
