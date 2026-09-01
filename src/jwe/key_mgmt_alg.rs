use std::fmt;

use crate::{
    base64,
    crypto::{DigestAlgorithm, aead, aes, mem, pbkdf2, rand::rand_bytes},
    error::JoseError,
    jwe::{ContentEncryptionAlgorithm, ContentEncryptionKeys, kdf},
    jwk::JsonWebKey,
    jwx::HeaderParameter,
};
use simd_json::derived::{MutableObject, ValueObjectAccess, ValueObjectAccessAsScalar as _};

/// Represents the key management algorithm identifiers for JWE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyManagementAlgorithm {
    /// `RSA1_5` -- RSAES-PKCS1-v1_5 key encryption (RFC 7518). Legacy; prefer OAEP.
    Rsa15,
    /// `RSA-OAEP` -- RSAES-OAEP with SHA-1 (RFC 7518).
    RsaOaep,
    /// `RSA-OAEP-256` -- RSAES-OAEP with SHA-256 (RFC 7518).
    RsaOaep256,
    /// `RSA-OAEP-384` -- RSAES-OAEP with SHA-384 (RFC 7518).
    RsaOaep384,
    /// `RSA-OAEP-512` -- RSAES-OAEP with SHA-512 (RFC 7518).
    RsaOaep512,
    /// `ECDH-ES` -- ECDH-ES direct key agreement (RFC 7518).
    EcdhEs,
    /// `ECDH-ES+A128KW` -- ECDH-ES key agreement with AES-128 key wrap (RFC 7518).
    EcdhEsA128Kw,
    /// `ECDH-ES+A192KW` -- ECDH-ES key agreement with AES-192 key wrap (RFC 7518).
    EcdhEsA192Kw,
    /// `ECDH-ES+A256KW` -- ECDH-ES key agreement with AES-256 key wrap (RFC 7518).
    EcdhEsA256Kw,
    /// `A128KW` -- AES-128 key wrap (RFC 7518).
    A128Kw,
    /// `A192KW` -- AES-192 key wrap (RFC 7518).
    A192Kw,
    /// `A256KW` -- AES-256 key wrap (RFC 7518).
    A256Kw,
    /// `A128GCMKW` -- AES-128 GCM key wrap (RFC 7518).
    A128GcmKw,
    /// `A192GCMKW` -- AES-192 GCM key wrap (RFC 7518).
    A192GcmKw,
    /// `A256GCMKW` -- AES-256 GCM key wrap (RFC 7518).
    A256GcmKw,
    /// `PBES2-HS256+A128KW` -- PBES2 with HMAC-SHA-256 and AES-128 key wrap (RFC 7518).
    Pbes2Hs256A128Kw,
    /// `PBES2-HS384+A192KW` -- PBES2 with HMAC-SHA-384 and AES-192 key wrap (RFC 7518).
    Pbes2Hs384A192Kw,
    /// `PBES2-HS512+A256KW` -- PBES2 with HMAC-SHA-512 and AES-256 key wrap (RFC 7518).
    Pbes2Hs512A256Kw,
    /// `dir` -- direct use of the shared symmetric key as the content key (RFC 7518).
    Direct,
}

impl std::str::FromStr for KeyManagementAlgorithm {
    type Err = JoseError;

    fn from_str(alg: &str) -> Result<Self, Self::Err> {
        match alg {
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
}

impl KeyManagementAlgorithm {
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

    /// Wraps or derives the content encryption key. `cek` contains
    /// pre-generated random bytes of `content_enc_alg.key_len()` length;
    /// algorithms that derive their own CEK (ECDH-ES, dir) ignore it.
    pub(super) fn manage_encrypt(
        &self,
        management_key: &JsonWebKey,
        content_enc_alg: &ContentEncryptionAlgorithm,
        cek: &[u8],
        headers: &mut simd_json::owned::Value,
    ) -> Result<ContentEncryptionKeys, JoseError> {
        match self {
            KeyManagementAlgorithm::Rsa15 => {
                let encrypted_key = match management_key {
                    JsonWebKey::Rsa(rsa_key) => rsa_key.encrypt_pcks1_1_5(cek),
                    _ => return Err(JoseError::InvalidKey("invalid key type".into())),
                };
                Ok(ContentEncryptionKeys::new(cek, encrypted_key))
            }
            KeyManagementAlgorithm::RsaOaep => {
                let encrypted_key = match management_key {
                    JsonWebKey::Rsa(rsa_key) => rsa_key.encrypt_oaep(cek, DigestAlgorithm::Sha1),
                    _ => return Err(JoseError::InvalidKey("invalid key type".into())),
                };
                Ok(ContentEncryptionKeys::new(cek, encrypted_key))
            }
            KeyManagementAlgorithm::RsaOaep256 => {
                let encrypted_key = match management_key {
                    JsonWebKey::Rsa(rsa_key) => rsa_key.encrypt_oaep(cek, DigestAlgorithm::Sha256),
                    _ => return Err(JoseError::InvalidKey("invalid key type".into())),
                };
                Ok(ContentEncryptionKeys::new(cek, encrypted_key))
            }
            KeyManagementAlgorithm::RsaOaep384 => {
                let encrypted_key = match management_key {
                    JsonWebKey::Rsa(rsa_key) => rsa_key.encrypt_oaep(cek, DigestAlgorithm::Sha384),
                    _ => return Err(JoseError::InvalidKey("invalid key type".into())),
                };
                Ok(ContentEncryptionKeys::new(cek, encrypted_key))
            }
            KeyManagementAlgorithm::RsaOaep512 => {
                let encrypted_key = match management_key {
                    JsonWebKey::Rsa(rsa_key) => rsa_key.encrypt_oaep(cek, DigestAlgorithm::Sha512),
                    _ => return Err(JoseError::InvalidKey("invalid key type".into())),
                };
                Ok(ContentEncryptionKeys::new(cek, encrypted_key))
            }
            KeyManagementAlgorithm::EcdhEs => {
                self.ecdh_es_encrypt(management_key, content_enc_alg, cek, headers, None)
            }
            KeyManagementAlgorithm::EcdhEsA128Kw => {
                self.ecdh_es_encrypt(management_key, content_enc_alg, cek, headers, Some(16))
            }
            KeyManagementAlgorithm::EcdhEsA192Kw => {
                self.ecdh_es_encrypt(management_key, content_enc_alg, cek, headers, Some(24))
            }
            KeyManagementAlgorithm::EcdhEsA256Kw => {
                self.ecdh_es_encrypt(management_key, content_enc_alg, cek, headers, Some(32))
            }
            KeyManagementAlgorithm::A128Kw => self.aes_kw_encrypt(management_key, cek, 16),
            KeyManagementAlgorithm::A192Kw => self.aes_kw_encrypt(management_key, cek, 24),
            KeyManagementAlgorithm::A256Kw => self.aes_kw_encrypt(management_key, cek, 32),
            KeyManagementAlgorithm::A128GcmKw => {
                self.aes_gcm_kw_encrypt(management_key, cek, aead::Algorithm::Aes128Gcm, headers)
            }
            KeyManagementAlgorithm::A192GcmKw => {
                self.aes_gcm_kw_encrypt(management_key, cek, aead::Algorithm::Aes192Gcm, headers)
            }
            KeyManagementAlgorithm::A256GcmKw => {
                self.aes_gcm_kw_encrypt(management_key, cek, aead::Algorithm::Aes256Gcm, headers)
            }
            KeyManagementAlgorithm::Pbes2Hs256A128Kw => {
                self.pbes2_encrypt(management_key, cek, DigestAlgorithm::Sha256, 16, headers)
            }
            KeyManagementAlgorithm::Pbes2Hs384A192Kw => {
                self.pbes2_encrypt(management_key, cek, DigestAlgorithm::Sha384, 24, headers)
            }
            KeyManagementAlgorithm::Pbes2Hs512A256Kw => {
                self.pbes2_encrypt(management_key, cek, DigestAlgorithm::Sha512, 32, headers)
            }
            KeyManagementAlgorithm::Direct => {
                let key_bytes = management_key
                    .key_bytes()
                    .ok_or(JoseError::InvalidKey("invalid key type".into()))?;
                if key_bytes.len() != content_enc_alg.key_len() {
                    return Err(JoseError::InvalidKey(
                        "direct key length does not match content encryption algorithm".into(),
                    ));
                }
                Ok(ContentEncryptionKeys::direct(key_bytes))
            }
        }
    }

    pub(super) fn manage_decrypt(
        &self,
        management_key: &JsonWebKey,
        encrypted_key: &[u8],
        headers: &simd_json::owned::Value,
    ) -> Result<mem::Zeroizing<Box<[u8]>>, JoseError> {
        match self {
            KeyManagementAlgorithm::Rsa15 => match management_key {
                JsonWebKey::Rsa(rsa_key) => rsa_key
                    .decrypt_pcks1_1_5(encrypted_key)
                    .map(mem::Zeroizing::new),
                _ => Err(JoseError::InvalidKey("invalid key type".into())),
            },
            KeyManagementAlgorithm::RsaOaep => match management_key {
                JsonWebKey::Rsa(rsa_key) => rsa_key
                    .decrypt_oaep(encrypted_key, DigestAlgorithm::Sha1)
                    .map(mem::Zeroizing::new),
                _ => Err(JoseError::InvalidKey("invalid key type".into())),
            },
            KeyManagementAlgorithm::RsaOaep256 => match management_key {
                JsonWebKey::Rsa(rsa_key) => rsa_key
                    .decrypt_oaep(encrypted_key, DigestAlgorithm::Sha256)
                    .map(mem::Zeroizing::new),
                _ => Err(JoseError::InvalidKey("invalid key type".into())),
            },
            KeyManagementAlgorithm::RsaOaep384 => match management_key {
                JsonWebKey::Rsa(rsa_key) => rsa_key
                    .decrypt_oaep(encrypted_key, DigestAlgorithm::Sha384)
                    .map(mem::Zeroizing::new),
                _ => Err(JoseError::InvalidKey("invalid key type".into())),
            },
            KeyManagementAlgorithm::RsaOaep512 => match management_key {
                JsonWebKey::Rsa(rsa_key) => rsa_key
                    .decrypt_oaep(encrypted_key, DigestAlgorithm::Sha512)
                    .map(mem::Zeroizing::new),
                _ => Err(JoseError::InvalidKey("invalid key type".into())),
            },
            KeyManagementAlgorithm::EcdhEs => {
                // RFC 7516 Section 5.2 step 6: for direct key agreement the JWE
                // Encrypted Key MUST be the empty octet sequence.
                if !encrypted_key.is_empty() {
                    return Err(JoseError::InvalidHeader(
                        "no encrypted key is to be used with direct key agreement (ECDH-ES)".into(),
                    ));
                }
                let epk = headers
                    .get(HeaderParameter::EphemeralPublicKey.name())
                    .ok_or_else(|| {
                        JoseError::InvalidHeader("missing 'epk' header parameter".into())
                    })?;
                let epk = JsonWebKey::from_value(epk)?;

                let private_key = match management_key {
                    JsonWebKey::EllipticCurve(ec) => ec.evp_pkey(),
                    JsonWebKey::OctetKeyPair(okp) => okp.evp_pkey(),
                    _ => return Err(JoseError::InvalidKey("invalid key type".into())),
                };
                let public_key = match &epk {
                    JsonWebKey::EllipticCurve(ec) => ec.evp_pkey(),
                    JsonWebKey::OctetKeyPair(okp) => okp.evp_pkey(),
                    _ => return Err(JoseError::InvalidKey("invalid key type".into())),
                };
                // derive() handles curve and parameter validation
                let shared_secret = private_key.derive(public_key)?;
                let content_enc_alg: ContentEncryptionAlgorithm = headers
                    .get_str(HeaderParameter::EncryptionMethod.name())
                    .ok_or_else(|| {
                        JoseError::InvalidHeader("missing 'enc' header parameter".into())
                    })?
                    .parse()?;
                let party_u_info = headers
                    .get_str(HeaderParameter::AgreementPartyUInfo.name())
                    .unwrap_or("");
                let party_v_info = headers
                    .get_str(HeaderParameter::AgreementPartyVInfo.name())
                    .unwrap_or("");
                let concat_kdf = kdf::ConcatKDF::init(DigestAlgorithm::Sha256);
                concat_kdf.kdf(
                    &shared_secret,
                    content_enc_alg.key_len() * 8,
                    content_enc_alg.name(),
                    party_u_info,
                    party_v_info,
                )
            }
            KeyManagementAlgorithm::EcdhEsA128Kw => {
                let epk = headers
                    .get(HeaderParameter::EphemeralPublicKey.name())
                    .ok_or_else(|| {
                        JoseError::InvalidHeader("missing 'epk' header parameter".into())
                    })?;
                let epk = JsonWebKey::from_value(epk)?;

                let private_key = match management_key {
                    JsonWebKey::EllipticCurve(ec) => ec.evp_pkey(),
                    JsonWebKey::OctetKeyPair(okp) => okp.evp_pkey(),
                    _ => return Err(JoseError::InvalidKey("invalid key type".into())),
                };
                let public_key = match &epk {
                    JsonWebKey::EllipticCurve(ec) => ec.evp_pkey(),
                    JsonWebKey::OctetKeyPair(okp) => okp.evp_pkey(),
                    _ => return Err(JoseError::InvalidKey("invalid key type".into())),
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
                    concat_kdf.kdf(&shared_secret, 128, self.name(), party_u_info, party_v_info)?;
                aes::unwrap_key(&aeskw_key, None, encrypted_key)
            }
            KeyManagementAlgorithm::EcdhEsA192Kw => {
                let epk = headers
                    .get(HeaderParameter::EphemeralPublicKey.name())
                    .ok_or_else(|| {
                        JoseError::InvalidHeader("missing 'epk' header parameter".into())
                    })?;
                let epk = JsonWebKey::from_value(epk)?;

                let private_key = match management_key {
                    JsonWebKey::EllipticCurve(ec) => ec.evp_pkey(),
                    JsonWebKey::OctetKeyPair(okp) => okp.evp_pkey(),
                    _ => return Err(JoseError::InvalidKey("invalid key type".into())),
                };
                let public_key = match &epk {
                    JsonWebKey::EllipticCurve(ec) => ec.evp_pkey(),
                    JsonWebKey::OctetKeyPair(okp) => okp.evp_pkey(),
                    _ => return Err(JoseError::InvalidKey("invalid key type".into())),
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
                    concat_kdf.kdf(&shared_secret, 192, self.name(), party_u_info, party_v_info)?;
                aes::unwrap_key(&aeskw_key, None, encrypted_key)
            }
            KeyManagementAlgorithm::EcdhEsA256Kw => {
                let epk = headers
                    .get(HeaderParameter::EphemeralPublicKey.name())
                    .ok_or_else(|| {
                        JoseError::InvalidHeader("missing 'epk' header parameter".into())
                    })?;
                let epk = JsonWebKey::from_value(epk)?;

                let private_key = match management_key {
                    JsonWebKey::EllipticCurve(ec) => ec.evp_pkey(),
                    JsonWebKey::OctetKeyPair(okp) => okp.evp_pkey(),
                    _ => return Err(JoseError::InvalidKey("invalid key type".into())),
                };
                let public_key = match &epk {
                    JsonWebKey::EllipticCurve(ec) => ec.evp_pkey(),
                    JsonWebKey::OctetKeyPair(okp) => okp.evp_pkey(),
                    _ => return Err(JoseError::InvalidKey("invalid key type".into())),
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
                    concat_kdf.kdf(&shared_secret, 256, self.name(), party_u_info, party_v_info)?;
                aes::unwrap_key(&aeskw_key, None, encrypted_key)
            }
            KeyManagementAlgorithm::A128Kw => {
                let key_bytes = management_key
                    .key_bytes()
                    .ok_or(JoseError::InvalidKey("invalid key type".into()))?;
                if key_bytes.len() != 16 {
                    return Err(JoseError::InvalidKey("invalid key length".into()));
                }
                // The wrapped key is the CEK plus 8 bytes of integrity check;
                // the CEK length depends on the content-encryption algorithm.
                if encrypted_key.len() < 16 || !encrypted_key.len().is_multiple_of(8) {
                    return Err(JoseError::InvalidKey("invalid encrypted key".into()));
                }
                aes::unwrap_key(key_bytes, None, encrypted_key)
            }
            KeyManagementAlgorithm::A192Kw => {
                let key_bytes = management_key
                    .key_bytes()
                    .ok_or(JoseError::InvalidKey("invalid key type".into()))?;
                if key_bytes.len() != 24 {
                    return Err(JoseError::InvalidKey("invalid key length".into()));
                }
                if encrypted_key.len() < 16 || !encrypted_key.len().is_multiple_of(8) {
                    return Err(JoseError::InvalidKey("invalid encrypted key".into()));
                }
                aes::unwrap_key(key_bytes, None, encrypted_key)
            }
            KeyManagementAlgorithm::A256Kw => {
                let key_bytes = management_key
                    .key_bytes()
                    .ok_or(JoseError::InvalidKey("invalid key type".into()))?;
                if key_bytes.len() != 32 {
                    return Err(JoseError::InvalidKey("invalid key length".into()));
                }
                if encrypted_key.len() < 16 || !encrypted_key.len().is_multiple_of(8) {
                    return Err(JoseError::InvalidKey("invalid encrypted key".into()));
                }
                aes::unwrap_key(key_bytes, None, encrypted_key)
            }
            KeyManagementAlgorithm::A128GcmKw => {
                let key_bytes = management_key
                    .key_bytes()
                    .ok_or(JoseError::InvalidKey("invalid key type".into()))?;
                let encoded_iv = headers
                    .get_str(HeaderParameter::InitializationVector.name())
                    .ok_or_else(|| JoseError::InvalidHeader("missing IV header param".into()))?;
                let encoded_tag = headers
                    .get_str(HeaderParameter::AuthenticationTag.name())
                    .ok_or_else(|| {
                        JoseError::InvalidHeader("missing authentication tag header param".into())
                    })?;
                let iv = base64::url_decode(encoded_iv)?;
                let tag = base64::url_decode(encoded_tag)?;

                let alg = aead::Algorithm::Aes128Gcm;
                if key_bytes.len() != alg.key_len() {
                    return Err(JoseError::InvalidKey("invalid key length".into()));
                }
                if iv.len() != alg.iv_len() {
                    return Err(JoseError::InvalidKey("invalid IV length".into()));
                }
                // RFC 7518 Section 4.7 fixes the GCMKW authentication tag at 128 bits.
                if tag.len() != alg.max_tag_len() {
                    return Err(JoseError::InvalidKey(
                        "invalid authentication tag length".into(),
                    ));
                }
                let mut out = mem::Zeroizing::new(Box::from(encrypted_key));
                let ctx = aead::EvpAeadCtx::init(alg, key_bytes);
                ctx.decrypt(&iv, &[], &mut out, &tag)?;
                Ok(out)
            }
            KeyManagementAlgorithm::A192GcmKw => {
                let key_bytes = management_key
                    .key_bytes()
                    .ok_or(JoseError::InvalidKey("invalid key type".into()))?;
                let encoded_iv = headers
                    .get_str(HeaderParameter::InitializationVector.name())
                    .ok_or_else(|| JoseError::InvalidHeader("missing IV header param".into()))?;
                let encoded_tag = headers
                    .get_str(HeaderParameter::AuthenticationTag.name())
                    .ok_or_else(|| {
                        JoseError::InvalidHeader("missing authentication tag header param".into())
                    })?;
                let iv = base64::url_decode(encoded_iv)?;
                let tag = base64::url_decode(encoded_tag)?;

                let alg = aead::Algorithm::Aes192Gcm;
                if key_bytes.len() != alg.key_len() {
                    return Err(JoseError::InvalidKey("invalid key length".into()));
                }
                if iv.len() != alg.iv_len() {
                    return Err(JoseError::InvalidKey("invalid IV length".into()));
                }
                if tag.len() != alg.max_tag_len() {
                    return Err(JoseError::InvalidKey(
                        "invalid authentication tag length".into(),
                    ));
                }
                let mut out = mem::Zeroizing::new(Box::from(encrypted_key));
                let ctx = aead::EvpAeadCtx::init(alg, key_bytes);
                ctx.decrypt(&iv, &[], &mut out, &tag)?;
                Ok(out)
            }
            KeyManagementAlgorithm::A256GcmKw => {
                let key_bytes = management_key
                    .key_bytes()
                    .ok_or(JoseError::InvalidKey("invalid key type".into()))?;
                let encoded_iv = headers
                    .get_str(HeaderParameter::InitializationVector.name())
                    .ok_or_else(|| JoseError::InvalidHeader("missing IV header param".into()))?;
                let encoded_tag = headers
                    .get_str(HeaderParameter::AuthenticationTag.name())
                    .ok_or_else(|| {
                        JoseError::InvalidHeader("missing authentication tag header param".into())
                    })?;
                let iv = base64::url_decode(encoded_iv)?;
                let tag = base64::url_decode(encoded_tag)?;

                let alg = aead::Algorithm::Aes256Gcm;
                if key_bytes.len() != alg.key_len() {
                    return Err(JoseError::InvalidKey("invalid key length".into()));
                }
                if iv.len() != alg.iv_len() {
                    return Err(JoseError::InvalidKey("invalid IV length".into()));
                }
                if tag.len() != alg.max_tag_len() {
                    return Err(JoseError::InvalidKey(
                        "invalid authentication tag length".into(),
                    ));
                }
                let mut out = mem::Zeroizing::new(Box::from(encrypted_key));
                let ctx = aead::EvpAeadCtx::init(alg, key_bytes);
                ctx.decrypt(&iv, &[], &mut out, &tag)?;
                Ok(out)
            }
            KeyManagementAlgorithm::Pbes2Hs256A128Kw => {
                let kek =
                    self.derive_pbes2_key(management_key, headers, DigestAlgorithm::Sha256, 16)?;
                aes::unwrap_key(&kek, None, encrypted_key)
            }
            KeyManagementAlgorithm::Pbes2Hs384A192Kw => {
                let kek =
                    self.derive_pbes2_key(management_key, headers, DigestAlgorithm::Sha384, 24)?;
                aes::unwrap_key(&kek, None, encrypted_key)
            }
            KeyManagementAlgorithm::Pbes2Hs512A256Kw => {
                let kek =
                    self.derive_pbes2_key(management_key, headers, DigestAlgorithm::Sha512, 32)?;
                aes::unwrap_key(&kek, None, encrypted_key)
            }
            KeyManagementAlgorithm::Direct => {
                if !encrypted_key.is_empty() {
                    return Err(JoseError::InvalidKey(
                        "no encrypted key is to be used when utilizing direct encryption".into(),
                    ));
                }
                let key_bytes = management_key
                    .key_bytes()
                    .ok_or(JoseError::InvalidKey("invalid key type".into()))?;
                Ok(mem::Zeroizing::new(Box::from(key_bytes)))
            }
        }
    }

    /// Maximum accepted PBES2 iteration count, mirroring jose4j's limit to
    /// guard against excessive resource utilization from hostile headers.
    const PBES2_MAX_ITERATION_COUNT: i64 = 2_499_999;
    /// Minimum accepted PBES2 iteration count. jose4j enforces this floor on
    /// encryption (citing the RFC 2898/JWA recommendation of >= 1000); applying
    /// it on decrypt too keeps a hostile header from weakening the KEK.
    const PBES2_MIN_ITERATION_COUNT: i64 = 1000;

    /// Derives the PBES2 key-encryption key per RFC 7518 section 4.8:
    /// PBKDF2 with salt = UTF8(alg) || 0x00 || p2s and the password as the key.
    fn derive_pbes2_key(
        &self,
        management_key: &JsonWebKey,
        headers: &simd_json::owned::Value,
        digest_alg: DigestAlgorithm,
        kek_len: usize,
    ) -> Result<mem::Zeroizing<Box<[u8]>>, JoseError> {
        let password = management_key
            .key_bytes()
            .ok_or(JoseError::InvalidKey("invalid key type".into()))?;

        let iteration_count = headers
            .get_i64(HeaderParameter::Pbes2IterationCount.name())
            .ok_or_else(|| JoseError::InvalidHeader("missing 'p2c' header parameter".into()))?;
        if !(Self::PBES2_MIN_ITERATION_COUNT..=Self::PBES2_MAX_ITERATION_COUNT)
            .contains(&iteration_count)
        {
            return Err(JoseError::InvalidAlgorithm(format!(
                "PBES2 iteration count ({iteration_count}) out of acceptable range"
            )));
        }

        let encoded_salt_input = headers
            .get_str(HeaderParameter::Pbes2SaltInput.name())
            .ok_or_else(|| JoseError::InvalidHeader("missing 'p2s' header parameter".into()))?;
        let salt_input = base64::url_decode(encoded_salt_input)?;
        if salt_input.len() < 8 {
            return Err(JoseError::InvalidHeader(
                "A 'p2s' salt input value containing 8 or more octets MUST be used".into(),
            ));
        }

        let mut salt = Vec::with_capacity(self.name().len() + 1 + salt_input.len());
        salt.extend_from_slice(self.name().as_bytes());
        salt.push(0);
        salt.extend_from_slice(&salt_input);

        pbkdf2::pbkdf2_hmac(digest_alg, password, &salt, iteration_count as u32, kek_len)
    }

    /// Default PBES2 iteration count used for encryption, mirroring jose4j.
    const PBES2_DEFAULT_ITERATION_COUNT: u32 = 8192 * 8;
    /// Default PBES2 salt input byte length used for encryption, mirroring jose4j.
    const PBES2_DEFAULT_SALT_LEN: usize = 12;

    fn aes_kw_encrypt(
        &self,
        management_key: &JsonWebKey,
        cek: &[u8],
        kek_len: usize,
    ) -> Result<ContentEncryptionKeys, JoseError> {
        let key_bytes = management_key
            .key_bytes()
            .ok_or(JoseError::InvalidKey("invalid key type".into()))?;
        if key_bytes.len() != kek_len {
            return Err(JoseError::InvalidKey("invalid key length".into()));
        }
        let encrypted_key = aes::wrap_key(key_bytes, None, cek)?;
        Ok(ContentEncryptionKeys::new(cek, encrypted_key))
    }

    fn aes_gcm_kw_encrypt(
        &self,
        management_key: &JsonWebKey,
        cek: &[u8],
        alg: aead::Algorithm,
        headers: &mut simd_json::owned::Value,
    ) -> Result<ContentEncryptionKeys, JoseError> {
        let key_bytes = management_key
            .key_bytes()
            .ok_or(JoseError::InvalidKey("invalid key type".into()))?;
        if key_bytes.len() != alg.key_len() {
            return Err(JoseError::InvalidKey("invalid key length".into()));
        }

        let iv = rand_bytes(alg.iv_len());
        let mut tag = mem::new_boxed_slice(alg.max_tag_len());
        let mut encrypted_key = cek.to_vec();
        let ctx = aead::EvpAeadCtx::init(alg, key_bytes);
        ctx.encrypt(&iv, &[], &mut encrypted_key, &mut tag)?;

        set_header_str(
            headers,
            HeaderParameter::InitializationVector.name(),
            &base64::url_encode(&iv),
        )?;
        set_header_str(
            headers,
            HeaderParameter::AuthenticationTag.name(),
            &base64::url_encode(&tag),
        )?;

        Ok(ContentEncryptionKeys::new(cek, encrypted_key))
    }

    fn pbes2_encrypt(
        &self,
        management_key: &JsonWebKey,
        cek: &[u8],
        digest_alg: DigestAlgorithm,
        kek_len: usize,
        headers: &mut simd_json::owned::Value,
    ) -> Result<ContentEncryptionKeys, JoseError> {
        let password = management_key
            .key_bytes()
            .ok_or(JoseError::InvalidKey("invalid key type".into()))?;

        // Honor caller-provided p2c/p2s headers, otherwise generate defaults.
        let iteration_count = match headers.get_i64(HeaderParameter::Pbes2IterationCount.name()) {
            Some(c)
                if (Self::PBES2_MIN_ITERATION_COUNT..=Self::PBES2_MAX_ITERATION_COUNT)
                    .contains(&c) =>
            {
                c as u32
            }
            Some(_) => {
                return Err(JoseError::InvalidAlgorithm(
                    "PBES2 iteration count out of acceptable range".to_string(),
                ));
            }
            None => {
                set_header_u64(
                    headers,
                    HeaderParameter::Pbes2IterationCount.name(),
                    u64::from(Self::PBES2_DEFAULT_ITERATION_COUNT),
                )?;
                Self::PBES2_DEFAULT_ITERATION_COUNT
            }
        };

        let salt_input: Box<[u8]> =
            if let Some(encoded) = headers.get_str(HeaderParameter::Pbes2SaltInput.name()) {
                base64::url_decode(encoded)?
            } else {
                let salt_input = rand_bytes(Self::PBES2_DEFAULT_SALT_LEN);
                set_header_str(
                    headers,
                    HeaderParameter::Pbes2SaltInput.name(),
                    &base64::url_encode(&salt_input),
                )?;
                salt_input
            };
        if salt_input.len() < 8 {
            return Err(JoseError::InvalidHeader(
                "A 'p2s' salt input value containing 8 or more octets MUST be used".into(),
            ));
        }

        let mut salt = Vec::with_capacity(self.name().len() + 1 + salt_input.len());
        salt.extend_from_slice(self.name().as_bytes());
        salt.push(0);
        salt.extend_from_slice(&salt_input);

        let kek = pbkdf2::pbkdf2_hmac(digest_alg, password, &salt, iteration_count, kek_len)?;

        let encrypted_key = aes::wrap_key(&kek, None, cek)?;
        Ok(ContentEncryptionKeys::new(cek, encrypted_key))
    }

    /// ECDH-ES key agreement, optionally followed by AES key wrap of the CEK.
    /// When `kw_len` is `None`, the derived key is used directly as the CEK
    /// (ECDH-ES); otherwise a KEK of `kw_len` bytes is derived and the CEK is
    /// wrapped (ECDH-ES+KW). Sets the `epk` header on success.
    fn ecdh_es_encrypt(
        &self,
        management_key: &JsonWebKey,
        content_enc_alg: &ContentEncryptionAlgorithm,
        cek: &[u8],
        headers: &mut simd_json::owned::Value,
        kw_len: Option<usize>,
    ) -> Result<ContentEncryptionKeys, JoseError> {
        use crate::crypto::EvpPkey;
        use crate::jwk::{ec::EcJsonWebKey, okp::OkpJsonWebKey};

        // Generate an ephemeral key on the same curve as the recipient's key,
        // and derive the ECDH shared secret.
        let (epk_jwk, shared_secret) = match management_key {
            JsonWebKey::EllipticCurve(ec) => {
                let curve = ec.get_curve();
                let ephemeral = EvpPkey::generate_ec(curve);
                let secret = ephemeral.derive(ec.evp_pkey())?;
                (
                    JsonWebKey::EllipticCurve(EcJsonWebKey::new(ephemeral, None)),
                    secret,
                )
            }
            JsonWebKey::OctetKeyPair(okp) => {
                let ephemeral = EvpPkey::generate_x25519();
                let secret = ephemeral.derive(okp.evp_pkey())?;
                (
                    JsonWebKey::OctetKeyPair(OkpJsonWebKey::new(ephemeral, None)),
                    secret,
                )
            }
            _ => return Err(JoseError::InvalidKey("invalid key type".into())),
        };

        // Set the ephemeral public key header (public components only).
        let epk_json = epk_jwk.to_json(crate::jwk::OutputControlLevel::PublicOnly);
        let mut epk_bytes = epk_json.into_bytes();
        let epk_value =
            simd_json::to_owned_value(&mut epk_bytes).map_err(|e| JoseError::json(&e))?;
        headers
            .insert(
                HeaderParameter::EphemeralPublicKey.name().to_string(),
                epk_value,
            )
            .map_err(|_| JoseError::new("failed to set 'epk' header parameter"))?;

        let party_u_info = headers
            .get_str(HeaderParameter::AgreementPartyUInfo.name())
            .unwrap_or("");
        let party_v_info = headers
            .get_str(HeaderParameter::AgreementPartyVInfo.name())
            .unwrap_or("");

        let concat_kdf = kdf::ConcatKDF::init(DigestAlgorithm::Sha256);
        match kw_len {
            None => {
                // ECDH-ES direct: derived key IS the CEK; ignore the random cek.
                let derived = concat_kdf.kdf(
                    &shared_secret,
                    content_enc_alg.key_len() * 8,
                    content_enc_alg.name(),
                    party_u_info,
                    party_v_info,
                )?;
                Ok(ContentEncryptionKeys::direct(&derived))
            }
            Some(kw_len) => {
                // ECDH-ES+AKW: derive a KEK and wrap the caller-provided CEK.
                let kek = concat_kdf.kdf(
                    &shared_secret,
                    kw_len * 8,
                    self.name(),
                    party_u_info,
                    party_v_info,
                )?;
                let encrypted_key = aes::wrap_key(&kek, None, cek)?;
                Ok(ContentEncryptionKeys::new(cek, encrypted_key))
            }
        }
    }
}

/// Sets a string header parameter on a JWE header object.
fn set_header_str(
    headers: &mut simd_json::owned::Value,
    name: &str,
    value: &[u8],
) -> Result<(), JoseError> {
    let value = std::str::from_utf8(value)
        .map_err(|_| JoseError::InvalidHeader("header value is not valid UTF-8".into()))?;
    headers
        .insert(name.to_string(), value)
        .map_err(|_| JoseError::new("failed to set header parameter"))?;
    Ok(())
}

/// Sets an unsigned integer header parameter on a JWE header object.
fn set_header_u64(
    headers: &mut simd_json::owned::Value,
    name: &str,
    value: u64,
) -> Result<(), JoseError> {
    headers
        .insert(name.to_string(), value)
        .map_err(|_| JoseError::new("failed to set header parameter"))?;
    Ok(())
}

impl TryFrom<&str> for KeyManagementAlgorithm {
    type Error = JoseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl TryFrom<String> for KeyManagementAlgorithm {
    type Error = JoseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl TryFrom<&String> for KeyManagementAlgorithm {
    type Error = JoseError;

    fn try_from(value: &String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl fmt::Display for KeyManagementAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwk::JsonWebKey;

    /// RFC 7518 (JWA) Appendix C ECDH-ES known-answer test. The receiver and
    /// ephemeral keys, apu, apv, and the expected derived CEK are all from the
    /// specification; this validates that apu/apv are base64url-DECODED before
    /// the Concat KDF (a port bug fed the encoded strings in directly).
    #[test]
    fn ecdh_es_jwa_appendix_c_kat() {
        let receiver = JsonWebKey::from_json(
            r#"{"kty":"EC","crv":"P-256",
                "x":"weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
                "y":"e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
                "d":"VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"}"#,
        )
        .unwrap();

        // Build the protected header with epk, enc, apu, apv.
        let header_json = r#"{"alg":"ECDH-ES","enc":"A128GCM",
            "apu":"QWxpY2U","apv":"Qm9i",
            "epk":{"kty":"EC","crv":"P-256",
                   "x":"gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
                   "y":"SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps"}}"#;
        let mut header_bytes = header_json.as_bytes().to_vec();
        let headers = simd_json::to_owned_value(&mut header_bytes).unwrap();

        let cek = KeyManagementAlgorithm::EcdhEs
            .manage_decrypt(&receiver, &[], &headers)
            .unwrap();

        let expected = base64::url_decode("VqqN6vgjbSBcIijNcacQGg").unwrap();
        assert_eq!(*cek, *expected);
    }

    /// Regression: ECDH-ES (direct key agreement) must reject a non-empty
    /// JWE Encrypted Key (RFC 7516 Section 5.2 step 6), consistent with the
    /// existing `dir` check.
    #[test]
    fn ecdh_es_rejects_nonempty_encrypted_key() {
        let receiver = JsonWebKey::from_json(
            r#"{"kty":"EC","crv":"P-256",
                "x":"weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
                "y":"e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
                "d":"VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"}"#,
        )
        .unwrap();

        let header_json = r#"{"alg":"ECDH-ES","enc":"A128GCM",
            "epk":{"kty":"EC","crv":"P-256",
                   "x":"gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
                   "y":"SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps"}}"#;
        let mut header_bytes = header_json.as_bytes().to_vec();
        let headers = simd_json::to_owned_value(&mut header_bytes).unwrap();

        // A non-empty encrypted key must be rejected.
        let result = KeyManagementAlgorithm::EcdhEs.manage_decrypt(&receiver, &[1, 2, 3], &headers);
        assert!(
            result.is_err(),
            "expected rejection of non-empty encrypted key"
        );
    }
}
