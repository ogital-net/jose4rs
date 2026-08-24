use super::aes_hmac::Algorithm as HmacAlgorithm;

use crate::crypto::aead::{Algorithm as AeadAlgorithm, EvpAeadCtx};
use crate::jwe::aes_hmac::AesHmacAeadCtx;
use crate::{error::JoseError, jwe::ContentEncryptionParts, jwe::MAX_TAG_LEN};

/// Represents the content encryption algorithm identifiers for JWE.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContentEncryptionAlgorithm {
    /// `A128CBC-HS256` -- AES-128 in CBC mode with HMAC-SHA-256 (RFC 7518).
    Aes128CbcHmacSha256,
    /// `A192CBC-HS384` -- AES-192 in CBC mode with HMAC-SHA-384 (RFC 7518).
    Aes192CbcHmacSha384,
    /// `A256CBC-HS512` -- AES-256 in CBC mode with HMAC-SHA-512 (RFC 7518).
    Aes256CbcHmacSha512,
    /// `A128GCM` -- AES-128 in GCM mode (RFC 7518).
    Aes128Gcm,
    /// `A192GCM` -- AES-192 in GCM mode (RFC 7518).
    Aes192Gcm,
    /// `A256GCM` -- AES-256 in GCM mode (RFC 7518).
    Aes256Gcm,
    /// `C20P` -- ChaCha20-Poly1305 (RFC 7539, as used by jose4j).
    ChaCha20Poly1305,
    /// `XC20P` -- XChaCha20-Poly1305 (extended-nonce variant, as used by jose4j).
    XChaCha20Poly1305,
}

impl std::fmt::Display for ContentEncryptionAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

impl std::str::FromStr for ContentEncryptionAlgorithm {
    type Err = JoseError;

    fn from_str(alg: &str) -> Result<Self, Self::Err> {
        match alg {
            "A128CBC-HS256" => Ok(ContentEncryptionAlgorithm::Aes128CbcHmacSha256),
            "A192CBC-HS384" => Ok(ContentEncryptionAlgorithm::Aes192CbcHmacSha384),
            "A256CBC-HS512" => Ok(ContentEncryptionAlgorithm::Aes256CbcHmacSha512),
            "A128GCM" => Ok(ContentEncryptionAlgorithm::Aes128Gcm),
            "A192GCM" => Ok(ContentEncryptionAlgorithm::Aes192Gcm),
            "A256GCM" => Ok(ContentEncryptionAlgorithm::Aes256Gcm),
            "C20P" => Ok(ContentEncryptionAlgorithm::ChaCha20Poly1305),
            "XC20P" => Ok(ContentEncryptionAlgorithm::XChaCha20Poly1305),
            alg => Err(crate::error::JoseError::InvalidAlgorithm(format!(
                "unsupported content encryption algorithm: {alg}"
            ))),
        }
    }
}

impl ContentEncryptionAlgorithm {
    /// Returns the string representation of the content encryption algorithm.
    pub fn name(&self) -> &'static str {
        match self {
            ContentEncryptionAlgorithm::Aes128CbcHmacSha256 => "A128CBC-HS256",
            ContentEncryptionAlgorithm::Aes192CbcHmacSha384 => "A192CBC-HS384",
            ContentEncryptionAlgorithm::Aes256CbcHmacSha512 => "A256CBC-HS512",
            ContentEncryptionAlgorithm::Aes128Gcm => "A128GCM",
            ContentEncryptionAlgorithm::Aes192Gcm => "A192GCM",
            ContentEncryptionAlgorithm::Aes256Gcm => "A256GCM",
            ContentEncryptionAlgorithm::ChaCha20Poly1305 => "C20P",
            ContentEncryptionAlgorithm::XChaCha20Poly1305 => "XC20P",
        }
    }

    /// The content-encryption key (CEK) length in bytes for this algorithm.
    pub fn key_len(&self) -> usize {
        match self {
            ContentEncryptionAlgorithm::Aes128CbcHmacSha256 => {
                HmacAlgorithm::Aes128CbcHmacSha256.key_len()
            }
            ContentEncryptionAlgorithm::Aes192CbcHmacSha384 => {
                HmacAlgorithm::Aes192CbcHmacSha384.key_len()
            }
            ContentEncryptionAlgorithm::Aes256CbcHmacSha512 => {
                HmacAlgorithm::Aes256CbcHmacSha512.key_len()
            }
            ContentEncryptionAlgorithm::Aes128Gcm => AeadAlgorithm::Aes128Gcm.key_len(),
            ContentEncryptionAlgorithm::Aes192Gcm => AeadAlgorithm::Aes192Gcm.key_len(),
            ContentEncryptionAlgorithm::Aes256Gcm => AeadAlgorithm::Aes256Gcm.key_len(),
            ContentEncryptionAlgorithm::ChaCha20Poly1305 => {
                AeadAlgorithm::ChaCha20Poly1305.key_len()
            }
            ContentEncryptionAlgorithm::XChaCha20Poly1305 => {
                AeadAlgorithm::XChaCha20Poly1305.key_len()
            }
        }
    }

    /// The initialization vector (IV / nonce) length in bytes.
    pub(super) fn iv_len(&self) -> usize {
        match self {
            ContentEncryptionAlgorithm::Aes128CbcHmacSha256
            | ContentEncryptionAlgorithm::Aes192CbcHmacSha384
            | ContentEncryptionAlgorithm::Aes256CbcHmacSha512 => 16,
            ContentEncryptionAlgorithm::Aes128Gcm => AeadAlgorithm::Aes128Gcm.iv_len(),
            ContentEncryptionAlgorithm::Aes192Gcm => AeadAlgorithm::Aes192Gcm.iv_len(),
            ContentEncryptionAlgorithm::Aes256Gcm => AeadAlgorithm::Aes256Gcm.iv_len(),
            ContentEncryptionAlgorithm::ChaCha20Poly1305 => {
                AeadAlgorithm::ChaCha20Poly1305.iv_len()
            }
            ContentEncryptionAlgorithm::XChaCha20Poly1305 => {
                AeadAlgorithm::XChaCha20Poly1305.iv_len()
            }
        }
    }

    /// Returns the AEAD algorithm for stream ciphers (GCM, `ChaCha20`), or
    /// `None` for CBC-HMAC (which uses padding and a different API).
    pub(super) fn aead_algorithm(&self) -> Option<AeadAlgorithm> {
        match self {
            ContentEncryptionAlgorithm::Aes128Gcm => Some(AeadAlgorithm::Aes128Gcm),
            ContentEncryptionAlgorithm::Aes192Gcm => Some(AeadAlgorithm::Aes192Gcm),
            ContentEncryptionAlgorithm::Aes256Gcm => Some(AeadAlgorithm::Aes256Gcm),
            ContentEncryptionAlgorithm::ChaCha20Poly1305 => Some(AeadAlgorithm::ChaCha20Poly1305),
            ContentEncryptionAlgorithm::XChaCha20Poly1305 => Some(AeadAlgorithm::XChaCha20Poly1305),
            _ => None,
        }
    }

    fn encrypt_aes_hmac(
        &self,
        alg: HmacAlgorithm,
        plaintext: &[u8],
        aad: &[u8],
        content_encryption_key: &[u8],
        iv: &[u8],
    ) -> Result<ContentEncryptionParts, JoseError> {
        let mut ctx = AesHmacAeadCtx::init(alg, content_encryption_key);
        let mut buf = plaintext.to_vec();
        let mut tag = [0u8; MAX_TAG_LEN];
        let tag_len = alg.tag_length();
        ctx.encrypt(iv, aad, &mut buf, &mut tag[..tag_len])?;

        Ok(ContentEncryptionParts {
            ciphertext: buf,
            tag,
            tag_len,
        })
    }

    fn decrypt_aes_hmac<'a>(
        &self,
        alg: HmacAlgorithm,
        ciphertext: &'a mut [u8],
        aad: &[u8],
        content_encryption_key: &[u8],
        iv: &[u8],
        authentication_tag: &[u8],
    ) -> Result<&'a [u8], JoseError> {
        let mut ctx = AesHmacAeadCtx::init(alg, content_encryption_key);
        let l = ctx.decrypt(iv, aad, ciphertext, authentication_tag)?.len();
        Ok(&ciphertext[..l])
    }

    fn encrypt_aead(
        &self,
        alg: AeadAlgorithm,
        plaintext: &[u8],
        aad: &[u8],
        content_encryption_key: &[u8],
        iv: &[u8],
    ) -> Result<ContentEncryptionParts, JoseError> {
        let ctx = EvpAeadCtx::init(alg, content_encryption_key);
        let mut buf = plaintext.to_vec();
        let mut tag = [0u8; MAX_TAG_LEN];
        let tag_len = alg.max_tag_len();
        ctx.encrypt(iv, aad, &mut buf, &mut tag[..tag_len])?;

        Ok(ContentEncryptionParts {
            ciphertext: buf,
            tag,
            tag_len,
        })
    }

    fn decrypt_aead<'a>(
        &self,
        alg: AeadAlgorithm,
        ciphertext: &'a mut [u8],
        aad: &[u8],
        content_encryption_key: &[u8],
        iv: &[u8],
        authentication_tag: &[u8],
    ) -> Result<&'a [u8], JoseError> {
        let ctx = EvpAeadCtx::init(alg, content_encryption_key);
        ctx.decrypt(iv, aad, ciphertext, authentication_tag)?;

        Ok(ciphertext)
    }

    pub(super) fn encrypt(
        &self,
        plaintext: &[u8],
        aad: &[u8],
        content_encryption_key: &[u8],
        iv: &[u8],
    ) -> Result<ContentEncryptionParts, JoseError> {
        match self {
            ContentEncryptionAlgorithm::Aes128CbcHmacSha256 => self.encrypt_aes_hmac(
                HmacAlgorithm::Aes128CbcHmacSha256,
                plaintext,
                aad,
                content_encryption_key,
                iv,
            ),
            ContentEncryptionAlgorithm::Aes192CbcHmacSha384 => self.encrypt_aes_hmac(
                HmacAlgorithm::Aes192CbcHmacSha384,
                plaintext,
                aad,
                content_encryption_key,
                iv,
            ),
            ContentEncryptionAlgorithm::Aes256CbcHmacSha512 => self.encrypt_aes_hmac(
                HmacAlgorithm::Aes256CbcHmacSha512,
                plaintext,
                aad,
                content_encryption_key,
                iv,
            ),
            ContentEncryptionAlgorithm::Aes128Gcm => self.encrypt_aead(
                AeadAlgorithm::Aes128Gcm,
                plaintext,
                aad,
                content_encryption_key,
                iv,
            ),
            ContentEncryptionAlgorithm::Aes192Gcm => self.encrypt_aead(
                AeadAlgorithm::Aes192Gcm,
                plaintext,
                aad,
                content_encryption_key,
                iv,
            ),
            ContentEncryptionAlgorithm::Aes256Gcm => self.encrypt_aead(
                AeadAlgorithm::Aes256Gcm,
                plaintext,
                aad,
                content_encryption_key,
                iv,
            ),
            ContentEncryptionAlgorithm::ChaCha20Poly1305 => self.encrypt_aead(
                AeadAlgorithm::ChaCha20Poly1305,
                plaintext,
                aad,
                content_encryption_key,
                iv,
            ),
            ContentEncryptionAlgorithm::XChaCha20Poly1305 => self.encrypt_aead(
                AeadAlgorithm::XChaCha20Poly1305,
                plaintext,
                aad,
                content_encryption_key,
                iv,
            ),
        }
    }

    pub(super) fn decrypt<'a>(
        &self,
        iv: &[u8],
        ciphertext: &'a mut [u8],
        authentication_tag: &[u8],
        aad: &[u8],
        content_encryption_key: &[u8],
    ) -> Result<&'a [u8], JoseError> {
        match self {
            ContentEncryptionAlgorithm::Aes128CbcHmacSha256 => {
                let alg = HmacAlgorithm::Aes128CbcHmacSha256;
                self.decrypt_aes_hmac(
                    alg,
                    ciphertext,
                    aad,
                    content_encryption_key,
                    iv,
                    authentication_tag,
                )
            }
            ContentEncryptionAlgorithm::Aes192CbcHmacSha384 => {
                let alg = HmacAlgorithm::Aes192CbcHmacSha384;
                self.decrypt_aes_hmac(
                    alg,
                    ciphertext,
                    aad,
                    content_encryption_key,
                    iv,
                    authentication_tag,
                )
            }
            ContentEncryptionAlgorithm::Aes256CbcHmacSha512 => {
                let alg = HmacAlgorithm::Aes256CbcHmacSha512;
                self.decrypt_aes_hmac(
                    alg,
                    ciphertext,
                    aad,
                    content_encryption_key,
                    iv,
                    authentication_tag,
                )
            }
            ContentEncryptionAlgorithm::Aes128Gcm => {
                let alg = AeadAlgorithm::Aes128Gcm;
                self.decrypt_aead(
                    alg,
                    ciphertext,
                    aad,
                    content_encryption_key,
                    iv,
                    authentication_tag,
                )
            }
            ContentEncryptionAlgorithm::Aes192Gcm => {
                let alg = AeadAlgorithm::Aes192Gcm;
                self.decrypt_aead(
                    alg,
                    ciphertext,
                    aad,
                    content_encryption_key,
                    iv,
                    authentication_tag,
                )
            }
            ContentEncryptionAlgorithm::Aes256Gcm => {
                let alg = AeadAlgorithm::Aes256Gcm;
                self.decrypt_aead(
                    alg,
                    ciphertext,
                    aad,
                    content_encryption_key,
                    iv,
                    authentication_tag,
                )
            }
            ContentEncryptionAlgorithm::ChaCha20Poly1305 => {
                let alg = AeadAlgorithm::ChaCha20Poly1305;
                self.decrypt_aead(
                    alg,
                    ciphertext,
                    aad,
                    content_encryption_key,
                    iv,
                    authentication_tag,
                )
            }
            ContentEncryptionAlgorithm::XChaCha20Poly1305 => {
                let alg = AeadAlgorithm::XChaCha20Poly1305;
                self.decrypt_aead(
                    alg,
                    ciphertext,
                    aad,
                    content_encryption_key,
                    iv,
                    authentication_tag,
                )
            }
        }
    }
}

impl TryFrom<&str> for ContentEncryptionAlgorithm {
    type Error = JoseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl TryFrom<String> for ContentEncryptionAlgorithm {
    type Error = crate::error::JoseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl TryFrom<&String> for ContentEncryptionAlgorithm {
    type Error = crate::error::JoseError;

    fn try_from(value: &String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

#[cfg(test)]
mod tests {
    use crate::base64;
    use crate::crypto::rand::rand_bytes;

    use super::*;

    // https://datatracker.ietf.org/doc/html/rfc7516#appendix-A.1
    #[test]
    fn test_example_encrypt_from_jwe_appendix1() {
        let plaintext = b"The true sign of intelligence is \
            not knowledge but imagination.";
        let encoded_header = b"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ";
        let content_enc_key: [u8; 32] = [
            177, 161, 244, 128, 84, 143, 225, 115, 63, 180, 3, 255, 107, 154, 212, 246, 138, 7,
            110, 91, 112, 46, 34, 105, 47, 130, 203, 46, 122, 234, 64, 252,
        ];
        let iv: [u8; 12] = [227, 197, 117, 252, 2, 219, 233, 68, 180, 225, 77, 219];

        let aad = encoded_header;
        let alg = ContentEncryptionAlgorithm::Aes256Gcm;
        let parts = alg
            .encrypt_aead(
                AeadAlgorithm::Aes256Gcm,
                plaintext,
                aad,
                &content_enc_key,
                &iv,
            )
            .unwrap();

        let expected_ciphertext =
            b"5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6ji\
            SdiwkIr3ajwQzaBtQD_A";
        let expected_auth_tag = b"XFBoMYUZodetZdvTiFvSkQ";

        assert_eq!(
            *parts.ciphertext,
            *base64::url_decode(expected_ciphertext).unwrap()
        );
        assert_eq!(
            parts.tag[..parts.tag_len],
            *base64::url_decode(expected_auth_tag).unwrap()
        );
    }

    #[test]
    fn test_example_decrypt_from_jwe_appendix1() {
        let encoded_header = b"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ";
        let content_enc_key: [u8; 32] = [
            177, 161, 244, 128, 84, 143, 225, 115, 63, 180, 3, 255, 107, 154, 212, 246, 138, 7,
            110, 91, 112, 46, 34, 105, 47, 130, 203, 46, 122, 234, 64, 252,
        ];
        let iv: [u8; 12] = [227, 197, 117, 252, 2, 219, 233, 68, 180, 225, 77, 219];

        let b64_ciphertext = b"5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6ji\
            SdiwkIr3ajwQzaBtQD_A";
        let b64_auth_tag = b"XFBoMYUZodetZdvTiFvSkQ";
        let mut ciphertext = base64::url_decode(b64_ciphertext).unwrap();
        let auth_tag = base64::url_decode(b64_auth_tag).unwrap();
        let aad = encoded_header;
        let expected_plaintext = b"The true sign of intelligence is \
            not knowledge but imagination.";

        let alg = ContentEncryptionAlgorithm::Aes256Gcm;
        let plaintext = alg
            .decrypt_aead(
                AeadAlgorithm::Aes256Gcm,
                &mut ciphertext,
                aad,
                &content_enc_key,
                &iv,
                &auth_tag,
            )
            .unwrap();

        assert_eq!(plaintext, expected_plaintext);
    }

    // https://datatracker.ietf.org/doc/html/rfc7516#appendix-A.2
    #[test]
    fn test_example_encrypt_from_jwe_appendix2() {
        let plaintext = b"Live long and prosper.";
        let encoded_header = b"eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0";
        let content_enc_key: [u8; 32] = [
            4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106, 206, 107, 124,
            212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156, 44, 207,
        ];
        let iv: [u8; 16] = [
            3, 22, 60, 12, 43, 67, 104, 105, 108, 108, 105, 99, 111, 116, 104, 101,
        ];

        let aad = encoded_header;

        let alg = ContentEncryptionAlgorithm::Aes128CbcHmacSha256;
        let parts = alg
            .encrypt_aes_hmac(
                HmacAlgorithm::Aes128CbcHmacSha256,
                plaintext,
                aad,
                &content_enc_key,
                &iv,
            )
            .unwrap();

        let expected_ciphertext = b"KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY";
        let expected_auth_tag = b"9hH0vgRfYgPnAHOd8stkvw";

        assert_eq!(
            *parts.ciphertext,
            *base64::url_decode(expected_ciphertext).unwrap()
        );
        assert_eq!(
            parts.tag[..parts.tag_len],
            *base64::url_decode(expected_auth_tag).unwrap()
        );
    }

    #[test]
    fn test_example_decrypt_from_jwe_appendix2() {
        let encoded_header = b"eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0";
        let content_enc_key: [u8; 32] = [
            4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106, 206, 107, 124,
            212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156, 44, 207,
        ];
        let iv: [u8; 16] = [
            3, 22, 60, 12, 43, 67, 104, 105, 108, 108, 105, 99, 111, 116, 104, 101,
        ];

        let b64_ciphertext = b"KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY";
        let b64_auth_tag = b"9hH0vgRfYgPnAHOd8stkvw";
        let mut ciphertext = base64::url_decode(b64_ciphertext).unwrap();
        let auth_tag = base64::url_decode(b64_auth_tag).unwrap();
        let aad = encoded_header;
        let expected_plaintext = b"Live long and prosper.";

        let alg = ContentEncryptionAlgorithm::Aes128CbcHmacSha256;
        let plaintext = alg
            .decrypt_aes_hmac(
                HmacAlgorithm::Aes128CbcHmacSha256,
                &mut ciphertext,
                aad,
                &content_enc_key,
                &iv,
                &auth_tag,
            )
            .unwrap();

        assert_eq!(plaintext, expected_plaintext);
    }

    #[test]
    fn test_end_to_end() {
        for alg in [
            ContentEncryptionAlgorithm::Aes128CbcHmacSha256,
            ContentEncryptionAlgorithm::Aes192CbcHmacSha384,
            ContentEncryptionAlgorithm::Aes256CbcHmacSha512,
            ContentEncryptionAlgorithm::Aes128Gcm,
            ContentEncryptionAlgorithm::Aes192Gcm,
            ContentEncryptionAlgorithm::Aes256Gcm,
            ContentEncryptionAlgorithm::ChaCha20Poly1305,
            ContentEncryptionAlgorithm::XChaCha20Poly1305,
        ] {
            let plaintext = rand_bytes(64);
            let content_encryption_key = rand_bytes(alg.key_len());
            let aad = rand_bytes(32);
            let iv = rand_bytes(alg.iv_len());
            let parts = alg
                .encrypt(&plaintext, &aad, &content_encryption_key, &iv)
                .unwrap();

            let mut ct = parts.ciphertext.clone();
            let out = alg
                .decrypt(
                    &iv,
                    &mut ct,
                    &parts.tag[..parts.tag_len],
                    &aad,
                    &content_encryption_key,
                )
                .unwrap();
            assert_eq!(*plaintext, *out);
        }
    }
}
