use super::aes_hmac::Algorithm as HmacAlgorithm;

use crate::crypto::aead::{Algorithm as AeadAlgorithm, EvpAeadCtx};
use crate::crypto::mem;
use crate::crypto::rand::rand_bytes;
use crate::jwe::aes_hmac::AesHmacAeadCtx;
use crate::{error::JoseError, jwe::ContentEncryptionParts};

/// Represents the content encryption algorithm identifiers for JWE.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContentEncryptionAlgorithm {
    Aes128CbcHmacSha256,
    Aes192CbcHmacSha384,
    Aes256CbcHmacSha512,
    Aes128Gcm,
    Aes192Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
    XChaCha20Poly1305,
}

impl ContentEncryptionAlgorithm {
    pub fn try_from_str(alg: impl AsRef<str>) -> Result<Self, JoseError> {
        match alg.as_ref() {
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

    fn encrypt_aes_hmac(
        &self,
        alg: HmacAlgorithm,
        plaintext: &[u8],
        aad: &[u8],
        content_encryption_key: &[u8],
        iv: Box<[u8]>,
    ) -> Result<ContentEncryptionParts, JoseError> {
        let mut ctx = AesHmacAeadCtx::init(alg, content_encryption_key);
        let mut buf = plaintext.to_vec();
        let mut tag = mem::new_boxed_slice(alg.tag_length());
        ctx.encrypt(&iv, aad, &mut buf, &mut tag)?;

        Ok(ContentEncryptionParts {
            iv,
            ciphertext: buf,
            authentication_tag: tag,
        })
    }

    fn decrypt_aes_hmac<'a>(
        &self,
        alg: HmacAlgorithm,
        mut ciphertext: &'a mut [u8],
        aad: &[u8],
        content_encryption_key: &[u8],
        iv: &[u8],
        authentication_tag: &[u8],
    ) -> Result<&'a [u8], JoseError> {
        let mut ctx = AesHmacAeadCtx::init(alg, content_encryption_key);
        let l = ctx
            .decrypt(iv, aad, &mut ciphertext, authentication_tag)?
            .len();
        Ok(&ciphertext[..l])
    }

    fn encrypt_aead(
        &self,
        alg: AeadAlgorithm,
        plaintext: &[u8],
        aad: &[u8],
        content_encryption_key: &[u8],
        iv: Box<[u8]>,
    ) -> Result<ContentEncryptionParts, JoseError> {
        let ctx = EvpAeadCtx::init(alg, content_encryption_key);
        let mut buf = plaintext.to_vec();
        let mut tag = mem::new_boxed_slice(alg.max_tag_len());
        ctx.encrypt(&iv, aad, &mut buf, &mut tag)?;

        Ok(ContentEncryptionParts {
            iv,
            ciphertext: buf,
            authentication_tag: tag,
        })
    }

    fn decrypt_aead<'a>(
        &self,
        alg: AeadAlgorithm,
        mut ciphertext: &'a mut [u8],
        aad: &[u8],
        content_encryption_key: &[u8],
        iv: &[u8],
        authentication_tag: &[u8],
    ) -> Result<&'a [u8], JoseError> {
        let ctx = EvpAeadCtx::init(alg, content_encryption_key);
        ctx.decrypt(iv, aad, &mut ciphertext, authentication_tag)?;

        Ok(ciphertext)
    }

    pub(super) fn encrypt(
        &self,
        plaintext: &[u8],
        aad: &[u8],
        content_encryption_key: &[u8],
    ) -> Result<ContentEncryptionParts, JoseError> {
        match self {
            ContentEncryptionAlgorithm::Aes128CbcHmacSha256 => {
                let alg = HmacAlgorithm::Aes128CbcHmacSha256;
                let iv = rand_bytes(16);

                self.encrypt_aes_hmac(alg, plaintext, aad, content_encryption_key, iv)
            }
            ContentEncryptionAlgorithm::Aes192CbcHmacSha384 => {
                let alg = HmacAlgorithm::Aes192CbcHmacSha384;
                let iv = rand_bytes(16);

                self.encrypt_aes_hmac(alg, plaintext, aad, content_encryption_key, iv)
            }
            ContentEncryptionAlgorithm::Aes256CbcHmacSha512 => {
                let alg = HmacAlgorithm::Aes256CbcHmacSha512;
                let iv = rand_bytes(16);

                self.encrypt_aes_hmac(alg, plaintext, aad, content_encryption_key, iv)
            }
            ContentEncryptionAlgorithm::Aes128Gcm => {
                let alg = AeadAlgorithm::Aes128Gcm;
                let iv = rand_bytes(alg.iv_len());

                self.encrypt_aead(alg, plaintext, aad, content_encryption_key, iv)
            }
            ContentEncryptionAlgorithm::Aes192Gcm => {
                let alg = AeadAlgorithm::Aes192Gcm;
                let iv = rand_bytes(alg.iv_len());

                self.encrypt_aead(alg, plaintext, aad, content_encryption_key, iv)
            }
            ContentEncryptionAlgorithm::Aes256Gcm => {
                let alg = AeadAlgorithm::Aes256Gcm;
                let iv = rand_bytes(alg.iv_len());

                self.encrypt_aead(alg, plaintext, aad, content_encryption_key, iv)
            }
            ContentEncryptionAlgorithm::ChaCha20Poly1305 => {
                let alg = AeadAlgorithm::ChaCha20Poly1305;
                let iv = rand_bytes(alg.iv_len());

                self.encrypt_aead(alg, plaintext, aad, content_encryption_key, iv)
            }
            ContentEncryptionAlgorithm::XChaCha20Poly1305 => {
                let alg = AeadAlgorithm::XChaCha20Poly1305;
                let iv = rand_bytes(alg.iv_len());

                self.encrypt_aead(alg, plaintext, aad, content_encryption_key, iv)
            }
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
        Self::try_from_str(value)
    }
}

impl TryFrom<String> for ContentEncryptionAlgorithm {
    type Error = crate::error::JoseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from_str(value)
    }
}

impl TryFrom<&String> for ContentEncryptionAlgorithm {
    type Error = crate::error::JoseError;

    fn try_from(value: &String) -> Result<Self, Self::Error> {
        Self::try_from_str(value)
    }
}

#[cfg(test)]
mod tests {
    use crate::base64;

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
        let iv = Box::new(iv);

        let aad = encoded_header;
        let alg = ContentEncryptionAlgorithm::Aes256Gcm;
        let parts = alg
            .encrypt_aead(
                AeadAlgorithm::Aes256Gcm,
                plaintext,
                aad,
                &content_enc_key,
                iv.clone(),
            )
            .unwrap();

        let expected_ciphertext =
            b"5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6ji\
            SdiwkIr3ajwQzaBtQD_A";
        let expected_auth_tag = b"XFBoMYUZodetZdvTiFvSkQ";

        assert_eq!(&*parts.iv, &*iv);
        assert_eq!(
            *parts.ciphertext,
            *base64::url_decode(expected_ciphertext).unwrap()
        );
        assert_eq!(
            *parts.authentication_tag,
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
        let iv = Box::new(iv);

        let aad = encoded_header;

        let alg = ContentEncryptionAlgorithm::Aes128CbcHmacSha256;
        let parts = alg
            .encrypt_aes_hmac(
                HmacAlgorithm::Aes128CbcHmacSha256,
                plaintext,
                aad,
                &content_enc_key,
                iv.clone(),
            )
            .unwrap();

        let expected_ciphertext = b"KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY";
        let expected_auth_tag = b"9hH0vgRfYgPnAHOd8stkvw";

        assert_eq!(&*parts.iv, &*iv);
        assert_eq!(
            *parts.ciphertext,
            *base64::url_decode(expected_ciphertext).unwrap()
        );
        assert_eq!(
            *parts.authentication_tag,
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
            let mut parts = alg
                .encrypt(&plaintext, &aad, &content_encryption_key)
                .unwrap();

            let out = alg
                .decrypt(
                    &parts.iv,
                    &mut parts.ciphertext,
                    &parts.authentication_tag,
                    &aad,
                    &content_encryption_key,
                )
                .unwrap();
            assert_eq!(*plaintext, *out);
        }
    }
}
