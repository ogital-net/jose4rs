use std::{mem::MaybeUninit, ptr};

#[cfg(feature = "aws-lc")]
use aws_lc_sys::{
    EVP_AEAD_CTX_cleanup, EVP_AEAD_CTX_init, EVP_AEAD_CTX_open_gather, EVP_AEAD_CTX_seal_scatter,
    EVP_aead_aes_128_gcm, EVP_aead_aes_192_gcm, EVP_aead_aes_256_gcm, EVP_aead_chacha20_poly1305,
    EVP_aead_xchacha20_poly1305, EVP_AEAD, EVP_AEAD_CTX,
};
#[cfg(feature = "boring")]
use boring_sys::{
    EVP_AEAD_CTX_cleanup, EVP_AEAD_CTX_init, EVP_AEAD_CTX_open_gather, EVP_AEAD_CTX_seal_scatter,
    EVP_aead_aes_128_gcm, EVP_aead_aes_192_gcm, EVP_aead_aes_256_gcm, EVP_aead_chacha20_poly1305,
    EVP_aead_xchacha20_poly1305, EVP_AEAD, EVP_AEAD_CTX,
};

use crate::error::JoseError;

pub(crate) struct EvpAeadCtx(EVP_AEAD_CTX);

impl EvpAeadCtx {
    pub(crate) fn init(algorithm: Algorithm, key: &[u8]) -> Self {
        let mut ctx = MaybeUninit::<EVP_AEAD_CTX>::uninit();
        unsafe {
            assert!(
                1 == EVP_AEAD_CTX_init(
                    ctx.as_mut_ptr(),
                    algorithm.as_ptr(),
                    key.as_ptr(),
                    key.len(),
                    0,
                    ptr::null_mut()
                ),
                "EVP_AEAD_CTX_init() failed"
            );
            Self(ctx.assume_init())
        }
    }

    pub(super) fn as_mut_ptr(&mut self) -> *mut EVP_AEAD_CTX {
        &mut self.0
    }

    pub(super) fn as_ptr(&self) -> *const EVP_AEAD_CTX {
        &self.0
    }

    pub(crate) fn encrypt<'a>(
        &self,
        iv: &[u8],
        aad: &[u8],
        in_out: &mut [u8],
        tag: &'a mut [u8],
    ) -> Result<&'a [u8], JoseError> {
        let mut tag_len = 0usize;

        unsafe {
            if 1 != EVP_AEAD_CTX_seal_scatter(
                self.as_ptr(),
                in_out.as_mut_ptr(),
                tag.as_mut_ptr(),
                &mut tag_len,
                tag.len(),
                iv.as_ptr(),
                iv.len(),
                in_out.as_ptr(),
                in_out.len(),
                ptr::null(),
                0usize,
                aad.as_ptr(),
                aad.len(),
            ) {
                return Err(JoseError::new("encryption failed"));
            }
        }

        Ok(&tag[..tag_len])
    }

    pub(crate) fn decrypt<'a>(
        &self,
        iv: &[u8],
        aad: &[u8],
        in_out: &'a mut [u8],
        tag: &[u8],
    ) -> Result<&'a [u8], JoseError> {
        unsafe {
            if 1 != EVP_AEAD_CTX_open_gather(
                self.as_ptr(),
                in_out.as_mut_ptr(),
                iv.as_ptr(),
                iv.len(),
                in_out.as_ptr(),
                in_out.len(),
                tag.as_ptr(),
                tag.len(),
                aad.as_ptr(),
                aad.len(),
            ) {
                return Err(JoseError::new("decryption failed"));
            }
        }

        Ok(in_out)
    }
}

unsafe impl Send for EvpAeadCtx {}
unsafe impl Sync for EvpAeadCtx {}

impl Drop for EvpAeadCtx {
    fn drop(&mut self) {
        unsafe { EVP_AEAD_CTX_cleanup(self.as_mut_ptr()) }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(clippy::enum_variant_names)]
pub(crate) enum Algorithm {
    Aes128Gcm,
    Aes192Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
    XChaCha20Poly1305,
}

impl Algorithm {
    pub(super) fn as_ptr(&self) -> *const EVP_AEAD {
        match self {
            Algorithm::Aes128Gcm => unsafe { EVP_aead_aes_128_gcm() },
            Algorithm::Aes192Gcm => unsafe { EVP_aead_aes_192_gcm() },
            Algorithm::Aes256Gcm => unsafe { EVP_aead_aes_256_gcm() },
            Algorithm::ChaCha20Poly1305 => unsafe { EVP_aead_chacha20_poly1305() },
            Algorithm::XChaCha20Poly1305 => unsafe { EVP_aead_xchacha20_poly1305() },
        }
    }

    #[inline]
    pub(crate) fn key_len(&self) -> usize {
        match self {
            Algorithm::Aes128Gcm => 16,
            Algorithm::Aes192Gcm => 24,
            Algorithm::Aes256Gcm => 32,
            Algorithm::ChaCha20Poly1305 => 32,
            Algorithm::XChaCha20Poly1305 => 32,
        }
    }

    #[inline]
    pub(crate) fn iv_len(&self) -> usize {
        match self {
            Algorithm::Aes128Gcm => 12,
            Algorithm::Aes192Gcm => 12,
            Algorithm::Aes256Gcm => 12,
            Algorithm::ChaCha20Poly1305 => 12,
            Algorithm::XChaCha20Poly1305 => 24,
        }
    }

    #[inline]
    pub(crate) fn max_overhead(&self) -> usize {
        match self {
            Algorithm::Aes128Gcm => 16,
            Algorithm::Aes192Gcm => 16,
            Algorithm::Aes256Gcm => 16,
            Algorithm::ChaCha20Poly1305 => 16,
            Algorithm::XChaCha20Poly1305 => 16,
        }
    }

    #[inline]
    pub(crate) fn max_tag_len(&self) -> usize {
        match self {
            Algorithm::Aes128Gcm => 16,
            Algorithm::Aes192Gcm => 16,
            Algorithm::Aes256Gcm => 16,
            Algorithm::ChaCha20Poly1305 => 16,
            Algorithm::XChaCha20Poly1305 => 16,
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "aws-lc")]
    use aws_lc_sys::{
        EVP_AEAD_key_length, EVP_AEAD_max_overhead, EVP_AEAD_max_tag_len, EVP_AEAD_nonce_length,
    };

    #[cfg(feature = "boring")]
    use boring_sys::{
        EVP_AEAD_key_length, EVP_AEAD_max_overhead, EVP_AEAD_max_tag_len, EVP_AEAD_nonce_length,
    };

    use crate::crypto::rand::rand_bytes;

    use super::*;

    #[test]
    fn test_key_len() {
        for alg in [
            Algorithm::Aes128Gcm,
            Algorithm::Aes192Gcm,
            Algorithm::Aes256Gcm,
            Algorithm::ChaCha20Poly1305,
            Algorithm::XChaCha20Poly1305,
        ] {
            let ossl_size = unsafe { EVP_AEAD_key_length(alg.as_ptr()) };
            assert_eq!(alg.key_len(), ossl_size);
        }
    }

    #[test]
    fn test_iv_len() {
        for alg in [
            Algorithm::Aes128Gcm,
            Algorithm::Aes192Gcm,
            Algorithm::Aes256Gcm,
            Algorithm::ChaCha20Poly1305,
            Algorithm::XChaCha20Poly1305,
        ] {
            let ossl_size = unsafe { EVP_AEAD_nonce_length(alg.as_ptr()) };
            assert_eq!(alg.iv_len(), ossl_size);
        }
    }

    #[test]
    fn test_max_overhead() {
        for alg in [
            Algorithm::Aes128Gcm,
            Algorithm::Aes192Gcm,
            Algorithm::Aes256Gcm,
            Algorithm::ChaCha20Poly1305,
            Algorithm::XChaCha20Poly1305,
        ] {
            let ossl_size = unsafe { EVP_AEAD_max_overhead(alg.as_ptr()) };
            assert_eq!(alg.max_overhead(), ossl_size);
        }
    }

    #[test]
    fn test_max_tag_len() {
        for alg in [
            Algorithm::Aes128Gcm,
            Algorithm::Aes192Gcm,
            Algorithm::Aes256Gcm,
            Algorithm::ChaCha20Poly1305,
            Algorithm::XChaCha20Poly1305,
        ] {
            let ossl_size = unsafe { EVP_AEAD_max_tag_len(alg.as_ptr()) };
            assert_eq!(alg.max_tag_len(), ossl_size);
        }
    }

    #[test]
    fn test_encrypt_decrypt_rt() {
        for alg in [
            Algorithm::Aes128Gcm,
            Algorithm::Aes192Gcm,
            Algorithm::Aes256Gcm,
            Algorithm::ChaCha20Poly1305,
            Algorithm::XChaCha20Poly1305,
        ] {
            let key = rand_bytes(alg.key_len());
            let iv = rand_bytes(alg.iv_len());

            let aad = rand_bytes(32);
            let input = "Hello World!".as_bytes();
            let mut buf = input.to_vec();

            let ctx = EvpAeadCtx::init(alg, &key);
            let mut tag_buf = [0u8; 16];

            let tag = ctx
                .encrypt(&iv, &aad, buf.as_mut_slice(), &mut tag_buf[..])
                .unwrap();

            let output = ctx.decrypt(&iv, &aad, buf.as_mut_slice(), tag).unwrap();
            assert_eq!(input, output);
        }
    }
}
