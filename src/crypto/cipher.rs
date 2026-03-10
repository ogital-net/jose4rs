use std::{mem::MaybeUninit, ptr};

#[cfg(feature = "aws-lc")]
use aws_lc_sys::{
    EVP_CIPHER_CTX_cleanup, EVP_CIPHER_CTX_init, EVP_DecryptFinal_ex, EVP_DecryptInit_ex,
    EVP_DecryptUpdate, EVP_EncryptFinal_ex, EVP_EncryptInit_ex, EVP_EncryptUpdate, EVP_aes_128_cbc,
    EVP_aes_192_cbc, EVP_aes_256_cbc, EVP_CIPHER, EVP_CIPHER_CTX,
};

#[cfg(feature = "boring")]
use boring_sys::{
    EVP_CIPHER_CTX_cleanup, EVP_CIPHER_CTX_init, EVP_DecryptFinal_ex, EVP_DecryptInit_ex,
    EVP_DecryptUpdate, EVP_EncryptFinal_ex, EVP_EncryptInit_ex, EVP_EncryptUpdate, EVP_aes_128_cbc,
    EVP_aes_192_cbc, EVP_aes_256_cbc, EVP_CIPHER, EVP_CIPHER_CTX,
};

use crate::error::JoseError;

pub(crate) struct EvpCipherCtx(EVP_CIPHER_CTX);

impl EvpCipherCtx {
    pub(crate) fn init() -> Self {
        let mut ctx = MaybeUninit::<EVP_CIPHER_CTX>::uninit();
        unsafe {
            EVP_CIPHER_CTX_init(ctx.as_mut_ptr());
            Self(ctx.assume_init())
        }
    }

    pub(super) fn as_mut_ptr(&mut self) -> *mut EVP_CIPHER_CTX {
        &mut self.0
    }

    pub(super) fn as_ptr(&self) -> *const EVP_CIPHER_CTX {
        &self.0
    }

    pub(crate) fn encrypt<'a>(
        &mut self,
        algorithm: Algorithm,
        key: &[u8],
        iv: &[u8],
        in_out: &'a mut Vec<u8>,
    ) -> Result<&'a mut [u8], JoseError> {
        if in_out.is_empty() {
            return Err(JoseError::new("buffer must not be empty"));
        }

        if key.len() != algorithm.key_len() {
            return Err(JoseError::invalid_key(format!(
                "invalid key length '{}', expected '{}'",
                key.len(),
                algorithm.key_len()
            )));
        }

        if iv.len() != algorithm.iv_len() {
            return Err(JoseError::invalid_key(format!(
                "invalid IV length '{}', expected '{}'",
                iv.len(),
                algorithm.iv_len()
            )));
        }
        let need = algorithm.encrypt_output_len(in_out.len());
        if need > in_out.capacity() {
            in_out.reserve_exact(need - in_out.capacity());
        }

        assert!(
            1 == unsafe {
                EVP_EncryptInit_ex(
                    self.as_mut_ptr(),
                    algorithm.as_ptr(),
                    ptr::null_mut(),
                    key.as_ptr(),
                    iv.as_ptr(),
                )
            },
            "EVP_EncryptInit_ex() failed"
        );

        unsafe {
            let mut written: std::ffi::c_int = 0;
            assert!(
                1 == EVP_EncryptUpdate(
                    self.as_mut_ptr(),
                    in_out.as_mut_ptr(),
                    &mut written,
                    in_out.as_ptr(),
                    in_out.len().try_into().unwrap()
                ),
                "EVP_EncryptUpdate() failed"
            );
            in_out.set_len(written as usize);
            assert!(
                1 == EVP_EncryptFinal_ex(
                    self.as_mut_ptr(),
                    in_out.as_mut_ptr().add(in_out.len()),
                    &mut written
                ),
                "EVP_EncryptFinal_ex() failed"
            );
            in_out.set_len(in_out.len() + written as usize);
        }
        Ok(in_out.as_mut_slice())
    }

    pub(crate) fn decrypt<'a>(
        &mut self,
        algorithm: Algorithm,
        key: &[u8],
        iv: &[u8],
        ciphertext: &'a mut [u8],
    ) -> Result<&'a [u8], JoseError> {
        if ciphertext.is_empty() {
            return Err(JoseError::new("ciphertext must not be empty"));
        }

        if key.len() != algorithm.key_len() {
            return Err(JoseError::invalid_key(format!(
                "invalid key length '{}', expected '{}'",
                key.len(),
                algorithm.key_len()
            )));
        }

        if iv.len() != algorithm.iv_len() {
            return Err(JoseError::invalid_key(format!(
                "invalid IV length '{}', expected '{}'",
                iv.len(),
                algorithm.iv_len()
            )));
        }

        if ciphertext.len() % algorithm.block_len() != 0 {
            return Err(JoseError::new(format!(
                "ciphertext length not multiple of {}",
                algorithm.block_len()
            )));
        }

        assert!(
            1 == unsafe {
                EVP_DecryptInit_ex(
                    self.as_mut_ptr(),
                    algorithm.as_ptr(),
                    ptr::null_mut(),
                    key.as_ptr(),
                    iv.as_ptr(),
                )
            },
            "EVP_DecryptInit_ex() failed"
        );

        let mut end = 0usize;

        unsafe {
            let mut written: std::ffi::c_int = 0;
            assert!(
                1 == EVP_DecryptUpdate(
                    self.as_mut_ptr(),
                    ciphertext.as_mut_ptr(),
                    &mut written,
                    ciphertext.as_ptr(),
                    ciphertext.len().try_into().unwrap()
                )
            );
            end += written as usize;
            if 1 != EVP_DecryptFinal_ex(
                self.as_mut_ptr(),
                ciphertext.as_mut_ptr().add(end),
                &mut written,
            ) {
                return Err(JoseError::invalid_key("decryption failed"));
            }
            end += written as usize;
        }
        Ok(&ciphertext[..end])
    }
}

unsafe impl Send for EvpCipherCtx {}
unsafe impl Sync for EvpCipherCtx {}

impl Drop for EvpCipherCtx {
    fn drop(&mut self) {
        unsafe { EVP_CIPHER_CTX_cleanup(self.as_mut_ptr()) };
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(clippy::enum_variant_names)]
pub(crate) enum Algorithm {
    Aes128Cbc,
    Aes192Cbc,
    Aes256Cbc,
}

impl Algorithm {
    pub(super) fn as_ptr(&self) -> *const EVP_CIPHER {
        match self {
            Algorithm::Aes128Cbc => unsafe { EVP_aes_128_cbc() },
            Algorithm::Aes192Cbc => unsafe { EVP_aes_192_cbc() },
            Algorithm::Aes256Cbc => unsafe { EVP_aes_256_cbc() },
        }
    }

    #[inline]
    pub(crate) fn key_len(&self) -> usize {
        match self {
            Algorithm::Aes128Cbc => 16,
            Algorithm::Aes192Cbc => 24,
            Algorithm::Aes256Cbc => 32,
        }
    }

    #[inline]
    pub(crate) fn iv_len(&self) -> usize {
        match self {
            Algorithm::Aes128Cbc => 16,
            Algorithm::Aes192Cbc => 16,
            Algorithm::Aes256Cbc => 16,
        }
    }

    #[inline]
    pub(super) fn block_len(&self) -> usize {
        match self {
            Algorithm::Aes128Cbc => 16,
            Algorithm::Aes192Cbc => 16,
            Algorithm::Aes256Cbc => 16,
        }
    }

    #[inline]
    pub(super) fn encrypt_output_len(&self, plain_len: usize) -> usize {
        plain_len + self.block_len() - (plain_len % self.block_len())
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "aws-lc")]
    use aws_lc_sys::{EVP_CIPHER_block_size, EVP_CIPHER_iv_length, EVP_CIPHER_key_length};
    #[cfg(feature = "boring")]
    use boring_sys::{EVP_CIPHER_block_size, EVP_CIPHER_iv_length, EVP_CIPHER_key_length};

    use crate::crypto::rand::rand_bytes;

    use super::*;

    #[test]
    fn test_iv_len() {
        for alg in [
            Algorithm::Aes128Cbc,
            Algorithm::Aes192Cbc,
            Algorithm::Aes256Cbc,
        ] {
            let ossl_size = unsafe { EVP_CIPHER_iv_length(alg.as_ptr()) as usize };
            assert_eq!(alg.iv_len(), ossl_size);
        }
    }

    #[test]
    fn test_key_len() {
        for alg in [
            Algorithm::Aes128Cbc,
            Algorithm::Aes192Cbc,
            Algorithm::Aes256Cbc,
        ] {
            let ossl_size = unsafe { EVP_CIPHER_key_length(alg.as_ptr()) as usize };
            assert_eq!(alg.key_len(), ossl_size);
        }
    }

    #[test]
    fn test_block_len() {
        for alg in [
            Algorithm::Aes128Cbc,
            Algorithm::Aes192Cbc,
            Algorithm::Aes256Cbc,
        ] {
            let ossl_size = unsafe { EVP_CIPHER_block_size(alg.as_ptr()) as usize };
            assert_eq!(alg.block_len(), ossl_size);
        }
    }

    #[test]
    fn test_encrypt_output_len() {
        for alg in [
            Algorithm::Aes128Cbc,
            Algorithm::Aes192Cbc,
            Algorithm::Aes256Cbc,
        ] {
            assert_eq!(alg.encrypt_output_len(0), 16);
            assert_eq!(alg.encrypt_output_len(1), 16);
            assert_eq!(alg.encrypt_output_len(17), 32);
            assert_eq!(alg.encrypt_output_len(32), 48);
        }
    }

    #[test]
    fn test_encrypt_aes_128_cbc() {
        // Key (K)
        let key: [u8; 16] = [
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
            0x1e, 0x1f,
        ];

        // Initialization Vector (IV)
        let iv: [u8; 16] = [
            0x1a, 0xf3, 0x8c, 0x2d, 0xc2, 0xb9, 0x6f, 0xfd, 0xd8, 0x66, 0x94, 0x09, 0x23, 0x41,
            0xbc, 0x04,
        ];

        // Plaintext (P)
        let plaintext: [u8; 128] = [
            0x41, 0x20, 0x63, 0x69, 0x70, 0x68, 0x65, 0x72, 0x20, 0x73, 0x79, 0x73, 0x74, 0x65,
            0x6d, 0x20, 0x6d, 0x75, 0x73, 0x74, 0x20, 0x6e, 0x6f, 0x74, 0x20, 0x62, 0x65, 0x20,
            0x72, 0x65, 0x71, 0x75, 0x69, 0x72, 0x65, 0x64, 0x20, 0x74, 0x6f, 0x20, 0x62, 0x65,
            0x20, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x2c, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x69,
            0x74, 0x20, 0x6d, 0x75, 0x73, 0x74, 0x20, 0x62, 0x65, 0x20, 0x61, 0x62, 0x6c, 0x65,
            0x20, 0x74, 0x6f, 0x20, 0x66, 0x61, 0x6c, 0x6c, 0x20, 0x69, 0x6e, 0x74, 0x6f, 0x20,
            0x74, 0x68, 0x65, 0x20, 0x68, 0x61, 0x6e, 0x64, 0x73, 0x20, 0x6f, 0x66, 0x20, 0x74,
            0x68, 0x65, 0x20, 0x65, 0x6e, 0x65, 0x6d, 0x79, 0x20, 0x77, 0x69, 0x74, 0x68, 0x6f,
            0x75, 0x74, 0x20, 0x69, 0x6e, 0x63, 0x6f, 0x6e, 0x76, 0x65, 0x6e, 0x69, 0x65, 0x6e,
            0x63, 0x65,
        ];

        // Expected Ciphertext (E)
        let expected_ciphertext: [u8; 144] = [
            0xc8, 0x0e, 0xdf, 0xa3, 0x2d, 0xdf, 0x39, 0xd5, 0xef, 0x00, 0xc0, 0xb4, 0x68, 0x83,
            0x42, 0x79, 0xa2, 0xe4, 0x6a, 0x1b, 0x80, 0x49, 0xf7, 0x92, 0xf7, 0x6b, 0xfe, 0x54,
            0xb9, 0x03, 0xa9, 0xc9, 0xa9, 0x4a, 0xc9, 0xb4, 0x7a, 0xd2, 0x65, 0x5c, 0x5f, 0x10,
            0xf9, 0xae, 0xf7, 0x14, 0x27, 0xe2, 0xfc, 0x6f, 0x9b, 0x3f, 0x39, 0x9a, 0x22, 0x14,
            0x89, 0xf1, 0x63, 0x62, 0xc7, 0x03, 0x23, 0x36, 0x09, 0xd4, 0x5a, 0xc6, 0x98, 0x64,
            0xe3, 0x32, 0x1c, 0xf8, 0x29, 0x35, 0xac, 0x40, 0x96, 0xc8, 0x6e, 0x13, 0x33, 0x14,
            0xc5, 0x40, 0x19, 0xe8, 0xca, 0x79, 0x80, 0xdf, 0xa4, 0xb9, 0xcf, 0x1b, 0x38, 0x4c,
            0x48, 0x6f, 0x3a, 0x54, 0xc5, 0x10, 0x78, 0x15, 0x8e, 0xe5, 0xd7, 0x9d, 0xe5, 0x9f,
            0xbd, 0x34, 0xd8, 0x48, 0xb3, 0xd6, 0x95, 0x50, 0xa6, 0x76, 0x46, 0x34, 0x44, 0x27,
            0xad, 0xe5, 0x4b, 0x88, 0x51, 0xff, 0xb5, 0x98, 0xf7, 0xf8, 0x00, 0x74, 0xb9, 0x47,
            0x3c, 0x82, 0xe2, 0xdb,
        ];

        let mut buf = plaintext.to_vec();
        let mut ctx = EvpCipherCtx::init();
        let ciphertext = ctx
            .encrypt(Algorithm::Aes128Cbc, &key, &iv, &mut buf)
            .unwrap();
        assert_eq!(ciphertext, expected_ciphertext);
    }

    #[test]
    fn test_encrypt_decrypt_rt() {
        for alg in [
            Algorithm::Aes128Cbc,
            Algorithm::Aes192Cbc,
            Algorithm::Aes256Cbc,
        ] {
            let key = rand_bytes(alg.key_len());
            let iv = rand_bytes(alg.iv_len());
            let input = "Hello World!".as_bytes();
            let mut buf = input.to_vec();

            let mut ctx = EvpCipherCtx::init();
            let ciphertext = ctx.encrypt(alg, &key, &iv, &mut buf).unwrap();

            let output = ctx.decrypt(alg, &key, &iv, ciphertext).unwrap();
            assert_eq!(input, output);
        }
    }
}
