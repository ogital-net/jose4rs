#[cfg(feature = "aws-lc")]
use aws_lc_sys::PKCS5_PBKDF2_HMAC;
#[cfg(all(feature = "boring", not(feature = "aws-lc")))]
use boring_sys::PKCS5_PBKDF2_HMAC;

use crate::error::JoseError;

use super::{digest, mem::Zeroizing};

/// Derives a key using PBKDF2-HMAC as specified by RFC 8018 / PKCS #5.
pub(crate) fn pbkdf2_hmac(
    md: digest::Algorithm,
    password: impl AsRef<[u8]>,
    salt: impl AsRef<[u8]>,
    iterations: u32,
    out_len: usize,
) -> Result<Zeroizing<Box<[u8]>>, JoseError> {
    let password = password.as_ref();
    let salt = salt.as_ref();

    if iterations == 0 {
        return Err(JoseError::InvalidAlgorithm(
            "PBKDF2 iteration count must be positive".to_string(),
        ));
    }

    let mut out = Zeroizing::new(super::mem::new_boxed_slice(out_len));

    let res = unsafe {
        PKCS5_PBKDF2_HMAC(
            password.as_ptr().cast(),
            password.len(),
            salt.as_ptr(),
            salt.len(),
            iterations,
            md.as_ptr(),
            out.len(),
            out.as_mut_ptr(),
        )
    };
    if res != 1 {
        return Err(JoseError::new("PKCS5_PBKDF2_HMAC() failed"));
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test vectors from RFC 6070 (PKCS #5 v2.1)
    #[test]
    fn test_rfc6070_sha1() {
        let out = pbkdf2_hmac(digest::Algorithm::Sha1, b"password", b"salt", 1, 20).unwrap();
        assert_eq!(
            *out,
            [
                0x0c, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71, 0xf3, 0xa9, 0xb5, 0x24, 0xaf, 0x60,
                0x12, 0x06, 0x2f, 0xe0, 0x37, 0xa6
            ]
        );

        let out = pbkdf2_hmac(digest::Algorithm::Sha1, b"password", b"salt", 2, 20).unwrap();
        assert_eq!(
            *out,
            [
                0xea, 0x6c, 0x01, 0x4d, 0xc7, 0x2d, 0x6f, 0x8c, 0xcd, 0x1e, 0xd9, 0x2a, 0xce, 0x1d,
                0x41, 0xf0, 0xd8, 0xde, 0x89, 0x57
            ]
        );

        let out = pbkdf2_hmac(digest::Algorithm::Sha1, b"password", b"salt", 4096, 20).unwrap();
        assert_eq!(
            *out,
            [
                0x4b, 0x00, 0x79, 0x01, 0xb7, 0x65, 0x48, 0x9a, 0xbe, 0xad, 0x49, 0xd9, 0x26, 0xf7,
                0x21, 0xd0, 0x65, 0xa4, 0x29, 0xc1
            ]
        );
    }

    // Test vectors from RFC 7914-style PBKDF2-HMAC-SHA-256
    #[test]
    fn test_pbkdf2_hmac_sha256() {
        let out = pbkdf2_hmac(digest::Algorithm::Sha256, b"password", b"salt", 1, 32).unwrap();
        assert_eq!(
            *out,
            [
                0x12, 0x0f, 0xb6, 0xcf, 0xfc, 0xf8, 0xb3, 0x2c, 0x43, 0xe7, 0x22, 0x52, 0x56, 0xc4,
                0xf8, 0x37, 0xa8, 0x65, 0x48, 0xc9, 0x2c, 0xcc, 0x35, 0x48, 0x08, 0x05, 0x98, 0x7c,
                0xb7, 0x0b, 0xe1, 0x7b
            ]
        );

        let out = pbkdf2_hmac(digest::Algorithm::Sha256, b"password", b"salt", 2, 32).unwrap();
        assert_eq!(
            *out,
            [
                0xae, 0x4d, 0x0c, 0x95, 0xaf, 0x6b, 0x46, 0xd3, 0x2d, 0x0a, 0xdf, 0xf9, 0x28, 0xf0,
                0x6d, 0xd0, 0x2a, 0x30, 0x3f, 0x8e, 0xf3, 0xc2, 0x51, 0xdf, 0xd6, 0xe2, 0xd8, 0x5a,
                0x95, 0x47, 0x4c, 0x43
            ]
        );
    }

    #[test]
    fn test_zero_iterations_rejected() {
        assert!(pbkdf2_hmac(digest::Algorithm::Sha256, b"password", b"salt", 0, 32).is_err());
    }
}
