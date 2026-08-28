use std::mem::MaybeUninit;

#[cfg(feature = "aws-lc")]
use aws_lc_sys::{AES_KEY, AES_set_decrypt_key, AES_set_encrypt_key, AES_unwrap_key, AES_wrap_key};
#[cfg(all(feature = "boring", not(feature = "aws-lc")))]
use boring_sys::{AES_KEY, AES_set_decrypt_key, AES_set_encrypt_key, AES_unwrap_key, AES_wrap_key};

use crate::{crypto::mem, error::JoseError};

struct AesKey(AES_KEY);

impl AesKey {
    fn as_ptr(&self) -> *const AES_KEY {
        &self.0
    }

    fn for_encryption(key: &[u8]) -> Self {
        let mut aes_key = MaybeUninit::<AES_KEY>::uninit();
        unsafe {
            assert!(
                0 == AES_set_encrypt_key(
                    key.as_ptr(),
                    (key.len() * 8) as ::std::os::raw::c_uint,
                    aes_key.as_mut_ptr()
                ),
                "AES_set_encrypt_key() failed"
            );
            Self(aes_key.assume_init())
        }
    }

    fn for_decryption(key: &[u8]) -> Self {
        let mut aes_key = MaybeUninit::<AES_KEY>::uninit();
        unsafe {
            assert!(
                0 == AES_set_decrypt_key(
                    key.as_ptr(),
                    (key.len() * 8) as ::std::os::raw::c_uint,
                    aes_key.as_mut_ptr()
                ),
                "AES_set_decrypt_key() failed"
            );
            Self(aes_key.assume_init())
        }
    }
}

pub(crate) fn wrap_key(
    aes_key: &[u8],
    iv: Option<&[u8]>,
    src: &[u8],
) -> Result<Box<[u8]>, JoseError> {
    let mut out = mem::new_boxed_slice(src.len() + 8);
    let written = wrap_key_buf(aes_key, iv, src, &mut out)?;
    debug_assert_eq!(written, out.len());
    Ok(out)
}

pub(crate) fn wrap_key_buf(
    aes_key: &[u8],
    iv: Option<&[u8]>,
    src: &[u8],
    dst: &mut [u8],
) -> Result<usize, JoseError> {
    assert!(src.len().is_multiple_of(8));
    assert!(dst.len() >= src.len() + 8);

    let aes_key = AesKey::for_encryption(aes_key);

    let len = unsafe {
        AES_wrap_key(
            aes_key.as_ptr(),
            iv.map_or(std::ptr::null(), <[u8]>::as_ptr),
            dst.as_mut_ptr(),
            src.as_ptr(),
            src.len(),
        ) as i32
    };
    if len <= 0 {
        return Err(JoseError::new("AES key wrap failed"));
    }
    Ok(len as usize)
}

pub(crate) fn unwrap_key(
    aes_key: &[u8],
    iv: Option<&[u8]>,
    src: &[u8],
) -> Result<Box<[u8]>, JoseError> {
    // RFC 3394: the wrapped key is at least one 8-byte block plus the 8-byte
    // integrity check value, and must be a multiple of 8 bytes. Validate the
    // length before allocating to avoid an underflow on `src.len() - 8`.
    if src.len() < 16 || !src.len().is_multiple_of(8) {
        return Err(JoseError::InvalidKey("invalid wrapped key length".into()));
    }
    let mut out = mem::new_boxed_slice(src.len() - 8);
    let written = unwrap_key_buf(aes_key, iv, src, &mut out)?;
    debug_assert_eq!(written, out.len());
    Ok(out)
}

pub(crate) fn unwrap_key_buf(
    aes_key: &[u8],
    iv: Option<&[u8]>,
    src: &[u8],
    dst: &mut [u8],
) -> Result<usize, JoseError> {
    assert!(src.len().is_multiple_of(8) && src.len() > 8);
    assert!(dst.len() >= src.len() - 8);

    let aes_key = AesKey::for_decryption(aes_key);
    let len = unsafe {
        AES_unwrap_key(
            aes_key.as_ptr(),
            iv.map_or(std::ptr::null(), <[u8]>::as_ptr),
            dst.as_mut_ptr(),
            src.as_ptr(),
            src.len(),
        ) as i32
    };
    if len <= 0 {
        return Err(JoseError::IntegrityError(
            "AES key unwrap failed (wrapped key integrity check failed)".into(),
        ));
    }
    Ok(len as usize)
}

#[cfg(test)]
mod tests {
    use crate::base64;

    use super::*;

    #[test]
    fn test_wrap_key() {
        let aes_key_b64 = "GawgguFyGrWKav7AX4VKUg";
        let aes_key = base64::url_decode(aes_key_b64).unwrap();
        let cek: [u8; 32] = [
            4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106, 206, 107, 124,
            212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156, 44, 207,
        ];
        let expected: [u8; 40] = [
            232, 160, 123, 211, 183, 76, 245, 132, 200, 128, 123, 75, 190, 216, 22, 67, 201, 138,
            193, 186, 9, 91, 122, 31, 246, 90, 28, 139, 57, 3, 76, 124, 193, 11, 98, 37, 173, 61,
            104, 57,
        ];
        let out = wrap_key(&aes_key, None, &cek).unwrap();
        assert_eq!(*out, expected);
    }

    #[test]
    fn test_unwrap_key() {
        let aes_key_b64 = "GawgguFyGrWKav7AX4VKUg";
        let aes_key = base64::url_decode(aes_key_b64).unwrap();
        let wrapped: [u8; 40] = [
            232, 160, 123, 211, 183, 76, 245, 132, 200, 128, 123, 75, 190, 216, 22, 67, 201, 138,
            193, 186, 9, 91, 122, 31, 246, 90, 28, 139, 57, 3, 76, 124, 193, 11, 98, 37, 173, 61,
            104, 57,
        ];
        let expected: [u8; 32] = [
            4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106, 206, 107, 124,
            212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156, 44, 207,
        ];
        let out = unwrap_key(&aes_key, None, &wrapped).unwrap();
        assert_eq!(*out, expected);
    }

    /// Regression: short or misaligned wrapped-key input must return an error,
    /// not underflow the `src.len() - 8` allocation (attacker-controlled via
    /// the JWE encrypted-key segment).
    #[test]
    fn test_unwrap_key_rejects_short_input() {
        let aes_key = base64::url_decode("GawgguFyGrWKav7AX4VKUg").unwrap();
        for bad in [&[][..], &[0u8; 8][..], &[0u8; 15][..], &[0u8; 17][..]] {
            assert!(
                unwrap_key(&aes_key, None, bad).is_err(),
                "len {}",
                bad.len()
            );
        }
    }
}
