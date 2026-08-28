#[cfg(feature = "aws-lc")]
use aws_lc_sys::{
    HMAC, HMAC_CTX, HMAC_CTX_free, HMAC_CTX_new, HMAC_Final, HMAC_Init_ex, HMAC_Update,
};
#[cfg(all(feature = "boring", not(feature = "aws-lc")))]
use boring_sys::{
    HMAC, HMAC_CTX, HMAC_CTX_free, HMAC_CTX_new, HMAC_Final, HMAC_Init_ex, HMAC_Update,
};

use crate::error::JoseError;

use super::digest;

pub(crate) fn hmac_buf(
    md: digest::Algorithm,
    key: impl AsRef<[u8]>,
    data: impl AsRef<[u8]>,
    buf: &mut [u8],
) -> Result<&[u8], JoseError> {
    let key = key.as_ref();
    let data = data.as_ref();
    let len = md.output_len();
    debug_assert!(buf.len() >= len);

    if key.len() < len {
        return Err(JoseError::InvalidKey("key too small".into()));
    }
    if key.len() > 1024 {
        return Err(JoseError::InvalidKey("key too large".into()));
    }

    let mut out_len: std::ffi::c_uint = 0;
    let ptr = unsafe {
        HMAC(
            md.as_ptr(),
            key.as_ptr().cast(),
            key.len(),
            data.as_ptr(),
            data.len(),
            buf.as_mut_ptr(),
            &mut out_len,
        )
    };
    assert!(!ptr.is_null(), "HMAC() failed");
    Ok(&buf[..out_len as usize])
}

pub(crate) fn hmac(
    md: digest::Algorithm,
    key: impl AsRef<[u8]>,
    data: impl AsRef<[u8]>,
) -> Result<Box<[u8]>, JoseError> {
    let mut buf = [0u8; digest::MAX_OUTPUT_LEN];
    let hash = hmac_buf(md, key, data, &mut buf)?;
    Ok(hash.into())
}

/// A streaming HMAC context that avoids concatenating the input into a single
/// buffer. Useful for `MACing` several disjoint byte slices (e.g. the JWE
/// AES-CBC-HMAC input `AAD || IV || ciphertext || AL`).
pub(crate) struct HmacCtx(std::ptr::NonNull<HMAC_CTX>);

impl HmacCtx {
    pub(crate) fn init(md: digest::Algorithm, key: &[u8]) -> Result<Self, JoseError> {
        const KEY_MAX: usize = 1024;
        if key.len() < md.output_len() / 2 {
            return Err(JoseError::InvalidKey("key too small".into()));
        }
        if key.len() > KEY_MAX {
            return Err(JoseError::InvalidKey("key too large".into()));
        }

        let ptr = unsafe { HMAC_CTX_new() };
        assert!(!ptr.is_null(), "HMAC_CTX_new() failed");
        let ctx = unsafe { Self(std::ptr::NonNull::new_unchecked(ptr)) };

        let res = unsafe {
            HMAC_Init_ex(
                ctx.0.as_ptr(),
                key.as_ptr().cast(),
                key.len(),
                md.as_ptr(),
                std::ptr::null_mut(),
            )
        };
        assert!(res == 1, "HMAC_Init_ex() failed");
        Ok(ctx)
    }

    pub(crate) fn update(&mut self, data: &[u8]) {
        let res = unsafe { HMAC_Update(self.0.as_ptr(), data.as_ptr(), data.len()) };
        assert!(res == 1, "HMAC_Update() failed");
    }

    pub(crate) fn finish_buf(self, buf: &mut [u8]) -> &[u8] {
        let mut out_len: std::ffi::c_uint = 0;
        let res = unsafe { HMAC_Final(self.0.as_ptr(), buf.as_mut_ptr(), &mut out_len) };
        assert!(res == 1, "HMAC_Final() failed");
        &buf[..out_len as usize]
    }
}

impl Drop for HmacCtx {
    fn drop(&mut self) {
        unsafe { HMAC_CTX_free(self.0.as_ptr()) }
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::rand;

    use super::*;

    #[test]
    fn test_hmac() {
        let data = rand::rand_bytes(64);

        for alg in [
            digest::Algorithm::Sha1,
            digest::Algorithm::Sha256,
            digest::Algorithm::Sha384,
            digest::Algorithm::Sha512,
        ] {
            let key = rand::rand_bytes(alg.output_len());
            let res = hmac(alg, key, &data).unwrap();
            assert_eq!(res.len(), alg.output_len());
            assert!(!res.starts_with(&[0, 0, 0, 0]));
        }
    }
}
