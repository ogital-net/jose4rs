#[cfg(feature = "aws-lc")]
use aws_lc_sys::HMAC;
#[cfg(feature = "boring")]
use boring_sys::HMAC;

use crate::error::JoseError;

use super::digest;

pub(crate) fn hmac(
    md: digest::Algorithm,
    key: impl AsRef<[u8]>,
    data: impl AsRef<[u8]>,
) -> Result<Box<[u8]>, JoseError> {
    let mut out = Vec::new();
    hmac_append(md, key, data, &mut out)?;

    Ok(out.into_boxed_slice())
}

pub(crate) fn hmac_append(
    md: digest::Algorithm,
    key: impl AsRef<[u8]>,
    data: impl AsRef<[u8]>,
    dst: &mut Vec<u8>,
) -> Result<(), JoseError> {
    const KEY_MAX: usize = 1024;

    let key = key.as_ref();
    let data = data.as_ref();

    if key.len() < md.output_len() / 2 {
        return Err(JoseError::invalid_key("key too small"));
    }

    if key.len() > KEY_MAX {
        return Err(JoseError::invalid_key("key too large"));
    }

    dst.reserve_exact(md.output_len());
    let dst_len = dst.len();

    let mut out_len: std::ffi::c_uint = 0;

    let ptr = unsafe {
        HMAC(
            md.as_ptr(),
            key.as_ptr().cast(),
            key.len(),
            data.as_ptr(),
            data.len(),
            dst.as_mut_ptr().add(dst_len),
            &mut out_len,
        )
    };
    assert!(!ptr.is_null(), "HMAC() failed");
    debug_assert!(out_len > 0);
    unsafe { dst.set_len(dst_len + out_len as usize) };

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::crypto::rand;

    use super::*;

    #[test]
    fn test_hmac_append() {
        let data = rand::rand_bytes(64);

        for alg in [
            digest::Algorithm::Sha1,
            digest::Algorithm::Sha256,
            digest::Algorithm::Sha384,
            digest::Algorithm::Sha512,
        ] {
            let mut out = vec![0u8; 4];
            let key = rand::rand_bytes(alg.output_len());
            hmac_append(alg, key, &data, &mut out).unwrap();
            assert_eq!(out.len(), 4 + &alg.output_len());
            assert!(out.starts_with(&[0, 0, 0, 0]));
        }
    }

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
