use std::mem::MaybeUninit;

#[cfg(feature = "aws-lc")]
use aws_lc_sys::{
    EVP_Digest, EVP_DigestFinal_ex, EVP_DigestInit_ex, EVP_DigestUpdate, EVP_MD_CTX_cleanup,
    EVP_MD_CTX_copy, EVP_MD_CTX_init, EVP_MD_CTX_md, EVP_MD_CTX_size, EVP_sha1, EVP_sha256,
    EVP_sha384, EVP_sha512, EVP_MD, EVP_MD_CTX,
};

#[cfg(feature = "boring")]
use boring_sys::{
    EVP_Digest, EVP_DigestFinal_ex, EVP_DigestInit_ex, EVP_DigestUpdate, EVP_MD_CTX_cleanup,
    EVP_MD_CTX_copy, EVP_MD_CTX_init, EVP_MD_CTX_md, EVP_MD_CTX_size, EVP_sha1, EVP_sha256,
    EVP_sha384, EVP_sha512, EVP_MD, EVP_MD_CTX,
};

use crate::{crypto::mem, error::JoseError};

pub(super) struct EvpMdCtx(EVP_MD_CTX);

impl EvpMdCtx {
    pub(super) fn init() -> Self {
        let mut ctx = MaybeUninit::<EVP_MD_CTX>::uninit();
        unsafe {
            EVP_MD_CTX_init(ctx.as_mut_ptr());
            Self(ctx.assume_init())
        }
    }

    pub(super) fn as_mut_ptr(&mut self) -> *mut EVP_MD_CTX {
        &mut self.0
    }

    pub(super) fn as_ptr(&self) -> *const EVP_MD_CTX {
        &self.0
    }
}

unsafe impl Send for EvpMdCtx {}
unsafe impl Sync for EvpMdCtx {}

impl Clone for EvpMdCtx {
    fn clone(&self) -> Self {
        let mut ctx = MaybeUninit::<EVP_MD_CTX>::uninit();
        unsafe {
            // The first parameter of `EVP_MD_CTX_copy` should not be initialized.
            // https://github.com/aws/aws-lc/blob/98ccf4a316401112943bed604562102ad52efac6/include/openssl/digest.h#L280
            assert!(
                1 == EVP_MD_CTX_copy(ctx.as_mut_ptr(), self.as_ptr()),
                "EVP_MD_CTX_copy() failed"
            );
            Self(ctx.assume_init())
        }
    }
}

impl Drop for EvpMdCtx {
    fn drop(&mut self) {
        unsafe {
            EVP_MD_CTX_cleanup(self.as_mut_ptr());
        }
    }
}

pub(crate) struct EvpMd {
    ctx: EvpMdCtx,
}

impl EvpMd {
    pub fn init(alg: Algorithm) -> Self {
        let mut ctx = EvpMdCtx::init();
        unsafe {
            assert!(
                1 == EVP_DigestInit_ex(ctx.as_mut_ptr(), alg.as_ptr(), std::ptr::null_mut()),
                "EVP_DigestInit_ex() failed"
            );
        }

        Self { ctx }
    }

    pub fn update(&mut self, data: impl AsRef<[u8]>) {
        let data = data.as_ref();
        if data.is_empty() {
            return;
        }
        unsafe {
            assert!(
                1 == EVP_DigestUpdate(self.ctx.as_mut_ptr(), data.as_ptr().cast(), data.len()),
                "EVP_DigestUpdate() failed"
            );
        }
    }

    pub fn finish(&mut self) -> Box<[u8]> {
        let mut buf = mem::new_boxed_slice(self.output_len());
        unsafe {
            assert!(
                1 == EVP_DigestFinal_ex(
                    self.ctx.as_mut_ptr(),
                    buf.as_mut_ptr(),
                    std::ptr::null_mut()
                ),
                "EVP_DigestFinal_ex() failed"
            );
            assert!(
                1 == EVP_DigestInit_ex(
                    self.ctx.as_mut_ptr(),
                    EVP_MD_CTX_md(self.ctx.as_ptr()),
                    std::ptr::null_mut()
                ),
                "EVP_DigestInit_ex() failed"
            );
        }
        buf
    }

    #[inline]
    pub fn output_len(&self) -> usize {
        unsafe { EVP_MD_CTX_size(self.ctx.as_ptr()) }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl Algorithm {
    pub(super) fn as_ptr(&self) -> *const EVP_MD {
        match self {
            Algorithm::Sha1 => unsafe { EVP_sha1() },
            Algorithm::Sha256 => unsafe { EVP_sha256() },
            Algorithm::Sha384 => unsafe { EVP_sha384() },
            Algorithm::Sha512 => unsafe { EVP_sha512() },
        }
    }

    /// Returns the size of the digest algorithm in bytes.
    /// Equivalent to EVP_MD_size() but without the FFI call.
    #[inline]
    pub(crate) fn output_len(&self) -> usize {
        match self {
            Algorithm::Sha1 => 160 / 8,
            Algorithm::Sha256 => 256 / 8,
            Algorithm::Sha384 => 384 / 8,
            Algorithm::Sha512 => 512 / 8,
        }
    }

    /// Returns the native block-size of the digest algorithm in bytes.
    /// Equivalent to EVP_MD_block_size() but without the FFI call.
    #[inline]
    pub(crate) fn block_len(&self) -> usize {
        match self {
            Algorithm::Sha1 => 512 / 8,
            Algorithm::Sha256 => 512 / 8,
            Algorithm::Sha384 => 1024 / 8,
            Algorithm::Sha512 => 1024 / 8,
        }
    }
}

pub(crate) fn digest(md: Algorithm, data: impl AsRef<[u8]>) -> Result<Box<[u8]>, JoseError> {
    let mut out = Vec::new();
    digest_append(md, data, &mut out)?;
    Ok(out.into_boxed_slice())
}

pub(crate) fn digest_append(
    md: Algorithm,
    data: impl AsRef<[u8]>,
    dst: &mut Vec<u8>,
) -> Result<(), JoseError> {
    let data = data.as_ref();

    dst.reserve_exact(md.output_len());
    let dst_len = dst.len();

    let mut out_len: std::ffi::c_uint = 0;

    assert!(
        1 == unsafe {
            EVP_Digest(
                data.as_ptr().cast(),
                data.len(),
                dst.as_mut_ptr().add(dst_len),
                &mut out_len,
                md.as_ptr(),
                std::ptr::null_mut(),
            )
        },
        "EVP_Digest() failed"
    );

    debug_assert!(out_len == md.output_len() as u32);
    unsafe { dst.set_len(dst_len + out_len as usize) };

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::crypto::rand;

    use super::*;

    #[cfg(feature = "aws-lc")]
    use aws_lc_sys::{EVP_MD_block_size, EVP_MD_size};

    #[cfg(feature = "boring")]
    use boring_sys::{EVP_MD_block_size, EVP_MD_size};

    #[test]
    fn test_output_len() {
        for alg in [
            Algorithm::Sha1,
            Algorithm::Sha256,
            Algorithm::Sha384,
            Algorithm::Sha512,
        ] {
            let ossl_size = unsafe { EVP_MD_size(alg.as_ptr()) };
            assert_eq!(alg.output_len(), ossl_size);
        }
    }

    #[test]
    fn test_block_len() {
        for alg in [
            Algorithm::Sha1,
            Algorithm::Sha256,
            Algorithm::Sha384,
            Algorithm::Sha512,
        ] {
            let ossl_size = unsafe { EVP_MD_block_size(alg.as_ptr()) };
            assert_eq!(alg.block_len(), ossl_size);
        }
    }

    #[test]
    fn test_digest_append() {
        let data = rand::rand_bytes(64);

        for alg in [
            Algorithm::Sha1,
            Algorithm::Sha256,
            Algorithm::Sha384,
            Algorithm::Sha512,
        ] {
            let mut out = vec![0u8; 4];
            digest_append(alg, &data, &mut out).unwrap();
            assert_eq!(out.len(), 4 + &alg.output_len());
            assert!(out.starts_with(&[0, 0, 0, 0]));
        }
    }

    #[test]
    fn test_digest_one_shot() {
        let data = rand::rand_bytes(64);

        for alg in [
            Algorithm::Sha1,
            Algorithm::Sha256,
            Algorithm::Sha384,
            Algorithm::Sha512,
        ] {
            let res = digest(alg, &data).unwrap();
            assert_eq!(res.len(), alg.output_len());
            assert!(!res.starts_with(&[0, 0, 0, 0]));
        }
    }

    #[test]
    fn test_evp_md() {
        let data = rand::rand_bytes(64);

        for alg in [
            Algorithm::Sha1,
            Algorithm::Sha256,
            Algorithm::Sha384,
            Algorithm::Sha512,
        ] {
            let mut md = EvpMd::init(alg);
            md.update(&data);
            let res = md.finish();
            assert_eq!(*res, *digest(alg, &data).unwrap());
        }

        for alg in [
            Algorithm::Sha1,
            Algorithm::Sha256,
            Algorithm::Sha384,
            Algorithm::Sha512,
        ] {
            let mut md = EvpMd::init(alg);
            for _ in 1..100 {
                md.update(&data);
                let res = md.finish();
                assert_eq!(*res, *digest(alg, &data).unwrap());
            }
        }
    }
}
