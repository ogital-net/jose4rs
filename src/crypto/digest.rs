use std::mem::MaybeUninit;

#[cfg(feature = "aws-lc")]
use aws_lc_sys::{
    EVP_DigestFinal_ex, EVP_DigestInit_ex, EVP_DigestUpdate, EVP_MD, EVP_MD_CTX,
    EVP_MD_CTX_cleanup, EVP_MD_CTX_copy, EVP_MD_CTX_init, EVP_MD_CTX_md, EVP_MD_CTX_size, EVP_sha1,
    EVP_sha256, EVP_sha384, EVP_sha512, SHA1, SHA256, SHA384, SHA512,
};

#[cfg(all(feature = "boring", not(feature = "aws-lc")))]
use boring_sys::{
    EVP_DigestFinal_ex, EVP_DigestInit_ex, EVP_DigestUpdate, EVP_MD, EVP_MD_CTX,
    EVP_MD_CTX_cleanup, EVP_MD_CTX_copy, EVP_MD_CTX_init, EVP_MD_CTX_md, EVP_MD_CTX_size, EVP_sha1,
    EVP_sha256, EVP_sha384, EVP_sha512, SHA1, SHA256, SHA384, SHA512,
};

use crate::crypto::mem;

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
    /// Equivalent to `EVP_MD_size()` but without the FFI call.
    #[inline]
    pub(crate) fn output_len(&self) -> usize {
        match self {
            Algorithm::Sha1 => 160 / 8,
            Algorithm::Sha256 => 256 / 8,
            Algorithm::Sha384 => 384 / 8,
            Algorithm::Sha512 => 512 / 8,
        }
    }
}

pub(crate) const MAX_OUTPUT_LEN: usize = 512 / 8;

/// Hashes `data` into the caller-supplied `buf`, returning the written slice.
pub(crate) fn digest_buf(md: Algorithm, data: impl AsRef<[u8]>, buf: &mut [u8]) -> &[u8] {
    let data = data.as_ref();
    let len = md.output_len();
    debug_assert!(buf.len() >= len);
    let out = unsafe {
        match md {
            Algorithm::Sha1 => SHA1(data.as_ptr(), data.len(), buf.as_mut_ptr()),
            Algorithm::Sha256 => SHA256(data.as_ptr(), data.len(), buf.as_mut_ptr()),
            Algorithm::Sha384 => SHA384(data.as_ptr(), data.len(), buf.as_mut_ptr()),
            Algorithm::Sha512 => SHA512(data.as_ptr(), data.len(), buf.as_mut_ptr()),
        }
    };
    assert!(!out.is_null(), "SHA one-shot digest failed");
    &buf[..len]
}

pub(crate) fn digest(md: Algorithm, data: impl AsRef<[u8]>) -> Box<[u8]> {
    let mut buf = [0u8; MAX_OUTPUT_LEN];
    let hash = digest_buf(md, data, &mut buf);
    hash.into()
}

#[cfg(test)]
mod tests {
    use crate::crypto::rand;

    use super::*;

    #[cfg(feature = "aws-lc")]
    use aws_lc_sys::EVP_MD_size;

    #[cfg(all(feature = "boring", not(feature = "aws-lc")))]
    use boring_sys::EVP_MD_size;

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
    fn test_digest_one_shot() {
        let data = rand::rand_bytes(64);

        for alg in [
            Algorithm::Sha1,
            Algorithm::Sha256,
            Algorithm::Sha384,
            Algorithm::Sha512,
        ] {
            let res = digest(alg, &data);
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
            assert_eq!(*res, *digest(alg, &data));
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
                assert_eq!(*res, *digest(alg, &data));
            }
        }
    }

    /// Known-answer tests pinning exact digest bytes so a future refactor that
    /// swaps or breaks an algorithm dispatch is caught immediately. Vectors are
    /// the FIPS 180-4 examples: the empty string and "abc".
    #[test]
    fn test_known_answers() {
        // (Algorithm, hex of SHA-"" digest, hex of SHA-"abc" digest)
        let vectors: &[(Algorithm, &str, &str)] = &[
            (
                Algorithm::Sha1,
                "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                "a9993e364706816aba3e25717850c26c9cd0d89d",
            ),
            (
                Algorithm::Sha256,
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (
                Algorithm::Sha384,
                "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
                "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
            ),
            (
                Algorithm::Sha512,
                "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
            ),
        ];

        for (alg, empty_hex, abc_hex) in vectors {
            assert_eq!(hex(&digest(*alg, b"")), *empty_hex, "{alg:?} empty");
            assert_eq!(hex(&digest(*alg, b"abc")), *abc_hex, "{alg:?} abc");
        }
    }

    /// Lowercase hex encoding, to keep the test self-contained (no extra dep).
    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write;
        bytes
            .iter()
            .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
                let _ = write!(s, "{b:02x}");
                s
            })
    }
}
