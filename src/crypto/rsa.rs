use std::mem;

#[cfg(feature = "aws-lc")]
use aws_lc_sys::{
    BIGNUM, RSA, RSA_PKCS1_OAEP_PADDING, RSA_PKCS1_PADDING, RSA_PKCS1_PSS_PADDING, RSA_free,
    RSA_get0_d, RSA_get0_dmp1, RSA_get0_dmq1, RSA_get0_e, RSA_get0_iqmp, RSA_get0_n, RSA_get0_p,
    RSA_get0_q, RSA_new, RSA_set0_crt_params, RSA_set0_factors, RSA_set0_key, RSA_up_ref,
};
#[cfg(all(feature = "boring", not(feature = "aws-lc")))]
use boring_sys::{
    BIGNUM, RSA, RSA_PKCS1_OAEP_PADDING, RSA_PKCS1_PADDING, RSA_PKCS1_PSS_PADDING, RSA_free,
    RSA_get0_d, RSA_get0_dmp1, RSA_get0_dmq1, RSA_get0_e, RSA_get0_iqmp, RSA_get0_n, RSA_get0_p,
    RSA_get0_q, RSA_new, RSA_set0_crt_params, RSA_set0_factors, RSA_set0_key, RSA_up_ref,
};

use crate::error::JoseError;

use super::bn::BigNum;

pub(crate) struct Rsa(*mut RSA);

impl Rsa {
    pub(crate) fn new() -> Self {
        let ptr = unsafe { RSA_new() };
        assert!(!ptr.is_null());
        Self(ptr)
    }

    pub(crate) fn from_ptr(ptr: *mut RSA) -> Self {
        assert!(!ptr.is_null());
        Self(ptr)
    }

    pub(crate) fn as_mut_ptr(&mut self) -> *mut RSA {
        self.0
    }

    pub(crate) fn as_ptr(&self) -> *const RSA {
        self.0
    }

    pub(super) fn manually_drop(self) -> mem::ManuallyDrop<Self> {
        mem::ManuallyDrop::new(self)
    }

    pub(crate) fn set_key(
        &mut self,
        mut n: BigNum,
        mut e: BigNum,
        mut d: Option<BigNum>,
    ) -> Result<(), JoseError> {
        let d_ptr = d
            .as_mut()
            .map_or(std::ptr::null_mut(), super::bn::BigNum::as_mut_ptr);
        // RSA_set0_key() takes ownership of the pointers on success only. It
        // fails only when a required component (n, and e or d) is missing.
        let res = unsafe { RSA_set0_key(self.as_mut_ptr(), n.as_mut_ptr(), e.as_mut_ptr(), d_ptr) };
        if res != 1 {
            // n/e/d are still owned by the caller's BigNum wrappers; they drop
            // normally here, freeing the BIGNUMs.
            return Err(JoseError::InvalidKey(
                "RSA key is missing a required modulus or exponent".into(),
            ));
        }
        n.manually_drop();
        e.manually_drop();
        if let Some(d) = d {
            d.manually_drop();
        }
        Ok(())
    }

    pub(crate) fn set_factors(&mut self, mut p: BigNum, mut q: BigNum) -> Result<(), JoseError> {
        // RSA_set0_factors() takes ownership of the pointers on success only. It
        // fails only when a factor (p or q) is missing.
        let res = unsafe { RSA_set0_factors(self.as_mut_ptr(), p.as_mut_ptr(), q.as_mut_ptr()) };
        if res != 1 {
            return Err(JoseError::InvalidKey(
                "RSA key is missing a prime factor (p or q)".into(),
            ));
        }
        p.manually_drop();
        q.manually_drop();
        Ok(())
    }

    pub(crate) fn set_crt_params(
        &mut self,
        mut dp: BigNum,
        mut dq: BigNum,
        mut qi: BigNum,
    ) -> Result<(), JoseError> {
        // RSA_set0_crt_params() takes ownership of the pointers on success
        // only. It fails only when a CRT parameter (dp, dq, or qi) is missing.
        let res = unsafe {
            RSA_set0_crt_params(
                self.as_mut_ptr(),
                dp.as_mut_ptr(),
                dq.as_mut_ptr(),
                qi.as_mut_ptr(),
            )
        };
        if res != 1 {
            return Err(JoseError::InvalidKey(
                "RSA key is missing a CRT parameter (dp, dq, or qi)".into(),
            ));
        }
        dp.manually_drop();
        dq.manually_drop();
        qi.manually_drop();
        Ok(())
    }

    pub(crate) fn is_private(&self) -> bool {
        unsafe { !RSA_get0_d(self.as_ptr()).is_null() }
    }

    pub(crate) fn n(&self) -> Option<RsaParam> {
        RsaParam::new(unsafe { RSA_get0_n(self.as_ptr()) })
    }

    pub(crate) fn e(&self) -> Option<RsaParam> {
        RsaParam::new(unsafe { RSA_get0_e(self.as_ptr()) })
    }

    pub(crate) fn d(&self) -> Option<RsaParam> {
        RsaParam::new(unsafe { RSA_get0_d(self.as_ptr()) })
    }

    pub(crate) fn p(&self) -> Option<RsaParam> {
        RsaParam::new(unsafe { RSA_get0_p(self.as_ptr()) })
    }

    pub(crate) fn q(&self) -> Option<RsaParam> {
        RsaParam::new(unsafe { RSA_get0_q(self.as_ptr()) })
    }

    pub(crate) fn dp(&self) -> Option<RsaParam> {
        RsaParam::new(unsafe { RSA_get0_dmp1(self.as_ptr()) })
    }

    pub(crate) fn dq(&self) -> Option<RsaParam> {
        RsaParam::new(unsafe { RSA_get0_dmq1(self.as_ptr()) })
    }

    pub(crate) fn qi(&self) -> Option<RsaParam> {
        RsaParam::new(unsafe { RSA_get0_iqmp(self.as_ptr()) })
    }
}

/// A borrowed reference to an RSA BIGNUM parameter, valid for the lifetime of
/// the `Rsa` it was obtained from. Encodes directly to base64 without an
/// intermediate owned `BigNum`.
#[derive(Clone, Copy)]
pub(crate) struct RsaParam(*const BIGNUM);

impl RsaParam {
    fn new(ptr: *const BIGNUM) -> Option<Self> {
        (!ptr.is_null()).then_some(Self(ptr))
    }

    /// Returns the byte length of the big-endian representation.
    pub(crate) fn len_bytes(self) -> usize {
        BigNum::ptr_len_bytes(self.0)
    }

    /// Encodes to base64url in a single allocation.
    pub(crate) fn to_b64(self) -> Box<[u8]> {
        BigNum::ptr_to_b64(self.0)
    }
}

unsafe impl Send for Rsa {}
unsafe impl Sync for Rsa {}

impl Drop for Rsa {
    #[inline]
    fn drop(&mut self) {
        unsafe { RSA_free(self.as_mut_ptr()) };
    }
}

impl Clone for Rsa {
    fn clone(&self) -> Self {
        let ptr = self.0;
        assert_eq!(1, unsafe { RSA_up_ref(ptr) });
        Self(ptr)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RsaPadding {
    Pkcs1,
    Pkcs1Pss,
    Pkcs1Oaep,
}

impl RsaPadding {
    fn to_id(self) -> i32 {
        match self {
            RsaPadding::Pkcs1 => RSA_PKCS1_PADDING,
            RsaPadding::Pkcs1Pss => RSA_PKCS1_PSS_PADDING,
            RsaPadding::Pkcs1Oaep => RSA_PKCS1_OAEP_PADDING,
        }
    }
}

impl TryFrom<i32> for RsaPadding {
    type Error = JoseError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            RSA_PKCS1_PADDING => Ok(RsaPadding::Pkcs1),
            RSA_PKCS1_PSS_PADDING => Ok(RsaPadding::Pkcs1Pss),
            RSA_PKCS1_OAEP_PADDING => Ok(RsaPadding::Pkcs1Oaep),
            _ => Err(JoseError::InvalidKey("invalid RSA padding type".into())),
        }
    }
}

impl From<RsaPadding> for i32 {
    fn from(value: RsaPadding) -> Self {
        value.to_id()
    }
}

impl From<&RsaPadding> for i32 {
    fn from(value: &RsaPadding) -> Self {
        value.to_id()
    }
}
