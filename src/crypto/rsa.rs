use std::mem;

#[cfg(feature = "aws-lc")]
use aws_lc_sys::{
    RSA_free, RSA_get0_d, RSA_new, RSA_set0_crt_params, RSA_set0_factors, RSA_set0_key, RSA_up_ref,
    RSA, RSA_PKCS1_OAEP_PADDING, RSA_PKCS1_PADDING, RSA_PKCS1_PSS_PADDING,
};
#[cfg(feature = "boring")]
use boring_sys::{
    RSA_free, RSA_get0_d, RSA_new, RSA_set0_crt_params, RSA_set0_factors, RSA_set0_key, RSA_up_ref,
    RSA, RSA_PKCS1_OAEP_PADDING, RSA_PKCS1_PADDING, RSA_PKCS1_PSS_PADDING,
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

    pub(crate) fn set_key(&mut self, mut n: BigNum, mut e: BigNum, mut d: Option<BigNum>) {
        let d_ptr = d
            .as_mut()
            .map(|d| d.as_mut_ptr())
            .unwrap_or(std::ptr::null_mut());
        // RSA_set0_key() takes ownership of the pointers on success
        let res = unsafe { RSA_set0_key(self.as_mut_ptr(), n.as_mut_ptr(), e.as_mut_ptr(), d_ptr) };
        assert!(res == 1, "RSA_set0_key() failed");
        n.manually_drop();
        e.manually_drop();
        if let Some(d) = d {
            d.manually_drop();
        }
    }

    pub(crate) fn set_factors(&mut self, mut p: BigNum, mut q: BigNum) {
        // RSA_set0_factors() takes ownership of the pointers on success
        let res = unsafe { RSA_set0_factors(self.as_mut_ptr(), p.as_mut_ptr(), q.as_mut_ptr()) };
        assert!(res == 1, "RSA_set0_factors() failed");
        p.manually_drop();
        q.manually_drop();
    }

    pub(crate) fn set_crt_params(&mut self, mut dp: BigNum, mut dq: BigNum, mut qi: BigNum) {
        // RSA_set0_crt_params() takes ownership of the pointers on success
        let res = unsafe {
            RSA_set0_crt_params(
                self.as_mut_ptr(),
                dp.as_mut_ptr(),
                dq.as_mut_ptr(),
                qi.as_mut_ptr(),
            )
        };
        assert!(res == 1, "RSA_set0_crt_params() failed");
        dp.manually_drop();
        dq.manually_drop();
        qi.manually_drop();
    }

    pub(crate) fn is_private(&self) -> bool {
        unsafe { !RSA_get0_d(self.as_ptr()).is_null() }
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
        assert!(1 == unsafe { RSA_up_ref(ptr) });
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
            _ => Err(JoseError::General("invalid RSA padding type".to_string())),
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
