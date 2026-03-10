use std::{mem, ptr};

#[cfg(feature = "aws-lc")]
use aws_lc_sys::{
    ECDSA_SIG_free, ECDSA_do_sign, ECDSA_do_verify, EC_GROUP_get_curve_name, EC_KEY_check_key,
    EC_KEY_free, EC_KEY_get0_group, EC_KEY_get0_private_key, EC_KEY_new_by_curve_name,
    EC_KEY_set_private_key, EC_KEY_set_public_key, EC_KEY_up_ref, EC_POINT_free, EC_POINT_new,
    EC_POINT_set_affine_coordinates, NID_X9_62_prime256v1, NID_secp256k1, NID_secp384r1,
    NID_secp521r1, ECDSA_SIG, EC_GROUP, EC_KEY, EC_POINT,
};

#[cfg(feature = "boring")]
use boring_sys::{
    ECDSA_SIG_free, ECDSA_do_sign, ECDSA_do_verify, EC_GROUP_get_curve_name, EC_KEY_check_key,
    EC_KEY_free, EC_KEY_get0_group, EC_KEY_get0_private_key, EC_KEY_new_by_curve_name,
    EC_KEY_set_private_key, EC_KEY_set_public_key, EC_KEY_up_ref, EC_POINT_free, EC_POINT_new,
    EC_POINT_set_affine_coordinates, NID_X9_62_prime256v1, NID_secp384r1, NID_secp521r1, ECDSA_SIG,
    EC_GROUP, EC_KEY, EC_POINT,
};

use crate::error::JoseError;

use super::{digest, BigNum};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Curve {
    P256,
    P384,
    P521,
    #[cfg(not(feature = "boring"))]
    Secp256k1,
}

impl From<Curve> for i32 {
    fn from(curve: Curve) -> Self {
        match curve {
            Curve::P256 => NID_X9_62_prime256v1,
            Curve::P384 => NID_secp384r1,
            Curve::P521 => NID_secp521r1,
            #[cfg(not(feature = "boring"))]
            Curve::Secp256k1 => NID_secp256k1,
        }
    }
}

impl TryFrom<&str> for Curve {
    type Error = JoseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "P-256" => Ok(Curve::P256),
            "P-384" => Ok(Curve::P384),
            "P-521" => Ok(Curve::P521),
            #[cfg(not(feature = "boring"))]
            "secp256k1" => Ok(Curve::Secp256k1),
            _ => Err(JoseError::invalid_key(format!(
                "unsupported curve: {}",
                value
            ))),
        }
    }
}

impl Curve {
    #[allow(non_upper_case_globals)]
    pub(super) fn from_nid(nid: std::ffi::c_int) -> Curve {
        match nid {
            NID_X9_62_prime256v1 => Curve::P256,
            NID_secp384r1 => Curve::P384,
            NID_secp521r1 => Curve::P521,
            #[cfg(not(feature = "boring"))]
            NID_secp256k1 => Curve::Secp256k1,
            _ => unreachable!("invalid NID value for curve"),
        }
    }
}

pub(crate) struct EcGroup(ptr::NonNull<EC_GROUP>);

impl EcGroup {
    pub(super) fn from_ptr(ptr: *mut EC_GROUP) -> Self {
        assert!(!ptr.is_null());
        unsafe { Self(ptr::NonNull::new_unchecked(ptr)) }
    }

    pub(crate) fn get_curve(&self) -> Curve {
        let nid = unsafe { EC_GROUP_get_curve_name(self.as_ptr()) };
        Curve::from_nid(nid)
    }

    fn as_ptr(&self) -> *const EC_GROUP {
        self.0.as_ptr()
    }

    fn as_mut(&mut self) -> *mut EC_GROUP {
        self.0.as_ptr()
    }

    pub(super) fn manually_drop(self) -> mem::ManuallyDrop<Self> {
        mem::ManuallyDrop::new(self)
    }
}

struct EcPoint(*mut EC_POINT);

impl EcPoint {
    fn new_pub(group: &EcGroup, mut x: BigNum, mut y: BigNum) -> Self {
        let ptr = unsafe { EC_POINT_new(group.as_ptr()) };
        assert!(!ptr.is_null());

        assert!(
            1 == unsafe {
                EC_POINT_set_affine_coordinates(
                    group.as_ptr(),
                    ptr,
                    x.as_mut_ptr(),
                    y.as_mut_ptr(),
                    std::ptr::null_mut(),
                )
            },
            "EC_POINT_set_affine_coordinates() failed"
        );
        Self(ptr)
    }

    fn as_mut_ptr(&mut self) -> *mut EC_POINT {
        self.0
    }

    fn as_ptr(&self) -> *const EC_POINT {
        self.0
    }

    pub(super) fn manually_drop(self) -> mem::ManuallyDrop<Self> {
        mem::ManuallyDrop::new(self)
    }
}

impl Drop for EcPoint {
    fn drop(&mut self) {
        unsafe { EC_POINT_free(self.0) }
    }
}

pub(crate) struct EcKey(ptr::NonNull<EC_KEY>);

impl EcKey {
    pub(crate) fn new(curve: Curve) -> Self {
        let ptr = unsafe { EC_KEY_new_by_curve_name(curve.into()) };
        assert!(!ptr.is_null(), "EC_KEY_new_by_curve_name() failed");
        unsafe { Self(ptr::NonNull::new_unchecked(ptr)) }
    }

    pub(super) fn from_ptr(ptr: *mut EC_KEY) -> Self {
        assert!(!ptr.is_null());
        unsafe { Self(ptr::NonNull::new_unchecked(ptr)) }
    }

    pub(crate) fn as_mut_ptr(&mut self) -> *mut EC_KEY {
        self.0.as_ptr()
    }

    pub(crate) fn as_ptr(&self) -> *const EC_KEY {
        self.0.as_ptr()
    }

    pub(super) fn manually_drop(self) -> mem::ManuallyDrop<Self> {
        mem::ManuallyDrop::new(self)
    }

    fn get_group(&self) -> mem::ManuallyDrop<EcGroup> {
        let ptr = unsafe { EC_KEY_get0_group(self.as_ptr()) };
        assert!(!ptr.is_null());
        EcGroup::from_ptr(ptr as *const _ as *mut EC_GROUP).manually_drop()
    }

    pub(crate) fn set_pub_key(&mut self, x: BigNum, y: BigNum) {
        let group = self.get_group();
        let point = EcPoint::new_pub(&group, x, y);
        assert!(
            1 == unsafe { EC_KEY_set_public_key(self.as_mut_ptr(), point.as_ptr()) },
            "EC_KEY_set_public_key() failed"
        );
    }

    pub(crate) fn set_priv_key(&mut self, mut d: BigNum) {
        assert!(
            1 == unsafe { EC_KEY_set_private_key(self.as_mut_ptr(), d.as_mut_ptr()) },
            "EC_KEY_set_private_key() failed"
        );
    }

    pub(crate) fn check_key(&self) -> Result<(), JoseError> {
        let res = unsafe { EC_KEY_check_key(self.as_ptr()) };
        if res == 1 {
            Ok(())
        } else {
            Err(JoseError::invalid_key("invalid EC key"))
        }
    }

    pub(crate) fn is_private(&self) -> bool {
        unsafe { !EC_KEY_get0_private_key(self.as_ptr()).is_null() }
    }

    pub(crate) fn sign_concatenated(
        &self,
        message: &[u8],
        digest_alg: digest::Algorithm,
    ) -> Box<[u8]> {
        let hash = digest::digest(digest_alg, message).unwrap();
        let hash = hash.as_ref();

        let padded_len = match digest_alg {
            digest::Algorithm::Sha256 => 32,
            digest::Algorithm::Sha384 => 48,
            digest::Algorithm::Sha512 => 66,
            _ => unreachable!(),
        };

        unsafe {
            let ecdsa_sig = ECDSA_do_sign(hash.as_ptr(), hash.len(), self.as_ptr());
            assert!(!ecdsa_sig.is_null(), "ECDSA_do_sign() failed");
            // ECDSA_SIG_free() frees the bignum pointers
            let r = BigNum::from_ptr((*ecdsa_sig).r).manually_drop();
            let s = BigNum::from_ptr((*ecdsa_sig).s).manually_drop();
            let sig = r.concat_padded(&s, padded_len);
            ECDSA_SIG_free(ecdsa_sig);
            sig
        }
    }

    pub(crate) fn verify_concatenated(
        &self,
        message: &[u8],
        digest_alg: digest::Algorithm,
        signature: &[u8],
    ) -> bool {
        let expected_len = match digest_alg {
            digest::Algorithm::Sha256 => 64,
            digest::Algorithm::Sha384 => 96,
            digest::Algorithm::Sha512 => 132,
            _ => return false,
        };
        if signature.len() != expected_len {
            return false;
        }
        let (r, s) = signature.split_at(expected_len / 2);

        let hash = digest::digest(digest_alg, message).unwrap();
        let hash = hash.as_ref();

        let mut r_bn = BigNum::from(r);
        let mut s_bn = BigNum::from(s);

        unsafe {
            let ecdsa_sig = ECDSA_SIG {
                r: r_bn.as_mut_ptr(),
                s: s_bn.as_mut_ptr(),
            };

            let res = ECDSA_do_verify(hash.as_ptr(), hash.len(), &ecdsa_sig, self.as_ptr());
            res == 1
        }
    }
}

unsafe impl Send for EcKey {}
unsafe impl Sync for EcKey {}

impl Drop for EcKey {
    fn drop(&mut self) {
        unsafe { EC_KEY_free(self.as_mut_ptr()) }
    }
}

impl Clone for EcKey {
    fn clone(&self) -> Self {
        let ptr = self.0.as_ptr();
        assert!(1 == unsafe { EC_KEY_up_ref(ptr) });
        unsafe { Self(ptr::NonNull::new_unchecked(ptr)) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ec_key_manually_drop() {
        let ptr = {
            let mut key = EcKey::new(Curve::P256);
            let ptr = key.as_mut_ptr();
            key.manually_drop();
            ptr
        };
        unsafe { EC_KEY_free(ptr) };
    }
}
