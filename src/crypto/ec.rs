use std::{mem, ptr};

#[cfg(feature = "aws-lc")]
use aws_lc_sys::{
    ECDSA_SIG_free, ECDSA_SIG_get0_r, ECDSA_SIG_get0_s, ECDSA_SIG_new, ECDSA_SIG_set0,
    ECDSA_do_sign, ECDSA_do_verify, EC_KEY_check_key, EC_KEY_free, EC_KEY_get0_group,
    EC_KEY_get0_private_key, EC_KEY_get0_public_key, EC_KEY_new_by_curve_name,
    EC_KEY_set_private_key, EC_KEY_set_public_key, EC_KEY_up_ref, EC_POINT_free,
    EC_POINT_get_affine_coordinates, EC_POINT_new, EC_POINT_set_affine_coordinates,
    NID_X9_62_prime256v1, NID_secp256k1, NID_secp384r1, NID_secp521r1, EC_GROUP, EC_KEY, EC_POINT,
};

#[cfg(all(feature = "boring", not(feature = "aws-lc")))]
use boring_sys::{
    ECDSA_SIG_free, ECDSA_SIG_get0_r, ECDSA_SIG_get0_s, ECDSA_SIG_new, ECDSA_SIG_set0,
    ECDSA_do_sign, ECDSA_do_verify, EC_KEY_check_key, EC_KEY_free, EC_KEY_get0_group,
    EC_KEY_get0_private_key, EC_KEY_get0_public_key, EC_KEY_new_by_curve_name,
    EC_KEY_set_private_key, EC_KEY_set_public_key, EC_KEY_up_ref, EC_POINT_free,
    EC_POINT_get_affine_coordinates, EC_POINT_new, EC_POINT_set_affine_coordinates,
    NID_X9_62_prime256v1, NID_secp384r1, NID_secp521r1, EC_GROUP, EC_KEY, EC_POINT,
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
                "unsupported curve: {value}"
            ))),
        }
    }
}

impl Curve {
    /// Returns the JOSE curve name (e.g. "P-256").
    pub(crate) fn jose_name(&self) -> &'static str {
        match self {
            Curve::P256 => "P-256",
            Curve::P384 => "P-384",
            Curve::P521 => "P-521",
            #[cfg(not(feature = "boring"))]
            Curve::Secp256k1 => "secp256k1",
        }
    }

    /// Returns the byte length of a field element (affine coordinate) for this
    /// curve, used for fixed-width JWK coordinate encoding.
    pub(crate) fn coordinate_len(&self) -> usize {
        match self {
            Curve::P256 => 32,
            Curve::P384 => 48,
            Curve::P521 => 66,
            #[cfg(not(feature = "boring"))]
            Curve::Secp256k1 => 32,
        }
    }

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

    fn as_ptr(&self) -> *const EC_GROUP {
        self.0.as_ptr()
    }

    pub(super) fn manually_drop(self) -> mem::ManuallyDrop<Self> {
        mem::ManuallyDrop::new(self)
    }
}

struct EcPoint(*mut EC_POINT);

impl EcPoint {
    fn new_pub(group: &EcGroup, mut x: BigNum, mut y: BigNum) -> Result<Self, JoseError> {
        let ptr = unsafe { EC_POINT_new(group.as_ptr()) };
        assert!(!ptr.is_null());

        let res = unsafe {
            EC_POINT_set_affine_coordinates(
                group.as_ptr(),
                ptr,
                x.as_mut_ptr(),
                y.as_mut_ptr(),
                std::ptr::null_mut(),
            )
        };
        if res != 1 {
            unsafe { EC_POINT_free(ptr) };
            return Err(JoseError::invalid_key(
                "EC public point is not on the curve",
            ));
        }
        Ok(Self(ptr))
    }

    fn as_ptr(&self) -> *const EC_POINT {
        self.0
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

    pub(crate) fn set_pub_key(&mut self, x: BigNum, y: BigNum) -> Result<(), JoseError> {
        let group = self.get_group();
        let point = EcPoint::new_pub(&group, x, y)?;
        // EC_KEY_set_public_key() rejects the point at infinity and points on a
        // different curve group; off-curve points were already rejected above.
        let res = unsafe { EC_KEY_set_public_key(self.as_mut_ptr(), point.as_ptr()) };
        if res != 1 {
            return Err(JoseError::invalid_key(
                "invalid EC public key (point at infinity or curve mismatch)",
            ));
        }
        Ok(())
    }

    pub(crate) fn set_priv_key(&mut self, mut d: BigNum) -> Result<(), JoseError> {
        let res = unsafe { EC_KEY_set_private_key(self.as_mut_ptr(), d.as_mut_ptr()) };
        if res != 1 {
            return Err(JoseError::invalid_key("invalid EC private key"));
        }
        Ok(())
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

    /// Returns the affine coordinates (x, y) of the public key point.
    pub(crate) fn pub_key_affine(&self) -> (BigNum, BigNum) {
        let group = self.get_group();
        let point = unsafe { EC_KEY_get0_public_key(self.as_ptr()) };
        assert!(!point.is_null());

        let mut x = BigNum::new();
        let mut y = BigNum::new();
        assert!(
            1 == unsafe {
                EC_POINT_get_affine_coordinates(
                    group.as_ptr(),
                    point,
                    x.as_mut_ptr(),
                    y.as_mut_ptr(),
                    ptr::null_mut(),
                )
            },
            "EC_POINT_get_affine_coordinates() failed"
        );
        (x, y)
    }

    /// Returns the private key scalar, if present.
    pub(crate) fn priv_key(&self) -> Option<BigNum> {
        let d = unsafe { EC_KEY_get0_private_key(self.as_ptr()) };
        if d.is_null() {
            None
        } else {
            Some(BigNum::dup(d))
        }
    }

    pub(crate) fn sign_concatenated(
        &self,
        message: &[u8],
        digest_alg: digest::Algorithm,
    ) -> Box<[u8]> {
        let mut hash_buf = [0u8; digest::MAX_OUTPUT_LEN];
        let hash = digest::digest_buf(digest_alg, message, &mut hash_buf);

        let padded_len = match digest_alg {
            digest::Algorithm::Sha256 => 32,
            digest::Algorithm::Sha384 => 48,
            digest::Algorithm::Sha512 => 66,
            _ => unreachable!(),
        };

        unsafe {
            let ecdsa_sig = ECDSA_do_sign(hash.as_ptr(), hash.len(), self.as_ptr());
            assert!(!ecdsa_sig.is_null(), "ECDSA_do_sign() failed");
            let r = ECDSA_SIG_get0_r(ecdsa_sig);
            let s = ECDSA_SIG_get0_s(ecdsa_sig);
            let sig = BigNum::concat_padded_raw(r, s, padded_len);
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

        let mut hash_buf = [0u8; digest::MAX_OUTPUT_LEN];
        let hash = digest::digest_buf(digest_alg, message, &mut hash_buf);

        let mut r_bn = BigNum::from(r);
        let mut s_bn = BigNum::from(s);

        unsafe {
            let ecdsa_sig = ECDSA_SIG_new();
            assert!(!ecdsa_sig.is_null());
            // ECDSA_SIG_set0 takes ownership of r and s on success
            assert_eq!(
                1,
                ECDSA_SIG_set0(ecdsa_sig, r_bn.as_mut_ptr(), s_bn.as_mut_ptr())
            );
            r_bn.manually_drop();
            s_bn.manually_drop();

            let res = ECDSA_do_verify(hash.as_ptr(), hash.len(), ecdsa_sig, self.as_ptr());
            ECDSA_SIG_free(ecdsa_sig);
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
        assert_eq!(1, unsafe { EC_KEY_up_ref(ptr) });
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
