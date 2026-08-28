use std::{ffi::CStr, fmt, mem, ptr};

#[cfg(feature = "aws-lc")]
use aws_lc_sys::{
    BIGNUM, BN_bin2bn, BN_bn2bin, BN_bn2bin_padded, BN_bn2dec, BN_bn2hex, BN_cmp, BN_cmp_word,
    BN_dup, BN_free, BN_is_odd, BN_is_word, BN_is_zero, BN_new, BN_num_bits, BN_num_bytes,
    OPENSSL_free,
};

#[cfg(all(feature = "boring", not(feature = "aws-lc")))]
use boring_sys::{
    BIGNUM, BN_bin2bn, BN_bn2bin, BN_bn2bin_padded, BN_bn2dec, BN_bn2hex, BN_cmp, BN_cmp_word,
    BN_dup, BN_free, BN_is_odd, BN_is_word, BN_is_zero, BN_new, BN_num_bits, BN_num_bytes,
    OPENSSL_free,
};

use crate::{base64, crypto::mem::new_boxed_slice, error::JoseError};

pub(crate) struct BigNum(ptr::NonNull<BIGNUM>);

impl BigNum {
    pub(crate) fn new() -> Self {
        let ptr = unsafe { BN_new() };
        assert!(!ptr.is_null());
        unsafe { Self(ptr::NonNull::new_unchecked(ptr)) }
    }

    /// Creates an owned copy from a const (borrowed) BIGNUM pointer.
    pub(crate) fn dup(ptr: *const BIGNUM) -> Self {
        assert!(!ptr.is_null());
        let dup = unsafe { BN_dup(ptr) };
        assert!(!dup.is_null());
        unsafe { Self(ptr::NonNull::new_unchecked(dup)) }
    }

    pub(crate) fn from_b64<T: AsRef<[u8]>>(b64: T) -> Result<Self, JoseError> {
        let bytes = base64::url_decode(b64)?;
        Ok(bytes.as_ref().into())
    }

    /// Returns the base64url encoding of this value left-padded with zero
    /// octets to `len` bytes, as required for JWK EC coordinates.
    pub(crate) fn to_b64_padded(&self, len: usize) -> Box<[u8]> {
        let ptr = self.as_ptr();
        let mut buffer = new_boxed_slice(len);
        assert!(
            1 == unsafe { BN_bn2bin_padded(buffer.as_mut_ptr(), len, ptr) },
            "BN_bn2bin_padded() failed"
        );
        base64::url_encode(&buffer)
    }

    pub(crate) fn as_mut_ptr(&mut self) -> *mut BIGNUM {
        self.0.as_ptr()
    }

    pub(crate) fn as_ptr(&self) -> *const BIGNUM {
        self.0.as_ptr()
    }

    /// Encodes a borrowed BIGNUM pointer directly to base64url in a single
    /// allocation, without creating an owning `BigNum` or intermediate buffer.
    pub(crate) fn ptr_to_b64(ptr: *const BIGNUM) -> Box<[u8]> {
        assert!(!ptr.is_null());
        let bytes = Self::bn_to_be_bytes(ptr);
        base64::url_encode(&bytes)
    }

    /// Returns the byte length of a borrowed BIGNUM pointer without allocating.
    pub(crate) fn ptr_len_bytes(ptr: *const BIGNUM) -> usize {
        assert!(!ptr.is_null());
        unsafe { BN_num_bytes(ptr) as usize }
    }

    fn bn_to_be_bytes(ptr: *const BIGNUM) -> Box<[u8]> {
        unsafe {
            let bn_bytes = BN_num_bytes(ptr) as usize;
            let mut buffer = Vec::with_capacity(bn_bytes);
            let out_bytes = BN_bn2bin(ptr, buffer.as_mut_ptr());
            debug_assert_eq!(out_bytes, bn_bytes);
            buffer.set_len(out_bytes);
            buffer.into_boxed_slice()
        }
    }

    pub(crate) fn to_hex(&self) -> String {
        let ptr = self.as_ptr();
        unsafe {
            let hex_ptr = BN_bn2hex(ptr);
            assert!(!hex_ptr.is_null(), "Failed to convert BIGNUM to hex");

            let bytes = CStr::from_ptr(hex_ptr).to_bytes().to_vec();
            OPENSSL_free(hex_ptr.cast());
            String::from_utf8_unchecked(bytes)
        }
    }

    pub(crate) fn to_dec(&self) -> String {
        let ptr = self.as_ptr();
        unsafe {
            let dec_ptr = BN_bn2dec(ptr);
            assert!(!dec_ptr.is_null(), "Failed to convert BIGNUM to decimal");

            let cstr = CStr::from_ptr(dec_ptr);
            let res = cstr.to_string_lossy().into_owned();
            OPENSSL_free(dec_ptr.cast());
            res
        }
    }

    pub(super) fn manually_drop(self) -> mem::ManuallyDrop<Self> {
        mem::ManuallyDrop::new(self)
    }

    /// Returns true if this value is zero.
    pub(crate) fn is_zero(&self) -> bool {
        unsafe { BN_is_zero(self.as_ptr()) == 1 }
    }

    /// Returns true if this value is odd.
    pub(crate) fn is_odd(&self) -> bool {
        unsafe { BN_is_odd(self.as_ptr()) == 1 }
    }

    /// Returns the number of significant bits (0 for zero).
    pub(crate) fn num_bits(&self) -> usize {
        unsafe { BN_num_bits(self.as_ptr()) as usize }
    }

    #[cfg(test)]
    pub(super) fn concat_padded(&self, other: &Self, padded_len: usize) -> Box<[u8]> {
        Self::concat_padded_raw(self.as_ptr(), other.as_ptr(), padded_len)
    }

    /// Concatenates two borrowed BIGNUM pointers into a fixed-width buffer.
    pub(super) fn concat_padded_raw(
        r: *const BIGNUM,
        s: *const BIGNUM,
        padded_len: usize,
    ) -> Box<[u8]> {
        unsafe {
            let mut buffer = new_boxed_slice(padded_len * 2);
            assert!(
                1 == BN_bn2bin_padded(buffer.as_mut_ptr(), padded_len, r),
                "BN_bn2bin_padded() failed"
            );
            assert!(
                1 == BN_bn2bin_padded(buffer.as_mut_ptr().add(padded_len), padded_len, s),
                "BN_bn2bin_padded() failed"
            );
            buffer
        }
    }
}

impl PartialEq for BigNum {
    fn eq(&self, other: &Self) -> bool {
        let ptr1 = self.as_ptr();
        let ptr2 = other.as_ptr();
        unsafe { BN_cmp(ptr1, ptr2) == 0 }
    }
}

impl Eq for BigNum {}

impl PartialOrd for BigNum {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        let ptr1 = self.as_ptr();
        let ptr2 = other.as_ptr();
        unsafe {
            let cmp_result = BN_cmp(ptr1, ptr2);
            match cmp_result.cmp(&0) {
                std::cmp::Ordering::Less => Some(std::cmp::Ordering::Less),
                std::cmp::Ordering::Greater => Some(std::cmp::Ordering::Greater),
                std::cmp::Ordering::Equal => Some(std::cmp::Ordering::Equal),
            }
        }
    }
}

impl PartialEq<u64> for BigNum {
    fn eq(&self, other: &u64) -> bool {
        unsafe { BN_is_word(self.as_ptr(), *other) == 1 }
    }
}

impl PartialOrd<u64> for BigNum {
    fn partial_cmp(&self, other: &u64) -> Option<std::cmp::Ordering> {
        unsafe {
            let cmp_result = BN_cmp_word(self.as_ptr(), *other);
            match cmp_result.cmp(&0) {
                std::cmp::Ordering::Less => Some(std::cmp::Ordering::Less),
                std::cmp::Ordering::Greater => Some(std::cmp::Ordering::Greater),
                std::cmp::Ordering::Equal => Some(std::cmp::Ordering::Equal),
            }
        }
    }
}

impl PartialEq<u32> for BigNum {
    fn eq(&self, other: &u32) -> bool {
        unsafe { BN_is_word(self.as_ptr(), (*other).into()) == 1 }
    }
}

impl PartialOrd<u32> for BigNum {
    fn partial_cmp(&self, other: &u32) -> Option<std::cmp::Ordering> {
        unsafe {
            let cmp_result = BN_cmp_word(self.as_ptr(), (*other).into());
            match cmp_result.cmp(&0) {
                std::cmp::Ordering::Less => Some(std::cmp::Ordering::Less),
                std::cmp::Ordering::Greater => Some(std::cmp::Ordering::Greater),
                std::cmp::Ordering::Equal => Some(std::cmp::Ordering::Equal),
            }
        }
    }
}

impl Drop for BigNum {
    #[inline]
    fn drop(&mut self) {
        unsafe { BN_free(self.as_mut_ptr()) };
    }
}

impl Clone for BigNum {
    fn clone(&self) -> Self {
        let ptr = unsafe { BN_dup(self.as_ptr()) };
        assert!(!ptr.is_null());
        unsafe { Self(ptr::NonNull::new_unchecked(ptr)) }
    }
}

impl fmt::Display for BigNum {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_dec())
    }
}

impl fmt::Debug for BigNum {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl From<&[u8]> for BigNum {
    fn from(value: &[u8]) -> Self {
        let ptr = unsafe { BN_bin2bn(value.as_ptr(), value.len(), ptr::null_mut()) };
        assert!(!ptr.is_null());
        unsafe { Self(ptr::NonNull::new_unchecked(ptr)) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fmt() {
        let bn = BigNum::from("A".as_bytes());
        assert_eq!("65".to_string(), format!("{bn}"));

        let bn = BigNum::from("AA".as_bytes());
        assert_eq!("16705".to_string(), format!("{bn}"));

        let bn = BigNum::from("AB".as_bytes());
        assert_eq!("16706".to_string(), format!("{bn}"));

        let bn = BigNum::from("Hello world!".as_bytes());
        assert_eq!("22405534230753963835153736737".to_string(), format!("{bn}"));
        assert_eq!(
            "48656C6C6F20776F726C6421".to_string(),
            format!("{bn:?}").to_uppercase()
        );
    }

    #[test]
    fn test_to_hex() {
        let bn = BigNum::from("Hello world!".as_bytes());
        assert_eq!("48656C6C6F20776F726C6421", bn.to_hex().to_uppercase());
    }

    #[test]
    fn test_to_dec() {
        let bn = BigNum::from("Hello world!".as_bytes());
        assert_eq!("22405534230753963835153736737", bn.to_dec());
    }

    #[test]
    fn test_manually_drop() {
        let ptr = {
            let mut bn = BigNum::from("Hello world!".as_bytes());
            let ptr = bn.as_mut_ptr();
            bn.manually_drop();
            ptr
        };
        unsafe {
            BN_free(ptr); // Ensure the pointer is freed
        }
    }

    #[test]
    fn test_clone() {
        let mut bn = BigNum::from("Hello world!".as_bytes());
        let mut cloned_bn = bn.clone();
        assert_eq!(bn.to_hex(), cloned_bn.to_hex());
        assert_ne!(
            bn.as_mut_ptr(),
            cloned_bn.as_mut_ptr(),
            "Cloned BIGNUM should have a different pointer"
        );
    }

    #[test]
    fn test_partial_eq_and_ord() {
        let bn1 = BigNum::from(10u64.to_be_bytes().as_slice());
        let bn2 = BigNum::from(10u64.to_be_bytes().as_slice());
        let bn3 = BigNum::from(20u64.to_be_bytes().as_slice());

        assert_eq!(bn1, bn2);
        assert_ne!(bn1, bn3);

        assert!(bn1 < bn3);
        assert!(bn3 > bn1);
        assert!(bn1 <= bn2);
        assert!(bn2 >= bn1);
    }

    #[test]
    fn test_partial_eq_u64() {
        let bn = BigNum::from(10u64.to_be_bytes().as_slice());
        assert_eq!(bn, 10u64);
        assert_ne!(bn, 20u64);
    }

    #[test]
    fn test_partial_ord_u64() {
        let bn1 = BigNum::from(10u64.to_be_bytes().as_slice());
        let bn2 = BigNum::from(20u64.to_be_bytes().as_slice());

        assert!(bn1 < 20u64);
        assert!(bn2 > 10u64);
        assert_eq!(bn1.partial_cmp(&10u64), Some(std::cmp::Ordering::Equal));
        assert_eq!(bn2.partial_cmp(&15u64), Some(std::cmp::Ordering::Greater));
    }

    #[test]
    fn test_partial_eq_u32() {
        let bn = BigNum::from(10u32.to_be_bytes().as_slice());
        assert_eq!(bn, 10u32);
        assert_ne!(bn, 20u32);
    }

    #[test]
    fn test_partial_ord_u32() {
        let bn1 = BigNum::from(10u32.to_be_bytes().as_slice());
        let bn2 = BigNum::from(20u32.to_be_bytes().as_slice());

        assert!(bn1 < 20u32);
        assert!(bn2 > 10u32);
        assert_eq!(bn1.partial_cmp(&10u32), Some(std::cmp::Ordering::Equal));
        assert_eq!(bn2.partial_cmp(&15u32), Some(std::cmp::Ordering::Greater));
    }

    #[test]
    fn test_from_b64() {
        let bn = BigNum::from_b64("AQAB").unwrap();
        assert_eq!(bn, 65537u32);
    }

    #[test]
    fn test_concat_padded() {
        let bn1 = BigNum::from("Hello".as_bytes());
        let bn2 = BigNum::from("World".as_bytes());
        let concatenated = bn1.concat_padded(&bn2, 7);
        assert_eq!(concatenated.len(), 14);
        assert_eq!(concatenated.as_ref(), b"\0\0Hello\0\0World");
    }
}
