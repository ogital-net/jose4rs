use std::{
    alloc,
    ops::{Deref, DerefMut},
};

#[cfg(feature = "aws-lc")]
use aws_lc_sys::{CRYPTO_memcmp, OPENSSL_cleanse};
#[cfg(all(feature = "boring", not(feature = "aws-lc")))]
use boring_sys::{CRYPTO_memcmp, OPENSSL_cleanse};

pub(crate) fn crypto_memcmp(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    unsafe { CRYPTO_memcmp(a.as_ptr() as *const _, b.as_ptr() as *const _, a.len()) == 0 }
}

pub(crate) fn cleanse(data: &mut [u8]) {
    unsafe {
        OPENSSL_cleanse(data.as_mut_ptr() as *mut _, data.len());
    }
}

#[derive(Clone)]
pub(crate) struct Zeroizing<T: AsMut<[u8]>>(T);

impl<T: AsMut<[u8]>> Zeroizing<T> {
    pub(crate) fn new(value: T) -> Self {
        Self(value)
    }

    pub(crate) fn as_inner_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T> AsRef<[u8]> for Zeroizing<T>
where
    T: AsMut<[u8]> + AsRef<[u8]>,
{
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<T> Deref for Zeroizing<T>
where
    T: AsMut<[u8]> + AsRef<[u8]>,
{
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

impl<T> DerefMut for Zeroizing<T>
where
    T: AsMut<[u8]> + AsRef<[u8]>,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.as_mut()
    }
}

impl<T: AsMut<[u8]>> Drop for Zeroizing<T> {
    fn drop(&mut self) {
        cleanse(self.0.as_mut());
    }
}

pub(crate) struct ZeroizingVec(Vec<u8>);

impl ZeroizingVec {
    pub(crate) fn new(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl Deref for ZeroizingVec {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for ZeroizingVec {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for ZeroizingVec {
    fn drop(&mut self) {
        // SAFETY: `as_mut_ptr()` addresses an allocation of `capacity()` bytes.
        // OPENSSL_cleanse writes each byte without requiring it to be initialized.
        unsafe {
            OPENSSL_cleanse(self.0.as_mut_ptr().cast(), self.0.capacity());
        }
    }
}

pub(crate) fn new_boxed_slice(len: usize) -> Box<[u8]> {
    debug_assert!(len > 0);
    unsafe {
        let layout = alloc::Layout::from_size_align_unchecked(len, 1);
        let ptr = alloc::alloc(layout);
        if ptr.is_null() {
            alloc::handle_alloc_error(layout);
        }
        Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zeroizing_cleanses_on_drop() {
        let mut bytes = [0x5a; 32];
        {
            let _secret = Zeroizing::new(bytes.as_mut_slice());
        }
        assert_eq!(bytes, [0; 32]);
    }
}
