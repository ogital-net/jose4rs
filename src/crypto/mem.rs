use std::alloc;

#[cfg(feature = "aws-lc")]
use aws_lc_sys::{CRYPTO_memcmp, OPENSSL_cleanse};
#[cfg(feature = "boring")]
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

pub(crate) fn new_boxed_slice(len: usize) -> Box<[u8]> {
    unsafe {
        let layout = alloc::Layout::from_size_align_unchecked(len, 1);
        let ptr = alloc::alloc(layout);
        if ptr.is_null() {
            alloc::handle_alloc_error(layout);
        }
        Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, len))
    }
}
