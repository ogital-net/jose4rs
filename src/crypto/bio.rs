use std::{marker::PhantomData, mem::MaybeUninit, ptr};

#[cfg(feature = "aws-lc")]
use aws_lc_sys::{
    BIO, BIO_free_all, BIO_mem_contents, BIO_new, BIO_new_mem_buf, BIO_s_mem, PEM_read_bio_PUBKEY,
    PEM_read_bio_PrivateKey,
};

#[cfg(all(feature = "boring", not(feature = "aws-lc")))]
use boring_sys::{
    BIO, BIO_free_all, BIO_mem_contents, BIO_new, BIO_new_mem_buf, BIO_s_mem, PEM_read_bio_PUBKEY,
    PEM_read_bio_PrivateKey,
};

use super::{EvpPkey, X509Cert};

pub(crate) struct Bio<'a>(ptr::NonNull<BIO>, PhantomData<&'a [u8]>);

impl Bio<'static> {
    pub(crate) fn new() -> Self {
        unsafe {
            let ptr = BIO_new(BIO_s_mem());
            assert!(!ptr.is_null(), "BIO_new() failed");
            Self(ptr::NonNull::new_unchecked(ptr), PhantomData)
        }
    }
}

impl<'a> Bio<'a> {
    /// Creates a read-only BIO that borrows the slice without copying it.
    pub(crate) fn from_slice(slice: &'a [u8]) -> Self {
        let ptr = unsafe { BIO_new_mem_buf(slice.as_ptr().cast(), slice.len() as isize) };
        Self(
            ptr::NonNull::new(ptr).expect("BIO_new_mem_buf() failed"),
            PhantomData,
        )
    }

    pub(crate) fn as_ptr(&self) -> *const BIO {
        self.0.as_ptr()
    }

    pub(crate) fn as_mut_ptr(&mut self) -> *mut BIO {
        self.0.as_ptr()
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        unsafe {
            let mut ptr = MaybeUninit::<*const u8>::uninit();
            let mut len: usize = 0;
            assert!(
                1 == BIO_mem_contents(self.as_ptr(), ptr.as_mut_ptr(), &raw mut len),
                "BIO_mem_contents() failed"
            );
            let ptr = ptr.assume_init();
            if len == 0 || ptr.is_null() {
                return &[];
            }
            std::slice::from_raw_parts(ptr, len)
        }
    }

    pub(crate) fn read_pem_private_key(mut self) -> Option<EvpPkey> {
        let ptr = unsafe {
            PEM_read_bio_PrivateKey(
                self.as_mut_ptr(),
                std::ptr::null_mut(),
                None,
                std::ptr::null_mut(),
            )
        };
        if ptr.is_null() {
            None
        } else {
            Some(unsafe { EvpPkey::from_raw_ptr(ptr) })
        }
    }

    pub(crate) fn read_pem_public_key(mut self) -> Option<EvpPkey> {
        let ptr = unsafe {
            PEM_read_bio_PUBKEY(
                self.as_mut_ptr(),
                std::ptr::null_mut(),
                None,
                std::ptr::null_mut(),
            )
        };
        if ptr.is_null() {
            None
        } else {
            Some(unsafe { EvpPkey::from_raw_ptr(ptr) })
        }
    }

    pub(crate) fn read_pem_x509(mut self) -> Option<X509Cert> {
        X509Cert::from_pem_bio(&mut self)
    }
}

impl Drop for Bio<'_> {
    fn drop(&mut self) {
        unsafe {
            BIO_free_all(self.as_mut_ptr());
        }
    }
}
