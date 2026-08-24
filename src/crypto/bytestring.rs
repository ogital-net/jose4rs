use std::{mem::MaybeUninit, ptr};

#[cfg(feature = "aws-lc")]
use aws_lc_sys::{CBB_cleanup, CBB_finish, CBB_init, OPENSSL_free, CBB};

#[cfg(all(feature = "boring", not(feature = "aws-lc")))]
use boring_sys::{CBB_cleanup, CBB_finish, CBB_init, OPENSSL_free, CBB};

pub(super) struct Cbb(CBB);

impl Cbb {
    pub(super) fn with_capacity(capacity: usize) -> Self {
        let mut cbb = MaybeUninit::<CBB>::uninit();
        unsafe {
            assert!(
                1 == CBB_init(cbb.as_mut_ptr(), capacity),
                "CBB_init() failed"
            );
            Self(cbb.assume_init())
        }
    }

    pub(super) fn as_mut_ptr(&mut self) -> *mut CBB {
        &mut self.0
    }

    pub(super) fn into_boxed_slice(mut self) -> Box<[u8]> {
        let mut out_data = ptr::null_mut::<u8>();
        let mut out_len: usize = 0;

        unsafe {
            assert!(
                1 == CBB_finish(self.as_mut_ptr(), &mut out_data, &mut out_len),
                "CBB_finish() failed"
            );
            let s = std::slice::from_raw_parts(out_data, out_len);
            let b = Box::from(s);
            OPENSSL_free(out_data.cast());
            b
        }
    }
}

impl Drop for Cbb {
    fn drop(&mut self) {
        unsafe {
            CBB_cleanup(self.as_mut_ptr());
        }
    }
}
