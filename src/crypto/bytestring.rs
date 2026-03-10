use std::{mem::MaybeUninit, ptr};

#[cfg(feature = "aws-lc")]
use aws_lc_sys::{CBB_cleanup, CBB_finish, CBB_init, CBS_init, CBS_len, OPENSSL_free, CBB, CBS};

#[cfg(feature = "boring")]
use boring_sys::{CBB_cleanup, CBB_finish, CBB_init, CBS_init, CBS_len, OPENSSL_free, CBB, CBS};

pub(super) struct Cbs(CBS);

impl Cbs {
    pub fn init(data: &[u8]) -> Self {
        let mut cbs = MaybeUninit::<CBS>::uninit();
        unsafe {
            CBS_init(cbs.as_mut_ptr(), data.as_ptr(), data.len());
            Self(cbs.assume_init())
        }
    }

    pub(super) fn as_ptr(&self) -> *const CBS {
        &self.0
    }

    pub(super) fn as_mut_ptr(&mut self) -> *mut CBS {
        &mut self.0
    }

    pub(super) fn len(&self) -> usize {
        unsafe { CBS_len(self.as_ptr()) }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

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

    pub(super) fn as_ptr(&self) -> *const CBB {
        &self.0
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
