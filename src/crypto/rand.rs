use super::mem;

#[cfg(target_os = "linux")]
#[link(name = "c")]
unsafe extern "C" {
    unsafe fn getrandom(buf: *mut u8, buflen: usize, flags: core::ffi::c_uint) -> isize;
}

#[cfg(target_os = "linux")]
pub(crate) fn rand_bytes_buf(mut dst: impl AsMut<[u8]>) {
    let dst = dst.as_mut();
    let len = dst.len();

    unsafe {
        let res = getrandom(dst.as_mut_ptr(), len, 0);
        // this call is infallible on a modern linux kernel, but just in case something changes.
        if res < 0 {
            panic!(std::io::Error::last_os_error());
        } else if res != len as isize {
            panic!("Unable to generate {} random bytes", len);
        }
    }
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    unsafe fn CCRandomGenerateBytes(bytes: *mut u8, count: usize) -> i32;
}

#[cfg(target_os = "macos")]
pub(crate) fn rand_bytes_buf(mut dst: impl AsMut<[u8]>) {
    let dst = dst.as_mut();

    unsafe {
        assert!(
            0 == CCRandomGenerateBytes(dst.as_mut_ptr(), dst.len()),
            "Unable to generate random bytes"
        );
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn rand_bytes_buf(mut dst: impl AsMut<[u8]>) {
    use aws_lc_sys::RAND_bytes;

    let dst = dst.as_mut();

    unsafe {
        assert!(
            1 == RAND_bytes(dst.as_mut_ptr(), dst.len()),
            "Unable to generate random bytes"
        );
    }
}

pub(crate) fn rand_bytes(len: usize) -> Box<[u8]> {
    let mut b = mem::new_boxed_slice(len);
    rand_bytes_buf(&mut b);
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rand_bytes_buf() {
        let mut out = vec![0u8; 16];
        rand_bytes_buf(&mut out);
        assert!(!out.starts_with(&[0, 0, 0, 0]));
        assert_eq!(out.len(), 16);
    }

    #[test]
    fn test_rand_bytes() {
        let bytes = rand_bytes(16);
        assert!(!bytes.starts_with(&[0, 0, 0, 0]));
        assert_eq!(bytes.len(), 16);
    }
}
