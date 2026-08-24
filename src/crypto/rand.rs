#[cfg(feature = "aws-lc")]
use aws_lc_sys::RAND_bytes;
#[cfg(all(feature = "boring", not(feature = "aws-lc")))]
use boring_sys::RAND_bytes;

use super::mem;

pub(crate) fn rand_bytes_buf(mut dst: impl AsMut<[u8]>) {
    let buf = dst.as_mut();
    if buf.is_empty() {
        return;
    }

    let result = unsafe { RAND_bytes(buf.as_mut_ptr(), buf.len()) };

    // RAND_bytes returns 1 on success, 0 or -1 on failure
    assert!(result == 1, "RAND_bytes failed");
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
