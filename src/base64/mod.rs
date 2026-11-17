use std::fmt;

#[cfg(feature = "base64")]
mod base64;
#[cfg(feature = "base64")]
pub(crate) use base64::*;

#[cfg(feature = "base64-simd")]
mod base64_simd;
#[cfg(feature = "base64-simd")]
pub(crate) use base64_simd::*;

pub struct Error(());

impl fmt::Debug for Error {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        <str as fmt::Debug>::fmt("Base64Error", f)
    }
}

impl fmt::Display for Error {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        <str as fmt::Display>::fmt("Base64Error", f)
    }
}

impl std::error::Error for Error {}

#[inline]
pub(crate) fn url_encode_size(src_len: usize) -> usize {
    ((src_len << 2) | 2) / 3
}

#[inline]
pub(crate) fn url_decode_size(src_len: usize) -> usize {
    (src_len * 3) >> 2
}

/// Test-only standard (padded, `+/`) base64 decode used by fixture decoding in
/// unit tests. Not part of the production API -- JOSE uses URL-safe base64, and
/// PEM goes through the crypto backend's BIO functions.
#[cfg(test)]
pub(crate) fn standard_decode(src: impl AsRef<[u8]>) -> Result<Box<[u8]>, Error> {
    standard_decode_impl(src)
}

/// Test-only PEM (base64 with newlines) decode for X.509 fixtures.
#[cfg(test)]
pub(crate) fn pem_decode(src: impl AsRef<[u8]>) -> Result<Box<[u8]>, Error> {
    let src = src.as_ref();
    let mut compact = Vec::with_capacity(src.len());
    for &b in src {
        if !matches!(b, b'\n' | b'\r' | b' ' | b'\t') {
            compact.push(b);
        }
    }
    standard_decode_impl(compact)
}

#[cfg(test)]
mod tests {
    use crate::crypto::rand::rand_bytes;

    use super::*;

    #[test]
    fn test_url_encode_size() {
        for i in 4..64 {
            let bytes = rand_bytes(i);
            let encode_size = url_encode_size(bytes.len());
            let encoded = url_encode(bytes);
            assert_eq!(encoded.len(), encode_size);
        }
    }

    #[test]
    fn test_url_decode_size() {
        for i in 4..64 {
            let bytes = rand_bytes(i);
            let encoded = url_encode(bytes);

            let decode_size = url_decode_size(encoded.len());
            let decoded = url_decode(encoded).unwrap();
            assert_eq!(decoded.len(), decode_size);
        }
    }

    /// Callers size secret-bearing buffers with `url_*_size`; the append
    /// helpers must never need more capacity than that, on either backend.
    #[test]
    fn test_append_fits_exact_size() {
        for len in 0..64usize {
            let bytes: Vec<u8> = (0..len).map(|i| i as u8 ^ 0x5a).collect();

            let mut encoded = Vec::with_capacity(3 + url_encode_size(len));
            encoded.extend_from_slice(b"pre");
            let capacity = encoded.capacity();
            url_encode_append(&bytes, &mut encoded);
            assert_eq!(encoded.capacity(), capacity, "encode {len}");
            assert_eq!(encoded.len(), capacity, "encode {len}");

            let mut decoded = Vec::with_capacity(3 + url_decode_size(encoded.len() - 3));
            decoded.extend_from_slice(b"pre");
            let capacity = decoded.capacity();
            url_decode_append(&encoded[3..], &mut decoded).unwrap();
            assert_eq!(decoded.capacity(), capacity, "decode {len}");
            assert_eq!(&decoded[3..], &bytes[..], "decode {len}");
        }

        let mut dst = b"pre".to_vec();
        for invalid in ["A", "AAAAA", "AA==", "A*AA"] {
            assert!(url_decode_append(invalid, &mut dst).is_err(), "{invalid}");
            assert_eq!(dst, b"pre", "{invalid}");
        }
    }
}
