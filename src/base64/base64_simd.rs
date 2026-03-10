use crate::{base64::Error, BufferRef};

impl From<base64_simd::Error> for Error {
    fn from(_value: base64_simd::Error) -> Self {
        Error(())
    }
}

#[inline]
pub(crate) fn standard_encode(src: impl AsRef<[u8]>) -> Box<[u8]> {
    base64_simd::STANDARD.encode_type(src)
}

#[inline]
pub(crate) fn standard_encode_append(src: impl AsRef<[u8]>, dst: &mut Vec<u8>) {
    base64_simd::STANDARD.encode_append(src, dst)
}

#[inline]
pub(crate) fn standard_decode(src: impl AsRef<[u8]>) -> Result<Box<[u8]>, Error> {
    Ok(base64_simd::STANDARD.decode_type(src)?)
}

#[inline]
pub(crate) fn standard_decode_append(
    src: impl AsRef<[u8]>,
    dst: &mut Vec<u8>,
) -> Result<(), Error> {
    Ok(base64_simd::STANDARD.decode_append(src, dst)?)
}

#[inline]
pub(crate) fn url_encode(src: impl AsRef<[u8]>) -> Box<[u8]> {
    base64_simd::URL_SAFE_NO_PAD.encode_type(src)
}

#[inline]
pub(crate) fn url_encode_append(src: impl AsRef<[u8]>, dst: &mut Vec<u8>) -> BufferRef {
    let start = dst.len();
    base64_simd::URL_SAFE_NO_PAD.encode_append(src, dst);
    BufferRef::new(start, dst.len())
}

#[inline]
pub(crate) fn url_decode(src: impl AsRef<[u8]>) -> Result<Box<[u8]>, Error> {
    Ok(base64_simd::URL_SAFE_NO_PAD.decode_type(src)?)
}

#[inline]
pub(crate) fn url_decode_append(
    src: impl AsRef<[u8]>,
    dst: &mut Vec<u8>,
) -> Result<BufferRef, Error> {
    let start = dst.len();
    base64_simd::URL_SAFE_NO_PAD.decode_append(src, dst)?;
    Ok(BufferRef::new(start, dst.len()))
}
