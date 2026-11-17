use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

/// Test-only standard (padded) base64 engine, used only by the test helpers.
#[cfg(test)]
use base64::engine::general_purpose::STANDARD;

use crate::{BufferRef, base64::Error};

impl From<base64::DecodeError> for Error {
    fn from(_value: base64::DecodeError) -> Self {
        Error(())
    }
}

#[inline]
pub(crate) fn url_encode(src: impl AsRef<[u8]>) -> Box<[u8]> {
    let need = base64::encoded_len(src.as_ref().len(), false).unwrap();
    let mut buf = vec![0; need];

    let size = URL_SAFE_NO_PAD
        .encode_slice(src.as_ref(), &mut buf)
        .unwrap();
    buf.truncate(size);
    buf.into_boxed_slice()
}

#[inline]
pub(crate) fn url_encode_append(src: impl AsRef<[u8]>, dst: &mut Vec<u8>) -> BufferRef {
    let src = src.as_ref();
    let start = dst.len();
    dst.resize(start + super::url_encode_size(src.len()), 0);
    let size = URL_SAFE_NO_PAD
        .encode_slice(src, &mut dst[start..])
        .unwrap();
    debug_assert_eq!(start + size, dst.len());
    BufferRef::new(start, dst.len())
}

#[inline]
pub(crate) fn url_decode(src: impl AsRef<[u8]>) -> Result<Box<[u8]>, Error> {
    let buf = URL_SAFE_NO_PAD.decode(src.as_ref())?;
    Ok(buf.into_boxed_slice())
}

#[inline]
pub(crate) fn url_decode_append(
    src: impl AsRef<[u8]>,
    dst: &mut Vec<u8>,
) -> Result<BufferRef, Error> {
    let src = src.as_ref();
    let start = dst.len();
    // base64 >= 0.22 accepts an exactly sized output slice.
    dst.resize(start + super::url_decode_size(src.len()), 0);
    let Ok(size) = URL_SAFE_NO_PAD.decode_slice(src, &mut dst[start..]) else {
        dst.truncate(start);
        return Err(Error(()));
    };
    dst.truncate(start + size);
    Ok(BufferRef::new(start, dst.len()))
}

/// Test-only standard (padded) base64 decode backing the test helpers in
/// [`crate::base64`].
#[cfg(test)]
pub(crate) fn standard_decode_impl(src: impl AsRef<[u8]>) -> Result<Box<[u8]>, Error> {
    Ok(STANDARD.decode(src.as_ref())?.into_boxed_slice())
}
