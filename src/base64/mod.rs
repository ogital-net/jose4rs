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
pub(crate) fn pem_encode(src: impl AsRef<[u8]>) -> Box<[u8]> {
    let mut out = Vec::new();
    pem_encode_append(src, &mut out);
    debug_assert_eq!(out.len(), out.capacity());
    out.into_boxed_slice()
}

#[inline]
pub(crate) fn pem_encode_append(src: impl AsRef<[u8]>, dst: &mut Vec<u8>) {
    const LINE_LEN: usize = 64;
    const LINE_BYTES: usize = LINE_LEN / 4 * 3;

    let src = src.as_ref();
    let encode_size = standard_encode_size(src.len());
    let line_count = encode_size.div_ceil(LINE_LEN);

    dst.reserve_exact(encode_size + line_count);
    for c in src.chunks(LINE_BYTES) {
        standard_encode_append(c, dst);
        dst.push(b'\n');
    }
}

#[inline]
pub(crate) fn pem_decode(src: impl AsRef<[u8]>) -> Result<Box<[u8]>, Error> {
    let mut out = Vec::new();
    pem_decode_append(src, &mut out)?;
    debug_assert_eq!(out.len(), out.capacity());
    Ok(out.into_boxed_slice())
}

#[inline]
pub(crate) fn pem_decode_append(src: impl AsRef<[u8]>, dst: &mut Vec<u8>) -> Result<(), Error> {
    let src = src.as_ref();

    let lines = src.split(|&b| b == b'\n').map(|line| match line.last() {
        Some(b'\r') => &line[..line.len() - 1],
        _ => line,
    });
    let lines = lines.into_iter();

    let mut size = 0;
    for l in lines.clone() {
        size += standard_decode_size(l.len());
    }
    dst.reserve_exact(size);
    for l in lines {
        standard_decode_append(l, dst)?;
    }
    Ok(())
}

#[inline]
pub(crate) fn standard_encode_size(src_len: usize) -> usize {
    ((src_len + 2) / 3) << 2
}

#[inline]
pub(crate) fn standard_decode_size(src_len: usize) -> usize {
    (src_len * 3) >> 2
}

#[inline]
pub(crate) fn url_encode_size(src_len: usize) -> usize {
    ((src_len << 2) | 2) / 3
}

#[inline]
pub(crate) fn url_decode_size(src_len: usize) -> usize {
    (src_len * 3) >> 2
}

#[cfg(test)]
mod tests {
    use crate::crypto::rand::rand_bytes;

    use super::*;

    #[test]
    fn test_pem_encode() {
        let expected = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAn+Mm25m+rMK++HbCvzK3\n\
            Lwatj8RB3bapmEw/ZhTLuOgvmkz05FS9JxYi8L5LMI/wVreazva70/JZ9eJ0PkAA\n\
            JseO49U9YZAIrs5knwaE2GQG/jKltYG2CV/50CLEcCSaCyEU6Xp2bHIXZylHmLp7\n\
            Hqq5oYkYh9oP+LriKZGVK45fGicqx3f9IQTMdRm+midHu+35mg2lAGjlmCFPBBlN\n\
            FP0JVuG542Rq23H+VC2XDdbMD66e38QTnhPF15MluQmo4oWdgr/g4iTqN8jwEv7/\n\
            i9Kyc00Y7WwFpXsmSfcp99i8Vjkk6m/06NJvLGWRwk+Xo4jxYtmNHcH9SARZ/826\n\
            GQIDAQAB\n";
        let b64_input = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAn+Mm25m+rMK++HbCvzK3\
            Lwatj8RB3bapmEw/ZhTLuOgvmkz05FS9JxYi8L5LMI/wVreazva70/JZ9eJ0PkAA\
            JseO49U9YZAIrs5knwaE2GQG/jKltYG2CV/50CLEcCSaCyEU6Xp2bHIXZylHmLp7\
            Hqq5oYkYh9oP+LriKZGVK45fGicqx3f9IQTMdRm+midHu+35mg2lAGjlmCFPBBlN\
            FP0JVuG542Rq23H+VC2XDdbMD66e38QTnhPF15MluQmo4oWdgr/g4iTqN8jwEv7/\
            i9Kyc00Y7WwFpXsmSfcp99i8Vjkk6m/06NJvLGWRwk+Xo4jxYtmNHcH9SARZ/826\
            GQIDAQAB";
        let input_bytes = standard_decode(b64_input).unwrap();
        let out = pem_encode(input_bytes);
        assert_eq!(out.as_ref(), expected.as_bytes());
    }

    #[test]
    fn test_pem_decode() {
        let b64_expected = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAn+Mm25m+rMK++HbCvzK3\
            Lwatj8RB3bapmEw/ZhTLuOgvmkz05FS9JxYi8L5LMI/wVreazva70/JZ9eJ0PkAA\
            JseO49U9YZAIrs5knwaE2GQG/jKltYG2CV/50CLEcCSaCyEU6Xp2bHIXZylHmLp7\
            Hqq5oYkYh9oP+LriKZGVK45fGicqx3f9IQTMdRm+midHu+35mg2lAGjlmCFPBBlN\
            FP0JVuG542Rq23H+VC2XDdbMD66e38QTnhPF15MluQmo4oWdgr/g4iTqN8jwEv7/\
            i9Kyc00Y7WwFpXsmSfcp99i8Vjkk6m/06NJvLGWRwk+Xo4jxYtmNHcH9SARZ/826\
            GQIDAQAB";
        let input_lf = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAn+Mm25m+rMK++HbCvzK3\n\
            Lwatj8RB3bapmEw/ZhTLuOgvmkz05FS9JxYi8L5LMI/wVreazva70/JZ9eJ0PkAA\n\
            JseO49U9YZAIrs5knwaE2GQG/jKltYG2CV/50CLEcCSaCyEU6Xp2bHIXZylHmLp7\n\
            Hqq5oYkYh9oP+LriKZGVK45fGicqx3f9IQTMdRm+midHu+35mg2lAGjlmCFPBBlN\n\
            FP0JVuG542Rq23H+VC2XDdbMD66e38QTnhPF15MluQmo4oWdgr/g4iTqN8jwEv7/\n\
            i9Kyc00Y7WwFpXsmSfcp99i8Vjkk6m/06NJvLGWRwk+Xo4jxYtmNHcH9SARZ/826\n\
            GQIDAQAB\n";
        let input_crlf = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAn+Mm25m+rMK++HbCvzK3\r\n\
            Lwatj8RB3bapmEw/ZhTLuOgvmkz05FS9JxYi8L5LMI/wVreazva70/JZ9eJ0PkAA\r\n\
            JseO49U9YZAIrs5knwaE2GQG/jKltYG2CV/50CLEcCSaCyEU6Xp2bHIXZylHmLp7\r\n\
            Hqq5oYkYh9oP+LriKZGVK45fGicqx3f9IQTMdRm+midHu+35mg2lAGjlmCFPBBlN\r\n\
            FP0JVuG542Rq23H+VC2XDdbMD66e38QTnhPF15MluQmo4oWdgr/g4iTqN8jwEv7/\r\n\
            i9Kyc00Y7WwFpXsmSfcp99i8Vjkk6m/06NJvLGWRwk+Xo4jxYtmNHcH9SARZ/826\r\n\
            GQIDAQAB\r\n";

        let expected = standard_decode(b64_expected).unwrap();
        let out = pem_decode(input_lf).unwrap();
        assert_eq!(out, expected);

        let out = pem_decode(input_crlf).unwrap();
        assert_eq!(out, expected);
    }

    #[test]
    fn test_standard_encode_size() {
        for i in 4..64 {
            let bytes = rand_bytes(i);
            let encode_size = standard_encode_size(bytes.len());
            let encoded = standard_encode(bytes);
            assert_eq!(encoded.len(), encode_size);
        }
    }

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
    fn test_standard_decode_size() {
        for i in 4..64 {
            let bytes = rand_bytes(i);
            let encoded = standard_encode(bytes);
            
            let decode_size = standard_decode_size(encoded.len());
            let decoded = standard_decode(encoded).unwrap();
            assert!(decode_size >= decoded.len());
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
}
