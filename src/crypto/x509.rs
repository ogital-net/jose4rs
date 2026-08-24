use std::ptr;

#[cfg(feature = "aws-lc")]
use aws_lc_sys::{d2i_X509, i2d_X509, PEM_read_bio_X509, X509_free, X509_get_pubkey, X509};

#[cfg(all(feature = "boring", not(feature = "aws-lc")))]
use boring_sys::{d2i_X509, i2d_X509, PEM_read_bio_X509, X509_free, X509_get_pubkey, X509};

use super::{digest, Bio, EvpPkey};
use crate::{base64, error::JoseError};

/// A wrapper around an X.509 certificate (`X509`).
///
/// Only the operations JOSE needs are exposed: parsing a certificate and
/// extracting the subject's public key. Certificate *generation* and chain
/// validation are out of scope.
pub(crate) struct X509Cert(ptr::NonNull<X509>);

impl X509Cert {
    /// Parses an X.509 certificate from its DER encoding.
    pub(crate) fn from_der(der: &[u8]) -> Result<Self, JoseError> {
        // d2i_X509() advances the input pointer, so use a local copy.
        let mut ptr = der.as_ptr();
        let x509 = unsafe { d2i_X509(ptr::null_mut(), &mut ptr, der.len() as _) };
        if x509.is_null() {
            return Err(JoseError::invalid_key("invalid X.509 certificate DER"));
        }
        unsafe { Ok(Self(ptr::NonNull::new_unchecked(x509))) }
    }

    /// Parses a PEM-encoded X.509 certificate.
    pub(crate) fn from_pem(pem: &[u8]) -> Result<Self, JoseError> {
        // SAFETY: pem is borrowed for the duration of the Bio's use below
        unsafe { Bio::from_slice(pem) }
            .read_pem_x509()
            .ok_or_else(|| JoseError::invalid_key("invalid X.509 certificate PEM"))
    }

    /// Parses from a BIO. Shared by `from_pem` and `Bio::read_pem_x509`.
    pub(super) fn from_pem_bio(bio: &mut Bio) -> Option<Self> {
        let x509 =
            unsafe { PEM_read_bio_X509(bio.as_mut_ptr(), ptr::null_mut(), None, ptr::null_mut()) };
        if x509.is_null() {
            None
        } else {
            unsafe { Some(Self(ptr::NonNull::new_unchecked(x509))) }
        }
    }

    /// Extracts the subject public key from the certificate.
    ///
    /// The returned `EvpPkey` owns its own reference (`X509_get_pubkey()`
    /// increments the reference count), so it outlives the certificate.
    pub(crate) fn public_key(&self) -> Result<EvpPkey, JoseError> {
        let pkey = unsafe { X509_get_pubkey(self.0.as_ptr()) };
        if pkey.is_null() {
            return Err(JoseError::invalid_key(
                "certificate has no usable public key",
            ));
        }
        Ok(EvpPkey::from_ptr(pkey))
    }

    /// Returns the DER encoding of the certificate.
    fn to_der(&self) -> Result<Box<[u8]>, JoseError> {
        // First call with a null output pointer to size the buffer.
        let len = unsafe { i2d_X509(self.0.as_ptr(), ptr::null_mut()) };
        if len <= 0 {
            return Err(JoseError::invalid_key("failed to encode X.509 certificate"));
        }
        let mut out = Vec::with_capacity(len as usize);
        let mut ptr = out.as_mut_ptr();
        let written = unsafe { i2d_X509(self.0.as_ptr(), &mut ptr) };
        if written != len {
            return Err(JoseError::invalid_key("failed to encode X.509 certificate"));
        }
        // SAFETY: i2d_X509 wrote exactly `len` bytes.
        unsafe { out.set_len(len as usize) };
        Ok(out.into_boxed_slice())
    }

    /// Computes the certificate thumbprint: the base64url (no-pad) encoding
    /// of the digest of the DER encoding, per RFC 7515 Section 4.1.7.
    ///
    /// `Sha1` yields the `x5t` value, `Sha256` the `x5t#S256` value.
    pub(crate) fn thumbprint(&self, alg: digest::Algorithm) -> Result<String, JoseError> {
        let digest = digest::digest(alg, self.to_der()?);
        let encoded = base64::url_encode(&digest);
        // SAFETY: base64url output is valid UTF-8.
        Ok(unsafe { std::str::from_utf8_unchecked(&encoded) }.to_string())
    }
}

impl Drop for X509Cert {
    fn drop(&mut self) {
        unsafe { X509_free(self.0.as_ptr()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base64;

    const RSA_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
        MIICojCCAYoCCQDjFCGvXJ6aRzANBgkqhkiG9w0BAQsFADATMREwDwYDVQQDDAh0\n\
        ZXN0LXJzYTAeFw0yNjA4MjAyMTA3MThaFw0yNzA4MjAyMTA3MThaMBMxETAPBgNV\n\
        BAMMCHRlc3QtcnNhMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqgZj\n\
        rugNDwxBcIvQXHv/76ifyuQvJfuJfdPAjDM9A9XoUdYfUPWtim8Ra4kmpiLPzezJ\n\
        x62XcLDvcIOzrINPInqs67ZteoTLSVCOHDPAA3YSk8uhQ2lAOH0wW4798qIKE8j9\n\
        RmebRct3dbLgtDyzjEKL+R72hCbFrqoM9qwkq8LQH3I/C/qxv8qmo98hE1Cm9C38\n\
        TL8AulZFGm+Jdkhq3fyAtxqfBsh2cFVhaFbZNQB1hyDhwJWeZAlJZLoeJXAQzw0O\n\
        TreK2uBUg3FdtQ9salM9dGzo2Enes/1NvHD56p0HiJ5Z9sEyGNGcobHK2+B6YAQb\n\
        B5KKW4jLcqIvhfQgBwIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQAr5jDlaVZ8dquC\n\
        +ovj3dFUELe1IUb5mQTG5fSE23FnOYJzxqk6kNOh/b76OP4SRAmk1YC2Fek93wl+\n\
        N1xJbT34cBrV8WTvrevwUnFTpUwQiZARy1UuoXok7S4mGjFFjkSe1vWS6SRiwuY6\n\
        WCg0TQ/Q4YKneIxwW+zGxCJFy/X1yU+F3fYQ1xgdoK36y9ViSrG7v2TYpylEV2IZ\n\
        X77BPJaM6Ipl29ejeiaqQxdi+lDW8NwQFd8A99CKxvBjcuXvn1xezOSkxif0iknT\n\
        i8uB/Gr41bm3vCtbfccScCfayb87HP0ZHeVnwCTd5AlhqVH5i4t4Z024TGt6PwXj\n\
        0Sn/VO7U\n\
        -----END CERTIFICATE-----";

    fn der() -> Box<[u8]> {
        base64::pem_decode(
            RSA_CERT_PEM
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", ""),
        )
        .unwrap()
    }

    #[test]
    fn test_from_der_parses() {
        let cert = X509Cert::from_der(&der()).expect("d2i_X509 parse");
        let key = cert.public_key().expect("X509_get_pubkey");
        assert_eq!(key.key_type(), crate::crypto::EvpPkeyType::Rsa);
    }

    #[test]
    fn test_from_pem_parses() {
        let cert = X509Cert::from_pem(RSA_CERT_PEM.as_bytes()).expect("PEM parse");
        let key = cert.public_key().expect("X509_get_pubkey");
        assert_eq!(key.key_type(), crate::crypto::EvpPkeyType::Rsa);
    }

    #[test]
    fn test_thumbprints() {
        // Known-good values computed with openssl over the cert's DER.
        let cert = X509Cert::from_pem(RSA_CERT_PEM.as_bytes()).unwrap();
        assert_eq!(
            cert.thumbprint(digest::Algorithm::Sha1).unwrap(),
            "9fUB4n5Oi7UOpmlQvneMQew7BgI"
        );
        assert_eq!(
            cert.thumbprint(digest::Algorithm::Sha256).unwrap(),
            "rCAyJQXv1uillTH_pEAxvTzRTDwoyQ6b3_scGHFjMkU"
        );

        // The DER-parsed cert yields the same thumbprints.
        let cert = X509Cert::from_der(&der()).unwrap();
        assert_eq!(
            cert.thumbprint(digest::Algorithm::Sha256).unwrap(),
            "rCAyJQXv1uillTH_pEAxvTzRTDwoyQ6b3_scGHFjMkU"
        );
    }
}
