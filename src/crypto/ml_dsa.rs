//! ML-DSA (FIPS 204 / RFC 9964) post-quantum signatures.
//!
//! This module is gated on the `pq-ml-dsa` feature. The `aws-lc-sys` crate
//! exposes the `EVP_PKEY` PQDSA entry points (`EVP_PKEY_pqdsa_*` and
//! `EVP_PKEY_CTX_pqdsa_set_params`) plus the parameter NIDs (`NID_MLDSA44`,
//! `NID_MLDSA65`, `NID_MLDSA87`); `BoringSSL`'s upstream has not landed ML-DSA,
//! so this backend is not (yet) supported through the `boring` feature.
//!
//! Per RFC 9964 Section 4, the `priv` member of an AKP JWK is the 32-byte seed form
//! (not the expanded private key). AWS-LC's
//! `EVP_PKEY_pqdsa_new_raw_private_key` accepts the seed and derives the full
//! expanded private key; the seed is recovered via
//! `EVP_PKEY_get_private_seed`.
//!
//! Sign/verify go through `EVP_DigestSign` / `EVP_DigestVerify` with a NULL
//! message digest (`md`), which selects pure (non-prehash) ML-DSA. ML-DSA
//! hashes the message internally; the caller passes the raw payload.

use std::ptr;

#[cfg(feature = "aws-lc")]
use aws_lc_sys::{
    EVP_PKEY, EVP_PKEY_CTX_free, EVP_PKEY_CTX_new_id, EVP_PKEY_CTX_pqdsa_set_params, EVP_PKEY_free,
    EVP_PKEY_get_raw_public_key, EVP_PKEY_keygen, EVP_PKEY_keygen_init,
    EVP_PKEY_pqdsa_new_raw_private_key, NID_MLDSA44, NID_MLDSA65, NID_MLDSA87, NID_PQDSA,
};

use crate::{crypto::mem, error::JoseError, jwk::ml_dsa::MlDsaParameterSet};

// Internal helpers on the parameter set are implemented as inherent methods
// on `MlDsaParameterSet` in `crate::jwk::ml_dsa`. Re-export them here as
// `pub(crate)` so the FFI layer can call them without depending on the JWK
// module's public surface.
impl MlDsaParameterSet {
    /// Returns the AWS-LC `NID_MLDSA*` value for this parameter set.
    pub(crate) fn nid(self) -> i32 {
        match self {
            MlDsaParameterSet::MlDsa44 => NID_MLDSA44,
            MlDsaParameterSet::MlDsa65 => NID_MLDSA65,
            MlDsaParameterSet::MlDsa87 => NID_MLDSA87,
        }
    }
}

/// A heap-allocated `EVP_PKEY` holding an ML-DSA key (public, private, or both).
///
/// ML-DSA is a pure signature scheme: sign takes the message verbatim and
/// produces a signature; verify accepts a message + signature. There is no
/// prehash variant and no separate digest; the message bytes go straight
/// to the signing operation.
pub(crate) struct MlDsaKey(ptr::NonNull<EVP_PKEY>);

impl MlDsaKey {
    /// Generates a fresh ML-DSA key pair using the OS RNG.
    pub(crate) fn generate(params: MlDsaParameterSet) -> Result<Self, JoseError> {
        // PQDSA is the umbrella key type; the parameter-specific NID is
        // applied via `EVP_PKEY_CTX_pqdsa_set_params` after the context is
        // constructed. `EVP_PKEY_CTX_new_id(NID_MLDSA44, NULL)` returns NULL
        // because `NID_MLDSA44` is not a base key type.
        let ctx = unsafe { EVP_PKEY_CTX_new_id(NID_PQDSA, ptr::null_mut()) };
        if ctx.is_null() {
            return Err(JoseError::InvalidKey(
                "EVP_PKEY_CTX_new_id failed for NID_PQDSA".into(),
            ));
        }
        if 1 != unsafe { EVP_PKEY_CTX_pqdsa_set_params(ctx, params.nid()) } {
            unsafe { EVP_PKEY_CTX_free(ctx) };
            return Err(JoseError::InvalidKey(format!(
                "EVP_PKEY_CTX_pqdsa_set_params failed for {}",
                params.jose_name()
            )));
        }
        if 1 != unsafe { EVP_PKEY_keygen_init(ctx) } {
            unsafe { EVP_PKEY_CTX_free(ctx) };
            return Err(JoseError::InvalidKey(
                "EVP_PKEY_keygen_init failed for ML-DSA".into(),
            ));
        }

        let mut pkey: *mut EVP_PKEY = ptr::null_mut();
        let rc = unsafe { EVP_PKEY_keygen(ctx, &mut pkey) };
        unsafe { EVP_PKEY_CTX_free(ctx) };
        if rc != 1 || pkey.is_null() {
            return Err(JoseError::InvalidKey(format!(
                "EVP_PKEY_keygen failed for {}",
                params.jose_name()
            )));
        }
        Ok(Self(unsafe { ptr::NonNull::new_unchecked(pkey) }))
    }

    /// Loads an ML-DSA private key from a 32-byte seed (RFC 9964 Section 4 form).
    ///
    /// AWS-LC's `EVP_PKEY_pqdsa_new_raw_private_key` derives both the public
    /// and the expanded private key from the seed; the seed is recoverable
    /// later via [`Self::private_seed`]. The caller-supplied buffer is
    /// cleansed before this function returns.
    pub(crate) fn from_seed(params: MlDsaParameterSet, seed: &mut [u8]) -> Result<Self, JoseError> {
        if seed.len() != MlDsaParameterSet::SEED_LEN {
            return Err(JoseError::InvalidKey(format!(
                "ML-DSA seed must be exactly {} bytes, got {}",
                MlDsaParameterSet::SEED_LEN,
                seed.len()
            )));
        }
        let pkey = unsafe {
            // AWS-LC duplicates the input buffer; we cleanse the caller's
            // seed after the call to drop it from the stack.
            //
            // Use `EVP_PKEY_pqdsa_new_raw_private_key` directly: the generic
            // `EVP_PKEY_new_raw_private_key` entry point does not currently
            // dispatch into the PQDSA code path and returns NULL for ML-DSA
            // NIDs even when the input is a valid seed.
            let ptr = EVP_PKEY_pqdsa_new_raw_private_key(params.nid(), seed.as_ptr(), seed.len());
            mem::cleanse(seed);
            if ptr.is_null() {
                return Err(JoseError::InvalidKey(
                    "failed to construct ML-DSA key from seed".into(),
                ));
            }
            ptr::NonNull::new_unchecked(ptr)
        };
        Ok(Self(pkey))
    }

    /// Returns the FIPS 204 raw public-key bytes.
    pub(crate) fn raw_public_key(&self) -> Result<Box<[u8]>, JoseError> {
        get_raw_bytes(self.0.as_ptr(), EVP_PKEY_get_raw_public_key)
    }

    /// Consumes `self` and returns the raw `EVP_PKEY*` pointer without
    /// freeing it. The caller takes ownership and is responsible for
    /// `EVP_PKEY_free`. This is used to hand ownership off to an `EvpPkey`
    /// wrapper without double-freeing the underlying key.
    pub(crate) fn into_raw(self) -> *mut EVP_PKEY {
        let raw = self.0.as_ptr();
        // Skip the Drop impl so the free is the caller's responsibility.
        std::mem::forget(self);
        raw
    }
}

impl Drop for MlDsaKey {
    fn drop(&mut self) {
        unsafe { EVP_PKEY_free(self.0.as_ptr()) };
    }
}

/// Helper: AWS-LC raw-bytes getter. Reads the length first (with `out == NULL`)
/// and then the bytes. Returns `None` from the underlying FFI as an error.
fn get_raw_bytes(
    pkey: *const EVP_PKEY,
    getter: unsafe extern "C" fn(*const EVP_PKEY, *mut u8, *mut usize) -> i32,
) -> Result<Box<[u8]>, JoseError> {
    let mut len: usize = 0;
    let rc = unsafe { getter(pkey, ptr::null_mut(), &mut len) };
    if rc != 1 || len == 0 {
        return Err(JoseError::InvalidKey(format!(
            "EVP_PKEY_get_raw_* size query returned {rc} with len={len}"
        )));
    }
    let mut buf = vec![0u8; len];
    let mut written = len;
    let rc = unsafe { getter(pkey, buf.as_mut_ptr(), &mut written) };
    if rc != 1 {
        return Err(JoseError::InvalidKey(
            "EVP_PKEY_get_raw_* read failed".into(),
        ));
    }
    buf.truncate(written);
    Ok(buf.into_boxed_slice())
}
