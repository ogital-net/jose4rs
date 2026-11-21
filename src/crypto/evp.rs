use std::ptr;

#[cfg(all(feature = "aws-lc", feature = "pq-ml-dsa"))]
use aws_lc_sys::EVP_PKEY_get_private_seed;
#[cfg(feature = "aws-lc")]
use aws_lc_sys::{
    EVP_DigestSign, EVP_DigestSignInit, EVP_DigestVerify, EVP_DigestVerifyInit, EVP_PKEY,
    EVP_PKEY_CTX, EVP_PKEY_CTX_free, EVP_PKEY_CTX_new, EVP_PKEY_CTX_new_id,
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid, EVP_PKEY_CTX_set_rsa_keygen_bits,
    EVP_PKEY_CTX_set_rsa_mgf1_md, EVP_PKEY_CTX_set_rsa_oaep_md, EVP_PKEY_CTX_set_rsa_padding,
    EVP_PKEY_CTX_set_rsa_pss_saltlen, EVP_PKEY_DH, EVP_PKEY_DSA, EVP_PKEY_EC, EVP_PKEY_ED25519,
    EVP_PKEY_HKDF, EVP_PKEY_NONE, EVP_PKEY_RSA, EVP_PKEY_RSA_PSS, EVP_PKEY_X25519,
    EVP_PKEY_assign_EC_KEY, EVP_PKEY_assign_RSA, EVP_PKEY_bits, EVP_PKEY_cmp, EVP_PKEY_decrypt,
    EVP_PKEY_decrypt_init, EVP_PKEY_derive, EVP_PKEY_derive_init, EVP_PKEY_derive_set_peer,
    EVP_PKEY_encrypt, EVP_PKEY_encrypt_init, EVP_PKEY_free, EVP_PKEY_get_raw_private_key,
    EVP_PKEY_get_raw_public_key, EVP_PKEY_id, EVP_PKEY_keygen, EVP_PKEY_keygen_init, EVP_PKEY_new,
    EVP_PKEY_new_raw_private_key, EVP_PKEY_new_raw_public_key, EVP_PKEY_paramgen,
    EVP_PKEY_paramgen_init, EVP_PKEY_up_ref, EVP_marshal_private_key, EVP_marshal_public_key,
    PEM_write_bio_PKCS8PrivateKey, PEM_write_bio_PUBKEY, d2i_AutoPrivateKey, d2i_PUBKEY,
};

#[cfg(all(feature = "boring", not(feature = "aws-lc")))]
use boring_sys::{
    EVP_DigestSign, EVP_DigestSignInit, EVP_DigestVerify, EVP_DigestVerifyInit, EVP_PKEY,
    EVP_PKEY_CTX, EVP_PKEY_CTX_free, EVP_PKEY_CTX_new, EVP_PKEY_CTX_new_id,
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid, EVP_PKEY_CTX_set_rsa_keygen_bits,
    EVP_PKEY_CTX_set_rsa_mgf1_md, EVP_PKEY_CTX_set_rsa_oaep_md, EVP_PKEY_CTX_set_rsa_padding,
    EVP_PKEY_CTX_set_rsa_pss_saltlen, EVP_PKEY_DH, EVP_PKEY_DSA, EVP_PKEY_EC, EVP_PKEY_ED25519,
    EVP_PKEY_HKDF, EVP_PKEY_NONE, EVP_PKEY_RSA, EVP_PKEY_RSA_PSS, EVP_PKEY_X25519,
    EVP_PKEY_assign_EC_KEY, EVP_PKEY_assign_RSA, EVP_PKEY_bits, EVP_PKEY_cmp, EVP_PKEY_decrypt,
    EVP_PKEY_decrypt_init, EVP_PKEY_derive, EVP_PKEY_derive_init, EVP_PKEY_derive_set_peer,
    EVP_PKEY_encrypt, EVP_PKEY_encrypt_init, EVP_PKEY_free, EVP_PKEY_get_raw_private_key,
    EVP_PKEY_get_raw_public_key, EVP_PKEY_id, EVP_PKEY_keygen, EVP_PKEY_keygen_init, EVP_PKEY_new,
    EVP_PKEY_new_raw_private_key, EVP_PKEY_new_raw_public_key, EVP_PKEY_paramgen,
    EVP_PKEY_paramgen_init, EVP_PKEY_up_ref, EVP_marshal_private_key, EVP_marshal_public_key,
    PEM_write_bio_PKCS8PrivateKey, PEM_write_bio_PUBKEY, d2i_AutoPrivateKey, d2i_PUBKEY,
};

use crate::{
    crypto::{
        digest, mem,
        rsa::{RsaPadding, RsaRef},
    },
    error::JoseError,
};

use super::{
    Bio,
    bytestring::Cbb,
    curve25519::{ed25519_keypair, x25519_keypair},
    ec::{Curve, EcKey, EcKeyRef},
    rsa::Rsa,
};

// boring-sys has no binding for this; BoringSSL documents -1 as "salt length = digest length".
const RSA_PSS_SALTLEN_DIGEST: i32 = -1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EvpPkeyType {
    None,
    Rsa,
    RsaPss,
    Dsa,
    Ec,
    Ed25519,
    X25519,
    Hkdf,
    Dh,
    #[cfg(all(feature = "pq-ml-dsa", feature = "aws-lc"))]
    MlDsa44,
    #[cfg(all(feature = "pq-ml-dsa", feature = "aws-lc"))]
    MlDsa65,
    #[cfg(all(feature = "pq-ml-dsa", feature = "aws-lc"))]
    MlDsa87,
}

impl EvpPkeyType {
    fn to_nid(self) -> i32 {
        match self {
            EvpPkeyType::None => EVP_PKEY_NONE,
            EvpPkeyType::Rsa => EVP_PKEY_RSA,
            EvpPkeyType::RsaPss => EVP_PKEY_RSA_PSS,
            EvpPkeyType::Dsa => EVP_PKEY_DSA,
            EvpPkeyType::Ec => EVP_PKEY_EC,
            EvpPkeyType::Ed25519 => EVP_PKEY_ED25519,
            EvpPkeyType::X25519 => EVP_PKEY_X25519,
            EvpPkeyType::Hkdf => EVP_PKEY_HKDF,
            EvpPkeyType::Dh => EVP_PKEY_DH,
            #[cfg(all(feature = "pq-ml-dsa", feature = "aws-lc"))]
            EvpPkeyType::MlDsa44 => aws_lc_sys::NID_MLDSA44,
            #[cfg(all(feature = "pq-ml-dsa", feature = "aws-lc"))]
            EvpPkeyType::MlDsa65 => aws_lc_sys::NID_MLDSA65,
            #[cfg(all(feature = "pq-ml-dsa", feature = "aws-lc"))]
            EvpPkeyType::MlDsa87 => aws_lc_sys::NID_MLDSA87,
        }
    }
}

impl TryFrom<i32> for EvpPkeyType {
    type Error = JoseError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        #[cfg(all(feature = "pq-ml-dsa", feature = "aws-lc"))]
        {
            use aws_lc_sys::{NID_MLDSA44, NID_MLDSA65, NID_MLDSA87};
            match value {
                NID_MLDSA44 => return Ok(EvpPkeyType::MlDsa44),
                NID_MLDSA65 => return Ok(EvpPkeyType::MlDsa65),
                NID_MLDSA87 => return Ok(EvpPkeyType::MlDsa87),
                _ => {}
            }
        }
        match value {
            EVP_PKEY_NONE => Ok(EvpPkeyType::None),
            EVP_PKEY_RSA => Ok(EvpPkeyType::Rsa),
            EVP_PKEY_RSA_PSS => Ok(EvpPkeyType::RsaPss),
            EVP_PKEY_DSA => Ok(EvpPkeyType::Dsa),
            EVP_PKEY_EC => Ok(EvpPkeyType::Ec),
            EVP_PKEY_ED25519 => Ok(EvpPkeyType::Ed25519),
            EVP_PKEY_X25519 => Ok(EvpPkeyType::X25519),
            EVP_PKEY_HKDF => Ok(EvpPkeyType::Hkdf),
            EVP_PKEY_DH => Ok(EvpPkeyType::Dh),
            _ => Err(JoseError::InvalidKey("unsupported key type".into())),
        }
    }
}

impl From<EvpPkeyType> for i32 {
    fn from(value: EvpPkeyType) -> Self {
        value.to_nid()
    }
}

impl From<&EvpPkeyType> for i32 {
    fn from(value: &EvpPkeyType) -> Self {
        value.to_nid()
    }
}

pub(crate) struct EvpPkey(ptr::NonNull<EVP_PKEY>);

impl EvpPkey {
    fn new() -> Self {
        let ptr = unsafe { EVP_PKEY_new() };
        Self(ptr::NonNull::new(ptr).expect("EVP_PKEY_new() failed"))
    }

    pub(crate) fn new_raw_private_key(
        key_type: EvpPkeyType,
        key: &[u8],
    ) -> Result<Self, JoseError> {
        let ptr = unsafe {
            // the key is duplicated and ownership is not transferred
            EVP_PKEY_new_raw_private_key(key_type.into(), ptr::null_mut(), key.as_ptr(), key.len())
        };
        let ptr = ptr::NonNull::new(ptr)
            .ok_or_else(|| JoseError::InvalidKey("invalid raw private key".into()))?;
        Ok(Self(ptr))
    }

    pub(crate) fn new_raw_public_key(key_type: EvpPkeyType, key: &[u8]) -> Result<Self, JoseError> {
        let ptr = unsafe {
            // the key is duplicated and ownership is not transferred
            EVP_PKEY_new_raw_public_key(key_type.into(), ptr::null_mut(), key.as_ptr(), key.len())
        };
        let ptr = ptr::NonNull::new(ptr)
            .ok_or_else(|| JoseError::InvalidKey("invalid raw public key".into()))?;
        Ok(Self(ptr))
    }

    /// Constructs an `EVP_PKEY` from the raw FIPS 204 public-key bytes for an
    /// ML-DSA parameter set. Uses `EVP_PKEY_pqdsa_new_raw_public_key` because
    /// the generic `EVP_PKEY_new_raw_public_key` does not currently dispatch
    /// into the PQDSA code path.
    #[cfg(all(feature = "pq-ml-dsa", feature = "aws-lc"))]
    pub(crate) fn new_pqdsa_raw_public_key(
        params: crate::jwk::ml_dsa::MlDsaParameterSet,
        key: &[u8],
    ) -> Result<Self, JoseError> {
        let ptr = unsafe {
            aws_lc_sys::EVP_PKEY_pqdsa_new_raw_public_key(params.nid(), key.as_ptr(), key.len())
        };
        let ptr = ptr::NonNull::new(ptr)
            .ok_or_else(|| JoseError::InvalidKey("invalid ML-DSA raw public key".into()))?;
        Ok(Self(ptr))
    }

    /// Takes ownership of one reference to an `EVP_PKEY`.
    ///
    /// # Safety
    ///
    /// `ptr` must point to a live `EVP_PKEY`. The caller must transfer one
    /// owned reference, which this wrapper releases on drop.
    pub(crate) unsafe fn from_raw_ptr(ptr: *mut EVP_PKEY) -> Self {
        Self(ptr::NonNull::new(ptr).expect("EVP_PKEY pointer must not be null"))
    }

    pub(crate) fn from_rsa(mut rsa: Rsa) -> Self {
        let mut pkey = Self::new();
        assert!(
            1 == unsafe { EVP_PKEY_assign_RSA(pkey.as_mut_ptr(), rsa.as_mut_ptr()) },
            "EVP_PKEY_assign_RSA() failed"
        );
        // EVP_PKEY_assign_RSA() takes ownership of the pointer on success
        rsa.manually_drop();
        pkey
    }

    pub(crate) fn from_ec_key(mut ec_key: EcKey) -> Self {
        let mut pkey = Self::new();
        assert!(
            1 == unsafe { EVP_PKEY_assign_EC_KEY(pkey.as_mut_ptr(), ec_key.as_mut_ptr()) },
            "EVP_PKEY_assign_EC_KEY() failed"
        );
        ec_key.manually_drop();
        pkey
    }

    pub(crate) fn generate_rsa(bits: u16) -> Self {
        let mut ctx = EvpPkeyCtx::new(EvpPkeyType::Rsa);
        ctx.keygen_init();
        ctx.set_keygen_rsa_bits(bits);
        ctx.keygen()
    }

    pub(crate) fn generate_ec(curve: Curve) -> Self {
        let mut ctx = EvpPkeyCtx::new(EvpPkeyType::Ec);
        ctx.paramgen_init();
        ctx.set_paramgen_ec_curve(curve);
        let params = ctx.paramgen();

        let mut ctx = EvpPkeyCtx::from_key(&params);
        ctx.keygen_init();
        ctx.keygen()
    }

    pub(crate) fn generate_ed25519() -> Self {
        let mut out_public_key = [0u8; 32];
        let mut out_private_key = mem::Zeroizing::new([0u8; 64]);
        ed25519_keypair(&mut out_public_key, out_private_key.as_inner_mut());
        EvpPkey::new_raw_private_key(EvpPkeyType::Ed25519, &out_private_key[..32])
            .expect("generated Ed25519 private key should be valid")
    }

    pub(crate) fn generate_x25519() -> Self {
        let mut out_public_value = [0u8; 32];
        let mut out_private_key = mem::Zeroizing::new([0u8; 32]);
        x25519_keypair(&mut out_public_value, out_private_key.as_inner_mut());
        EvpPkey::new_raw_private_key(EvpPkeyType::X25519, &out_private_key)
            .expect("generated X25519 private key should be valid")
    }

    /// Generates a fresh ML-DSA key pair using the OS RNG. Only available
    /// behind the `pq-ml-dsa` feature (which requires `aws-lc-sys`).
    #[cfg(feature = "pq-ml-dsa")]
    pub(crate) fn generate_ml_dsa(params: crate::jwk::ml_dsa::MlDsaParameterSet) -> Self {
        // Build via `MlDsaKey::generate` and transfer ownership of the raw
        // `EVP_PKEY*` into an `EvpPkey`. Avoids duplicating the keygen logic.
        let key = crate::crypto::MlDsaKey::generate(params)
            .expect("AWS-LC ML-DSA key generation should not fail");
        let raw = key.into_raw();
        unsafe { Self::from_raw_ptr(raw) }
    }

    fn as_mut_ptr(&mut self) -> *mut EVP_PKEY {
        self.0.as_ptr()
    }

    pub(crate) fn as_ptr(&self) -> *const EVP_PKEY {
        self.0.as_ptr()
    }

    pub(crate) fn key_type(&self) -> EvpPkeyType {
        // For PQDSA keys `EVP_PKEY_id` returns the umbrella `NID_PQDSA` rather
        // than the parameter-specific NID; resolve the latter via
        // `EVP_PKEY_pqdsa_get_type` so callers can distinguish
        // ML-DSA-44/65/87. Falls back to `EVP_PKEY_id` for non-PQDSA keys.
        #[cfg(all(feature = "pq-ml-dsa", feature = "aws-lc"))]
        {
            let base_id = unsafe { EVP_PKEY_id(self.as_ptr()) };
            if base_id == aws_lc_sys::EVP_PKEY_PQDSA {
                let param_id = unsafe { aws_lc_sys::EVP_PKEY_pqdsa_get_type(self.as_ptr()) };
                return param_id.try_into().unwrap_or(EvpPkeyType::None);
            }
        }
        unsafe { EVP_PKEY_id(self.as_ptr()) }
            .try_into()
            .unwrap_or(EvpPkeyType::None)
    }

    fn key_size_bytes(&self) -> usize {
        self.key_size_bits() / 8
    }

    pub(crate) fn key_size_bits(&self) -> usize {
        unsafe { EVP_PKEY_bits(self.as_ptr()) }.try_into().unwrap()
    }

    pub(crate) fn sign(&self, message: &[u8], digest: digest::Algorithm) -> Box<[u8]> {
        self.sign_internal(message, Some(digest), false)
            .expect("signing with an RSA/EC key should not fail to initialize")
    }

    pub(crate) fn sign_rsa_pss(&self, message: &[u8], digest: digest::Algorithm) -> Box<[u8]> {
        self.sign_internal(message, Some(digest), true)
            .expect("RSA-PSS signing should not fail to initialize")
    }

    pub(crate) fn sign_eddsa(&self, message: &[u8]) -> Result<Box<[u8]>, JoseError> {
        // EdDSA requires an Edwards-curve key (Ed25519). A key-agreement key
        // such as X25519 cannot sign; reject it with a descriptive error
        // rather than letting signature initialization fail without context.
        if self.key_type() != EvpPkeyType::Ed25519 {
            return Err(JoseError::InvalidKey(
                "key cannot be used for EdDSA signing; an Ed25519 key is required".into(),
            ));
        }
        self.sign_internal(message, None, false)
    }

    fn sign_internal(
        &self,
        message: &[u8],
        digest_alg: Option<digest::Algorithm>,
        rsa_pss: bool,
    ) -> Result<Box<[u8]>, JoseError> {
        let mut md_ctx = digest::EvpMdCtx::init();
        let mut pctx = ptr::null_mut::<EVP_PKEY_CTX>();

        let md = digest_alg.map_or(ptr::null(), |alg| alg.as_ptr());

        if 1 != unsafe {
            EVP_DigestSignInit(
                md_ctx.as_mut_ptr(),
                &raw mut pctx,
                md,
                ptr::null_mut(),
                self.0.as_ptr(),
            )
        } {
            return Err(JoseError::InvalidKey(
                "key cannot be used for this signing operation".into(),
            ));
        }

        if rsa_pss {
            assert!(
                1 == unsafe { EVP_PKEY_CTX_set_rsa_padding(pctx, RsaPadding::Pkcs1Pss.into()) },
                "EVP_PKEY_CTX_set_rsa_padding() failed"
            );
            assert!(
                1 == unsafe { EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, md) },
                "EVP_PKEY_CTX_set_rsa_mgf1_md() failed"
            );
            assert!(
                1 == unsafe { EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) },
                "EVP_PKEY_CTX_set_rsa_pss_saltlen() failed"
            );
        }

        // Determine the maximum length of the signature.
        let mut sig_len = 0;
        assert!(
            1 == unsafe {
                EVP_DigestSign(
                    md_ctx.as_mut_ptr(),
                    ptr::null_mut(),
                    &raw mut sig_len,
                    message.as_ptr(),
                    message.len(),
                )
            },
            "EVP_DigestSign() failed"
        );

        let mut signature = Vec::with_capacity(sig_len);
        assert!(
            1 == unsafe {
                EVP_DigestSign(
                    md_ctx.as_mut_ptr(),
                    signature.as_mut_ptr(),
                    &raw mut sig_len,
                    message.as_ptr(),
                    message.len(),
                )
            },
            "EVP_DigestSign() failed"
        );
        unsafe {
            signature.set_len(sig_len);
        }
        Ok(signature.into_boxed_slice())
    }

    pub(crate) fn verify(
        &self,
        message: &[u8],
        digest: digest::Algorithm,
        signature: &[u8],
    ) -> bool {
        self.verify_internal(message, Some(digest), signature, false)
    }

    pub(crate) fn verify_rsa_pss(
        &self,
        message: &[u8],
        digest: digest::Algorithm,
        signature: &[u8],
    ) -> bool {
        self.verify_internal(message, Some(digest), signature, true)
    }

    pub(crate) fn verify_eddsa(&self, message: &[u8], signature: &[u8]) -> bool {
        // EdDSA requires an Edwards-curve key (Ed25519). Any other key (e.g.
        // X25519) cannot verify; report the signature as invalid.
        if self.key_type() != EvpPkeyType::Ed25519 {
            return false;
        }
        self.verify_internal(message, None, signature, false)
    }

    /// Pure ML-DSA signing (no prehash, empty context).
    ///
    /// The caller is responsible for confirming that `self` is an ML-DSA
    /// private key (one of `EvpPkeyType::MlDsa{44,65,87}`); this method does
    /// not double-check so it can be called from the AKP dispatch path that
    /// has already validated the key type.
    #[cfg(feature = "pq-ml-dsa")]
    pub(crate) fn sign_ml_dsa(&self, message: &[u8]) -> Result<Box<[u8]>, JoseError> {
        self.sign_internal(message, None, false)
    }

    /// Pure ML-DSA verification. Returns false for keys that are not ML-DSA.
    #[cfg(feature = "pq-ml-dsa")]
    pub(crate) fn verify_ml_dsa(&self, message: &[u8], signature: &[u8]) -> bool {
        if !matches!(
            self.key_type(),
            EvpPkeyType::MlDsa44 | EvpPkeyType::MlDsa65 | EvpPkeyType::MlDsa87
        ) {
            return false;
        }
        self.verify_internal(message, None, signature, false)
    }

    fn verify_internal(
        &self,
        message: &[u8],
        digest_alg: Option<digest::Algorithm>,
        signature: &[u8],
        rsa_pss: bool,
    ) -> bool {
        let mut md_ctx = digest::EvpMdCtx::init();
        let mut pctx = ptr::null_mut::<EVP_PKEY_CTX>();

        let md = digest_alg.map_or(ptr::null(), |alg| alg.as_ptr());

        // A key that cannot initialize this verification operation simply fails
        // verification (returns false) rather than aborting the caller.
        if 1 != unsafe {
            EVP_DigestVerifyInit(
                md_ctx.as_mut_ptr(),
                &raw mut pctx,
                md,
                ptr::null_mut(),
                self.0.as_ptr(),
            )
        } {
            return false;
        }

        // RSASSA-PSS-restricted keys can reject these parameters; fail closed.
        if rsa_pss
            && (1 != unsafe { EVP_PKEY_CTX_set_rsa_padding(pctx, RsaPadding::Pkcs1Pss.into()) }
                || 1 != unsafe { EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, md) }
                || 1 != unsafe { EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) })
        {
            return false;
        }

        1 == unsafe {
            EVP_DigestVerify(
                md_ctx.as_mut_ptr(),
                signature.as_ptr(),
                signature.len(),
                message.as_ptr(),
                message.len(),
            )
        }
    }

    pub(crate) fn derive(&self, peer: &EvpPkey) -> Result<mem::Zeroizing<Box<[u8]>>, JoseError> {
        // Only key-agreement-capable keys (ECDH: EC or X25519) can derive a
        // shared secret. A signing-only key such as Ed25519 cannot; reject it
        // here with a descriptive error instead of letting the key-agreement
        // initialization fail (which carries no useful context).
        if !matches!(self.key_type(), EvpPkeyType::Ec | EvpPkeyType::X25519) {
            return Err(JoseError::InvalidKey(
                "key cannot be used for key agreement (ECDH); an EC or X25519 key is required"
                    .into(),
            ));
        }
        let mut pctx = EvpPkeyCtx::from_key(self);
        let mut len = 0usize;
        unsafe {
            if 1 != EVP_PKEY_derive_init(pctx.as_mut_ptr()) {
                return Err(JoseError::InvalidKey(
                    "key cannot be used for key agreement (ECDH)".into(),
                ));
            }
            // SAFETY: EVP_PKEY_derive_set_peer only reads the key and bumps the refcount
            if 1 != EVP_PKEY_derive_set_peer(pctx.as_mut_ptr(), peer.as_ptr().cast_mut()) {
                return Err(JoseError::InvalidKey(
                    "peer key is not suitable for key agreement (ECDH); it must use the same curve"
                        .into(),
                ));
            }
            if 1 != EVP_PKEY_derive(pctx.as_mut_ptr(), ptr::null_mut(), &raw mut len) {
                return Err(JoseError::InvalidKey("key agreement (ECDH) failed".into()));
            }
        }
        let mut out = mem::Zeroizing::new(vec![0; len].into_boxed_slice());
        unsafe {
            if 1 != EVP_PKEY_derive(pctx.as_mut_ptr(), out.as_mut_ptr(), &raw mut len) {
                return Err(JoseError::InvalidKey("key agreement (ECDH) failed".into()));
            }
        }
        if out.len() != len {
            return Err(JoseError::InvalidKey(
                "key agreement (ECDH) returned an unexpected secret length".into(),
            ));
        }
        Ok(out)
    }

    pub(crate) fn private_key_to_der(&self) -> Result<Box<[u8]>, JoseError> {
        let mut cbb = Cbb::with_capacity(self.key_size_bytes() * 4);
        if 1 != unsafe { EVP_marshal_private_key(cbb.as_mut_ptr(), self.as_ptr()) } {
            return Err(JoseError::InvalidKey("unsupported key type".into()));
        }
        Ok(cbb.into_boxed_slice())
    }

    pub(crate) fn public_key_to_der(&self) -> Result<Box<[u8]>, JoseError> {
        let mut cbb = Cbb::with_capacity(self.key_size_bytes() * 4);
        if 1 != unsafe { EVP_marshal_public_key(cbb.as_mut_ptr(), self.as_ptr()) } {
            return Err(JoseError::InvalidKey("unsupported key type".into()));
        }
        Ok(cbb.into_boxed_slice())
    }

    /// Parses a private key from DER, auto-detecting PKCS#8 and legacy formats.
    pub(crate) fn from_private_key_der(der: &[u8]) -> Result<Self, JoseError> {
        let len = der
            .len()
            .try_into()
            .map_err(|_| JoseError::InvalidKey("private key DER is too large".into()))?;
        let mut inp = der.as_ptr();
        let pkey = unsafe { d2i_AutoPrivateKey(ptr::null_mut(), &raw mut inp, len) };
        if pkey.is_null() {
            return Err(JoseError::InvalidKey("invalid private key DER".into()));
        }
        Ok(unsafe { Self::from_raw_ptr(pkey) })
    }

    /// Parses a public key from SPKI DER.
    pub(crate) fn from_public_key_der(der: &[u8]) -> Result<Self, JoseError> {
        let len = der
            .len()
            .try_into()
            .map_err(|_| JoseError::InvalidKey("public key DER is too large".into()))?;
        let mut inp = der.as_ptr();
        let pkey = unsafe { d2i_PUBKEY(ptr::null_mut(), &raw mut inp, len) };
        if pkey.is_null() {
            return Err(JoseError::InvalidKey("invalid public key DER".into()));
        }
        Ok(unsafe { Self::from_raw_ptr(pkey) })
    }

    pub(crate) fn private_key_to_pem(&self) -> Result<Box<str>, JoseError> {
        let mut bio = Bio::new();
        if 1 != unsafe {
            PEM_write_bio_PKCS8PrivateKey(
                bio.as_mut_ptr(),
                self.as_ptr(),
                ptr::null(),
                ptr::null_mut(),
                0,
                None,
                ptr::null_mut(),
            )
        } {
            return Err(JoseError::InvalidKey("unsupported key type".into()));
        }
        // SAFETY: PEM format is guaranteed to be valid UTF-8
        unsafe { Ok(Box::from(std::str::from_utf8_unchecked(bio.as_slice()))) }
    }

    pub(crate) fn public_key_to_pem(&self) -> Result<Box<str>, JoseError> {
        let mut bio = Bio::new();
        if 1 != unsafe {
            // SAFETY: PEM_write_bio_PUBKEY only reads the key; C API lacks const qualifier
            PEM_write_bio_PUBKEY(bio.as_mut_ptr(), self.as_ptr().cast_mut())
        } {
            return Err(JoseError::InvalidKey("unsupported key type".into()));
        }
        // SAFETY: PEM format is guaranteed to be valid UTF-8
        unsafe { Ok(Box::from(std::str::from_utf8_unchecked(bio.as_slice()))) }
    }

    pub(crate) fn rsa(&self) -> Option<RsaRef<'_>> {
        RsaRef::from_evp_pkey(self)
    }

    pub(crate) fn ec(&self) -> Option<EcKeyRef<'_>> {
        EcKeyRef::from_evp_pkey(self)
    }

    pub(crate) fn get_raw_private_key(&self) -> Option<Box<[u8]>> {
        let mut need = 0usize;
        if 1 != unsafe {
            EVP_PKEY_get_raw_private_key(self.as_ptr(), ptr::null_mut(), &raw mut need)
        } {
            return None;
        }
        unsafe {
            let mut b = Box::<[u8]>::new_uninit_slice(need);
            assert!(
                1 == EVP_PKEY_get_raw_private_key(
                    self.as_ptr(),
                    b.as_mut_ptr().cast::<u8>(),
                    &raw mut need
                ),
                "EVP_PKEY_get_raw_private_key() failed"
            );
            Some(b.assume_init())
        }
    }

    pub(crate) fn get_raw_public_key(&self) -> Option<Box<[u8]>> {
        let mut need = 0usize;
        if 1 != unsafe {
            EVP_PKEY_get_raw_public_key(self.as_ptr(), ptr::null_mut(), &raw mut need)
        } {
            return None;
        }
        unsafe {
            let mut b = Box::<[u8]>::new_uninit_slice(need);
            assert!(
                1 == EVP_PKEY_get_raw_public_key(
                    self.as_ptr(),
                    b.as_mut_ptr().cast::<u8>(),
                    &raw mut need
                ),
                "EVP_PKEY_get_raw_public_key() failed"
            );
            Some(b.assume_init())
        }
    }
    /// Returns the 32-byte ML-DSA seed (RFC 9964 Section 4 private-key form) for
    /// ML-DSA private keys, or `None` otherwise. The seed is the value
    /// originally supplied to `EVP_PKEY_pqdsa_new_raw_private_key`.
    ///
    /// AWS-LC may return an expanded private key from `EVP_PKEY_get_raw_private_key`
    /// for some PQ schemes, so we deliberately use `EVP_PKEY_get_private_seed`
    /// which always returns the seed form for ML-DSA.
    #[cfg(all(feature = "aws-lc", feature = "pq-ml-dsa"))]
    pub(crate) fn get_ml_dsa_seed(&self) -> Option<Box<[u8]>> {
        if !matches!(
            self.key_type(),
            EvpPkeyType::MlDsa44 | EvpPkeyType::MlDsa65 | EvpPkeyType::MlDsa87
        ) {
            return None;
        }
        let mut need = 0usize;
        if 1 != unsafe { EVP_PKEY_get_private_seed(self.as_ptr(), ptr::null_mut(), &mut need) } {
            return None;
        }
        if need != 32 {
            // RFC 9964 Section 4 mandates the 32-byte seed form. Surface the
            // discrepancy rather than returning an oversized buffer that the
            // JWK layer would treat as `priv`.
            return None;
        }
        unsafe {
            let mut b = Box::<[u8]>::new_uninit_slice(need);
            assert!(
                1 == EVP_PKEY_get_private_seed(self.as_ptr(), b.as_mut_ptr() as *mut u8, &mut need),
                "EVP_PKEY_get_private_seed() failed"
            );
            Some(b.assume_init())
        }
    }
    fn rsaes_init(
        &self,
        encrypt: bool,
        padding: RsaPadding,
        digest_alg: digest::Algorithm,
    ) -> Result<EvpPkeyCtx, JoseError> {
        let mut pctx = EvpPkeyCtx::try_from_key(self)?;
        let initialized = unsafe {
            if encrypt {
                EVP_PKEY_encrypt_init(pctx.as_mut_ptr())
            } else {
                EVP_PKEY_decrypt_init(pctx.as_mut_ptr())
            }
        };
        if initialized != 1
            || 1 != unsafe { EVP_PKEY_CTX_set_rsa_padding(pctx.as_mut_ptr(), padding.into()) }
        {
            return Err(JoseError::InvalidKey(
                "key cannot be used for the requested RSA encryption or decryption".into(),
            ));
        }
        if padding == RsaPadding::Pkcs1Oaep
            && unsafe {
                1 != EVP_PKEY_CTX_set_rsa_oaep_md(pctx.as_mut_ptr(), digest_alg.as_ptr())
                    || 1 != EVP_PKEY_CTX_set_rsa_mgf1_md(pctx.as_mut_ptr(), digest_alg.as_ptr())
            }
        {
            return Err(JoseError::InvalidKey(
                "key cannot be used with the requested RSA-OAEP parameters".into(),
            ));
        }
        Ok(pctx)
    }

    pub(crate) fn rsa_encrypt(
        &self,
        padding: RsaPadding,
        digest_alg: digest::Algorithm,
        plaintext: &[u8],
    ) -> Result<Box<[u8]>, JoseError> {
        let mut pctx = self.rsaes_init(true, padding, digest_alg)?;

        // Determine the maximum length of the ciphertext.
        let mut out_len = 0;
        if 1 != unsafe {
            EVP_PKEY_encrypt(
                pctx.as_mut_ptr(),
                ptr::null_mut(),
                &raw mut out_len,
                plaintext.as_ptr(),
                plaintext.len(),
            )
        } {
            return Err(JoseError::InvalidKey(
                "could not size RSA ciphertext".into(),
            ));
        }

        let mut ciphertext = vec![0; out_len];
        let ret = unsafe {
            EVP_PKEY_encrypt(
                pctx.as_mut_ptr(),
                ciphertext.as_mut_ptr(),
                &raw mut out_len,
                plaintext.as_ptr(),
                plaintext.len(),
            )
        };
        if ret != 1 || out_len > ciphertext.len() {
            return Err(JoseError::InvalidKey(
                "RSA encryption failed for the supplied key and plaintext".into(),
            ));
        }
        ciphertext.truncate(out_len);
        Ok(ciphertext.into_boxed_slice())
    }

    pub(crate) fn rsa_decrypt(
        &self,
        padding: RsaPadding,
        digest_alg: digest::Algorithm,
        ciphertext: &[u8],
    ) -> Result<mem::ZeroizingVec, JoseError> {
        let mut pctx = self.rsaes_init(false, padding, digest_alg)?;

        // Determine the maximum length of the plaintext.
        let mut out_len = 0;
        if 1 != unsafe {
            EVP_PKEY_decrypt(
                pctx.as_mut_ptr(),
                ptr::null_mut(),
                &raw mut out_len,
                ciphertext.as_ptr(),
                ciphertext.len(),
            )
        } {
            return Err(JoseError::IntegrityError(
                "asymmetric decryption failed".into(),
            ));
        }

        let mut plaintext = mem::ZeroizingVec::new(vec![0; out_len]);
        let ret = unsafe {
            EVP_PKEY_decrypt(
                pctx.as_mut_ptr(),
                plaintext.as_mut_slice().as_mut_ptr(),
                &raw mut out_len,
                ciphertext.as_ptr(),
                ciphertext.len(),
            )
        };
        if ret != 1 || out_len > plaintext.len() {
            return Err(JoseError::IntegrityError(
                "asymmetric decryption failed (ciphertext integrity check failed)".into(),
            ));
        }

        plaintext.truncate(out_len);
        Ok(plaintext)
    }

    pub(crate) fn get_ec_curve(&self) -> Option<Curve> {
        self.ec()?.curve()
    }
}

unsafe impl Send for EvpPkey {}
unsafe impl Sync for EvpPkey {}

impl PartialEq for EvpPkey {
    /// Only compares params and public key
    fn eq(&self, other: &Self) -> bool {
        // EVP_PKEY_cmp only compares params and public key
        1 == unsafe { EVP_PKEY_cmp(self.as_ptr(), other.as_ptr()) }
    }
}

impl Clone for EvpPkey {
    fn clone(&self) -> Self {
        assert_eq!(1, unsafe { EVP_PKEY_up_ref(self.0.as_ptr()) });
        Self(self.0)
    }
}

impl Drop for EvpPkey {
    fn drop(&mut self) {
        unsafe {
            EVP_PKEY_free(self.as_mut_ptr());
        }
    }
}

struct EvpPkeyCtx(ptr::NonNull<EVP_PKEY_CTX>);

impl EvpPkeyCtx {
    fn new(key_type: EvpPkeyType) -> Self {
        let ptr = unsafe { EVP_PKEY_CTX_new_id(key_type.into(), ptr::null_mut()) };
        Self(ptr::NonNull::new(ptr).expect("EVP_PKEY_CTX_new_id() failed"))
    }

    fn from_key(key: &EvpPkey) -> Self {
        Self::try_from_key(key).expect("EVP_PKEY_CTX_new() failed")
    }

    fn try_from_key(key: &EvpPkey) -> Result<Self, JoseError> {
        // EVP_PKEY_CTX_new() increments the reference count of the key
        // so we dont need to specify a lifetime for the EvpPkey reference
        let ptr = unsafe { EVP_PKEY_CTX_new(key.0.as_ptr(), ptr::null_mut()) };
        ptr::NonNull::new(ptr)
            .map(Self)
            .ok_or_else(|| JoseError::InvalidKey("could not initialize key operation".into()))
    }

    fn as_mut_ptr(&mut self) -> *mut EVP_PKEY_CTX {
        self.0.as_ptr()
    }

    fn paramgen_init(&mut self) {
        assert_eq!(1, unsafe { EVP_PKEY_paramgen_init(self.as_mut_ptr()) });
    }

    fn set_paramgen_ec_curve(&mut self, curve: Curve) {
        assert!(
            1 == unsafe { EVP_PKEY_CTX_set_ec_paramgen_curve_nid(self.as_mut_ptr(), curve.into()) },
            "EVP_PKEY_CTX_set_ec_paramgen_curve_nid() failed"
        );
    }

    fn paramgen(&mut self) -> EvpPkey {
        let mut evp_pkey_ptr = ptr::null_mut::<EVP_PKEY>();
        unsafe {
            assert!(
                1 == EVP_PKEY_paramgen(self.as_mut_ptr(), &raw mut evp_pkey_ptr),
                "EVP_PKEY_paramgen() failed"
            );
            EvpPkey::from_raw_ptr(evp_pkey_ptr)
        }
    }

    fn keygen_init(&mut self) {
        assert_eq!(1, unsafe { EVP_PKEY_keygen_init(self.as_mut_ptr()) });
    }

    fn set_keygen_rsa_bits(&mut self, bits: u16) {
        assert!(
            1 == unsafe { EVP_PKEY_CTX_set_rsa_keygen_bits(self.as_mut_ptr(), bits.into()) },
            "EVP_PKEY_CTX_set_rsa_keygen_bits() failed"
        );
    }

    fn keygen(&mut self) -> EvpPkey {
        let mut evp_pkey_ptr = ptr::null_mut::<EVP_PKEY>();
        unsafe {
            assert!(
                1 == EVP_PKEY_keygen(self.as_mut_ptr(), &raw mut evp_pkey_ptr),
                "EVP_PKEY_keygen() failed"
            );
            EvpPkey::from_raw_ptr(evp_pkey_ptr)
        }
    }
}

impl Drop for EvpPkeyCtx {
    fn drop(&mut self) {
        unsafe {
            EVP_PKEY_CTX_free(self.as_mut_ptr());
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::rand::rand_bytes;

    #[cfg(feature = "aws-lc")]
    use aws_lc_sys::{RSA_sign_pss_mgf1, RSA_verify_pss_mgf1};
    #[cfg(all(feature = "boring", not(feature = "aws-lc")))]
    use boring_sys::{RSA_sign_pss_mgf1, RSA_verify_pss_mgf1};

    use super::*;

    #[test]
    fn test_raw_public_key_equality_compares_key_material() {
        let key_type = EvpPkeyType::Ed25519;
        let first = EvpPkey::new_raw_public_key(key_type, &[2; 32]).unwrap();
        let same = EvpPkey::new_raw_public_key(key_type, &[2; 32]).unwrap();
        let different = EvpPkey::new_raw_public_key(key_type, &[3; 32]).unwrap();

        assert!(first == same);
        assert!(first != different);
    }

    #[test]
    fn test_raw_key_import_rejects_wrong_length() {
        for key_type in [EvpPkeyType::Ed25519, EvpPkeyType::X25519] {
            for key in [&[0; 31][..], &[0; 33][..]] {
                assert!(matches!(
                    EvpPkey::new_raw_private_key(key_type, key),
                    Err(JoseError::InvalidKey(_))
                ));
                assert!(matches!(
                    EvpPkey::new_raw_public_key(key_type, key),
                    Err(JoseError::InvalidKey(_))
                ));
            }
        }
    }

    #[cfg(all(feature = "pq-ml-dsa", feature = "aws-lc"))]
    #[test]
    fn test_ml_dsa_raw_public_key_rejects_wrong_length() {
        let params = crate::jwk::ml_dsa::MlDsaParameterSet::MlDsa44;
        assert!(matches!(
            EvpPkey::new_pqdsa_raw_public_key(params, &[0; 32]),
            Err(JoseError::InvalidKey(_))
        ));
    }

    #[test]
    fn test_x25519_rejects_all_zero_peer() {
        let key = EvpPkey::new_raw_private_key(EvpPkeyType::X25519, &[1; 32]).unwrap();
        let peer = EvpPkey::new_raw_public_key(EvpPkeyType::X25519, &[0; 32]).unwrap();
        assert!(matches!(key.derive(&peer), Err(JoseError::InvalidKey(_))));
    }

    #[test]
    fn test_rsa_oaep_rejects_oversized_plaintext() {
        let key = EvpPkey::generate_rsa(2048);
        let plaintext = vec![0; key.key_size_bytes()];
        assert!(matches!(
            key.rsa_encrypt(RsaPadding::Pkcs1Oaep, digest::Algorithm::Sha256, &plaintext),
            Err(JoseError::InvalidKey(_))
        ));
    }

    #[test]
    fn test_rsa_oaep_returns_integrity_error_for_invalid_ciphertext() {
        let key = EvpPkey::generate_rsa(2048);
        let ciphertext = vec![0; key.key_size_bytes()];
        assert!(matches!(
            key.rsa_decrypt(
                RsaPadding::Pkcs1Oaep,
                digest::Algorithm::Sha256,
                &ciphertext
            ),
            Err(JoseError::IntegrityError(_))
        ));
    }

    #[test]
    fn test_rsa_pss_signing_uses_digest_length_salt() {
        let key = EvpPkey::generate_rsa(2048);
        let rsa = key.rsa().unwrap();
        let message = b"JOSE RSA-PSS salt length";

        for algorithm in [
            digest::Algorithm::Sha256,
            digest::Algorithm::Sha384,
            digest::Algorithm::Sha512,
        ] {
            let signature = key.sign_rsa_pss(message, algorithm);
            let mut hash_buf = [0; digest::MAX_OUTPUT_LEN];
            let hash = digest::digest_buf(algorithm, message, &mut hash_buf);
            let verified = unsafe {
                RSA_verify_pss_mgf1(
                    rsa.as_ptr().cast_mut(),
                    hash.as_ptr(),
                    hash.len(),
                    algorithm.as_ptr(),
                    algorithm.as_ptr(),
                    RSA_PSS_SALTLEN_DIGEST,
                    signature.as_ptr(),
                    signature.len(),
                )
            };
            assert_eq!(verified, 1);
        }
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    #[allow(clippy::cast_possible_wrap)]
    fn test_rsa_pss_verification_requires_digest_length_salt() {
        let key = EvpPkey::generate_rsa(2048);
        let rsa = key.rsa().unwrap();
        let message = b"JOSE RSA-PSS salt length";

        for algorithm in [
            digest::Algorithm::Sha256,
            digest::Algorithm::Sha384,
            digest::Algorithm::Sha512,
        ] {
            let mut hash_buf = [0; digest::MAX_OUTPUT_LEN];
            let hash = digest::digest_buf(algorithm, message, &mut hash_buf);
            for salt_len in [0, 1, hash.len() as i32, -2] {
                let mut signature = vec![0; key.key_size_bytes()];
                let mut signature_len = signature.len();
                let signed = unsafe {
                    RSA_sign_pss_mgf1(
                        rsa.as_ptr().cast_mut(),
                        &raw mut signature_len,
                        signature.as_mut_ptr(),
                        signature.len(),
                        hash.as_ptr(),
                        hash.len(),
                        algorithm.as_ptr(),
                        algorithm.as_ptr(),
                        salt_len,
                    )
                };
                assert_eq!(signed, 1);
                signature.truncate(signature_len);
                assert_eq!(
                    key.verify_rsa_pss(message, algorithm, &signature),
                    salt_len == hash.len() as i32,
                );
            }
        }
    }

    // BoringSSL does not parse RSASSA-PSS SPKIs.
    #[cfg(feature = "aws-lc")]
    #[test]
    fn test_rsa_pss_restricted_key_with_incompatible_salt_fails_closed() {
        // RSASSA-PSS SPKI restricted to SHA-256/MGF1-SHA-256 with a 64-byte minimum salt.
        let pem = "-----BEGIN PUBLIC KEY-----
MIIBVjBBBgkqhkiG9w0BAQowNKAPMA0GCWCGSAFlAwQCAQUAoRwwGgYJKoZIhvcN
AQEIMA0GCWCGSAFlAwQCAQUAogMCAUADggEPADCCAQoCggEBALw2fPy8DUz6nnvi
TpqThTkSKpTlQj5U4QholCR7WVvUISd75q4k/zuHFe2Mzc1eXfJu0jRkfzMNyUF8
/jJRx3AcKW7l+sSN5uoBtB16D0uKvaCcTqGjGQs+M8d2+5G6N1n8PrLA7UZO5Z6u
tVc68PDmLvCMfab73g6tboDpXXOmN0okuofKhDEDVyBWDvVe+CVL88URFB5xm5qX
IOE5lcYl6WtM47vKEGThVBdev4vE291PgAopzQGjS8WQ3X71mpgFWmywTLk3q4zK
ctK/F9tZ169/SnmFBh6003SI3XLD1FA1TkdWH9PkgiMgDi2DA0yZ+RdjZLsCnCbB
FjsRvi0CAwEAAQ==
-----END PUBLIC KEY-----
";
        let crate::jwk::JsonWebKey::Rsa(key) = crate::jwk::JsonWebKey::from_pem(pem).unwrap()
        else {
            panic!("expected an RSA key");
        };
        assert!(!key.verify_rsa_pss(b"message", digest::Algorithm::Sha256, &[0; 256]));
        assert!(!key.verify_rsa_pss(b"message", digest::Algorithm::Sha512, &[0; 256]));
    }

    #[test]
    fn test_generate_rsa() {
        for bits in [2048, 3072, 4096] {
            let rsa = EvpPkey::generate_rsa(bits);
            assert_eq!(rsa.key_type(), EvpPkeyType::Rsa);
            assert_eq!(rsa.key_size_bits(), bits.into());
        }
    }

    #[test]
    fn test_generate_ec() {
        #[cfg(not(feature = "boring"))]
        for curve in [Curve::P256, Curve::P384, Curve::P521, Curve::Secp256k1] {
            let size = match curve {
                Curve::P256 => 256,
                Curve::P384 => 384,
                Curve::P521 => 521,
                Curve::Secp256k1 => 256,
            };

            let ec = EvpPkey::generate_ec(curve);
            assert_eq!(ec.key_type(), EvpPkeyType::Ec);
            assert_eq!(ec.key_size_bits(), size);
        }
        #[cfg(feature = "boring")]
        for curve in [Curve::P256, Curve::P384, Curve::P521] {
            let size = match curve {
                Curve::P256 => 256,
                Curve::P384 => 384,
                Curve::P521 => 521,
            };

            let ec = EvpPkey::generate_ec(curve);
            assert_eq!(ec.key_type(), EvpPkeyType::Ec);
            assert_eq!(ec.key_size_bits(), size);
        }
    }

    #[test]
    fn test_generate_ed25519() {
        let ed25519 = EvpPkey::generate_ed25519();
        assert_eq!(ed25519.key_type(), EvpPkeyType::Ed25519);
        assert_eq!(ed25519.key_size_bits(), 253);
    }

    #[test]
    fn test_generate_x25519() {
        let x25519 = EvpPkey::generate_x25519();
        assert_eq!(x25519.key_type(), EvpPkeyType::X25519);
        assert_eq!(x25519.key_size_bits(), 253);
    }

    #[test]
    fn test_key_to_pem() {
        let rsa = EvpPkey::generate_rsa(2048);
        let ec = EvpPkey::generate_ec(Curve::P256);
        let eddsa = EvpPkey::generate_ed25519();

        for key in [rsa, ec, eddsa] {
            assert!(
                key.private_key_to_pem()
                    .unwrap()
                    .starts_with("-----BEGIN PRIVATE KEY-----")
            );
            print!("{}", key.private_key_to_pem().unwrap());
            assert!(
                key.public_key_to_pem()
                    .unwrap()
                    .starts_with("-----BEGIN PUBLIC KEY-----")
            );
        }
    }

    #[test]
    fn test_get_raw() {
        let evp = EvpPkey::generate_rsa(2048);
        assert!(evp.get_raw_public_key().is_none());
        assert!(evp.get_raw_private_key().is_none());

        let evp = EvpPkey::generate_ed25519();
        assert!(evp.get_raw_public_key().is_some());
        assert!(evp.get_raw_private_key().is_some());
    }

    #[test]
    fn test_rsaes() {
        let evp = EvpPkey::generate_rsa(2048);

        for (padding, md) in [
            (RsaPadding::Pkcs1, digest::Algorithm::Sha1),
            (RsaPadding::Pkcs1Oaep, digest::Algorithm::Sha1),
            (RsaPadding::Pkcs1Oaep, digest::Algorithm::Sha256),
            (RsaPadding::Pkcs1Oaep, digest::Algorithm::Sha384),
            (RsaPadding::Pkcs1Oaep, digest::Algorithm::Sha512),
        ] {
            let plain = rand_bytes(64);
            let ciphertext = evp.rsa_encrypt(padding, md, &plain).unwrap();
            let out = evp.rsa_decrypt(padding, md, &ciphertext).unwrap();
            assert_eq!(&*plain, out.as_slice());
            assert!(out.capacity() >= ciphertext.len());
        }
    }

    #[test]
    fn test_derive() {
        let curve = Curve::P256;
        let evp_ec1 = EvpPkey::generate_ec(curve);
        let evp_ec2 = EvpPkey::generate_ec(curve);
        let out = evp_ec1.derive(&evp_ec2).unwrap();
        assert_eq!(out.len(), 32);

        let evp_ec3 = EvpPkey::generate_ec(Curve::P521);
        assert!(evp_ec1.derive(&evp_ec3).is_err());
        let evp_rsa = EvpPkey::generate_rsa(2048);
        assert!(evp_ec1.derive(&evp_rsa).is_err());

        let evp_x25519_1 = EvpPkey::generate_x25519();
        let evp_x25519_2 = EvpPkey::generate_x25519();
        let out = evp_x25519_1.derive(&evp_x25519_2).unwrap();
        assert_eq!(out.len(), 32);
    }
}
