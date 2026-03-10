use std::{mem::ManuallyDrop, ptr};

#[cfg(feature = "aws-lc")]
use aws_lc_sys::{
    EC_GROUP_get_curve_name, EC_KEY_get0_group, EVP_DigestSign, EVP_DigestSignInit,
    EVP_DigestVerify, EVP_DigestVerifyInit, EVP_PKEY_CTX_free, EVP_PKEY_CTX_new,
    EVP_PKEY_CTX_new_id, EVP_PKEY_CTX_set_ec_paramgen_curve_nid, EVP_PKEY_CTX_set_rsa_keygen_bits,
    EVP_PKEY_CTX_set_rsa_mgf1_md, EVP_PKEY_CTX_set_rsa_oaep_md, EVP_PKEY_CTX_set_rsa_padding,
    EVP_PKEY_assign_EC_KEY, EVP_PKEY_assign_RSA, EVP_PKEY_bits, EVP_PKEY_cmp, EVP_PKEY_decrypt,
    EVP_PKEY_decrypt_init, EVP_PKEY_derive, EVP_PKEY_derive_init, EVP_PKEY_derive_set_peer,
    EVP_PKEY_encrypt, EVP_PKEY_encrypt_init, EVP_PKEY_free, EVP_PKEY_get0_EC_KEY,
    EVP_PKEY_get0_RSA, EVP_PKEY_get_raw_private_key, EVP_PKEY_get_raw_public_key, EVP_PKEY_id,
    EVP_PKEY_keygen, EVP_PKEY_keygen_init, EVP_PKEY_new, EVP_PKEY_new_raw_private_key,
    EVP_PKEY_new_raw_public_key, EVP_PKEY_paramgen, EVP_PKEY_paramgen_init, EVP_PKEY_size,
    EVP_PKEY_up_ref, EVP_marshal_private_key, EVP_marshal_public_key,
    PEM_write_bio_PKCS8PrivateKey, PEM_write_bio_PUBKEY, EVP_PKEY, EVP_PKEY_CTX, EVP_PKEY_DH,
    EVP_PKEY_DSA, EVP_PKEY_EC, EVP_PKEY_ED25519, EVP_PKEY_HKDF, EVP_PKEY_NONE, EVP_PKEY_RSA,
    EVP_PKEY_RSA_PSS, EVP_PKEY_X25519,
};

#[cfg(feature = "boring")]
use boring_sys::{
    EC_GROUP_get_curve_name, EC_KEY_get0_group, EVP_DigestSign, EVP_DigestSignInit,
    EVP_DigestVerify, EVP_DigestVerifyInit, EVP_PKEY_CTX_free, EVP_PKEY_CTX_new,
    EVP_PKEY_CTX_new_id, EVP_PKEY_CTX_set_ec_paramgen_curve_nid, EVP_PKEY_CTX_set_rsa_keygen_bits,
    EVP_PKEY_CTX_set_rsa_mgf1_md, EVP_PKEY_CTX_set_rsa_oaep_md, EVP_PKEY_CTX_set_rsa_padding,
    EVP_PKEY_assign_EC_KEY, EVP_PKEY_assign_RSA, EVP_PKEY_bits, EVP_PKEY_cmp, EVP_PKEY_decrypt,
    EVP_PKEY_decrypt_init, EVP_PKEY_derive, EVP_PKEY_derive_init, EVP_PKEY_derive_set_peer,
    EVP_PKEY_encrypt, EVP_PKEY_encrypt_init, EVP_PKEY_free, EVP_PKEY_get0_EC_KEY,
    EVP_PKEY_get0_RSA, EVP_PKEY_get_raw_private_key, EVP_PKEY_get_raw_public_key, EVP_PKEY_id,
    EVP_PKEY_keygen, EVP_PKEY_keygen_init, EVP_PKEY_new, EVP_PKEY_new_raw_private_key,
    EVP_PKEY_new_raw_public_key, EVP_PKEY_paramgen, EVP_PKEY_paramgen_init, EVP_PKEY_size,
    EVP_PKEY_up_ref, EVP_marshal_private_key, EVP_marshal_public_key,
    PEM_write_bio_PKCS8PrivateKey, PEM_write_bio_PUBKEY, EVP_PKEY, EVP_PKEY_CTX, EVP_PKEY_DH,
    EVP_PKEY_DSA, EVP_PKEY_EC, EVP_PKEY_ED25519, EVP_PKEY_HKDF, EVP_PKEY_NONE, EVP_PKEY_RSA,
    EVP_PKEY_RSA_PSS, EVP_PKEY_X25519,
};

use crate::{
    crypto::{digest, mem, rsa::RsaPadding},
    error::JoseError,
};

use super::{
    bytestring::Cbb,
    curve25519::{ed25519_keypair, x25519_keypair},
    ec::{Curve, EcKey},
    rsa::Rsa,
    Bio,
};

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
        }
    }
}

impl TryFrom<i32> for EvpPkeyType {
    type Error = JoseError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
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
            _ => Err(JoseError::invalid_key("unsupported key type")),
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
        assert!(!ptr.is_null());
        unsafe { Self(ptr::NonNull::new_unchecked(ptr)) }
    }

    pub(crate) fn new_raw_private_key(key_type: EvpPkeyType, key: &mut [u8]) -> Self {
        let ptr = unsafe {
            // the key is duplicated and ownership is not transferred
            EVP_PKEY_new_raw_private_key(key_type.into(), ptr::null_mut(), key.as_ptr(), key.len())
        };
        assert!(!ptr.is_null());
        mem::cleanse(key);
        unsafe { Self(ptr::NonNull::new_unchecked(ptr)) }
    }

    pub(crate) fn new_raw_public_key(key_type: EvpPkeyType, key: &mut [u8]) -> Self {
        let ptr = unsafe {
            // the key is duplicated and ownership is not transferred
            EVP_PKEY_new_raw_public_key(key_type.into(), ptr::null_mut(), key.as_ptr(), key.len())
        };
        assert!(!ptr.is_null());
        mem::cleanse(key);
        unsafe { Self(ptr::NonNull::new_unchecked(ptr)) }
    }

    pub(super) fn from_ptr(ptr: *mut EVP_PKEY) -> Self {
        assert!(!ptr.is_null());
        unsafe { Self(ptr::NonNull::new_unchecked(ptr)) }
    }

    pub(crate) fn from_rsa(mut rsa: Rsa) -> Self {
        let mut pkey = Self::new();
        assert!(
            1 == unsafe { EVP_PKEY_assign_RSA(pkey.as_mut_ptr(), rsa.as_mut_ptr()) },
            "EVP_PKEY_assign_RSA() failed"
        );
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
        let mut out_private_key = [0u8; 64];
        ed25519_keypair(&mut out_public_key, &mut out_private_key);
        EvpPkey::new_raw_private_key(EvpPkeyType::Ed25519, &mut out_private_key[..32])
    }

    pub(crate) fn generate_x25519() -> Self {
        let mut out_public_value = [0u8; 32];
        let mut out_private_key = [0u8; 32];
        x25519_keypair(&mut out_public_value, &mut out_private_key);
        EvpPkey::new_raw_private_key(EvpPkeyType::X25519, &mut out_private_key)
    }

    fn as_mut_ptr(&mut self) -> *mut EVP_PKEY {
        self.0.as_ptr()
    }

    fn as_ptr(&self) -> *const EVP_PKEY {
        self.0.as_ptr()
    }

    pub(crate) fn key_type(&self) -> EvpPkeyType {
        unsafe { EVP_PKEY_id(self.as_ptr()) }.try_into().unwrap()
    }

    fn key_size_bytes(&self) -> usize {
        self.key_size_bits() / 8
    }

    pub(crate) fn key_size_bits(&self) -> usize {
        unsafe { EVP_PKEY_bits(self.as_ptr()) }.try_into().unwrap()
    }

    fn signature_size_bytes(&self) -> usize {
        unsafe { EVP_PKEY_size(self.as_ptr()) }.try_into().unwrap()
    }

    pub(crate) fn sign(&self, message: &[u8], digest: digest::Algorithm) -> Box<[u8]> {
        self.sign_internal(message, Some(digest), false)
    }

    pub(crate) fn sign_rsa_pss(&self, message: &[u8], digest: digest::Algorithm) -> Box<[u8]> {
        self.sign_internal(message, Some(digest), true)
    }

    pub(crate) fn sign_eddsa(&self, message: &[u8]) -> Box<[u8]> {
        self.sign_internal(message, None, false)
    }

    fn sign_internal(
        &self,
        message: &[u8],
        digest_alg: Option<digest::Algorithm>,
        rsa_pss: bool,
    ) -> Box<[u8]> {
        let mut md_ctx = digest::EvpMdCtx::init();
        let mut pctx = ptr::null_mut::<EVP_PKEY_CTX>();

        let md = digest_alg.map_or(ptr::null(), |alg| alg.as_ptr());

        assert!(
            1 == unsafe {
                EVP_DigestSignInit(
                    md_ctx.as_mut_ptr(),
                    &mut pctx,
                    md,
                    ptr::null_mut(),
                    self.0.as_ptr(),
                )
            },
            "EVP_DigestSignInit() failed"
        );

        if rsa_pss {
            assert!(
                1 == unsafe { EVP_PKEY_CTX_set_rsa_padding(pctx, RsaPadding::Pkcs1Pss.into()) },
                "EVP_PKEY_CTX_set_rsa_padding() failed"
            );
            assert!(
                1 == unsafe { EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, md) },
                "EVP_PKEY_CTX_set_rsa_mgf1_md() failed"
            );
        }

        // Determine the maximum length of the signature.
        let mut sig_len = 0;
        assert!(
            1 == unsafe {
                EVP_DigestSign(
                    md_ctx.as_mut_ptr(),
                    ptr::null_mut(),
                    &mut sig_len,
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
                    &mut sig_len,
                    message.as_ptr(),
                    message.len(),
                )
            },
            "EVP_DigestSign() failed"
        );
        unsafe {
            signature.set_len(sig_len);
        }
        signature.into_boxed_slice()
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

        assert!(
            1 == unsafe {
                EVP_DigestVerifyInit(
                    md_ctx.as_mut_ptr(),
                    &mut pctx,
                    md,
                    ptr::null_mut(),
                    self.0.as_ptr(),
                )
            },
            "EVP_DigestVerifyInit() failed"
        );

        if rsa_pss {
            assert!(
                1 == unsafe { EVP_PKEY_CTX_set_rsa_padding(pctx, RsaPadding::Pkcs1Pss.into()) },
                "EVP_PKEY_CTX_set_rsa_padding() failed"
            );
            assert!(
                1 == unsafe { EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, md) },
                "EVP_PKEY_CTX_set_rsa_mgf1_md() failed"
            );
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

    pub(crate) fn derive(&self, peer: &EvpPkey) -> Result<Box<[u8]>, JoseError> {
        let mut pctx = EvpPkeyCtx::from_key(self);
        let mut len = 0usize;
        unsafe {
            assert!(
                1 == EVP_PKEY_derive_init(pctx.as_mut_ptr()),
                "EVP_PKEY_derive_init() failed"
            );
            if 1 != EVP_PKEY_derive_set_peer(pctx.as_mut_ptr(), peer.as_ptr() as *mut EVP_PKEY) {
                return Err(JoseError::InvalidKey(
                    "Invalid peer key type or parameters".into(),
                ));
            }
            assert!(
                1 == EVP_PKEY_derive(pctx.as_mut_ptr(), ptr::null_mut(), &mut len),
                "EVP_PKEY_derive() failed"
            );
        }
        let mut out = Vec::with_capacity(len);
        unsafe {
            if 1 != EVP_PKEY_derive(pctx.as_mut_ptr(), out.as_mut_ptr(), &mut len) {
                return Err(JoseError::InvalidKey(
                    "Invalid peer key type or parameters".into(),
                ));
            }
            out.set_len(len);
        }
        debug_assert!(out.capacity() == len);
        Ok(out.into_boxed_slice())
    }

    pub(crate) fn private_key_to_der(&self) -> Result<Box<[u8]>, JoseError> {
        let mut cbb = Cbb::with_capacity(self.key_size_bytes() * 4);
        if 1 != unsafe { EVP_marshal_private_key(cbb.as_mut_ptr(), self.as_ptr()) } {
            return Err(JoseError::invalid_key("unsupported key type"));
        }
        Ok(cbb.into_boxed_slice())
    }

    pub(crate) fn public_key_to_der(&self) -> Result<Box<[u8]>, JoseError> {
        let mut cbb = Cbb::with_capacity(self.key_size_bytes() * 4);
        if 1 != unsafe { EVP_marshal_public_key(cbb.as_mut_ptr(), self.as_ptr()) } {
            return Err(JoseError::invalid_key("unsupported key type"));
        }
        Ok(cbb.into_boxed_slice())
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
            return Err(JoseError::invalid_key("unsupported key type"));
        }
        // SAFETY: PEM format is guaranteed to be valid UTF-8
        unsafe { Ok(Box::from(std::str::from_utf8_unchecked(bio.as_slice()))) }
    }

    pub(crate) fn public_key_to_pem(&self) -> Result<Box<str>, JoseError> {
        let mut bio = Bio::new();
        if 1 != unsafe {
            PEM_write_bio_PUBKEY(bio.as_mut_ptr(), self.as_ptr() as *const _ as *mut EVP_PKEY)
        } {
            return Err(JoseError::invalid_key("unsupported key type"));
        }
        // SAFETY: PEM format is guaranteed to be valid UTF-8
        unsafe { Ok(Box::from(std::str::from_utf8_unchecked(bio.as_slice()))) }
    }

    pub(crate) fn rsa(&self) -> Option<ManuallyDrop<Rsa>> {
        // EVP_PKEY_get0_RSA() does not increment the reference count and the pointer must not be freed
        let ptr = unsafe { EVP_PKEY_get0_RSA(self.as_ptr()) };
        if ptr.is_null() {
            return None;
        }
        Some(Rsa::from_ptr(ptr).manually_drop())
    }

    pub(crate) fn ec(&self) -> Option<ManuallyDrop<EcKey>> {
        // EVP_PKEY_get0_EC_KEY() does not increment the reference count and the pointer must not be freed
        let ptr = unsafe { EVP_PKEY_get0_EC_KEY(self.as_ptr()) };
        if ptr.is_null() {
            return None;
        }
        Some(EcKey::from_ptr(ptr).manually_drop())
    }

    pub(crate) fn get_raw_private_key(&self) -> Option<Box<[u8]>> {
        let mut need = 0usize;
        if 1 != unsafe { EVP_PKEY_get_raw_private_key(self.as_ptr(), ptr::null_mut(), &mut need) } {
            return None;
        }
        unsafe {
            let mut b = mem::new_boxed_slice(need);
            assert!(
                1 == EVP_PKEY_get_raw_private_key(self.as_ptr(), b.as_mut_ptr(), &mut need),
                "EVP_PKEY_get_raw_private_key() failed"
            );
            Some(b)
        }
    }

    pub(crate) fn get_raw_public_key(&self) -> Option<Box<[u8]>> {
        let mut need = 0usize;
        if 1 != unsafe { EVP_PKEY_get_raw_public_key(self.as_ptr(), ptr::null_mut(), &mut need) } {
            return None;
        }
        unsafe {
            let mut b = mem::new_boxed_slice(need);
            assert!(
                1 == EVP_PKEY_get_raw_public_key(self.as_ptr(), b.as_mut_ptr(), &mut need),
                "EVP_PKEY_get_raw_public_key() failed"
            );
            Some(b)
        }
    }

    fn rsaes_init(
        &self,
        encrypt: bool,
        padding: RsaPadding,
        digest_alg: digest::Algorithm,
    ) -> EvpPkeyCtx {
        let mut pctx = EvpPkeyCtx::from_key(self);
        unsafe {
            if encrypt {
                assert!(
                    1 == EVP_PKEY_encrypt_init(pctx.as_mut_ptr()),
                    "EVP_PKEY_encrypt_init() failed"
                );
            } else {
                assert!(
                    1 == EVP_PKEY_decrypt_init(pctx.as_mut_ptr()),
                    "EVP_PKEY_decrypt_init() failed"
                );
            }
            assert!(
                1 == EVP_PKEY_CTX_set_rsa_padding(pctx.as_mut_ptr(), padding.into()),
                "EVP_PKEY_CTX_set_rsa_padding() failed"
            );
        }
        if padding == RsaPadding::Pkcs1Oaep {
            unsafe {
                assert!(
                    1 == EVP_PKEY_CTX_set_rsa_oaep_md(pctx.as_mut_ptr(), digest_alg.as_ptr()),
                    "EVP_PKEY_CTX_set_rsa_oaep_md() failed"
                );
                assert!(
                    1 == EVP_PKEY_CTX_set_rsa_mgf1_md(pctx.as_mut_ptr(), digest_alg.as_ptr()),
                    "EVP_PKEY_CTX_set_rsa_mgf1_md() failed"
                );
            }
        }
        pctx
    }

    pub(crate) fn rsa_encrypt(
        &self,
        padding: RsaPadding,
        digest_alg: digest::Algorithm,
        plaintext: &[u8],
    ) -> Box<[u8]> {
        let mut pctx = self.rsaes_init(true, padding, digest_alg);

        // Determine the maximum length of the ciphertext.
        let mut out_len = 0;
        assert!(
            1 == unsafe {
                EVP_PKEY_encrypt(
                    pctx.as_mut_ptr(),
                    ptr::null_mut(),
                    &mut out_len,
                    plaintext.as_ptr(),
                    plaintext.len(),
                )
            },
            "EVP_PKEY_encrypt() failed"
        );

        let mut ciphertext = Vec::with_capacity(out_len);
        assert!(
            1 == unsafe {
                EVP_PKEY_encrypt(
                    pctx.as_mut_ptr(),
                    ciphertext.as_mut_ptr(),
                    &mut out_len,
                    plaintext.as_ptr(),
                    plaintext.len(),
                )
            },
            "EVP_PKEY_encrypt() failed"
        );
        unsafe {
            ciphertext.set_len(out_len);
        }
        ciphertext.into_boxed_slice()
    }

    pub(crate) fn rsa_decrypt(
        &self,
        padding: RsaPadding,
        digest_alg: digest::Algorithm,
        ciphertext: &[u8],
    ) -> Result<Box<[u8]>, JoseError> {
        let mut pctx = self.rsaes_init(false, padding, digest_alg);

        // Determine the maximum length of the plaintext.
        let mut out_len = 0;
        assert!(
            1 == unsafe {
                EVP_PKEY_decrypt(
                    pctx.as_mut_ptr(),
                    ptr::null_mut(),
                    &mut out_len,
                    ciphertext.as_ptr(),
                    ciphertext.len(),
                )
            },
            "EVP_PKEY_decrypt() failed"
        );

        let mut plaintext = Vec::with_capacity(out_len);
        let ret = unsafe {
            EVP_PKEY_decrypt(
                pctx.as_mut_ptr(),
                plaintext.as_mut_ptr(),
                &mut out_len,
                ciphertext.as_ptr(),
                ciphertext.len(),
            )
        };
        if ret != 1 {
            return Err(JoseError::new("decryption failed"));
        }

        unsafe {
            plaintext.set_len(out_len);
        }
        Ok(plaintext.into_boxed_slice())
    }

    pub(crate) fn get_ec_curve(&self) -> Option<Curve> {
        let ec_ptr = unsafe { EVP_PKEY_get0_EC_KEY(self.as_ptr()) };
        if ec_ptr.is_null() {
            return None;
        }
        let nid = unsafe {
            let grp_ptr = EC_KEY_get0_group(ec_ptr);
            EC_GROUP_get_curve_name(grp_ptr)
        };
        Some(Curve::from_nid(nid))
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
        assert!(1 == unsafe { EVP_PKEY_up_ref(self.0.as_ptr()) });
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
        assert!(!ptr.is_null());
        unsafe { Self(ptr::NonNull::new_unchecked(ptr)) }
    }

    fn from_key(key: &EvpPkey) -> Self {
        // EVP_PKEY_CTX_new() increments the reference count of the key
        // so we dont need to specify a lifetime for the EvpPkey reference
        let ptr = unsafe { EVP_PKEY_CTX_new(key.0.as_ptr(), ptr::null_mut()) };
        assert!(!ptr.is_null());
        unsafe { Self(ptr::NonNull::new_unchecked(ptr)) }
    }

    fn as_ptr(&self) -> *const EVP_PKEY_CTX {
        self.0.as_ptr()
    }

    fn as_mut_ptr(&mut self) -> *mut EVP_PKEY_CTX {
        self.0.as_ptr()
    }

    fn paramgen_init(&mut self) {
        assert!(1 == unsafe { EVP_PKEY_paramgen_init(self.as_mut_ptr()) });
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
                1 == EVP_PKEY_paramgen(self.as_mut_ptr(), &mut evp_pkey_ptr),
                "EVP_PKEY_paramgen() failed"
            );
        }
        EvpPkey::from_ptr(evp_pkey_ptr)
    }

    fn keygen_init(&mut self) {
        assert!(1 == unsafe { EVP_PKEY_keygen_init(self.as_mut_ptr()) });
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
                1 == EVP_PKEY_keygen(self.as_mut_ptr(), &mut evp_pkey_ptr),
                "EVP_PKEY_keygen() failed"
            );
        }
        EvpPkey::from_ptr(evp_pkey_ptr)
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

    use super::*;

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
            assert!(key
                .private_key_to_pem()
                .unwrap()
                .starts_with("-----BEGIN PRIVATE KEY-----"));
            print!("{}", key.private_key_to_pem().unwrap());
            assert!(key
                .public_key_to_pem()
                .unwrap()
                .starts_with("-----BEGIN PUBLIC KEY-----"));
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
            let ciphertext = evp.rsa_encrypt(padding, md, &plain);
            let out = evp.rsa_decrypt(padding, md, &ciphertext).unwrap();
            assert_eq!(*plain, *out);
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
