//! ML-DSA (`kty: "AKP"`) JSON Web Key support (RFC 9964).
//!
//! An AKP key carries an ML-DSA public key (`pub`) and, optionally, the
//! 32-byte seed form of the private key (`priv`). RFC 9964 Section 4 mandates the
//! seed form -- *not* the expanded private key. AWS-LC accepts the seed via
//! `EVP_PKEY_pqdsa_new_raw_private_key` and stores it under the hood, so we
//! can round-trip `priv` through the `EVP_PKEY` representation.
//!
//! Three parameter sets are supported:
//! - `ML-DSA-44` (security category 2)
//! - `ML-DSA-65` (security category 3)
//! - `ML-DSA-87` (security category 5)
//!
//! This module is gated on the `pq-ml-dsa` feature (which itself requires
//! `aws-lc`); the `boring` backend does not expose `NID_MLDSA*` upstream.

use std::collections::BTreeMap;

use crate::{
    base64,
    crypto::{EvpPkey, EvpPkeyType, MlDsaKey},
    error::JoseError,
    jws::AlgorithmIdentifier,
};

/// The ML-DSA parameter sets defined by FIPS 204, in ascending strength order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MlDsaParameterSet {
    /// ML-DSA-44 (security category 2). Public key: 1312 bytes. Signature: 2420 bytes.
    MlDsa44,
    /// ML-DSA-65 (security category 3). Public key: 1952 bytes. Signature: 3309 bytes.
    MlDsa65,
    /// ML-DSA-87 (security category 5). Public key: 2592 bytes. Signature: 4627 bytes.
    MlDsa87,
}

impl MlDsaParameterSet {
    /// Returns the JOSE algorithm name (`ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87`).
    pub fn jose_name(self) -> &'static str {
        match self {
            MlDsaParameterSet::MlDsa44 => "ML-DSA-44",
            MlDsaParameterSet::MlDsa65 => "ML-DSA-65",
            MlDsaParameterSet::MlDsa87 => "ML-DSA-87",
        }
    }

    /// The public-key byte length (FIPS 204).
    pub fn public_key_len(self) -> usize {
        match self {
            MlDsaParameterSet::MlDsa44 => 1312,
            MlDsaParameterSet::MlDsa65 => 1952,
            MlDsaParameterSet::MlDsa87 => 2592,
        }
    }

    /// The signature byte length (FIPS 204).
    pub fn signature_len(self) -> usize {
        match self {
            MlDsaParameterSet::MlDsa44 => 2420,
            MlDsaParameterSet::MlDsa65 => 3309,
            MlDsaParameterSet::MlDsa87 => 4627,
        }
    }

    /// The seed byte length (FIPS 204). Per RFC 9964 Section 4 the JWK `priv`
    /// member MUST be exactly this many bytes; AWS-LC re-expands the seed
    /// internally on key load.
    pub const SEED_LEN: usize = 32;

    /// Returns the parameter set for a given JOSE algorithm name.
    ///
    /// # Errors
    ///
    /// Returns an error if `name` is not one of `"ML-DSA-44"`, `"ML-DSA-65"`,
    /// or `"ML-DSA-87"`.
    pub fn from_jose_name(name: &str) -> Result<Self, JoseError> {
        match name {
            "ML-DSA-44" => Ok(MlDsaParameterSet::MlDsa44),
            "ML-DSA-65" => Ok(MlDsaParameterSet::MlDsa65),
            "ML-DSA-87" => Ok(MlDsaParameterSet::MlDsa87),
            _ => Err(JoseError::InvalidAlgorithm(format!(
                "unsupported ML-DSA algorithm '{name}'"
            ))),
        }
    }

    /// Returns the parameter set for a given raw public-key byte length.
    /// Each FIPS 204 parameter set has a unique public-key size, so length
    /// is a sufficient discriminator.
    pub(crate) fn from_public_key_len(len: usize) -> Result<Self, JoseError> {
        match len {
            1312 => Ok(MlDsaParameterSet::MlDsa44),
            1952 => Ok(MlDsaParameterSet::MlDsa65),
            2592 => Ok(MlDsaParameterSet::MlDsa87),
            other => Err(JoseError::InvalidKey(format!(
                "unrecognized ML-DSA public-key length: {other} bytes"
            ))),
        }
    }
}

use super::{GetStr, JwkAlgorithm, OutputControlLevel};

/// An AKP JSON Web Key (`kty: "AKP"`), holding an ML-DSA public key and,
/// optionally, the 32-byte seed form of its private key (RFC 9964 Section 4).
#[derive(Clone)]
pub struct MlDsaJsonWebKey {
    evp_pkey: EvpPkey,
    alg: JwkAlgorithm,
    key_use: Option<super::KeyUse>,
    key_id: Option<String>,
    x5t: Option<String>,
    x5t_s256: Option<String>,
}

impl std::fmt::Debug for MlDsaJsonWebKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MlDsaJsonWebKey")
            .field("kty", &self.key_type())
            .field("alg", &self.alg())
            .field("use", &self.key_use())
            .field("kid", &self.key_id())
            .field("x5t", &self.x5t())
            .finish()
    }
}

impl MlDsaJsonWebKey {
    pub(crate) fn new(evp_pkey: EvpPkey) -> Self {
        let algorithm = match evp_pkey.key_type() {
            EvpPkeyType::MlDsa44 => AlgorithmIdentifier::MlDsa44,
            EvpPkeyType::MlDsa65 => AlgorithmIdentifier::MlDsa65,
            EvpPkeyType::MlDsa87 => AlgorithmIdentifier::MlDsa87,
            _ => unreachable!("MlDsaJsonWebKey must contain an ML-DSA key"),
        };
        Self {
            evp_pkey,
            alg: algorithm.into(),
            key_use: None,
            key_id: None,
            x5t: None,
            x5t_s256: None,
        }
    }

    /// Builds an ML-DSA JWK from a 32-byte seed (RFC 9964 Section 4 private-key form).
    ///
    /// The public key is derived from the seed by the crypto backend.
    /// The mandatory `alg` member is derived from `params`; usage and key-ID
    /// metadata are left unset.
    ///
    /// # Errors
    ///
    /// Returns an error if the seed is not exactly 32 bytes or the backend
    /// rejects it.
    pub fn from_seed(params: MlDsaParameterSet, seed: impl AsRef<[u8]>) -> Result<Self, JoseError> {
        let mut seed =
            crate::crypto::mem::Zeroizing::new(seed.as_ref().to_vec().into_boxed_slice());
        // `MlDsaKey::from_seed` zeroes its own copy of the seed, but we zero
        // ours defensively in case the caller dropped it without using this
        // helper.
        let key = MlDsaKey::from_seed(params, &mut seed)?;
        // The `EvpPkey` we expose to JWK callers is the same underlying
        // `EVP_PKEY` pointer; both wrappers independently call `EVP_PKEY_free`
        // on drop, which would double-free. Move the key into a raw pointer
        // and re-wrap on this side so only one owner exists.
        let raw = key.into_raw();
        Ok(Self::new(unsafe { EvpPkey::from_raw_ptr(raw) }))
    }

    /// Builds an ML-DSA JWK from the raw FIPS 204 public-key bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the key length does not match the parameter set's
    /// expected public-key size.
    pub fn from_public_bytes(
        params: MlDsaParameterSet,
        key: impl AsRef<[u8]>,
    ) -> Result<Self, JoseError> {
        let evp_pkey = EvpPkey::new_pqdsa_raw_public_key(params, key.as_ref())?;
        Ok(Self::new(evp_pkey))
    }

    /// Builds an ML-DSA JWK from the FIPS 204 expanded private-key bytes.
    ///
    /// This is provided for symmetric round-tripping of keys that were loaded
    /// from PEM/DER; it is **not** the form required by the JWK `priv`
    /// member, which is always the 32-byte seed per RFC 9964 Section 4. Use
    pub(super) fn from_evp_pkey(evp_pkey: EvpPkey) -> Self {
        Self::new(evp_pkey)
    }

    /// The ML-DSA parameter set for this key, inferred from the FIPS 204
    /// public-key byte length (each set has a unique size).
    ///
    /// # Panics
    ///
    /// Panics if the underlying key's raw public-key length does not match
    /// any FIPS 204 parameter set. This cannot happen for a key constructed
    /// through this module's public API, which validates the length up
    /// front (`from_public_bytes`, `from_map`) or derives it from a
    /// backend-generated key (`from_seed`, key generation).
    pub fn parameter_set(&self) -> MlDsaParameterSet {
        // Recover the parameter set by reading the raw public key and
        // matching its length. We use the crypto helper for size.
        let raw = self.public_key_bytes();
        match raw.len() {
            1312 => MlDsaParameterSet::MlDsa44,
            1952 => MlDsaParameterSet::MlDsa65,
            2592 => MlDsaParameterSet::MlDsa87,
            _ => panic!(
                "MlDsaJsonWebKey public key has an unexpected length ({} bytes)",
                raw.len()
            ),
        }
    }

    /// Returns an owned copy of the FIPS 204 raw public-key bytes.
    // Every `MlDsaJsonWebKey` is constructed from a PQDSA `EVP_PKEY` (via
    // generation, seed import, raw public bytes, or an existing EvpPkey of
    // one of the MlDsa44/65/87 types), so `get_raw_public_key` always
    // succeeds; the `expect` cannot actually panic.
    #[allow(clippy::missing_panics_doc)]
    pub fn public_key_bytes(&self) -> Box<[u8]> {
        self.evp_pkey
            .get_raw_public_key()
            .expect("ML-DSA keys must have a raw public key")
    }

    /// Returns the 32-byte ML-DSA seed (RFC 9964 Section 4 form), or `None` for a
    /// public-only key.
    pub fn seed_bytes(&self) -> Option<Box<[u8]>> {
        self.evp_pkey.get_ml_dsa_seed()
    }

    /// Signs a message using the pure ML-DSA mode.
    ///
    /// # Errors
    ///
    /// Returns an error if the key holds no private material or the backend
    /// refuses to initialize signing.
    pub fn sign(&self, message: &[u8]) -> Result<Box<[u8]>, JoseError> {
        self.evp_pkey.sign_ml_dsa(message)
    }

    /// Verifies an ML-DSA signature over a message.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        self.evp_pkey.verify_ml_dsa(message, signature)
    }

    /// The key ID (`kid`), if set.
    pub fn key_id(&self) -> Option<&str> {
        self.key_id.as_deref()
    }

    /// Sets the key ID (`kid`).
    pub fn set_key_id(&mut self, key_id: impl Into<String>) {
        self.key_id = Some(key_id.into());
    }

    /// The key usage (`use`), if set.
    pub fn key_use(&self) -> Option<super::KeyUse> {
        self.key_use
    }

    /// Sets the key usage (`use`).
    pub fn set_key_use(&mut self, key_use: super::KeyUse) {
        self.key_use = Some(key_use);
    }

    /// The X.509 certificate SHA-1 thumbprint (`x5t`), if this key was built
    /// from a certificate. Always `None` for ML-DSA keys loaded from
    /// `JsonWebKey::from_pem` / `from_der`, since AWS-LC does not currently
    /// surface the issuer chain through the `EVP_PKEY_pqdsa_*` path.
    pub fn x5t(&self) -> Option<&str> {
        self.x5t.as_deref()
    }

    /// The X.509 certificate SHA-256 thumbprint (`x5t#S256`), if this key was
    /// built from a certificate.
    pub fn x5t_s256(&self) -> Option<&str> {
        self.x5t_s256.as_deref()
    }

    /// The algorithm (`alg`) fixed by this key's ML-DSA parameter set.
    pub fn alg(&self) -> Option<&str> {
        Some(self.alg.name())
    }

    /// The typed algorithm metadata fixed by this key's ML-DSA parameter set.
    pub fn jwk_algorithm(&self) -> Option<&JwkAlgorithm> {
        Some(&self.alg)
    }

    /// Serializes the key to PEM (PKCS#8 if private material is held,
    /// otherwise `SubjectPublicKeyInfo`).
    ///
    /// # Errors
    ///
    /// Returns an error if private output is requested but the key holds no
    /// private material, or if the backend fails to encode the key.
    pub fn to_pem(&self, level: OutputControlLevel) -> Result<String, JoseError> {
        match level {
            OutputControlLevel::IncludePrivate => {
                self.evp_pkey.private_key_to_pem().map(str::into_string)
            }
            _ => self.evp_pkey.public_key_to_pem().map(str::into_string),
        }
    }

    /// Serializes the key to DER (private PKCS#8 if private material is held,
    /// otherwise public `SubjectPublicKeyInfo`).
    // Every `MlDsaJsonWebKey` holds a valid PQDSA `EVP_PKEY`, which
    // `EVP_marshal_public_key` always supports; the fallback `unwrap` cannot
    // actually panic.
    #[allow(clippy::missing_panics_doc)]
    pub fn to_der(&self) -> Box<[u8]> {
        match self.evp_pkey.private_key_to_der() {
            Ok(der) => der,
            Err(_) => self.evp_pkey.public_key_to_der().unwrap(),
        }
    }

    /// Serializes the key to its JWK JSON form, honoring the given output level.
    pub fn to_json(&self, level: OutputControlLevel) -> String {
        let alg = self.alg.name();
        let alg_len = 9 + alg.len();
        let use_len = self.key_use.map_or(0, |u| 8 + u.as_str().len());
        let kid_len = self.key_id.as_ref().map_or(0, |v| 8 + v.len());
        let x5t_len = self.x5t.as_ref().map_or(0, |v| 8 + v.len());
        let x5t_s256_len = self.x5t_s256.as_ref().map_or(0, |v| 13 + v.len());

        let pub_bytes = self.public_key_bytes();
        let pub_len = 8 + base64::url_encode_size(pub_bytes.len());

        let priv_bytes = match level {
            OutputControlLevel::IncludePrivate => {
                self.seed_bytes().map(crate::crypto::mem::Zeroizing::new)
            }
            _ => None,
        };
        let priv_len = priv_bytes
            .as_ref()
            .map_or(0, |v| 8 + base64::url_encode_size(v.len()));

        let capacity =
            20 + alg_len + use_len + kid_len + x5t_len + x5t_s256_len + pub_len + priv_len;
        let mut out = String::with_capacity(capacity);

        out.push_str("{\"kty\":\"AKP\",\"alg\":\"");
        out.push_str(alg);
        out.push('"');
        if let Some(key_use) = self.key_use {
            out.push_str(",\"use\":\"");
            out.push_str(key_use.as_str());
            out.push('"');
        }
        if let Some(key_id) = &self.key_id {
            out.push_str(",\"kid\":\"");
            out.push_str(key_id);
            out.push('"');
        }
        if let Some(x5t) = &self.x5t {
            out.push_str(",\"x5t\":\"");
            out.push_str(x5t);
            out.push('"');
        }
        if let Some(x5t_s256) = &self.x5t_s256 {
            out.push_str(",\"x5t#S256\":\"");
            out.push_str(x5t_s256);
            out.push('"');
        }
        out.push_str(",\"pub\":\"");
        let pub_b64 = base64::url_encode(&pub_bytes);
        // SAFETY: base64url output is pure ASCII, always valid UTF-8.
        out.push_str(unsafe { std::str::from_utf8_unchecked(&pub_b64) });
        out.push('"');
        if let Some(priv_bytes) = priv_bytes {
            out.push_str(",\"priv\":\"");
            let priv_b64 = crate::crypto::mem::Zeroizing::new(base64::url_encode(&priv_bytes));
            out.push_str(unsafe { std::str::from_utf8_unchecked(&priv_b64) });
            out.push('"');
        }
        out.push('}');
        out
    }

    /// The JWK key type: always `"AKP"`.
    pub fn key_type(&self) -> &'static str {
        "AKP"
    }

    /// The JOSE parameter-set name (`pub` is named by the bound algorithm;
    /// see [`Self::parameter_set`] for the FIPS 204 identifier).
    pub fn curve_name(&self) -> Option<&'static str> {
        Some(self.parameter_set().jose_name())
    }

    pub(super) fn from_map(value: impl GetStr) -> Result<Self, JoseError> {
        let alg = value
            .get("alg")
            .ok_or_else(|| JoseError::InvalidKey("missing 'alg' parameter".to_string()))?;
        let declared_params = MlDsaParameterSet::from_jose_name(alg)?;

        let pub_b64 = value
            .get("pub")
            .ok_or_else(|| JoseError::InvalidKey("missing 'pub' parameter".to_string()))?;
        let pub_bytes: Box<[u8]> = base64::url_decode(pub_b64)?;
        let params = MlDsaParameterSet::from_public_key_len(pub_bytes.len())?;
        if params != declared_params {
            return Err(JoseError::InvalidKey(format!(
                "AKP 'alg' '{alg}' does not match a {}-byte public key",
                pub_bytes.len()
            )));
        }
        // Per RFC 9964 Section 4, the JWK `priv` member is the 32-byte seed form. If
        // the caller supplies a `priv`, verify it round-trips to the same
        // public key as `pub`.
        let priv_bytes = value
            .get("priv")
            .map(|encoded| base64::url_decode(encoded).map(crate::crypto::mem::Zeroizing::new))
            .transpose()?;

        let mut jwk = if let Some(mut seed) = priv_bytes {
            if seed.len() != MlDsaParameterSet::SEED_LEN {
                return Err(JoseError::InvalidKey(format!(
                    "AKP 'priv' must be exactly {} bytes (RFC 9964 Section 4); got {}",
                    MlDsaParameterSet::SEED_LEN,
                    seed.len()
                )));
            }
            let key = MlDsaKey::from_seed(params, &mut seed)?;
            let derived = key.raw_public_key().map_err(|_| {
                JoseError::InvalidKey("could not derive ML-DSA public key from seed".into())
            })?;
            if derived.as_ref() != pub_bytes.as_ref() {
                return Err(JoseError::InvalidKey(
                    "AKP 'priv' seed does not match 'pub'".into(),
                ));
            }
            // Wrap the EVP_PKEY so that ownership stays in this side and we
            // don't double-free when the inner `MlDsaKey` drops.
            let raw = key.into_raw();
            Self::new(unsafe { EvpPkey::from_raw_ptr(raw) })
        } else {
            let evp_pkey = EvpPkey::new_pqdsa_raw_public_key(params, &pub_bytes)?;
            Self::new(evp_pkey)
        };

        jwk.x5t = value.get("x5t").map(str::to_string);
        jwk.x5t_s256 = value.get("x5t#S256").map(str::to_string);
        jwk.key_id = value.get("kid").map(str::to_string);
        jwk.key_use = value.get("use").map(str::parse).transpose()?;
        Ok(jwk)
    }

    pub(crate) fn evp_pkey(&self) -> &EvpPkey {
        &self.evp_pkey
    }
}

impl TryFrom<BTreeMap<String, String>> for MlDsaJsonWebKey {
    type Error = JoseError;

    fn try_from(value: BTreeMap<String, String>) -> Result<Self, Self::Error> {
        MlDsaJsonWebKey::from_map(value)
    }
}
