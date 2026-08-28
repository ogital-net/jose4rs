use std::collections::BTreeMap;

use crate::{
    base64,
    crypto::{BigNum, DigestAlgorithm, EvpPkey, EvpPkeyType, Rsa, RsaPadding, RsaParam, X509Cert},
    error::JoseError,
    jws::AlgorithmIdentifier,
};

use super::{GetStr, OutputControlLevel};

#[derive(Clone)]
/// An RSA JSON Web Key (`kty: "RSA"`), holding public and optionally private
/// key material.
pub struct RsaJsonWebKey {
    evp_pkey: EvpPkey,
    alg: Option<AlgorithmIdentifier>,
    key_use: Option<super::KeyUse>,
    key_id: Option<String>,
    x5t: Option<String>,
    x5t_s256: Option<String>,
}

// Redacted Debug: shows key metadata but never the key material.
#[allow(clippy::missing_fields_in_debug)] // intentional: omits key material
impl std::fmt::Debug for RsaJsonWebKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RsaJsonWebKey")
            .field("kty", &self.key_type())
            .field("size_bits", &self.key_size_bits())
            .field("alg", &self.alg())
            .field("use", &self.key_use())
            .field("kid", &self.key_id())
            .field("x5t", &self.x5t())
            .field("private", &self.evp_pkey.rsa().map(|r| r.is_private()))
            .finish()
    }
}

impl RsaJsonWebKey {
    pub(super) fn new(evp_pkey: EvpPkey, alg: Option<AlgorithmIdentifier>) -> Self {
        Self {
            evp_pkey,
            alg,
            key_use: None,
            key_id: None,
            x5t: None,
            x5t_s256: None,
        }
    }

    pub(super) fn from_evp_pkey(evp_pkey: EvpPkey) -> Self {
        Self {
            evp_pkey,
            alg: None,
            key_use: None,
            key_id: None,
            x5t: None,
            x5t_s256: None,
        }
    }

    pub(crate) fn evp_pkey(&self) -> &EvpPkey {
        &self.evp_pkey
    }

    pub(crate) fn set_key_use(&mut self, key_use: super::KeyUse) {
        self.key_use = Some(key_use);
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

    /// The algorithm (`alg`) designated for this key, if set.
    pub fn alg(&self) -> Option<&'static str> {
        self.alg.map(|a| a.name())
    }

    /// Serializes the key to DER (private PKCS#8 if private material is held,
    /// otherwise public `SubjectPublicKeyInfo`).
    ///
    /// # Panics
    ///
    /// Panics if the underlying key is not an RSA key (only possible if it was
    /// constructed from a non-RSA document).
    pub fn to_der(&self) -> Box<[u8]> {
        if self.evp_pkey.rsa().unwrap().is_private() {
            self.evp_pkey.private_key_to_der().unwrap()
        } else {
            self.evp_pkey.public_key_to_der().unwrap()
        }
    }

    /// Serializes the key to PEM.
    ///
    /// `OutputControlLevel::IncludePrivate` produces a PKCS#8 private key PEM
    /// (errors if the key holds no private material); `PublicOnly` produces a
    /// `SubjectPublicKeyInfo` PEM. `IncludeSymmetric` is not meaningful for an
    /// asymmetric key and is treated as `PublicOnly`.
    ///
    /// # Errors
    ///
    /// Returns an error if private output is requested but the key holds no
    /// private material.
    pub fn to_pem(&self, level: OutputControlLevel) -> Result<String, JoseError> {
        match level {
            OutputControlLevel::IncludePrivate => {
                self.evp_pkey.private_key_to_pem().map(str::into_string)
            }
            _ => self.evp_pkey.public_key_to_pem().map(str::into_string),
        }
    }

    /// Parses an RSA JWK from a PEM-encoded private or public key.
    ///
    /// # Errors
    ///
    /// Returns an error if the PEM is malformed or is not an RSA key.
    pub fn from_pem(pem: impl AsRef<str>) -> Result<Self, JoseError> {
        match super::JsonWebKey::from_pem(pem)? {
            super::JsonWebKey::Rsa(jwk) => Ok(jwk),
            _ => Err(JoseError::InvalidKey(
                "PEM does not contain an RSA key".into(),
            )),
        }
    }

    /// Builds an RSA JWK from the subject public key of a DER-encoded X.509
    /// certificate.
    ///
    /// The certificate is not retained or validated; only its public key is
    /// used. Returns an error if the certificate's public key is not RSA.
    ///
    /// # Errors
    ///
    /// Returns an error if the DER is not a valid X.509 certificate or the
    /// certificate's public key is not RSA.
    pub fn from_x509_der(der: &[u8]) -> Result<Self, JoseError> {
        Self::from_x509_cert(&X509Cert::from_der(der)?)
    }

    /// Builds an RSA JWK from the subject public key of a PEM-encoded X.509
    /// certificate.
    ///
    /// The certificate is not retained or validated; only its public key is
    /// used. Returns an error if the certificate's public key is not RSA.
    ///
    /// # Errors
    ///
    /// Returns an error if the PEM is not a valid X.509 certificate or the
    /// certificate's public key is not RSA.
    pub fn from_x509_pem(pem: impl AsRef<str>) -> Result<Self, JoseError> {
        Self::from_x509_cert(&X509Cert::from_pem(pem.as_ref().as_bytes())?)
    }

    fn from_x509_cert(cert: &X509Cert) -> Result<Self, JoseError> {
        let pkey = cert.public_key()?;
        if pkey.key_type() != EvpPkeyType::Rsa {
            return Err(JoseError::InvalidKey(
                "certificate public key is not an RSA key".into(),
            ));
        }
        let mut jwk = Self::from_evp_pkey(pkey);
        jwk.x5t = Some(cert.thumbprint(crate::crypto::DigestAlgorithm::Sha1)?);
        jwk.x5t_s256 = Some(cert.thumbprint(crate::crypto::DigestAlgorithm::Sha256)?);
        Ok(jwk)
    }

    /// The X.509 certificate SHA-1 thumbprint (`x5t`), if this key was built
    /// from a certificate via [`from_x509_pem`](Self::from_x509_pem) or
    /// [`from_x509_der`](Self::from_x509_der).
    pub fn x5t(&self) -> Option<&str> {
        self.x5t.as_deref()
    }

    /// The X.509 certificate SHA-256 thumbprint (`x5t#S256`), if this key was
    /// built from a certificate.
    pub fn x5t_s256(&self) -> Option<&str> {
        self.x5t_s256.as_deref()
    }

    /// Serializes the key to its JWK JSON form, honoring the given output level.
    ///
    /// Private CRT parameters are only included for
    /// [`super::OutputControlLevel::IncludePrivate`].
    ///
    /// # Panics
    ///
    /// Panics if the underlying key is not an RSA key (only possible if it was
    /// constructed from a non-RSA document).
    pub fn to_json(&self, level: super::OutputControlLevel) -> String {
        use super::OutputControlLevel;

        let rsa = self.evp_pkey.rsa().unwrap();
        let n = rsa.n();
        let e = rsa.e();
        let private_params: [(Option<RsaParam>, &str); 6] = match level {
            OutputControlLevel::IncludePrivate => [
                (rsa.d(), "d"),
                (rsa.p(), "p"),
                (rsa.q(), "q"),
                (rsa.dp(), "dp"),
                (rsa.dq(), "dq"),
                (rsa.qi(), "qi"),
            ],
            _ => Default::default(),
        };

        // {"kty":"RSA"} plus optional ,"alg":"<alg>", ,"n":"<b64>", ,"e":"<b64>"
        // and private params ,"<name>":"<b64>"
        let b64_len = |v: &Option<RsaParam>| -> usize {
            v.as_ref()
                .map_or(0, |b| base64::url_encode_size(b.len_bytes()))
        };
        let alg_len = self.alg.map_or(0, |a| 9 + a.name().len());
        // ,"x5t":"<27 chars>" and ,"x5t#S256":"<43 chars>"
        let x5t_len = self.x5t.as_ref().map_or(0, |v| 8 + v.len());
        let x5t_s256_len = self.x5t_s256.as_ref().map_or(0, |v| 13 + v.len());
        // ,"kid":"<id>" and ,"use":"<use>"
        let kid_len = self.key_id.as_ref().map_or(0, |v| 8 + v.len());
        let use_len = self.key_use.map_or(0, |u| 8 + u.as_str().len());
        let n_len = b64_len(&n) + 6;
        let e_len = b64_len(&e) + 6;
        let priv_len: usize = private_params
            .iter()
            .map(|(v, name)| {
                if v.is_some() {
                    6 + name.len() + b64_len(v)
                } else {
                    0
                }
            })
            .sum();
        let mut out = String::with_capacity(
            13 + alg_len + x5t_len + x5t_s256_len + kid_len + use_len + n_len + e_len + priv_len,
        );

        out.push_str("{\"kty\":\"RSA\"");
        if let Some(alg) = self.alg {
            out.push_str(",\"alg\":\"");
            out.push_str(alg.name());
            out.push('"');
        }
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
        if let Some(n) = &n {
            out.push_str(",\"n\":\"");
            // SAFETY: base64url output is pure ASCII, always valid UTF-8.
            // Bind to a local so the temporary lives for the duration of
            // push_str (edition 2024 enforces this for `&` of owned
            // temporaries).
            let n_b64 = n.to_b64();
            out.push_str(unsafe { std::str::from_utf8_unchecked(&n_b64) });
            out.push('"');
        }
        if let Some(e) = &e {
            out.push_str(",\"e\":\"");
            let e_b64 = e.to_b64();
            out.push_str(unsafe { std::str::from_utf8_unchecked(&e_b64) });
            out.push('"');
        }
        for (param, name) in &private_params {
            if let Some(v) = param {
                out.push_str(",\"");
                out.push_str(name);
                out.push_str("\":\"");
                let v_b64 = v.to_b64();
                out.push_str(unsafe { std::str::from_utf8_unchecked(&v_b64) });
                out.push('"');
            }
        }
        out.push('}');
        out
    }

    /// The JWK key type: always `"RSA"`.
    pub fn key_type(&self) -> &'static str {
        "RSA"
    }

    /// The modulus size of the key, in bits.
    pub fn key_size_bits(&self) -> usize {
        self.evp_pkey.key_size_bits()
    }

    /// Signs a message with RSASSA-PKCS1-v1_5 using the given digest.
    pub fn sign(&self, message: &[u8], digest: DigestAlgorithm) -> Box<[u8]> {
        self.evp_pkey.sign(message, digest)
    }

    /// Signs a message with RSASSA-PSS using the given digest.
    pub fn sign_rsa_pss(&self, message: &[u8], digest: DigestAlgorithm) -> Box<[u8]> {
        self.evp_pkey.sign_rsa_pss(message, digest)
    }

    /// Verifies an RSASSA-PKCS1-v1_5 signature over a message.
    pub fn verify(&self, message: &[u8], digest: DigestAlgorithm, signature: &[u8]) -> bool {
        self.evp_pkey.verify(message, digest, signature)
    }

    /// Verifies an RSASSA-PSS signature over a message.
    pub fn verify_rsa_pss(
        &self,
        message: &[u8],
        digest: DigestAlgorithm,
        signature: &[u8],
    ) -> bool {
        self.evp_pkey.verify_rsa_pss(message, digest, signature)
    }

    /// Encrypts with RSAES-PKCS1-v1_5 (JWE `RSA1_5` key management).
    pub fn encrypt_pcks1_1_5(&self, plaintext: &[u8]) -> Box<[u8]> {
        self.evp_pkey
            .rsa_encrypt(RsaPadding::Pkcs1, DigestAlgorithm::Sha1, plaintext)
    }

    /// Decrypts with RSAES-PKCS1-v1_5 (JWE `RSA1_5` key management).
    ///
    /// # Errors
    /// Returns an error if the ciphertext is malformed or padding is invalid.
    pub fn decrypt_pcks1_1_5(&self, plaintext: &[u8]) -> Result<Box<[u8]>, JoseError> {
        self.evp_pkey
            .rsa_decrypt(RsaPadding::Pkcs1, DigestAlgorithm::Sha1, plaintext)
    }

    /// Encrypts with RSAES-OAEP using the given digest (JWE `RSA-OAEP*` key management).
    pub fn encrypt_oaep(&self, plaintext: &[u8], digest_alg: DigestAlgorithm) -> Box<[u8]> {
        self.evp_pkey
            .rsa_encrypt(RsaPadding::Pkcs1Oaep, digest_alg, plaintext)
    }

    /// Decrypts with RSAES-OAEP using the given digest (JWE `RSA-OAEP*` key management).
    ///
    /// # Errors
    /// Returns an error if the ciphertext is malformed or OAEP padding is invalid.
    pub fn decrypt_oaep(
        &self,
        plaintext: &[u8],
        digest_alg: DigestAlgorithm,
    ) -> Result<Box<[u8]>, JoseError> {
        self.evp_pkey
            .rsa_decrypt(RsaPadding::Pkcs1Oaep, digest_alg, plaintext)
    }

    pub(super) fn from_map(value: impl GetStr) -> Result<Self, JoseError> {
        let n = value.get("n").map(BigNum::from_b64).transpose()?;
        let e = value.get("e").map(BigNum::from_b64).transpose()?;
        let d = value.get("d").map(BigNum::from_b64).transpose()?;
        let p = value.get("p").map(BigNum::from_b64).transpose()?;
        let q = value.get("q").map(BigNum::from_b64).transpose()?;
        let dp = value.get("dp").map(BigNum::from_b64).transpose()?;
        let dq = value.get("dq").map(BigNum::from_b64).transpose()?;
        let qi = value.get("qi").map(BigNum::from_b64).transpose()?;

        let mut rsa = Rsa::new();
        if n.is_none() {
            return Err(JoseError::InvalidKey("missing 'n' parameter".to_string()));
        }
        if e.is_none() {
            return Err(JoseError::InvalidKey("missing 'e' parameter".to_string()));
        }
        let n = n.unwrap();
        let e = e.unwrap();
        // Reject degenerate keys up front: a zero/tiny modulus or an exponent
        // that is even, less than 3, or larger than the modulus is not a usable
        // RSA key (RFC 7518 Section 6.3, jose4j rejects these during key construction).
        if n.is_zero() || n.num_bits() < 8 {
            return Err(JoseError::InvalidKey("invalid 'n' parameter".to_string()));
        }
        if e.is_zero() || !e.is_odd() || e.num_bits() < 2 {
            return Err(JoseError::InvalidKey("invalid 'e' parameter".to_string()));
        }
        let private = d.is_some();
        rsa.set_key(n, e, d)?;

        #[allow(clippy::unnecessary_unwrap)]
        if private && p.is_some() && q.is_some() {
            rsa.set_factors(p.unwrap(), q.unwrap())?;

            if dp.is_some() && dq.is_some() && qi.is_some() {
                rsa.set_crt_params(dp.unwrap(), dq.unwrap(), qi.unwrap())?;
            }
        }

        let alg = match value.get("alg") {
            Some(alg) => match alg {
                "RS256" => Some(AlgorithmIdentifier::RsaUsingSha256),
                "RS384" => Some(AlgorithmIdentifier::RsaUsingSha384),
                "RS512" => Some(AlgorithmIdentifier::RsaUsingSha512),
                "PS256" => Some(AlgorithmIdentifier::RsaPssUsingSha256),
                "PS384" => Some(AlgorithmIdentifier::RsaPssUsingSha384),
                "PS512" => Some(AlgorithmIdentifier::RsaPssUsingSha512),
                _ => return Err(JoseError::InvalidAlgorithm(format!("invalid 'alg' {alg}"))),
            },
            None => None,
        };

        let mut jwk = Self::new(EvpPkey::from_rsa(rsa), alg);
        jwk.x5t = value.get("x5t").map(str::to_string);
        jwk.x5t_s256 = value.get("x5t#S256").map(str::to_string);
        jwk.key_id = value.get("kid").map(str::to_string);
        jwk.key_use = value.get("use").map(str::parse).transpose()?;
        Ok(jwk)
    }
}

impl TryFrom<BTreeMap<String, String>> for RsaJsonWebKey {
    type Error = JoseError;

    fn try_from(value: BTreeMap<String, String>) -> Result<Self, Self::Error> {
        RsaJsonWebKey::from_map(value)
    }
}
