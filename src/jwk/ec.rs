use std::collections::BTreeMap;

use crate::{
    base64,
    crypto::{BigNum, DigestAlgorithm, EcCurve, EcKey, EvpPkey, EvpPkeyType, X509Cert},
    error::JoseError,
    jws::AlgorithmIdentifier,
};

use super::{GetStr, OutputControlLevel};

#[derive(Clone)]
/// An elliptic-curve JSON Web Key (`kty: "EC"`), holding public and optionally
/// private key material on a named NIST curve.
pub struct EcJsonWebKey {
    evp_pkey: EvpPkey,
    alg: Option<AlgorithmIdentifier>,
    key_use: Option<super::KeyUse>,
    key_id: Option<String>,
    x5t: Option<String>,
    x5t_s256: Option<String>,
}

// Redacted Debug: shows key metadata but never the key material.
#[allow(clippy::missing_fields_in_debug)] // intentional: omits key material
impl std::fmt::Debug for EcJsonWebKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EcJsonWebKey")
            .field("kty", &self.key_type())
            .field("crv", &self.curve_name())
            .field("alg", &self.alg())
            .field("use", &self.key_use())
            .field("kid", &self.key_id())
            .field("x5t", &self.x5t())
            .field("private", &self.evp_pkey.ec().map(|k| k.is_private()))
            .finish()
    }
}

impl EcJsonWebKey {
    pub(crate) fn new(evp_pkey: EvpPkey, alg: Option<AlgorithmIdentifier>) -> Self {
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

    /// The algorithm (`alg`) designated for this key, if set.
    pub fn alg(&self) -> Option<&'static str> {
        self.alg.map(|a| a.name())
    }

    /// Serializes the key to DER (private PKCS#8 if private material is held,
    /// otherwise public `SubjectPublicKeyInfo`).
    ///
    /// # Panics
    ///
    /// Panics if the underlying key is not an EC key (only possible if it was
    /// constructed from a non-EC document).
    pub fn to_der(&self) -> Box<[u8]> {
        if self.evp_pkey.ec().unwrap().is_private() {
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

    /// Parses an EC JWK from a PEM-encoded private or public key.
    ///
    /// # Errors
    ///
    /// Returns an error if the PEM is malformed or is not an EC key.
    pub fn from_pem(pem: impl AsRef<str>) -> Result<Self, JoseError> {
        match super::JsonWebKey::from_pem(pem)? {
            super::JsonWebKey::EllipticCurve(jwk) => Ok(jwk),
            _ => Err(JoseError::InvalidKey(
                "PEM does not contain an EC key".into(),
            )),
        }
    }

    /// Builds an EC JWK from the subject public key of a DER-encoded X.509
    /// certificate.
    ///
    /// The certificate is not retained or validated; only its public key is
    /// used. Returns an error if the certificate's public key is not EC.
    ///
    /// # Errors
    ///
    /// Returns an error if the DER is not a valid X.509 certificate or the
    /// certificate's public key is not EC.
    pub fn from_x509_der(der: &[u8]) -> Result<Self, JoseError> {
        Self::from_x509_cert(&X509Cert::from_der(der)?)
    }

    /// Builds an EC JWK from the subject public key of a PEM-encoded X.509
    /// certificate.
    ///
    /// The certificate is not retained or validated; only its public key is
    /// used. Returns an error if the certificate's public key is not EC.
    ///
    /// # Errors
    ///
    /// Returns an error if the PEM is not a valid X.509 certificate or the
    /// certificate's public key is not EC.
    pub fn from_x509_pem(pem: impl AsRef<str>) -> Result<Self, JoseError> {
        Self::from_x509_cert(&X509Cert::from_pem(pem.as_ref().as_bytes())?)
    }

    fn from_x509_cert(cert: &X509Cert) -> Result<Self, JoseError> {
        let pkey = cert.public_key()?;
        if pkey.key_type() != EvpPkeyType::Ec {
            return Err(JoseError::InvalidKey(
                "certificate public key is not an EC key".into(),
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
    /// # Panics
    ///
    /// Panics if the underlying key is not an EC key (only possible if it was
    /// constructed from a non-EC document).
    pub fn to_json(&self, level: super::OutputControlLevel) -> String {
        use super::OutputControlLevel;

        let curve = self.get_curve();
        let coordinate_len = curve.coordinate_len();
        let b64_coordinate_len = base64::url_encode_size(coordinate_len);

        let ec = self.evp_pkey.ec().unwrap();
        let (x, y) = ec.pub_key_affine();
        let d = match level {
            OutputControlLevel::IncludePrivate => ec.priv_key(),
            _ => None,
        };

        // {"kty":"EC","crv":"<crv>","x":"<b64>","y":"<b64>"} plus optional
        // ,"alg":"<alg>", ,"use":"<use>", ,"kid":"<id>", ,"x5t":"<tp>",
        // ,"x5t#S256":"<tp>" and ,"d":"<b64>"
        let alg_len = self.alg.map_or(0, |a| 9 + a.name().len());
        let use_len = self.key_use.map_or(0, |u| 8 + u.as_str().len());
        let kid_len = self.key_id.as_ref().map_or(0, |v| 8 + v.len());
        let x5t_len = self.x5t.as_ref().map_or(0, |v| 8 + v.len());
        let x5t_s256_len = self.x5t_s256.as_ref().map_or(0, |v| 13 + v.len());
        let d_len = d.as_ref().map_or(0, |_| 6 + b64_coordinate_len);
        let mut out = String::with_capacity(
            27 + curve.jose_name().len()
                + (2 * b64_coordinate_len)
                + alg_len
                + use_len
                + kid_len
                + x5t_len
                + x5t_s256_len
                + d_len,
        );

        out.push_str("{\"kty\":\"EC\",\"crv\":\"");
        out.push_str(curve.jose_name());
        out.push('"');
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
        out.push_str(",\"x\":\"");
        // SAFETY: base64url output is pure ASCII, always valid UTF-8.
        // Bind to a local so the temporary lives for the duration of push_str
        // (edition 2024 enforces this for `&` of owned temporaries).
        let x_b64 = x.to_b64_padded(coordinate_len);
        out.push_str(unsafe { std::str::from_utf8_unchecked(&x_b64) });
        out.push_str("\",\"y\":\"");
        let y_b64 = y.to_b64_padded(coordinate_len);
        out.push_str(unsafe { std::str::from_utf8_unchecked(&y_b64) });
        out.push('"');
        if let Some(d) = d {
            out.push_str(",\"d\":\"");
            let d_b64 = d.to_b64_padded(coordinate_len);
            out.push_str(unsafe { std::str::from_utf8_unchecked(&d_b64) });
            out.push('"');
        }
        out.push('}');
        out
    }

    /// The JWK key type: always `"EC"`.
    pub fn key_type(&self) -> &'static str {
        "EC"
    }

    /// Signs a message with ECDSA using the given digest, producing the JWS
    /// raw (concatenated `r || s`) signature form.
    ///
    /// # Panics
    ///
    /// Panics if the underlying key is not an EC key (only possible if it was
    /// constructed from a non-EC document).
    pub fn sign(&self, message: &[u8], digest_alg: DigestAlgorithm) -> Box<[u8]> {
        let ec = self.evp_pkey.ec().unwrap();
        ec.sign_concatenated(message, digest_alg)
    }

    /// Verifies an ECDSA signature (JWS raw `r || s` form) over a message.
    ///
    /// # Panics
    ///
    /// Panics if the underlying key is not an EC key (only possible if it was
    /// constructed from a non-EC document).
    pub fn verify(&self, message: &[u8], digest_alg: DigestAlgorithm, signature: &[u8]) -> bool {
        let expected_len = match digest_alg {
            DigestAlgorithm::Sha256 => 64,
            DigestAlgorithm::Sha384 => 96,
            DigestAlgorithm::Sha512 => 132,
            _ => 0,
        };
        if signature.len() != expected_len {
            return false;
        }

        let ec = self.evp_pkey.ec().unwrap();
        ec.verify_concatenated(message, digest_alg, signature)
    }

    pub(super) fn from_map(value: impl GetStr) -> Result<Self, JoseError> {
        // Decode coordinates to raw bytes first so the exact field-octet length
        // can be enforced (RFC 7518 Section 6.2.1: coordinates MUST be exactly
        // the field size; a BigNum value alone loses the encoded length).
        let curve = value
            .get("crv")
            .ok_or_else(|| JoseError::InvalidKey("missing 'crv' parameter".to_string()))?;
        let curve: EcCurve = curve.try_into()?;
        let coord_len = curve.coordinate_len();

        let decode_coord = |key: &str| -> Result<BigNum, JoseError> {
            let encoded = value
                .get(key)
                .ok_or_else(|| JoseError::InvalidKey(format!("missing '{key}' parameter")))?;
            let bytes = crate::base64::url_decode(encoded)?;
            if bytes.len() != coord_len {
                return Err(JoseError::InvalidKey(format!(
                    "'{key}' coordinate is {} bytes but {coord_len} are required for {curve:?}",
                    bytes.len()
                )));
            }
            Ok(bytes.as_ref().into())
        };

        let x = decode_coord("x")?;
        let y = decode_coord("y")?;
        let d = value.get("d").map(BigNum::from_b64).transpose()?;

        let mut ec_key = EcKey::new(curve);
        let private = d.is_some();
        ec_key.set_pub_key(x, y)?;
        if private {
            ec_key.set_priv_key(d.unwrap())?;
        }
        ec_key.check_key()?;

        let alg = match value.get("alg") {
            Some(alg) => match alg {
                "ES256" => Some(AlgorithmIdentifier::EcdsaUsingP256CurveAndSha256),
                "ES384" => Some(AlgorithmIdentifier::EcdsaUsingP384CurveAndSha384),
                "ES512" => Some(AlgorithmIdentifier::EcdsaUsingP521CurveAndSha512),
                #[cfg(not(feature = "boring"))]
                "ES256K" => Some(AlgorithmIdentifier::EcdsaUsingSecp256k1CurveAndSha256),
                _ => return Err(JoseError::InvalidAlgorithm(format!("invalid 'alg' {alg}"))),
            },
            None => None,
        };

        let mut jwk = Self::new(EvpPkey::from_ec_key(ec_key), alg);
        jwk.x5t = value.get("x5t").map(str::to_string);
        jwk.x5t_s256 = value.get("x5t#S256").map(str::to_string);
        jwk.key_id = value.get("kid").map(str::to_string);
        jwk.key_use = value.get("use").map(str::parse).transpose()?;
        Ok(jwk)
    }

    pub(crate) fn evp_pkey(&self) -> &EvpPkey {
        &self.evp_pkey
    }

    pub(crate) fn get_curve(&self) -> EcCurve {
        self.evp_pkey.get_ec_curve().unwrap()
    }

    /// The JOSE curve name (`crv`): `P-256`, `P-384`, `P-521`, or `secp256k1`.
    pub fn curve_name(&self) -> &'static str {
        self.get_curve().jose_name()
    }
}

impl TryFrom<BTreeMap<String, String>> for EcJsonWebKey {
    type Error = JoseError;

    fn try_from(value: BTreeMap<String, String>) -> Result<Self, Self::Error> {
        EcJsonWebKey::from_map(value)
    }
}
