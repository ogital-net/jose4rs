use std::collections::BTreeMap;

use crate::{
    base64,
    crypto::{curve25519::ed25519_pubkey_is_valid_for_private_key, EvpPkey, EvpPkeyType, X509Cert},
    error::JoseError,
    jws::AlgorithmIdentifier,
};

use super::{GetStr, OutputControlLevel};

#[derive(Clone)]
/// An octet key pair JSON Web Key (`kty: "OKP"`), holding an Ed25519 or
/// X25519 public key and optionally its private counterpart (RFC 8037).
pub struct OkpJsonWebKey {
    evp_pkey: EvpPkey,
    alg: Option<AlgorithmIdentifier>,
    key_use: Option<super::KeyUse>,
    key_id: Option<String>,
    x5t: Option<String>,
    x5t_s256: Option<String>,
}

// Redacted Debug: shows key metadata but never the key material.
impl std::fmt::Debug for OkpJsonWebKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OkpJsonWebKey")
            .field("kty", &self.key_type())
            .field("crv", &self.curve_name())
            .field("alg", &self.alg())
            .field("use", &self.key_use())
            .field("kid", &self.key_id())
            .field("x5t", &self.x5t())
            .finish()
    }
}

impl OkpJsonWebKey {
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
    /// Panics if the key holds private material that cannot be serialized and
    /// its public key cannot be serialized either (not expected to occur).
    pub fn to_der(&self) -> Box<[u8]> {
        match self.evp_pkey.private_key_to_der() {
            Ok(der) => der,
            Err(_) => self.evp_pkey.public_key_to_der().unwrap(),
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

    /// Parses an OKP JWK (Ed25519 or X25519) from a PEM-encoded private or
    /// public key.
    ///
    /// # Errors
    ///
    /// Returns an error if the PEM is malformed or is not an Ed25519 or X25519
    /// key.
    pub fn from_pem(pem: impl AsRef<str>) -> Result<Self, JoseError> {
        match super::JsonWebKey::from_pem(pem)? {
            super::JsonWebKey::OctetKeyPair(jwk) => Ok(jwk),
            _ => Err(JoseError::InvalidKey(
                "PEM does not contain an Ed25519 or X25519 key".into(),
            )),
        }
    }

    /// Builds an OKP JWK from the subject public key of a DER-encoded X.509
    /// certificate.
    ///
    /// The certificate is not retained or validated; only its public key is
    /// used. Returns an error if the certificate's public key is not an
    /// Ed25519 or X25519 key.
    ///
    /// # Errors
    ///
    /// Returns an error if the DER is not a valid X.509 certificate or the
    /// certificate's public key is not an Ed25519 or X25519 key.
    pub fn from_x509_der(der: &[u8]) -> Result<Self, JoseError> {
        Self::from_x509_cert(&X509Cert::from_der(der)?)
    }

    /// Builds an OKP JWK from the subject public key of a PEM-encoded X.509
    /// certificate.
    ///
    /// The certificate is not retained or validated; only its public key is
    /// used. Returns an error if the certificate's public key is not an
    /// Ed25519 or X25519 key.
    ///
    /// # Errors
    ///
    /// Returns an error if the PEM is not a valid X.509 certificate or the
    /// certificate's public key is not an Ed25519 or X25519 key.
    pub fn from_x509_pem(pem: impl AsRef<str>) -> Result<Self, JoseError> {
        Self::from_x509_cert(&X509Cert::from_pem(pem.as_ref().as_bytes())?)
    }

    fn from_x509_cert(cert: &X509Cert) -> Result<Self, JoseError> {
        let pkey = cert.public_key()?;
        match pkey.key_type() {
            EvpPkeyType::Ed25519 | EvpPkeyType::X25519 => {
                let mut jwk = Self::from_evp_pkey(pkey);
                jwk.x5t = Some(cert.thumbprint(crate::crypto::DigestAlgorithm::Sha1)?);
                jwk.x5t_s256 = Some(cert.thumbprint(crate::crypto::DigestAlgorithm::Sha256)?);
                Ok(jwk)
            }
            _ => Err(JoseError::InvalidKey(
                "certificate public key is not an Ed25519 or X25519 key".into(),
            )),
        }
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
    pub fn to_json(&self, level: super::OutputControlLevel) -> String {
        use super::OutputControlLevel;

        let crv = match self.evp_pkey.key_type() {
            EvpPkeyType::Ed25519 => "Ed25519",
            EvpPkeyType::X25519 => "X25519",
            _ => return String::from("{\"kty\":\"OKP\"}"),
        };

        let x = self.evp_pkey.get_raw_public_key();
        let d = match level {
            OutputControlLevel::IncludePrivate => self.evp_pkey.get_raw_private_key(),
            OutputControlLevel::IncludeSymmetric | OutputControlLevel::PublicOnly => None,
        };

        // {"kty":"OKP","crv":"<crv>"} plus optional ,"alg":"<alg>",
        // ,"x5t":"<tp>", ,"x5t#S256":"<tp>", ,"x":"<b64>" and ,"d":"<b64>"
        let alg_len = self.alg.map_or(0, |a| 9 + a.name().len());
        let use_len = self.key_use.map_or(0, |u| 8 + u.as_str().len());
        let kid_len = self.key_id.as_ref().map_or(0, |v| 8 + v.len());
        let x5t_len = self.x5t.as_ref().map_or(0, |v| 8 + v.len());
        let x5t_s256_len = self.x5t_s256.as_ref().map_or(0, |v| 13 + v.len());
        let x_len = x
            .as_ref()
            .map_or(0, |v| 6 + base64::url_encode_size(v.len()));
        let d_len = d
            .as_ref()
            .map_or(0, |v| 6 + base64::url_encode_size(v.len()));
        let mut out = String::with_capacity(
            21 + crv.len() + alg_len + use_len + kid_len + x5t_len + x5t_s256_len + x_len + d_len,
        );

        out.push_str("{\"kty\":\"OKP\",\"crv\":\"");
        out.push_str(crv);
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
        if let Some(x) = x {
            out.push_str(",\"x\":\"");
            // SAFETY: base64url output is pure ASCII, always valid UTF-8.
            // Bind to a local so the temporary lives for the duration of
            // push_str (edition 2024 enforces this for `&` of owned
            // temporaries).
            let x_b64 = base64::url_encode(&x);
            out.push_str(unsafe { std::str::from_utf8_unchecked(&x_b64) });
            out.push('"');
        }
        if let Some(d) = d {
            out.push_str(",\"d\":\"");
            let d_b64 = base64::url_encode(&d);
            out.push_str(unsafe { std::str::from_utf8_unchecked(&d_b64) });
            out.push('"');
        }
        out.push('}');
        out
    }

    /// The JWK key type: always `"OKP"`.
    pub fn key_type(&self) -> &'static str {
        "OKP"
    }

    /// The JOSE curve name (`crv`): `Ed25519` or `X25519`.
    pub fn curve_name(&self) -> &'static str {
        match self.evp_pkey.key_type() {
            EvpPkeyType::Ed25519 => "Ed25519",
            EvpPkeyType::X25519 => "X25519",
            _ => "unknown",
        }
    }

    /// Signs a message with `EdDSA` (Ed25519 only; X25519 is key-agreement only).
    ///
    /// # Errors
    ///
    /// Returns an error if the key is not an Ed25519 private key.
    pub fn sign(&self, message: &[u8]) -> Result<Box<[u8]>, JoseError> {
        self.evp_pkey.sign_eddsa(message)
    }

    /// Verifies an `EdDSA` signature over a message.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        self.evp_pkey.verify_eddsa(message, signature)
    }

    pub(super) fn from_map(value: impl GetStr) -> Result<Self, JoseError> {
        let mut x = value.get("x").map_or_else(
            || Err(JoseError::InvalidKey("missing 'x' parameter".to_string())),
            |v| Ok(base64::url_decode(v)?),
        )?;

        let d = value.get("d").map(base64::url_decode).transpose()?;

        let alg = match value.get("alg") {
            Some(alg) => match alg {
                "EdDSA" => Some(AlgorithmIdentifier::EdDsa),
                _ => return Err(JoseError::InvalidAlgorithm(format!("invalid 'alg' {alg}"))),
            },
            None => None,
        };

        let jwk = match value.get("crv") {
            Some("Ed25519") => {
                if let Some(mut private) = d {
                    if private.len() != 32 {
                        return Err(JoseError::InvalidKey(
                            "invalid 'd' parameter length for Ed25519".to_string(),
                        ));
                    }
                    if !ed25519_pubkey_is_valid_for_private_key(&private, &x) {
                        return Err(JoseError::InvalidKey(
                            "invalid 'x' parameter for Ed25519".to_string(),
                        ));
                    }
                    Ok(OkpJsonWebKey::new(
                        EvpPkey::new_raw_private_key(EvpPkeyType::Ed25519, &mut private),
                        alg,
                    ))
                } else {
                    if x.len() != 32 {
                        return Err(JoseError::InvalidKey(
                            "invalid 'x' parameter length for Ed25519".to_string(),
                        ));
                    }
                    Ok(OkpJsonWebKey::new(
                        EvpPkey::new_raw_public_key(EvpPkeyType::Ed25519, &mut x),
                        alg,
                    ))
                }
            }
            Some("X25519") => {
                if let Some(mut private) = d {
                    if private.len() != 32 {
                        return Err(JoseError::InvalidKey(
                            "invalid 'd' parameter length for X25519".to_string(),
                        ));
                    }
                    Ok(OkpJsonWebKey::new(
                        EvpPkey::new_raw_private_key(EvpPkeyType::X25519, &mut private),
                        alg,
                    ))
                } else {
                    if x.len() != 32 {
                        return Err(JoseError::InvalidKey(
                            "invalid 'x' parameter length for X25519".to_string(),
                        ));
                    }
                    Ok(OkpJsonWebKey::new(
                        EvpPkey::new_raw_public_key(EvpPkeyType::X25519, &mut x),
                        alg,
                    ))
                }
            }
            Some(crv) => Err(JoseError::InvalidKey(format!("unsupported curve '{crv}'"))),
            None => Err(JoseError::InvalidKey("missing 'crv' parameter".to_string())),
        }?;

        let mut jwk = jwk;
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

impl TryFrom<BTreeMap<String, String>> for OkpJsonWebKey {
    type Error = JoseError;

    fn try_from(value: BTreeMap<String, String>) -> Result<Self, Self::Error> {
        OkpJsonWebKey::from_map(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The public entry point for parsing an untrusted JWK; these tests lock in
    // the rejection of malformed OKP keys (wrong lengths, curve mismatches,
    // unsupported curves) so a crafted JWK can never slip an invalid key into
    // the verify/derive path.
    fn parse(json: &str) -> Result<super::super::JsonWebKey, JoseError> {
        super::super::JsonWebKey::from_json(json)
    }

    #[test]
    fn test_from_map() {
        let mut map: BTreeMap<String, String> = BTreeMap::new();
        map.insert("kty".to_string(), "OKP".to_string());
        map.insert("crv".to_string(), "Ed25519".to_string());
        map.insert(
            "d".to_string(),
            "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A".to_string(),
        );
        map.insert(
            "x".to_string(),
            "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo".to_string(),
        );

        let jwk = OkpJsonWebKey::try_from(map).unwrap();
        assert_eq!(jwk.key_type(), "OKP");
        assert_eq!(jwk.evp_pkey.key_type(), EvpPkeyType::Ed25519);
    }

    #[test]
    fn rejects_ed25519_private_key_of_wrong_length() {
        // 'd' decodes to 16 bytes; Ed25519 requires 32.
        let json = r#"{"kty":"OKP","crv":"Ed25519","d":"nWGxne_9WmC6hEr0kuwsxA","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#;
        assert!(parse(json).is_err());
    }

    #[test]
    fn rejects_ed25519_private_key_with_mismatched_public_key() {
        // Valid 32-byte 'd' but 'x' belongs to a different key.
        let json = r#"{"kty":"OKP","crv":"Ed25519","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURg"}"#;
        assert!(parse(json).is_err());
    }

    #[test]
    fn rejects_ed25519_public_key_of_wrong_length() {
        // No 'd'; 'x' decodes to 16 bytes but Ed25519 requires 32.
        let json = r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg"}"#;
        assert!(parse(json).is_err());
    }

    #[test]
    fn rejects_x25519_private_key_of_wrong_length() {
        // 'd' decodes to 16 bytes; X25519 requires 32.
        let json = r#"{"kty":"OKP","crv":"X25519","d":"nWGxne_9WmC6hEr0kuwsxA","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#;
        assert!(parse(json).is_err());
    }

    #[test]
    fn rejects_x25519_public_key_of_wrong_length() {
        let json = r#"{"kty":"OKP","crv":"X25519","x":"11qYAYKxCrfVS_7TyWQHOg"}"#;
        assert!(parse(json).is_err());
    }

    #[test]
    fn rejects_unsupported_curve() {
        let json =
            r#"{"kty":"OKP","crv":"Ed448","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#;
        assert!(parse(json).is_err());
    }

    #[test]
    fn rejects_missing_curve() {
        let json = r#"{"kty":"OKP","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#;
        assert!(parse(json).is_err());
    }

    #[test]
    fn rejects_missing_x_parameter() {
        let json =
            r#"{"kty":"OKP","crv":"Ed25519","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"}"#;
        assert!(parse(json).is_err());
    }

    #[test]
    fn rejects_invalid_alg() {
        let json = r#"{"kty":"OKP","crv":"Ed25519","alg":"HS256","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#;
        assert!(parse(json).is_err());
    }
}
