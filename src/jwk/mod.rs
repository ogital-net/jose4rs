use std::collections::BTreeMap;

use ec::EcJsonWebKey;
use oct::OctetSequenceJsonWebKey;
use okp::OkpJsonWebKey;
use rsa::RsaJsonWebKey;
use simd_json::derived::ValueObjectAccessAsScalar as _;

use crate::{
    crypto::{Bio, EcCurve, EvpPkey, EvpPkeyType, rand::rand_bytes},
    error::JoseError,
    jwe::{ContentEncryptionAlgorithm, KeyManagementAlgorithm},
    jws::AlgorithmIdentifier,
};

/// Elliptic-curve (`EC`) JSON Web Keys.
pub mod ec;
#[cfg(feature = "jwks-https")]
mod https;
#[cfg(feature = "jwks-https-async")]
mod https_async;
/// ML-DSA (`AKP`) JSON Web Keys (RFC 9964).
#[cfg(all(feature = "pq-ml-dsa", feature = "aws-lc"))]
pub mod ml_dsa;
#[cfg(all(feature = "pq-ml-dsa", feature = "aws-lc"))]
pub use ml_dsa::{MlDsaJsonWebKey, MlDsaParameterSet};
/// Symmetric (`oct`) JSON Web Keys.
pub mod oct;
/// Octet key pair (`OKP`) JSON Web Keys (Ed25519, X25519).
pub mod okp;
/// RSA JSON Web Keys.
pub mod rsa;
mod selector;
mod set;

#[cfg(feature = "jwks-https")]
pub use https::{
    DEFAULT_CACHE_DURATION, FetchResponse, HttpsJwks, JwksFetcher, KID_MISS_REFRESH_COOLDOWN,
    REFRESH_REPRIEVE_THRESHOLD,
};
#[cfg(feature = "jwks-https-async")]
pub use https_async::{AsyncHttpsJwks, AsyncJwksFetcher, FetchFuture};
pub use selector::{DecryptionJwkSelector, VerificationJwkSelector};
pub use set::JsonWebKeySet;

/// An algorithm named by a JWK `alg` parameter.
///
/// Known algorithms retain their typed representation. Other ASCII names are
/// preserved so newly registered and collision-resistant algorithm names can
/// round-trip without requiring a jose4rs release first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JwkAlgorithm {
    /// A JWS signature or MAC algorithm.
    Jws(AlgorithmIdentifier),
    /// A JWE key-management algorithm.
    Jwe(KeyManagementAlgorithm),
    /// A JWE content-encryption algorithm, used by direct symmetric keys.
    ContentEncryption(ContentEncryptionAlgorithm),
    /// An algorithm not currently known to jose4rs.
    Custom(Box<str>),
}

impl JwkAlgorithm {
    /// Returns the JOSE algorithm name.
    pub fn name(&self) -> &str {
        match self {
            Self::Jws(algorithm) => algorithm.name(),
            Self::Jwe(algorithm) => algorithm.name(),
            Self::ContentEncryption(algorithm) => algorithm.name(),
            Self::Custom(algorithm) => algorithm,
        }
    }
}

impl std::str::FromStr for JwkAlgorithm {
    type Err = JoseError;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        if name.is_empty() || !name.is_ascii() {
            return Err(JoseError::InvalidKey(
                "JWK 'alg' must be a non-empty ASCII string".into(),
            ));
        }
        if let Ok(algorithm) = name.parse::<AlgorithmIdentifier>() {
            return Ok(Self::Jws(algorithm));
        }
        if let Ok(algorithm) = name.parse::<KeyManagementAlgorithm>() {
            return Ok(Self::Jwe(algorithm));
        }
        if let Ok(algorithm) = name.parse::<ContentEncryptionAlgorithm>() {
            return Ok(Self::ContentEncryption(algorithm));
        }
        Ok(Self::Custom(name.into()))
    }
}

impl std::fmt::Display for JwkAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

impl From<AlgorithmIdentifier> for JwkAlgorithm {
    fn from(algorithm: AlgorithmIdentifier) -> Self {
        Self::Jws(algorithm)
    }
}

impl From<KeyManagementAlgorithm> for JwkAlgorithm {
    fn from(algorithm: KeyManagementAlgorithm) -> Self {
        Self::Jwe(algorithm)
    }
}

impl From<ContentEncryptionAlgorithm> for JwkAlgorithm {
    fn from(algorithm: ContentEncryptionAlgorithm) -> Self {
        Self::ContentEncryption(algorithm)
    }
}

/// The intended use of a JWK (the `use` parameter, RFC 7517 Section 4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyUse {
    /// `sig` -- the key is used for creating or verifying signatures.
    Signature,
    /// `enc` -- the key is used for encrypting or decrypting content/keys.
    Encryption,
}

impl KeyUse {
    /// The JWK `use` value: `sig` or `enc`.
    pub fn as_str(&self) -> &'static str {
        match self {
            KeyUse::Signature => "sig",
            KeyUse::Encryption => "enc",
        }
    }
}

impl std::fmt::Display for KeyUse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for KeyUse {
    type Err = JoseError;

    /// Parses a JWK `use` value (`sig` or `enc`).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "sig" => Ok(KeyUse::Signature),
            "enc" => Ok(KeyUse::Encryption),
            _ => Err(JoseError::InvalidKey(format!(
                "invalid JWK 'use' value: {s}"
            ))),
        }
    }
}

/// How much key material to include when serializing a JWK to JSON or DER.
///
/// Controls whether private material is emitted, guarding against accidental
/// leakage of private keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputControlLevel {
    /// Include private (and public) key material.
    IncludePrivate,
    /// Include symmetric (`oct`) key material as well as private asymmetric material.
    IncludeSymmetric,
    /// Include only public key material; never private or symmetric material.
    PublicOnly,
}

/// A JSON Web Key (RFC 7517).
///
/// An enum over the supported key types (`kty`): RSA, elliptic curve (EC),
/// octet key pair (OKP), symmetric (oct), and ML-DSA (AKP, RFC 9964).
/// Parse with [`JsonWebKey::from_json`] or [`JsonWebKey::from_pem`].
#[derive(Clone)]
pub enum JsonWebKey {
    /// An elliptic-curve key (`kty: "EC"`).
    EllipticCurve(EcJsonWebKey),
    /// An octet key pair (`kty: "OKP"`): Ed25519 or X25519.
    OctetKeyPair(OkpJsonWebKey),
    /// An RSA key (`kty: "RSA"`).
    Rsa(RsaJsonWebKey),
    /// A symmetric (shared-secret) key (`kty: "oct"`).
    Oct(OctetSequenceJsonWebKey),
    /// An ML-DSA post-quantum key (`kty: "AKP"`, RFC 9964).
    #[cfg(all(feature = "pq-ml-dsa", feature = "aws-lc"))]
    MlDsa(MlDsaJsonWebKey),
}

impl From<EcJsonWebKey> for JsonWebKey {
    fn from(key: EcJsonWebKey) -> Self {
        Self::EllipticCurve(key)
    }
}

impl From<OkpJsonWebKey> for JsonWebKey {
    fn from(key: OkpJsonWebKey) -> Self {
        Self::OctetKeyPair(key)
    }
}

impl From<RsaJsonWebKey> for JsonWebKey {
    fn from(key: RsaJsonWebKey) -> Self {
        Self::Rsa(key)
    }
}

impl From<OctetSequenceJsonWebKey> for JsonWebKey {
    fn from(key: OctetSequenceJsonWebKey) -> Self {
        Self::Oct(key)
    }
}

#[cfg(all(feature = "pq-ml-dsa", feature = "aws-lc"))]
impl From<MlDsaJsonWebKey> for JsonWebKey {
    fn from(key: MlDsaJsonWebKey) -> Self {
        Self::MlDsa(key)
    }
}

impl std::fmt::Debug for JsonWebKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JsonWebKey::EllipticCurve(k) => std::fmt::Debug::fmt(k, f),
            JsonWebKey::OctetKeyPair(k) => std::fmt::Debug::fmt(k, f),
            JsonWebKey::Rsa(k) => std::fmt::Debug::fmt(k, f),
            JsonWebKey::Oct(k) => std::fmt::Debug::fmt(k, f),
            #[cfg(all(feature = "pq-ml-dsa", feature = "aws-lc"))]
            JsonWebKey::MlDsa(k) => std::fmt::Debug::fmt(k, f),
        }
    }
}

pub(super) trait GetStr {
    fn get(&self, key: &str) -> Option<&str>;
}

impl GetStr for BTreeMap<String, String> {
    fn get(&self, key: &str) -> Option<&str> {
        self.get(key).map(std::string::String::as_str)
    }
}

impl GetStr for simd_json::BorrowedValue<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.get_str(key)
    }
}

impl GetStr for &simd_json::OwnedValue {
    fn get(&self, key: &str) -> Option<&str> {
        self.get_str(key)
    }
}

pub(super) fn push_json_string(out: &mut String, value: &str) {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    out.push('"');
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{00}'..='\u{1f}' => {
                let byte = character as usize;
                out.push_str("\\u00");
                out.push(HEX[byte >> 4] as char);
                out.push(HEX[byte & 0x0f] as char);
            }
            _ => out.push(character),
        }
    }
    out.push('"');
}

impl JsonWebKey {
    /// Parses a JWK from its JSON serialization.
    ///
    /// The key type is selected by the `kty` member (`RSA`, `EC`, `oct`, or
    /// `OKP`).
    ///
    /// # Errors
    /// Returns an error if the JSON is malformed, `kty` is missing or
    /// unsupported, or the key parameters are invalid for the type.
    pub fn from_json(json: impl AsRef<[u8]>) -> Result<Self, JoseError> {
        let mut json = Box::from(json.as_ref());

        let value = simd_json::to_borrowed_value(&mut json).map_err(JoseError::json)?;

        let jwk = match value.get_str("kty") {
            Some(val) => match val {
                "RSA" => JsonWebKey::Rsa(RsaJsonWebKey::from_map(value)?),
                "EC" => JsonWebKey::EllipticCurve(EcJsonWebKey::from_map(value)?),
                "oct" => JsonWebKey::Oct(OctetSequenceJsonWebKey::from_map(value)?),
                "OKP" => JsonWebKey::OctetKeyPair(OkpJsonWebKey::from_map(value)?),
                #[cfg(all(feature = "pq-ml-dsa", feature = "aws-lc"))]
                "AKP" => JsonWebKey::MlDsa(MlDsaJsonWebKey::from_map(value)?),
                _ => {
                    return Err(JoseError::InvalidJson(
                        "'kty' must be one of 'EC', RSA', 'OKP', 'AKP', or 'oct'".into(),
                    ));
                }
            },
            None => return Err(JoseError::InvalidJson("'kty' field missing".into())),
        };

        Ok(jwk)
    }

    pub(crate) fn from_value(value: &simd_json::OwnedValue) -> Result<Self, JoseError> {
        let jwk = match value.get_str("kty") {
            Some(val) => match val {
                "RSA" => JsonWebKey::Rsa(RsaJsonWebKey::from_map(value)?),
                "EC" => JsonWebKey::EllipticCurve(EcJsonWebKey::from_map(value)?),
                "oct" => JsonWebKey::Oct(OctetSequenceJsonWebKey::from_map(value)?),
                "OKP" => JsonWebKey::OctetKeyPair(OkpJsonWebKey::from_map(value)?),
                #[cfg(all(feature = "pq-ml-dsa", feature = "aws-lc"))]
                "AKP" => JsonWebKey::MlDsa(MlDsaJsonWebKey::from_map(value)?),
                _ => {
                    return Err(JoseError::InvalidJson(
                        "'kty' must be one of 'EC', RSA', 'OKP', 'AKP', or 'oct'".into(),
                    ));
                }
            },
            None => return Err(JoseError::InvalidJson("'kty' field missing".into())),
        };

        Ok(jwk)
    }

    /// Parses a JWK from a PEM-encoded private or public key.
    ///
    /// Supports RSA, EC (named curves only), Ed25519, and X25519 keys in
    /// PKCS#8 private-key or `SubjectPublicKeyInfo` form.
    ///
    /// # Errors
    /// Returns an error if the PEM is malformed or the key type is unsupported.
    pub fn from_pem(pem: impl AsRef<str>) -> Result<Self, JoseError> {
        let bytes = pem.as_ref().as_bytes();
        // SAFETY: bytes is borrowed for the duration of each Bio's use below
        let evp_pkey = match unsafe { Bio::from_slice(bytes) }.read_pem_private_key() {
            Some(k) => k,
            None => match unsafe { Bio::from_slice(bytes) }.read_pem_public_key() {
                Some(k) => k,
                None => return Err(JoseError::InvalidKey("key not found".into())),
            },
        };

        match evp_pkey.key_type() {
            EvpPkeyType::Rsa => Ok(JsonWebKey::Rsa(RsaJsonWebKey::from_evp_pkey(evp_pkey))),
            EvpPkeyType::RsaPss => Ok(JsonWebKey::Rsa(RsaJsonWebKey::from_evp_pkey(evp_pkey))),
            EvpPkeyType::Ec => Ok(JsonWebKey::EllipticCurve(EcJsonWebKey::from_evp_pkey(
                evp_pkey,
            ))),
            EvpPkeyType::Ed25519 => Ok(JsonWebKey::OctetKeyPair(OkpJsonWebKey::from_evp_pkey(
                evp_pkey,
            ))),
            EvpPkeyType::X25519 => Ok(JsonWebKey::OctetKeyPair(OkpJsonWebKey::from_evp_pkey(
                evp_pkey,
            ))),
            #[cfg(all(feature = "pq-ml-dsa", feature = "aws-lc"))]
            EvpPkeyType::MlDsa44 | EvpPkeyType::MlDsa65 | EvpPkeyType::MlDsa87 => {
                Ok(JsonWebKey::MlDsa(MlDsaJsonWebKey::from_evp_pkey(evp_pkey)))
            }
            _ => Err(JoseError::InvalidKey("unsupported key type".into())),
        }
    }

    fn from_evp_pkey(evp_pkey: EvpPkey) -> Result<Self, JoseError> {
        match evp_pkey.key_type() {
            EvpPkeyType::Rsa | EvpPkeyType::RsaPss => {
                Ok(JsonWebKey::Rsa(RsaJsonWebKey::from_evp_pkey(evp_pkey)))
            }
            EvpPkeyType::Ec => Ok(JsonWebKey::EllipticCurve(EcJsonWebKey::from_evp_pkey(
                evp_pkey,
            ))),
            EvpPkeyType::Ed25519 | EvpPkeyType::X25519 => Ok(JsonWebKey::OctetKeyPair(
                OkpJsonWebKey::from_evp_pkey(evp_pkey),
            )),
            #[cfg(all(feature = "pq-ml-dsa", feature = "aws-lc"))]
            EvpPkeyType::MlDsa44 | EvpPkeyType::MlDsa65 | EvpPkeyType::MlDsa87 => {
                Ok(JsonWebKey::MlDsa(MlDsaJsonWebKey::from_evp_pkey(evp_pkey)))
            }
            _ => Err(JoseError::InvalidKey("unsupported key type".into())),
        }
    }

    /// Serializes the key to PEM.
    ///
    /// `OutputControlLevel::IncludePrivate` produces a PKCS#8 private key PEM
    /// (errors if the key holds no private material); `PublicOnly` produces a
    /// `SubjectPublicKeyInfo` PEM. Symmetric `oct` keys have no PEM
    /// representation and return an error.
    ///
    /// # Errors
    ///
    /// Returns an error for symmetric `oct` keys (which have no PEM
    /// representation) or if private output is requested but the key holds no
    /// private material.
    pub fn to_pem(&self, level: OutputControlLevel) -> Result<String, JoseError> {
        match self {
            JsonWebKey::EllipticCurve(ec) => ec.to_pem(level),
            JsonWebKey::OctetKeyPair(okp) => okp.to_pem(level),
            JsonWebKey::Rsa(rsa) => rsa.to_pem(level),
            #[cfg(all(feature = "pq-ml-dsa", feature = "aws-lc"))]
            JsonWebKey::MlDsa(ml_dsa) => ml_dsa.to_pem(level),
            JsonWebKey::Oct(_) => Err(JoseError::InvalidKey(
                "oct keys have no PEM representation".into(),
            )),
        }
    }

    /// Serializes the private key to PKCS#8 DER.
    ///
    /// Returns `None` for symmetric `oct` keys or public-only keys.
    pub fn to_pkcs8_der(&self) -> Option<Box<[u8]>> {
        match self {
            JsonWebKey::EllipticCurve(ec) => ec.evp_pkey().private_key_to_der().ok(),
            JsonWebKey::OctetKeyPair(okp) => okp.evp_pkey().private_key_to_der().ok(),
            JsonWebKey::Rsa(rsa) => rsa.evp_pkey().private_key_to_der().ok(),
            #[cfg(all(feature = "pq-ml-dsa", feature = "aws-lc"))]
            JsonWebKey::MlDsa(ml_dsa) => ml_dsa.evp_pkey().private_key_to_der().ok(),
            JsonWebKey::Oct(_) => None,
        }
    }

    /// Serializes the public key to `SubjectPublicKeyInfo` (SPKI) DER.
    ///
    /// Returns `None` for symmetric `oct` keys.
    pub fn to_spki_der(&self) -> Option<Box<[u8]>> {
        match self {
            JsonWebKey::EllipticCurve(ec) => ec.evp_pkey().public_key_to_der().ok(),
            JsonWebKey::OctetKeyPair(okp) => okp.evp_pkey().public_key_to_der().ok(),
            JsonWebKey::Rsa(rsa) => rsa.evp_pkey().public_key_to_der().ok(),
            #[cfg(all(feature = "pq-ml-dsa", feature = "aws-lc"))]
            JsonWebKey::MlDsa(ml_dsa) => ml_dsa.evp_pkey().public_key_to_der().ok(),
            JsonWebKey::Oct(_) => None,
        }
    }

    /// Serializes the key to DER: PKCS#8 if private material is held,
    /// otherwise SPKI.
    ///
    /// Returns `None` for symmetric `oct` keys.
    pub fn to_der(&self) -> Option<Box<[u8]>> {
        match self {
            JsonWebKey::EllipticCurve(ec) => Some(ec.to_der()),
            JsonWebKey::OctetKeyPair(okp) => Some(okp.to_der()),
            JsonWebKey::Oct(_) => None,
            JsonWebKey::Rsa(rsa) => Some(rsa.to_der()),
            #[cfg(all(feature = "pq-ml-dsa", feature = "aws-lc"))]
            JsonWebKey::MlDsa(ml_dsa) => Some(ml_dsa.to_der()),
        }
    }

    /// Parses a key from DER, auto-detecting the format.
    ///
    /// Accepts PKCS#8 private keys, legacy (PKCS#1 / SEC1) private keys,
    /// and `SubjectPublicKeyInfo` (SPKI) public keys.
    ///
    /// # Errors
    ///
    /// Returns an error for symmetric keys or unrecognised encodings.
    pub fn from_der(der: impl AsRef<[u8]>) -> Result<Self, JoseError> {
        let der = der.as_ref();
        // Try private key first (handles PKCS#8, PKCS#1, SEC1).
        if let Ok(pkey) = EvpPkey::from_private_key_der(der) {
            return Self::from_evp_pkey(pkey);
        }
        // Fall back to SPKI public key.
        let pkey = EvpPkey::from_public_key_der(der)?;
        Self::from_evp_pkey(pkey)
    }

    /// Serializes the key to its JWK JSON form, honoring the given output level.
    pub fn to_json(&self, level: OutputControlLevel) -> String {
        match self {
            JsonWebKey::EllipticCurve(ec) => ec.to_json(level),
            JsonWebKey::OctetKeyPair(okp) => okp.to_json(level),
            JsonWebKey::Oct(oct) => oct.to_json(level),
            JsonWebKey::Rsa(rsa) => rsa.to_json(level),
            #[cfg(all(feature = "pq-ml-dsa", feature = "aws-lc"))]
            JsonWebKey::MlDsa(ml_dsa) => ml_dsa.to_json(level),
        }
    }

    /// The X.509 certificate SHA-1 thumbprint (`x5t`), if this key was built
    /// from a certificate. Always `None` for symmetric `oct` keys.
    pub fn x5t(&self) -> Option<&str> {
        match self {
            JsonWebKey::EllipticCurve(ec) => ec.x5t(),
            JsonWebKey::OctetKeyPair(okp) => okp.x5t(),
            JsonWebKey::Rsa(rsa) => rsa.x5t(),
            #[cfg(all(feature = "pq-ml-dsa", feature = "aws-lc"))]
            JsonWebKey::MlDsa(ml_dsa) => ml_dsa.x5t(),
            JsonWebKey::Oct(_) => None,
        }
    }

    /// The X.509 certificate SHA-256 thumbprint (`x5t#S256`), if this key was
    /// built from a certificate. Always `None` for symmetric `oct` keys.
    pub fn x5t_s256(&self) -> Option<&str> {
        match self {
            JsonWebKey::EllipticCurve(ec) => ec.x5t_s256(),
            JsonWebKey::OctetKeyPair(okp) => okp.x5t_s256(),
            JsonWebKey::Rsa(rsa) => rsa.x5t_s256(),
            #[cfg(all(feature = "pq-ml-dsa", feature = "aws-lc"))]
            JsonWebKey::MlDsa(ml_dsa) => ml_dsa.x5t_s256(),
            JsonWebKey::Oct(_) => None,
        }
    }

    /// Computes the JWK thumbprint (RFC 7638): the base64url encoding of the
    /// SHA-256 digest of the canonical JSON of the key's required members.
    ///
    /// The canonical form lists only the required members for the key type, in
    /// lexicographic order, with no whitespace:
    /// - EC:  `crv`, `kty`, `x`, `y`
    /// - RSA: `e`, `kty`, `n`
    /// - OKP: `crv`, `kty`, `x`
    /// - oct: `k`, `kty`
    /// - AKP: `alg`, `kty`, `pub`
    ///
    /// This is the key identity used by ACME `key-change` and External Account
    /// Binding. SHA-256 is the hash RFC 7638 registers and the one ACME uses.
    ///
    /// # Errors
    ///
    /// Returns an error if serializing the key to its canonical JSON fails.
    pub fn thumbprint(&self) -> Result<String, JoseError> {
        let canonical = self.thumbprint_canonical_json()?;
        let digest =
            crate::crypto::digest(crate::crypto::DigestAlgorithm::Sha256, canonical.as_bytes());
        let encoded = crate::base64::url_encode(&digest);
        // SAFETY: base64url output is valid UTF-8.
        Ok(unsafe { std::str::from_utf8_unchecked(&encoded) }.to_string())
    }

    /// Builds the RFC 7638 canonical JSON: the required members for the key
    /// type, in lexicographic member-name order, with no whitespace.
    fn thumbprint_canonical_json(&self) -> Result<String, JoseError> {
        // Extract the JWK, then pull the required members out of it so the
        // canonical form is independent of `to_json`'s field ordering. For
        // symmetric `oct` keys the required `k` member is secret, so it is only
        // present at the IncludePrivate level.
        let level = match self {
            JsonWebKey::Oct(_) => OutputControlLevel::IncludePrivate,
            _ => OutputControlLevel::PublicOnly,
        };
        let json = self.to_json(level);
        // The canonical output keeps only the required members, so it is never
        // larger than the source JSON -- a safe upper bound for the capacity.
        let capacity = json.len();
        let mut buf = json.into_bytes();
        let value = simd_json::to_owned_value(buf.as_mut_slice()).map_err(JoseError::json)?;

        // Member names in lexicographic order per key type.
        let members: &[&str] = match self {
            JsonWebKey::EllipticCurve(_) => &["crv", "kty", "x", "y"],
            JsonWebKey::Rsa(_) => &["e", "kty", "n"],
            JsonWebKey::OctetKeyPair(_) => &["crv", "kty", "x"],
            JsonWebKey::Oct(_) => &["k", "kty"],
            #[cfg(all(feature = "pq-ml-dsa", feature = "aws-lc"))]
            JsonWebKey::MlDsa(_) => &["alg", "kty", "pub"],
        };

        canonical_jwk_json(&value, members, capacity)
    }

    /// The key ID (`kid`), if set.
    pub fn key_id(&self) -> Option<&str> {
        match self {
            JsonWebKey::EllipticCurve(ec) => ec.key_id(),
            JsonWebKey::OctetKeyPair(okp) => okp.key_id(),
            JsonWebKey::Rsa(rsa) => rsa.key_id(),
            #[cfg(all(feature = "pq-ml-dsa", feature = "aws-lc"))]
            JsonWebKey::MlDsa(ml_dsa) => ml_dsa.key_id(),
            JsonWebKey::Oct(oct) => oct.key_id(),
        }
    }

    /// Sets the key ID (`kid`).
    pub fn set_key_id(&mut self, key_id: impl Into<String>) {
        let key_id = key_id.into();
        match self {
            JsonWebKey::EllipticCurve(ec) => ec.set_key_id(key_id),
            JsonWebKey::OctetKeyPair(okp) => okp.set_key_id(key_id),
            JsonWebKey::Rsa(rsa) => rsa.set_key_id(key_id),
            #[cfg(all(feature = "pq-ml-dsa", feature = "aws-lc"))]
            JsonWebKey::MlDsa(ml_dsa) => ml_dsa.set_key_id(key_id),
            JsonWebKey::Oct(oct) => oct.set_key_id(key_id),
        }
    }

    /// The key usage (`use`), if set.
    pub fn key_use(&self) -> Option<KeyUse> {
        match self {
            JsonWebKey::EllipticCurve(ec) => ec.key_use(),
            JsonWebKey::OctetKeyPair(okp) => okp.key_use(),
            JsonWebKey::Rsa(rsa) => rsa.key_use(),
            #[cfg(all(feature = "pq-ml-dsa", feature = "aws-lc"))]
            JsonWebKey::MlDsa(ml_dsa) => ml_dsa.key_use(),
            JsonWebKey::Oct(oct) => oct.key_use(),
        }
    }

    /// The algorithm (`alg`) designated for this key, if set.
    pub fn algorithm(&self) -> Option<&str> {
        match self {
            JsonWebKey::EllipticCurve(ec) => ec.alg(),
            JsonWebKey::OctetKeyPair(okp) => okp.alg(),
            JsonWebKey::Rsa(rsa) => rsa.alg(),
            #[cfg(all(feature = "pq-ml-dsa", feature = "aws-lc"))]
            JsonWebKey::MlDsa(ml_dsa) => ml_dsa.alg(),
            JsonWebKey::Oct(oct) => oct.alg(),
        }
    }

    /// The typed algorithm metadata designated for this key, if set.
    pub fn jwk_algorithm(&self) -> Option<&JwkAlgorithm> {
        match self {
            JsonWebKey::EllipticCurve(ec) => ec.jwk_algorithm(),
            JsonWebKey::OctetKeyPair(okp) => okp.jwk_algorithm(),
            JsonWebKey::Rsa(rsa) => rsa.jwk_algorithm(),
            #[cfg(all(feature = "pq-ml-dsa", feature = "aws-lc"))]
            JsonWebKey::MlDsa(ml_dsa) => ml_dsa.jwk_algorithm(),
            JsonWebKey::Oct(oct) => oct.jwk_algorithm(),
        }
    }

    /// The JOSE curve name (`crv`) for EC and OKP keys, the ML-DSA parameter
    /// set name for AKP keys, and `None` for RSA and oct.
    pub fn curve_name(&self) -> Option<&'static str> {
        match self {
            JsonWebKey::EllipticCurve(ec) => Some(ec.curve_name()),
            JsonWebKey::OctetKeyPair(okp) => Some(okp.curve_name()),
            JsonWebKey::Rsa(_) | JsonWebKey::Oct(_) => None,
            #[cfg(all(feature = "pq-ml-dsa", feature = "aws-lc"))]
            JsonWebKey::MlDsa(ml_dsa) => ml_dsa.curve_name(),
        }
    }

    /// The raw symmetric key bytes for `oct` keys; `None` for asymmetric keys.
    pub fn key_bytes(&self) -> Option<&[u8]> {
        match self {
            JsonWebKey::Oct(oct) => Some(oct.key_bytes()),
            _ => None,
        }
    }

    /// The JWK key type (`kty`): `"RSA"`, `"EC"`, `"OKP"`, `"AKP"`, or `"oct"`.
    pub fn key_type(&self) -> &'static str {
        match self {
            JsonWebKey::EllipticCurve(ec) => ec.key_type(),
            JsonWebKey::OctetKeyPair(okp) => okp.key_type(),
            JsonWebKey::Oct(oct) => oct.key_type(),
            JsonWebKey::Rsa(rsa) => rsa.key_type(),
            #[cfg(all(feature = "pq-ml-dsa", feature = "aws-lc"))]
            JsonWebKey::MlDsa(ml_dsa) => ml_dsa.key_type(),
        }
    }
}

/// The elliptic curve of an Octet Key Pair (OKP) JWK to generate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OkpCurve {
    /// The Ed25519 signature curve (RFC 8032).
    Ed25519,
    /// The X25519 ECDH key-agreement curve (RFC 7748).
    X25519,
}

impl OkpCurve {
    /// The JOSE curve name.
    pub fn jose_name(self) -> &'static str {
        match self {
            Self::Ed25519 => "Ed25519",
            Self::X25519 => "X25519",
        }
    }
}

/// Builds an RFC 7638 canonical JWK JSON object from a parsed JWK value and
/// the ordered list of required member names (lexicographic order, no
/// whitespace). `capacity` is a pre-allocation hint (the full serialized key
/// length is a safe upper bound). Returns an error if a member is absent.
fn canonical_jwk_json(
    value: &simd_json::owned::Value,
    members: &[&str],
    capacity: usize,
) -> Result<String, JoseError> {
    let mut out = String::with_capacity(capacity);
    out.push('{');
    for (i, name) in members.iter().enumerate() {
        let field = value.get_str(*name).ok_or_else(|| {
            JoseError::InvalidKey(format!("missing required JWK member '{name}'"))
        })?;
        if i > 0 {
            out.push(',');
        }
        out.push('"');
        out.push_str(name);
        out.push_str("\":\"");
        out.push_str(field);
        out.push('"');
    }
    out.push('}');
    Ok(out)
}

/// Generates JSON Web Keys appropriate for a given JOSE algorithm.
///
/// Construct via [`JsonWebKeyGenerator::for_signature`] or
/// [`JsonWebKeyGenerator::for_encryption`], optionally refine with the `with_*`
/// methods, then call [`JsonWebKeyGenerator::generate`].
#[derive(Debug)]
pub struct JsonWebKeyGenerator {
    key_mgmt_alg: Option<KeyManagementAlgorithm>,
    sig_alg: Option<AlgorithmIdentifier>,
    key_bits: Option<u16>,
    okp_curve: Option<OkpCurve>,
}

impl JsonWebKeyGenerator {
    /// Creates a generator for a key suitable for the given JWE key management
    /// algorithm (`alg`). The generated JWK is restricted to this algorithm in
    /// its `alg` metadata.
    pub fn for_encryption(alg: KeyManagementAlgorithm) -> Self {
        JsonWebKeyGenerator {
            key_mgmt_alg: Some(alg),
            sig_alg: None,
            key_bits: None,
            okp_curve: None,
        }
    }
    /// Creates a generator for a key suitable for the given JWS signature
    /// algorithm (`alg`). The generated JWK is restricted to this algorithm in
    /// its `alg` metadata.
    pub fn for_signature(alg: AlgorithmIdentifier) -> Self {
        JsonWebKeyGenerator {
            key_mgmt_alg: None,
            sig_alg: Some(alg),
            key_bits: None,
            okp_curve: None,
        }
    }

    /// Select the key size in bits. Applies to symmetric `oct` keys and EC/
    /// RSA where a non-default size is wanted. If unset, a size appropriate
    /// for the algorithm is used.
    pub fn with_key_bits(mut self, bits: u16) -> Self {
        self.key_bits = Some(bits);
        self
    }

    /// Select the curve for OKP (RFC 8037) key generation: `X25519` for
    /// ECDH-ES key management algorithms, `Ed25519` for `EdDSA` signatures.
    /// Without this, ECDH-ES generation defaults to an EC P-256 key.
    pub fn with_okp_curve(mut self, curve: OkpCurve) -> Self {
        self.okp_curve = Some(curve);
        self
    }

    /// Generate a fresh random key suitable for the configured algorithm.
    ///
    /// # Errors
    ///
    /// Returns an error if the configured algorithm does not support key
    /// generation or the requested key parameters are invalid.
    pub fn generate(&self) -> Result<JsonWebKey, JoseError> {
        if let Some(alg) = self.key_mgmt_alg {
            // Number of symmetric key bytes for the AES-KW / AES-GCMKW /
            // direct algorithms that need an oct key of a specific size.
            let symmetric_key_bytes = |default_bits: u16| match self.key_bits {
                Some(bits) => bits as usize / 8,
                None => default_bits as usize / 8,
            };

            match alg {
                KeyManagementAlgorithm::Rsa15
                | KeyManagementAlgorithm::RsaOaep
                | KeyManagementAlgorithm::RsaOaep256
                | KeyManagementAlgorithm::RsaOaep384
                | KeyManagementAlgorithm::RsaOaep512 => {
                    let key = EvpPkey::generate_rsa(self.key_bits.unwrap_or(2048));
                    let mut jwk = RsaJsonWebKey::new(key, Some(alg.into()));
                    jwk.set_key_use(KeyUse::Encryption);
                    Ok(JsonWebKey::Rsa(jwk))
                }
                KeyManagementAlgorithm::EcdhEs
                | KeyManagementAlgorithm::EcdhEsA128Kw
                | KeyManagementAlgorithm::EcdhEsA192Kw
                | KeyManagementAlgorithm::EcdhEsA256Kw => match self.okp_curve {
                    Some(OkpCurve::X25519) => {
                        let key = EvpPkey::generate_x25519();
                        Ok(JsonWebKey::OctetKeyPair(OkpJsonWebKey::new(
                            key,
                            Some(alg.into()),
                        )))
                    }
                    Some(OkpCurve::Ed25519) => {
                        // Ed25519 is a signature curve and cannot do ECDH key
                        // agreement; fall through to the EC default below.
                        let key = EvpPkey::generate_ec(EcCurve::P256);
                        Ok(JsonWebKey::EllipticCurve(EcJsonWebKey::new(
                            key,
                            Some(alg.into()),
                        )))
                    }
                    None => {
                        // Default to the widely-supported P-256 curve for ECDH.
                        let key = EvpPkey::generate_ec(EcCurve::P256);
                        Ok(JsonWebKey::EllipticCurve(EcJsonWebKey::new(
                            key,
                            Some(alg.into()),
                        )))
                    }
                },
                KeyManagementAlgorithm::A128Kw | KeyManagementAlgorithm::A128GcmKw => {
                    let key = rand_bytes(symmetric_key_bytes(128));
                    Ok(JsonWebKey::Oct(OctetSequenceJsonWebKey::new(
                        key,
                        Some(alg.into()),
                    )))
                }
                KeyManagementAlgorithm::A192Kw | KeyManagementAlgorithm::A192GcmKw => {
                    let key = rand_bytes(symmetric_key_bytes(192));
                    Ok(JsonWebKey::Oct(OctetSequenceJsonWebKey::new(
                        key,
                        Some(alg.into()),
                    )))
                }
                KeyManagementAlgorithm::A256Kw | KeyManagementAlgorithm::A256GcmKw => {
                    let key = rand_bytes(symmetric_key_bytes(256));
                    Ok(JsonWebKey::Oct(OctetSequenceJsonWebKey::new(
                        key,
                        Some(alg.into()),
                    )))
                }
                KeyManagementAlgorithm::Pbes2Hs256A128Kw
                | KeyManagementAlgorithm::Pbes2Hs384A192Kw
                | KeyManagementAlgorithm::Pbes2Hs512A256Kw => {
                    // PBES2 uses a password; default to 256 bits of entropy.
                    let key = rand_bytes(symmetric_key_bytes(256));
                    Ok(JsonWebKey::Oct(OctetSequenceJsonWebKey::new(
                        key,
                        Some(alg.into()),
                    )))
                }
                KeyManagementAlgorithm::Direct => {
                    let key = rand_bytes(symmetric_key_bytes(256));
                    Ok(JsonWebKey::Oct(OctetSequenceJsonWebKey::new(
                        key,
                        Some(alg.into()),
                    )))
                }
            }
        } else if let Some(alg) = self.sig_alg {
            match alg {
                AlgorithmIdentifier::HmacSha256 => {
                    let key_bytes = match self.key_bits {
                        Some(bits) => bits as usize / 8,
                        None => 32, // Default to 256 bits
                    };
                    let key = rand_bytes(key_bytes);
                    Ok(JsonWebKey::Oct(OctetSequenceJsonWebKey::new(
                        key,
                        Some(alg.into()),
                    )))
                }
                AlgorithmIdentifier::HmacSha384 => {
                    let key_bytes = match self.key_bits {
                        Some(bits) => bits as usize / 8,
                        None => 48, // Default to 384 bits
                    };
                    let key = rand_bytes(key_bytes);
                    Ok(JsonWebKey::Oct(OctetSequenceJsonWebKey::new(
                        key,
                        Some(alg.into()),
                    )))
                }
                AlgorithmIdentifier::HmacSha512 => {
                    let key_bytes = match self.key_bits {
                        Some(bits) => bits as usize / 8,
                        None => 64, // Default to 512 bits
                    };
                    let key = rand_bytes(key_bytes);
                    Ok(JsonWebKey::Oct(OctetSequenceJsonWebKey::new(
                        key,
                        Some(alg.into()),
                    )))
                }
                AlgorithmIdentifier::RsaUsingSha256 => {
                    let key = EvpPkey::generate_rsa(self.key_bits.unwrap_or(2048));
                    Ok(JsonWebKey::Rsa(RsaJsonWebKey::new(key, Some(alg.into()))))
                }
                AlgorithmIdentifier::RsaUsingSha384 => {
                    let key = EvpPkey::generate_rsa(self.key_bits.unwrap_or(2048));
                    Ok(JsonWebKey::Rsa(RsaJsonWebKey::new(key, Some(alg.into()))))
                }
                AlgorithmIdentifier::RsaUsingSha512 => {
                    let key = EvpPkey::generate_rsa(self.key_bits.unwrap_or(3072));
                    Ok(JsonWebKey::Rsa(RsaJsonWebKey::new(key, Some(alg.into()))))
                }
                AlgorithmIdentifier::EcdsaUsingP256CurveAndSha256 => {
                    let key = EvpPkey::generate_ec(EcCurve::P256);
                    Ok(JsonWebKey::EllipticCurve(EcJsonWebKey::new(
                        key,
                        Some(alg.into()),
                    )))
                }
                AlgorithmIdentifier::EcdsaUsingP384CurveAndSha384 => {
                    let key = EvpPkey::generate_ec(EcCurve::P384);
                    Ok(JsonWebKey::EllipticCurve(EcJsonWebKey::new(
                        key,
                        Some(alg.into()),
                    )))
                }
                AlgorithmIdentifier::EcdsaUsingP521CurveAndSha512 => {
                    let key = EvpPkey::generate_ec(EcCurve::P521);
                    Ok(JsonWebKey::EllipticCurve(EcJsonWebKey::new(
                        key,
                        Some(alg.into()),
                    )))
                }
                #[cfg(not(feature = "boring"))]
                AlgorithmIdentifier::EcdsaUsingSecp256k1CurveAndSha256 => {
                    let key = EvpPkey::generate_ec(EcCurve::Secp256k1);
                    Ok(JsonWebKey::EllipticCurve(EcJsonWebKey::new(
                        key,
                        Some(alg.into()),
                    )))
                }
                AlgorithmIdentifier::EdDsa => {
                    let key = EvpPkey::generate_ed25519();
                    Ok(JsonWebKey::OctetKeyPair(OkpJsonWebKey::new(
                        key,
                        Some(alg.into()),
                    )))
                }
                AlgorithmIdentifier::RsaPssUsingSha256 => {
                    let key = EvpPkey::generate_rsa(self.key_bits.unwrap_or(2048));
                    Ok(JsonWebKey::Rsa(RsaJsonWebKey::new(key, Some(alg.into()))))
                }
                AlgorithmIdentifier::RsaPssUsingSha384 => {
                    let key = EvpPkey::generate_rsa(self.key_bits.unwrap_or(2048));
                    Ok(JsonWebKey::Rsa(RsaJsonWebKey::new(key, Some(alg.into()))))
                }
                AlgorithmIdentifier::RsaPssUsingSha512 => {
                    let key = EvpPkey::generate_rsa(self.key_bits.unwrap_or(3072));
                    Ok(JsonWebKey::Rsa(RsaJsonWebKey::new(key, Some(alg.into()))))
                }
                // `alg` is one of the three `MlDsa*` variants matched here, so
                // `ml_dsa_parameter_set_name()` always returns `Some(..)` with a
                // name that `MlDsaParameterSet::from_jose_name` always accepts;
                // neither `expect` can actually panic.
                #[cfg(all(feature = "pq-ml-dsa", feature = "aws-lc"))]
                #[allow(clippy::missing_panics_doc)]
                AlgorithmIdentifier::MlDsa44
                | AlgorithmIdentifier::MlDsa65
                | AlgorithmIdentifier::MlDsa87 => {
                    let params_name = alg
                        .ml_dsa_parameter_set_name()
                        .expect("ML-DSA algorithm always pins a parameter set");
                    let params = MlDsaParameterSet::from_jose_name(params_name)
                        .expect("ML-DSA algorithm name is always a valid parameter set");
                    let key = EvpPkey::generate_ml_dsa(params);
                    Ok(JsonWebKey::MlDsa(MlDsaJsonWebKey::new(key)))
                }
                _ => Err(JoseError::InvalidAlgorithm(
                    "unsupported algorithm for key generation".into(),
                )),
            }
        } else {
            Err(JoseError::InvalidAlgorithm("no algorithm specified".into()))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::base64;

    use super::*;

    #[test]
    fn test_deserialize_rsa() {
        let json = r#"{
            "p": "9rlKEAowx-3trZteNDqjtV8SGs_r9BHbXMWkzUxZ1P8lHaOjKqGgnlVw18iXIlxyHVzhSFQuZ_dlycuBDHDdUaXydTvIcqL710Q29OpPS74Y9Iv8S0RYIJcz1BkqOTk7Tg_ulFxZR_jtlA9CVhMFcYuwWsZXRfSI7ElJyTLz8HM",
            "kty": "RSA",
            "q": "uC6IM6LLCULFSPPYDMf8x1NV5kJpVKpJ-m-WtkHSTxNpTtLo4mGkOFPnX71_t0qM5lsNMfLwCavmK5-XnwB_JIwmxjoBuFQ39FOkfrLZPPjqRbuGJLOVN41jUNuxZyr5UmuA3j3IE6BRdQjjFVe-VAh09x2e6UCD8s_njMotk8E",
            "d": "o6M5s_Ls9NrC0p0dhPwh9nYD4A_q3LNktAzO8Q19oMxcWlV2FWVJNr2c-b-aCytQbh_i1BpxGsoAjAIgIbXVKOytvZyfl9VccXPTCXXBs7ygRVF-gZFkM7qQvYW4u_D9KMR5xMn_URMNnzz87kHLbLZoJo5wTiZkjb5Q9MRJn4S7fu2ImVDgvGMS9uun7-C_OVeX1gBRoTZAXq-6xHpCTAfNuoINopDYfnpT41EdzZhvori_G2U4aaapaS6ekYBkN1ADxKZ0Rh8woyROjjfPr0a_Ebai1s9Vsh-BLNcpzSrexzYyL7FjEhiS4uRGwajLZpe4nE-bKSbBXM1MjpoB",
            "e": "AQAB",
            "use": "sig",
            "kid": "dENjP+Fgp/5YeJrnAyFeo2GqZO0=",
            "qi": "k3FAdDhrKo1WYveCX7YnoGPgSV0gyfeZpDjejjPrh2BMfVDLIYtsXstcVwcxkf0fKd4DvNb5Fxc0STo0AzfrjeyAHrVnQ0U3MDIrPEJdKS2jexdI950Qih9W9gm7CSMNCy7tA_q1EB-q3pz1yn2Nk71dA8DusspZRDHLBdHeLME",
            "dp": "xLqwLKQDi5fTeie18Q2E9h0tkYWTTlVixdGu_ChSRP2BeeW-OEMSkM3uIZGHuVVfhLxHwmWlby8c0dBcQTBJuU4KS6J0zbvZ9iclbxraSbn1qiFo9hcz8iC-qfO68FALUs5vXYtZgYMi5XlZWsrl_0j0QR1__37iIw65MB5Z1rM",
            "alg": "RS256",
            "dq": "lWXpRTk_yHtI3Cwvi-6MtIJ8oxIrrmmTKHlrnts1ZL8yJKYgEcFyG96zR43HEz59nD0vLt0IqE-vnKMPsgINH_AvY4uZ6ZMm8CEIxVz9qd-e6IF8BjlFSJJ_hQ8vj6fkJV7eYWdr67-XU3-p854A3NkfR3PXewzB-yt5f1JgNgE",
            "n": "sYIFywlcGcugMThW7JVRTJOAXV87lDIs6bOJwO8c8SCHwdaT-mvKbIDlqIcifH9NqsfvrYw5t5KOd1VW7ndIiX_TKYkSqbdFuUoNjD2bS2H7q1Ra7aBuZQMAgkPBXOwslW4_fzPQYsop-c7Db_6eBw8A77BeOQuazBR4FLM_VpNswGboCzF8ouJ8XU7KnlMgmqN3gImFFJYGe6xvcAY0GWD5N_hJ6egSYy_jT3dltvRtMIJq59Cyg7MXHNNHYCLtNh3SU8yUGon-UJ-64PtfY5UNGEeKmgm8fPOQq3gycZTQJun-90xI5sl_T_kfGmyBTg6sJRTK1moRjd1xfzFPsw"
        }"#;

        let expected = "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCxggXLCVwZy6Ax\
            OFbslVFMk4BdXzuUMizps4nA7xzxIIfB1pP6a8psgOWohyJ8f02qx++tjDm3ko53\
            VVbud0iJf9MpiRKpt0W5Sg2MPZtLYfurVFrtoG5lAwCCQ8Fc7CyVbj9/M9Biyin5\
            zsNv/p4HDwDvsF45C5rMFHgUsz9Wk2zAZugLMXyi4nxdTsqeUyCao3eAiYUUlgZ7\
            rG9wBjQZYPk3+Enp6BJjL+NPd2W29G0wgmrn0LKDsxcc00dgIu02HdJTzJQaif5Q\
            n7rg+19jlQ0YR4qaCbx885CreDJxlNAm6f73TEjmyX9P+R8abIFODqwlFMrWahGN\
            3XF/MU+zAgMBAAECggEAAKOjObPy7PTawtKdHYT8IfZ2A+AP6tyzZLQMzvENfaDM\
            XFpVdhVlSTa9nPm/mgsrUG4f4tQacRrKAIwCICG11Sjsrb2cn5fVXHFz0wl1wbO8\
            oEVRfoGRZDO6kL2FuLvw/SjEecTJ/1ETDZ88/O5By2y2aCaOcE4mZI2+UPTESZ+E\
            u37tiJlQ4LxjEvbrp+/gvzlXl9YAUaE2QF6vusR6QkwHzbqCDaKQ2H56U+NRHc2Y\
            b6K4vxtlOGmmqWkunpGAZDdQA8SmdEYfMKMkTo43z69GvxG2otbPVbIfgSzXKc0q\
            3sc2Mi+xYxIYkuLkRsGoy2aXuJxPmykmwVzNTI6aAQKBgQD2uUoQCjDH7e2tm140\
            OqO1XxIaz+v0EdtcxaTNTFnU/yUdo6MqoaCeVXDXyJciXHIdXOFIVC5n92XJy4EM\
            cN1RpfJ1O8hyovvXRDb06k9Lvhj0i/xLRFgglzPUGSo5OTtOD+6UXFlH+O2UD0JW\
            EwVxi7BaxldF9IjsSUnJMvPwcwKBgQC4LogzossJQsVI89gMx/zHU1XmQmlUqkn6\
            b5a2QdJPE2lO0ujiYaQ4U+dfvX+3SozmWw0x8vAJq+Yrn5efAH8kjCbGOgG4VDf0\
            U6R+stk8+OpFu4Yks5U3jWNQ27FnKvlSa4DePcgToFF1COMVV75UCHT3HZ7pQIPy\
            z+eMyi2TwQKBgQDEurAspAOLl9N6J7XxDYT2HS2RhZNOVWLF0a78KFJE/YF55b44\
            QxKQze4hkYe5VV+EvEfCZaVvLxzR0FxBMEm5TgpLonTNu9n2JyVvGtpJufWqIWj2\
            FzPyIL6p87rwUAtSzm9di1mBgyLleVlayuX/SPRBHX//fuIjDrkwHlnWswKBgQCV\
            ZelFOT/Ie0jcLC+L7oy0gnyjEiuuaZMoeWue2zVkvzIkpiARwXIb3rNHjccTPn2c\
            PS8u3QioT6+cow+yAg0f8C9ji5npkybwIQjFXP2p357ogXwGOUVIkn+FDy+Pp+Ql\
            Xt5hZ2vrv5dTf6nzngDc2R9Hc9d7DMH7K3l/UmA2AQKBgQCTcUB0OGsqjVZi94Jf\
            tiegY+BJXSDJ95mkON6OM+uHYEx9UMshi2xey1xXBzGR/R8p3gO81vkXFzRJOjQD\
            N+uN7IAetWdDRTcwMis8Ql0pLaN7F0j3nRCKH1b2CbsJIw0LLu0D+rUQH6renPXK\
            fY2TvV0DwO6yyllEMcsF0d4swQ==";

        let key: JsonWebKey = JsonWebKey::from_json(json).unwrap();
        assert!(matches!(key, JsonWebKey::Rsa(_)), "Expected RSA key type");
        assert_eq!(
            key.to_der().unwrap(),
            base64::standard_decode(expected).unwrap()
        );
    }

    #[test]
    fn test_deserialize_rsa_pub() {
        let json = r#"{
            "e": "AQAB",
            "use": "sig",
            "kty": "RSA",
            "kid": "23f7a3583796f97129e5418f9b2136fcc0a96462",
            "alg": "RS256",
            "n": "jb7Wtq9aDMpiXvHGCB5nrfAS2UutDEkSbK16aDtDhbYJhDWhd7vqWhFbnP0C_XkSxsqWJoku69y49EzgabEiUMf0q3X5N0pNvV64krviH2m9uLnyGP5GMdwZpjTXARK9usGgYZGuWhjfgTTvooKDUdqVQYvbrmXlblkM6xjbA8GnShSaOZ4AtMJCjWnaN_UaMD_vAXvOYj4SaefDMSlSoiI46yipFdggfoIV8RDg1jeffyre_8DwOWsGz7b2yQrL7grhYCvoiPrybKmViXqu-17LTIgBw6TDk8EzKdKzm33_LvxU7AKs3XWW_NvZ4WCPwp4gr7uw6RAkdDX_ZAn0TQ"
            }"#;

        let key: JsonWebKey = JsonWebKey::from_json(json).unwrap();
        assert!(matches!(key, JsonWebKey::Rsa(_)), "Expected RSA key type");
    }

    #[test]
    fn test_deserialize_ec() {
        let json = r#"{
            "kty": "EC",
            "d": "hauIyknXv6hMuNcy3EiF4EuE6LEVPqBIW94WUAodWDk",
            "use": "sig",
            "crv": "P-256",
            "kid": "3szM3lFjViEdWTe1lY0ZJ6g7jJ4=",
            "x": "KejbjRrFQ2RW9UImw57J8kJZzhUvxpxscmwaPZ31WNI",
            "y": "R87oaokXcS0J2EpIB4yCo_6A-pzxpymMOieq2WM_yIY",
            "alg": "ES256"
        }"#;

        let expected = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQghauIyknXv6hMuNcy\
            3EiF4EuE6LEVPqBIW94WUAodWDmhRANCAAQp6NuNGsVDZFb1QibDnsnyQlnOFS/GnGxybBo9nfVY0kfO6G\
            qJF3EtCdhKSAeMgqP+gPqc8acpjDonqtljP8iG";

        let key: JsonWebKey = JsonWebKey::from_json(json).unwrap();
        assert!(
            matches!(key, JsonWebKey::EllipticCurve(_)),
            "Expected EC key type"
        );
        assert_eq!(
            key.to_der().unwrap(),
            base64::standard_decode(expected).unwrap()
        );
    }

    #[test]
    fn test_deserialize_hmac() {
        let json = r#"{
            "kty": "oct",
            "alg": "HS256",
            "k": "FdFYFzERwC2uCBB46pZQi4GG85LujR8obt-KWRBICVQ"
        }"#;

        let expected = "FdFYFzERwC2uCBB46pZQi4GG85LujR8obt-KWRBICVQ";

        let key: JsonWebKey = JsonWebKey::from_json(json).unwrap();
        assert!(matches!(key, JsonWebKey::Oct(_)), "Expected 'oct' key type");
        assert_eq!(
            *key.key_bytes().unwrap(),
            *base64::url_decode(expected).unwrap()
        );
    }

    #[test]
    fn test_deserialize_oct() {
        let json = r#"{
            "kty": "oct",
            "k": "FdFYFzERwC2uCBB46pZQi4GG85LujR8obt-KWRBICVQ"
        }"#;

        let expected = "FdFYFzERwC2uCBB46pZQi4GG85LujR8obt-KWRBICVQ";

        let key: JsonWebKey = JsonWebKey::from_json(json).unwrap();
        assert!(matches!(key, JsonWebKey::Oct(_)), "Expected Oct key type");
        assert_eq!(
            *key.key_bytes().unwrap(),
            *base64::url_decode(expected).unwrap()
        );
    }

    #[test]
    fn test_from_pem() {
        let rsa_key = EvpPkey::generate_rsa(2048);
        let ec_key = EvpPkey::generate_ec(EcCurve::P256);
        let eddsa_key = EvpPkey::generate_ed25519();

        for (key, expected) in [(rsa_key, "RSA"), (ec_key, "EC"), (eddsa_key, "OKP")] {
            assert_eq!(
                JsonWebKey::from_pem(key.private_key_to_pem().unwrap())
                    .unwrap()
                    .key_type(),
                expected
            );
            assert_eq!(
                JsonWebKey::from_pem(key.public_key_to_pem().unwrap())
                    .unwrap()
                    .key_type(),
                expected
            );
        }
    }

    #[test]
    fn test_generate_for_encryption_rsa() {
        for alg in [
            KeyManagementAlgorithm::Rsa15,
            KeyManagementAlgorithm::RsaOaep,
            KeyManagementAlgorithm::RsaOaep256,
            KeyManagementAlgorithm::RsaOaep384,
            KeyManagementAlgorithm::RsaOaep512,
        ] {
            let key = JsonWebKeyGenerator::for_encryption(alg).generate().unwrap();
            assert_eq!(key.key_type(), "RSA");
        }
    }

    #[test]
    fn test_generate_for_encryption_ecdh() {
        for alg in [
            KeyManagementAlgorithm::EcdhEs,
            KeyManagementAlgorithm::EcdhEsA128Kw,
            KeyManagementAlgorithm::EcdhEsA192Kw,
            KeyManagementAlgorithm::EcdhEsA256Kw,
        ] {
            let key = JsonWebKeyGenerator::for_encryption(alg).generate().unwrap();
            assert_eq!(key.key_type(), "EC");
            assert_eq!(key.algorithm(), Some(alg.name()));
        }
    }

    #[test]
    fn test_generate_for_encryption_symmetric() {
        for (alg, expected_bytes) in [
            (KeyManagementAlgorithm::A128Kw, 16),
            (KeyManagementAlgorithm::A192Kw, 24),
            (KeyManagementAlgorithm::A256Kw, 32),
            (KeyManagementAlgorithm::A128GcmKw, 16),
            (KeyManagementAlgorithm::A192GcmKw, 24),
            (KeyManagementAlgorithm::A256GcmKw, 32),
            (KeyManagementAlgorithm::Pbes2Hs256A128Kw, 32),
            (KeyManagementAlgorithm::Pbes2Hs384A192Kw, 32),
            (KeyManagementAlgorithm::Pbes2Hs512A256Kw, 32),
            (KeyManagementAlgorithm::Direct, 32),
        ] {
            let key = JsonWebKeyGenerator::for_encryption(alg).generate().unwrap();
            assert_eq!(key.key_type(), "oct");
            assert_eq!(key.key_bytes().unwrap().len(), expected_bytes);
            assert_eq!(key.algorithm(), Some(alg.name()));
        }
    }

    #[test]
    fn test_generate_for_encryption_symmetric_custom_bits() {
        let key = JsonWebKeyGenerator::for_encryption(KeyManagementAlgorithm::Direct)
            .with_key_bits(128)
            .generate()
            .unwrap();
        assert_eq!(key.key_bytes().unwrap().len(), 16);
    }

    #[test]
    fn test_to_json_round_trip() {
        // RSA (private includes private params, public excludes them)
        let rsa = JsonWebKeyGenerator::for_encryption(KeyManagementAlgorithm::RsaOaep256)
            .generate()
            .unwrap();
        let json = rsa.to_json(OutputControlLevel::IncludePrivate);
        let parsed = JsonWebKey::from_json(&json).unwrap();
        assert_eq!(parsed.key_type(), "RSA");
        assert!(json.contains("\"d\":"));
        let public_json = rsa.to_json(OutputControlLevel::PublicOnly);
        assert!(!public_json.contains("\"d\":"));
        let parsed_pub = JsonWebKey::from_json(&public_json).unwrap();
        assert_eq!(parsed_pub.key_type(), "RSA");

        // EC
        let ec = JsonWebKeyGenerator::for_encryption(KeyManagementAlgorithm::EcdhEs)
            .generate()
            .unwrap();
        let json = ec.to_json(OutputControlLevel::IncludePrivate);
        let parsed = JsonWebKey::from_json(&json).unwrap();
        assert_eq!(parsed.key_type(), "EC");
        assert!(json.contains("\"crv\":\"P-256\""));
        assert!(json.contains("\"x\":"));
        assert!(json.contains("\"y\":"));
        assert!(json.contains("\"d\":"));
        let public_json = ec.to_json(OutputControlLevel::PublicOnly);
        assert!(!public_json.contains("\"d\":"));
        JsonWebKey::from_json(&public_json).unwrap();

        // oct (symmetric: only emitted for IncludePrivate/IncludeSymmetric)
        let oct = JsonWebKeyGenerator::for_encryption(KeyManagementAlgorithm::A256Kw)
            .generate()
            .unwrap();
        let json = oct.to_json(OutputControlLevel::IncludeSymmetric);
        let parsed = JsonWebKey::from_json(&json).unwrap();
        assert_eq!(parsed.key_type(), "oct");
        assert_eq!(parsed.key_bytes().unwrap(), oct.key_bytes().unwrap());
        let public_json = oct.to_json(OutputControlLevel::PublicOnly);
        assert!(!public_json.contains("\"k\":"));

        // OKP
        let okp = JsonWebKeyGenerator::for_signature(AlgorithmIdentifier::EdDsa)
            .generate()
            .unwrap();
        let json = okp.to_json(OutputControlLevel::IncludePrivate);
        let parsed = JsonWebKey::from_json(&json).unwrap();
        assert_eq!(parsed.key_type(), "OKP");
        assert!(json.contains("\"crv\":\"Ed25519\""));
        assert!(json.contains("\"x\":"));
        assert!(json.contains("\"d\":"));
        let public_json = okp.to_json(OutputControlLevel::PublicOnly);
        assert!(!public_json.contains("\"d\":"));
        JsonWebKey::from_json(&public_json).unwrap();
    }

    #[test]
    fn test_pem_round_trip() {
        use crate::jwk::OkpCurve;

        // RSA
        let rsa = JsonWebKeyGenerator::for_signature(AlgorithmIdentifier::RsaUsingSha256)
            .generate()
            .unwrap();
        let priv_pem = rsa.to_pem(OutputControlLevel::IncludePrivate).unwrap();
        assert!(priv_pem.starts_with("-----BEGIN PRIVATE KEY-----"));
        let pub_pem = rsa.to_pem(OutputControlLevel::PublicOnly).unwrap();
        assert!(pub_pem.starts_with("-----BEGIN PUBLIC KEY-----"));
        // Round-trip both forms back through the facade.
        assert_eq!(JsonWebKey::from_pem(&priv_pem).unwrap().key_type(), "RSA");
        let parsed_pub = JsonWebKey::from_pem(&pub_pem).unwrap();
        assert_eq!(parsed_pub.key_type(), "RSA");
        // A public-only parse must not offer a private PEM.
        assert!(
            parsed_pub
                .to_pem(OutputControlLevel::IncludePrivate)
                .is_err()
        );

        // EC
        let ec =
            JsonWebKeyGenerator::for_signature(AlgorithmIdentifier::EcdsaUsingP256CurveAndSha256)
                .generate()
                .unwrap();
        let priv_pem = ec.to_pem(OutputControlLevel::IncludePrivate).unwrap();
        assert_eq!(JsonWebKey::from_pem(&priv_pem).unwrap().key_type(), "EC");
        let pub_pem = ec.to_pem(OutputControlLevel::PublicOnly).unwrap();
        assert_eq!(JsonWebKey::from_pem(&pub_pem).unwrap().key_type(), "EC");

        // OKP (Ed25519 and X25519)
        let ed = JsonWebKeyGenerator::for_signature(AlgorithmIdentifier::EdDsa)
            .generate()
            .unwrap();
        let priv_pem = ed.to_pem(OutputControlLevel::IncludePrivate).unwrap();
        assert_eq!(JsonWebKey::from_pem(&priv_pem).unwrap().key_type(), "OKP");
        let pub_pem = ed.to_pem(OutputControlLevel::PublicOnly).unwrap();
        assert_eq!(JsonWebKey::from_pem(&pub_pem).unwrap().key_type(), "OKP");

        let x = JsonWebKeyGenerator::for_encryption(KeyManagementAlgorithm::EcdhEs)
            .with_okp_curve(OkpCurve::X25519)
            .generate()
            .unwrap();
        let pub_pem = x.to_pem(OutputControlLevel::PublicOnly).unwrap();
        let parsed = JsonWebKey::from_pem(&pub_pem).unwrap();
        assert_eq!(parsed.key_type(), "OKP");
        assert!(
            parsed
                .to_json(OutputControlLevel::PublicOnly)
                .contains("X25519")
        );

        // oct keys have no PEM representation.
        let oct = JsonWebKeyGenerator::for_encryption(KeyManagementAlgorithm::A128Kw)
            .generate()
            .unwrap();
        assert!(oct.to_pem(OutputControlLevel::PublicOnly).is_err());
    }

    #[test]
    fn test_typed_from_pem() {
        // A typed from_pem validates the key type.
        let rsa = JsonWebKeyGenerator::for_signature(AlgorithmIdentifier::RsaUsingSha256)
            .generate()
            .unwrap();
        let pem = rsa.to_pem(OutputControlLevel::IncludePrivate).unwrap();

        // Right type succeeds.
        assert!(rsa::RsaJsonWebKey::from_pem(&pem).is_ok());
        // Wrong type fails rather than silently coercing.
        assert!(ec::EcJsonWebKey::from_pem(&pem).is_err());
        assert!(okp::OkpJsonWebKey::from_pem(&pem).is_err());
    }

    #[test]
    fn test_typed_from_der() {
        let rsa = JsonWebKeyGenerator::for_signature(AlgorithmIdentifier::RsaUsingSha256)
            .generate()
            .unwrap();
        let ec =
            JsonWebKeyGenerator::for_signature(AlgorithmIdentifier::EcdsaUsingP256CurveAndSha256)
                .generate()
                .unwrap();
        let okp = JsonWebKeyGenerator::for_signature(AlgorithmIdentifier::EdDsa)
            .generate()
            .unwrap();

        for der in [rsa.to_pkcs8_der().unwrap(), rsa.to_spki_der().unwrap()] {
            assert!(rsa::RsaJsonWebKey::from_der(der).is_ok());
        }
        for der in [ec.to_pkcs8_der().unwrap(), ec.to_spki_der().unwrap()] {
            assert!(ec::EcJsonWebKey::from_der(der).is_ok());
        }
        for der in [okp.to_pkcs8_der().unwrap(), okp.to_spki_der().unwrap()] {
            assert!(okp::OkpJsonWebKey::from_der(der).is_ok());
        }

        let rsa_der = rsa.to_pkcs8_der().unwrap();
        assert!(ec::EcJsonWebKey::from_der(&rsa_der).is_err());
        assert!(okp::OkpJsonWebKey::from_der(&rsa_der).is_err());
    }

    #[test]
    fn test_from_x509() {
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

        // A self-signed P-256 certificate using a *named* curve (the OID form).
        // BoringSSL only accepts named curves and rejects explicitly-encoded
        // curve parameters, so the fixture must use the interoperable OID form
        // for both backends to parse it.
        const EC_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
            MIIBEzCBugIJAPxq0hjaNU3GMAoGCCqGSM49BAMCMBIxEDAOBgNVBAMMB3Rlc3Qt\n\
            ZWMwHhcNMjYwODIxMDE0NzAwWhcNMjcwODIxMDE0NzAwWjASMRAwDgYDVQQDDAd0\n\
            ZXN0LWVjMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE11Yuowmhk/PDAVQ67Ytn\n\
            E5z9bhBzk+wYRcGRBg+E7Zz0Bg42r695k/Fe01jEMV+M2IT4uszNaUWPswfqO6Ln\n\
            jjAKBggqhkjOPQQDAgNIADBFAiARe9WCKo8HAaJDfb5OcNtW+Z7nJ/fCDif0xdiC\n\
            qxK5zAIhANNTkXGEICrIBYz41EUn81353XCuZAjcQirOhBbdcygd\n\
            -----END CERTIFICATE-----";

        // Extract an RSA public key from a certificate (PEM and DER forms).
        let der = crate::base64::pem_decode(
            RSA_CERT_PEM
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", ""),
        )
        .unwrap();
        let rsa_from_der = rsa::RsaJsonWebKey::from_x509_der(&der).unwrap();
        assert_eq!(rsa_from_der.key_type(), "RSA");
        let rsa = rsa::RsaJsonWebKey::from_x509_pem(RSA_CERT_PEM).unwrap();
        assert_eq!(rsa.key_type(), "RSA");
        assert_eq!(rsa.key_size_bits(), 2048);

        // Extract an EC public key from a certificate.
        let ec = ec::EcJsonWebKey::from_x509_pem(EC_CERT_PEM).unwrap();
        assert_eq!(ec.key_type(), "EC");
        assert!(ec.to_json(OutputControlLevel::PublicOnly).contains("P-256"));

        // Type mismatches are rejected.
        assert!(ec::EcJsonWebKey::from_x509_pem(RSA_CERT_PEM).is_err());
        assert!(rsa::RsaJsonWebKey::from_x509_pem(EC_CERT_PEM).is_err());
        assert!(okp::OkpJsonWebKey::from_x509_pem(RSA_CERT_PEM).is_err());

        // Garbage input is rejected.
        assert!(rsa::RsaJsonWebKey::from_x509_pem("not a cert").is_err());
        assert!(rsa::RsaJsonWebKey::from_x509_der(b"garbage").is_err());
    }

    #[test]
    fn test_x509_thumbprints_stored_on_jwk() {
        // The RSA test cert's known-good thumbprints (openssl over the DER).
        const EXPECTED_X5T: &str = "9fUB4n5Oi7UOpmlQvneMQew7BgI";
        const EXPECTED_X5T_S256: &str = "rCAyJQXv1uillTH_pEAxvTzRTDwoyQ6b3_scGHFjMkU";

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

        // Thumbprints are captured at extraction time.
        let rsa = rsa::RsaJsonWebKey::from_x509_pem(RSA_CERT_PEM).unwrap();
        assert_eq!(rsa.x5t(), Some(EXPECTED_X5T));
        assert_eq!(rsa.x5t_s256(), Some(EXPECTED_X5T_S256));

        // And surface through the JsonWebKey facade.
        let jwk = JsonWebKey::Rsa(rsa.clone());
        assert_eq!(jwk.x5t(), Some(EXPECTED_X5T));
        assert_eq!(jwk.x5t_s256(), Some(EXPECTED_X5T_S256));

        // And are emitted in the JWK JSON.
        let json = rsa.to_json(OutputControlLevel::PublicOnly);
        assert!(
            json.contains(&format!("\"x5t\":\"{EXPECTED_X5T}\"")),
            "{json}"
        );
        assert!(
            json.contains(&format!("\"x5t#S256\":\"{EXPECTED_X5T_S256}\"")),
            "{json}"
        );

        // And survive a JSON round trip.
        let parsed = JsonWebKey::from_json(&json).unwrap();
        assert_eq!(parsed.x5t(), Some(EXPECTED_X5T));
        assert_eq!(parsed.x5t_s256(), Some(EXPECTED_X5T_S256));
        // Re-serializing keeps them (idempotent round trip).
        let json2 = parsed.to_json(OutputControlLevel::PublicOnly);
        assert!(
            json2.contains(&format!("\"x5t\":\"{EXPECTED_X5T}\"")),
            "{json2}"
        );

        // Keys not built from a certificate carry no thumbprints.
        let generated = JsonWebKeyGenerator::for_signature(AlgorithmIdentifier::RsaUsingSha256)
            .generate()
            .unwrap();
        assert_eq!(generated.x5t(), None);
        assert_eq!(generated.x5t_s256(), None);
        assert!(
            !generated
                .to_json(OutputControlLevel::PublicOnly)
                .contains("x5t")
        );

        // Symmetric keys never have thumbprints.
        let oct = JsonWebKeyGenerator::for_encryption(KeyManagementAlgorithm::A128Kw)
            .generate()
            .unwrap();
        assert_eq!(oct.x5t(), None);
        assert_eq!(oct.x5t_s256(), None);
    }

    /// RFC 7638 Section 3.1 known-answer vector: an RSA JWK and its SHA-256
    /// thumbprint.
    #[test]
    fn test_rfc7638_rsa_thumbprint() {
        let jwk_json = r#"{
            "kty": "RSA",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e": "AQAB",
            "alg": "RS256",
            "kid": "2011-04-29"
        }"#;
        let jwk = JsonWebKey::from_json(jwk_json).unwrap();
        assert_eq!(
            jwk.thumbprint().unwrap(),
            "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
        );
    }

    /// The thumbprint is independent of optional members and field order, and
    /// works for every key type's required-member set.
    #[test]
    fn test_thumbprint_all_key_types_stable() {
        // EC P-256
        let ec = JsonWebKey::from_json(
            r#"{"kty":"EC","crv":"P-256","x":"amuk6RkDZi-48mKrzgBN_zUZ_9qupIwTZHJjM03qL-4","y":"ZOESj6_dpPiZZR-fJ-XVszQta28Cjgti7JudooQJ0co"}"#,
        )
        .unwrap();
        let t1 = ec.thumbprint().unwrap();
        // Adding optional members must not change the thumbprint.
        let ec_with_meta = JsonWebKey::from_json(
            r#"{"kty":"EC","crv":"P-256","x":"amuk6RkDZi-48mKrzgBN_zUZ_9qupIwTZHJjM03qL-4","y":"ZOESj6_dpPiZZR-fJ-XVszQta28Cjgti7JudooQJ0co","kid":"k1","use":"sig","alg":"ES256"}"#,
        )
        .unwrap();
        assert_eq!(t1, ec_with_meta.thumbprint().unwrap());

        // OKP (Ed25519) and oct just need to produce a well-formed value.
        let okp = JsonWebKey::from_json(
            r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#,
        )
        .unwrap();
        assert_eq!(okp.thumbprint().unwrap().len(), 43); // 32 bytes -> 43 b64url chars

        let oct = JsonWebKey::from_json(r#"{"kty":"oct","k":"c2hvcnQ"}"#).unwrap();
        assert_eq!(oct.thumbprint().unwrap().len(), 43);
    }

    /// `canonical_jwk_json` errors when a required member is absent (defensive;
    /// unreachable via the public constructors, which validate members).
    #[test]
    fn test_canonical_jwk_json_missing_member() {
        let value =
            simd_json::to_owned_value(&mut br#"{"kty":"RSA","e":"AQAB"}"#.to_vec()).unwrap();
        // RSA requires "n", which is missing here.
        let err = canonical_jwk_json(&value, &["e", "kty", "n"], 64).unwrap_err();
        assert!(
            matches!(err, JoseError::InvalidKey(ref m) if m.contains("'n'")),
            "{err:?}"
        );
    }

    #[test]
    fn test_x5t_parsed_across_key_types() {
        // x5t/x5t#S256 in JWK JSON are preserved on parse for each asymmetric
        // key type (each has its own from_map).
        let ec_json = r#"{"kty":"EC","crv":"P-256","x5t":"abc","x5t#S256":"def","x":"amuk6RkDZi-48mKrzgBN_zUZ_9qupIwTZHJjM03qL-4","y":"ZOESj6_dpPiZZR-fJ-XVszQta28Cjgti7JudooQJ0co"}"#;
        let ec = JsonWebKey::from_json(ec_json).unwrap();
        assert_eq!(ec.x5t(), Some("abc"));
        assert_eq!(ec.x5t_s256(), Some("def"));
        // Round trip preserves them.
        let json = ec.to_json(OutputControlLevel::PublicOnly);
        assert!(json.contains("\"x5t\":\"abc\""), "{json}");
        assert!(json.contains("\"x5t#S256\":\"def\""), "{json}");

        let okp_json = r#"{"kty":"OKP","crv":"Ed25519","x5t":"ghi","x5t#S256":"jkl","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#;
        let okp = JsonWebKey::from_json(okp_json).unwrap();
        assert_eq!(okp.x5t(), Some("ghi"));
        assert_eq!(okp.x5t_s256(), Some("jkl"));

        // Absent thumbprints parse as None.
        let ec_plain = r#"{"kty":"EC","crv":"P-256","x":"amuk6RkDZi-48mKrzgBN_zUZ_9qupIwTZHJjM03qL-4","y":"ZOESj6_dpPiZZR-fJ-XVszQta28Cjgti7JudooQJ0co"}"#;
        let ec_plain = JsonWebKey::from_json(ec_plain).unwrap();
        assert_eq!(ec_plain.x5t(), None);
        assert_eq!(ec_plain.x5t_s256(), None);
    }

    /// Off-curve / zero / oversized EC public points must return an error, not panic.
    #[test]
    fn test_ec_off_curve_point_rejected_not_panics() {
        // Valid P-256 x, but y == x (off-curve).
        let off_curve = r#"{"kty":"EC","crv":"P-256","x":"amuk6RkDZi-48mKrzgBN_zUZ_9qupIwTZHJjM03qL-4","y":"amuk6RkDZi-48mKrzgBN_zUZ_9qupIwTZHJjM03qL-4"}"#;
        assert!(JsonWebKey::from_json(off_curve).is_err());

        // x == y == 0.
        let zero = r#"{"kty":"EC","crv":"P-256","x":"AA","y":"AA"}"#;
        assert!(JsonWebKey::from_json(zero).is_err());

        // Oversized coordinate (2^256) exceeds the P-256 field width.
        let oversized = r#"{"kty":"EC","crv":"P-256","x":"AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","y":"ZOESj6_dpPiZZR-fJ-XVszQta28Cjgti7JudooQJ0co"}"#;
        assert!(JsonWebKey::from_json(oversized).is_err());

        // A valid key still parses.
        let valid = r#"{"kty":"EC","crv":"P-256","x":"amuk6RkDZi-48mKrzgBN_zUZ_9qupIwTZHJjM03qL-4","y":"ZOESj6_dpPiZZR-fJ-XVszQta28Cjgti7JudooQJ0co"}"#;
        assert!(JsonWebKey::from_json(valid).is_ok());
    }

    /// Regression: degenerate RSA keys (zero modulus, even/tiny exponent) must
    /// return an error, not panic on `RSA_set0_key`.
    #[test]
    fn test_rsa_degenerate_key_rejected_not_panics() {
        for json in [
            r#"{"kty":"RSA","n":"","e":""}"#,     // both zero
            r#"{"kty":"RSA","n":"AA","e":"AA"}"#, // 0x00, 0x00
            r#"{"kty":"RSA","n":"sYIFywlcGcugMThW7JVRTJOAXV87lDIs6bOJwO8c8SCHwdaT-mvKbIDlqIcifH9NqsfvrYw5t5KOd1VW7ndIiX_TKYkSqbdFuUoNjD2bS2H7q1Ra7aBuZQMAgkPBXOwslW4_fzPQYsop-c7Db_6eBw8A77BeOQuazBR4FLM_VpNswGboCzF8ouJ8XU7KnlMgmqN3gImFFJYGe6xvcAY0GWD5N_hJ6egSYy_jT3dltvRtMIJq59Cyg7MXHNNHYCLtNh3SU8yUGon-UJ-64PtfY5UNGEeKmgm8fPOQq3gycZTQJun-90xI5sl_T_kfGmyBTg6sJRTK1moRjd1xfzFPsw","e":"Ag"}"#, // e = 2 (even)
        ] {
            assert!(JsonWebKey::from_json(json).is_err(), "{json}");
        }
    }

    /// Regression: an invalid JWK `use` value is a parse error, not silently
    /// treated as "no use restriction".
    #[test]
    fn test_invalid_use_rejected() {
        let json = r#"{"kty":"EC","crv":"P-256","use":"sign-verify","x":"amuk6RkDZi-48mKrzgBN_zUZ_9qupIwTZHJjM03qL-4","y":"ZOESj6_dpPiZZR-fJ-XVszQta28Cjgti7JudooQJ0co"}"#;
        assert!(JsonWebKey::from_json(json).is_err());
    }

    /// Regression: EC coordinates must be exactly the field-octet length.
    /// A 31-byte (under-width) coordinate for P-256 must be rejected even
    /// though its integer value fits in 32 bytes.
    #[test]
    fn test_ec_underwidth_coordinate_rejected() {
        // base64url of a 31-byte value (leading zero byte dropped) for x.
        // 31 bytes -> 42 base64url chars (31*4/3 rounded). Use a valid y.
        let underwidth_x = base64::url_encode([0xABu8; 31]);
        let json = format!(
            r#"{{"kty":"EC","crv":"P-256","x":"{}","y":"ZOESj6_dpPiZZR-fJ-XVszQta28Cjgti7JudooQJ0co"}}"#,
            String::from_utf8(underwidth_x.into_vec()).unwrap()
        );
        let err = JsonWebKey::from_json(&json).unwrap_err();
        assert!(
            matches!(err, JoseError::InvalidKey(_)),
            "expected InvalidKey for 31-byte coordinate, got {err:?}"
        );

        // Over-width (33 bytes) also rejected.
        let overwidth_x = base64::url_encode([0xCDu8; 33]);
        let json = format!(
            r#"{{"kty":"EC","crv":"P-256","x":"{}","y":"ZOESj6_dpPiZZR-fJ-XVszQta28Cjgti7JudooQJ0co"}}"#,
            String::from_utf8(overwidth_x.into_vec()).unwrap()
        );
        assert!(JsonWebKey::from_json(&json).is_err());

        // Exact 32-byte coordinate (a valid on-curve point) parses fine.
        let valid = r#"{"kty":"EC","crv":"P-256","x":"amuk6RkDZi-48mKrzgBN_zUZ_9qupIwTZHJjM03qL-4","y":"ZOESj6_dpPiZZR-fJ-XVszQta28Cjgti7JudooQJ0co"}"#;
        assert!(JsonWebKey::from_json(valid).is_ok());
    }
}
