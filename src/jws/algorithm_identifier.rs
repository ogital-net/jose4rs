use std::fmt;

use crate::error::JoseError;

/// Represents the algorithm identifiers for JWS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlgorithmIdentifier {
    /// none
    None,
    /// HS256
    HmacSha256,
    /// HS384
    HmacSha384,
    /// HS512
    HmacSha512,
    /// RS256
    RsaUsingSha256,
    /// RS384
    RsaUsingSha384,
    /// RS512
    RsaUsingSha512,
    /// ES256
    EcdsaUsingP256CurveAndSha256,
    /// ES384
    EcdsaUsingP384CurveAndSha384,
    /// ES512
    EcdsaUsingP521CurveAndSha512,
    /// ES256K
    #[cfg(not(feature = "boring"))]
    EcdsaUsingSecp256k1CurveAndSha256,
    /// `EdDSA`
    EdDsa,
    /// PS256
    RsaPssUsingSha256,
    /// PS384
    RsaPssUsingSha384,
    /// PS512
    RsaPssUsingSha512,
}

impl std::str::FromStr for AlgorithmIdentifier {
    type Err = JoseError;

    fn from_str(alg: &str) -> Result<Self, Self::Err> {
        match alg {
            "none" => Ok(AlgorithmIdentifier::None),
            "HS256" => Ok(AlgorithmIdentifier::HmacSha256),
            "HS384" => Ok(AlgorithmIdentifier::HmacSha384),
            "HS512" => Ok(AlgorithmIdentifier::HmacSha512),
            "RS256" => Ok(AlgorithmIdentifier::RsaUsingSha256),
            "RS384" => Ok(AlgorithmIdentifier::RsaUsingSha384),
            "RS512" => Ok(AlgorithmIdentifier::RsaUsingSha512),
            "ES256" => Ok(AlgorithmIdentifier::EcdsaUsingP256CurveAndSha256),
            "ES384" => Ok(AlgorithmIdentifier::EcdsaUsingP384CurveAndSha384),
            "ES512" => Ok(AlgorithmIdentifier::EcdsaUsingP521CurveAndSha512),
            #[cfg(not(feature = "boring"))]
            "ES256K" => Ok(AlgorithmIdentifier::EcdsaUsingSecp256k1CurveAndSha256),
            "EdDSA" => Ok(AlgorithmIdentifier::EdDsa),
            "PS256" => Ok(AlgorithmIdentifier::RsaPssUsingSha256),
            "PS384" => Ok(AlgorithmIdentifier::RsaPssUsingSha384),
            "PS512" => Ok(AlgorithmIdentifier::RsaPssUsingSha512),
            alg => Err(JoseError::InvalidAlgorithm(format!(
                "unsupported algorithm: {alg}"
            ))),
        }
    }
}

impl AlgorithmIdentifier {
    /// Returns the string representation of the algorithm identifier.
    pub fn name(&self) -> &'static str {
        match self {
            AlgorithmIdentifier::None => "none",
            AlgorithmIdentifier::HmacSha256 => "HS256",
            AlgorithmIdentifier::HmacSha384 => "HS384",
            AlgorithmIdentifier::HmacSha512 => "HS512",
            AlgorithmIdentifier::RsaUsingSha256 => "RS256",
            AlgorithmIdentifier::RsaUsingSha384 => "RS384",
            AlgorithmIdentifier::RsaUsingSha512 => "RS512",
            AlgorithmIdentifier::EcdsaUsingP256CurveAndSha256 => "ES256",
            AlgorithmIdentifier::EcdsaUsingP384CurveAndSha384 => "ES384",
            AlgorithmIdentifier::EcdsaUsingP521CurveAndSha512 => "ES512",
            #[cfg(not(feature = "boring"))]
            AlgorithmIdentifier::EcdsaUsingSecp256k1CurveAndSha256 => "ES256K",
            AlgorithmIdentifier::EdDsa => "EdDSA",
            AlgorithmIdentifier::RsaPssUsingSha256 => "PS256",
            AlgorithmIdentifier::RsaPssUsingSha384 => "PS384",
            AlgorithmIdentifier::RsaPssUsingSha512 => "PS512",
        }
    }

    /// The JWK `kty` (key type) a key for this algorithm belongs to:
    /// `"RSA"`, `"EC"`, `"OKP"`, or `"oct"`. `None` for the `none` algorithm.
    pub fn key_type(&self) -> Option<&'static str> {
        match self {
            AlgorithmIdentifier::None => None,
            AlgorithmIdentifier::HmacSha256
            | AlgorithmIdentifier::HmacSha384
            | AlgorithmIdentifier::HmacSha512 => Some("oct"),
            AlgorithmIdentifier::RsaUsingSha256
            | AlgorithmIdentifier::RsaUsingSha384
            | AlgorithmIdentifier::RsaUsingSha512
            | AlgorithmIdentifier::RsaPssUsingSha256
            | AlgorithmIdentifier::RsaPssUsingSha384
            | AlgorithmIdentifier::RsaPssUsingSha512 => Some("RSA"),
            AlgorithmIdentifier::EcdsaUsingP256CurveAndSha256
            | AlgorithmIdentifier::EcdsaUsingP384CurveAndSha384
            | AlgorithmIdentifier::EcdsaUsingP521CurveAndSha512 => Some("EC"),
            #[cfg(not(feature = "boring"))]
            AlgorithmIdentifier::EcdsaUsingSecp256k1CurveAndSha256 => Some("EC"),
            AlgorithmIdentifier::EdDsa => Some("OKP"),
        }
    }

    /// The JWK `crv` (curve) implied by this algorithm, if it pins one down:
    /// ES256 -> `P-256`, ES384 -> `P-384`, ES512 -> `P-521`, ES256K -> `secp256k1`.
    /// `None` for algorithms that don't determine a single curve (including
    /// `EdDSA`, which admits both Ed25519 and Ed448).
    pub fn ec_curve(&self) -> Option<&'static str> {
        match self {
            AlgorithmIdentifier::EcdsaUsingP256CurveAndSha256 => Some("P-256"),
            AlgorithmIdentifier::EcdsaUsingP384CurveAndSha384 => Some("P-384"),
            AlgorithmIdentifier::EcdsaUsingP521CurveAndSha512 => Some("P-521"),
            #[cfg(not(feature = "boring"))]
            AlgorithmIdentifier::EcdsaUsingSecp256k1CurveAndSha256 => Some("secp256k1"),
            _ => None,
        }
    }
}

impl TryFrom<&str> for AlgorithmIdentifier {
    type Error = JoseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl TryFrom<String> for AlgorithmIdentifier {
    type Error = JoseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl TryFrom<&String> for AlgorithmIdentifier {
    type Error = JoseError;

    fn try_from(value: &String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl fmt::Display for AlgorithmIdentifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}
