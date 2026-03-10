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
    /// EdDSA
    EdDsa,
    /// PS256
    RsaPssUsingSha256,
    /// PS384
    RsaPssUsingSha384,
    /// PS512
    RsaPssUsingSha512,
}

impl AlgorithmIdentifier {
    fn try_from_str(alg: impl AsRef<str>) -> Result<Self, JoseError> {
        match alg.as_ref() {
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
}

impl TryFrom<&str> for AlgorithmIdentifier {
    type Error = JoseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::try_from_str(value)
    }
}

impl TryFrom<String> for AlgorithmIdentifier {
    type Error = JoseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from_str(value)
    }
}

impl TryFrom<&String> for AlgorithmIdentifier {
    type Error = JoseError;

    fn try_from(value: &String) -> Result<Self, Self::Error> {
        Self::try_from_str(value)
    }
}

impl fmt::Display for AlgorithmIdentifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}
