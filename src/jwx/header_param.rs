/// Represents the header parameter names as defined in various RFCs.
#[derive(PartialEq, Eq)]
pub enum HeaderParameter {
    Algorithm,
    EncryptionMethod,
    KeyId,
    Type,
    ContentType,
    JwkSetUrl,
    Jwk,
    X509CertificateChain,
    X509CertificateThumbprint,
    X509CertificateSha256Thumbprint,
    X509Url,
    EphemeralPublicKey,
    AgreementPartyUInfo,
    AgreementPartyVInfo,
    Zip,
    Pbes2SaltInput,
    Pbes2IterationCount,
    InitializationVector,
    AuthenticationTag,
    Critical,
    Base64UrlEncodePayload,
}

impl HeaderParameter {
    /// Returns the string representation of the header parameter name.
    pub fn name(&self) -> &'static str {
        match self {
            HeaderParameter::Algorithm => "alg",
            HeaderParameter::EncryptionMethod => "enc",
            HeaderParameter::KeyId => "kid",
            HeaderParameter::Type => "typ",
            HeaderParameter::ContentType => "cty",
            HeaderParameter::JwkSetUrl => "jku",
            HeaderParameter::Jwk => "jwk",
            HeaderParameter::X509CertificateChain => "x5c",
            HeaderParameter::X509CertificateThumbprint => "x5t",
            HeaderParameter::X509CertificateSha256Thumbprint => "x5t#S256",
            HeaderParameter::X509Url => "x5u",
            HeaderParameter::EphemeralPublicKey => "epk",
            HeaderParameter::AgreementPartyUInfo => "apu",
            HeaderParameter::AgreementPartyVInfo => "apv",
            HeaderParameter::Zip => "zip",
            HeaderParameter::Pbes2SaltInput => "p2s",
            HeaderParameter::Pbes2IterationCount => "p2c",
            HeaderParameter::InitializationVector => "iv",
            HeaderParameter::AuthenticationTag => "tag",
            HeaderParameter::Critical => "crit",
            HeaderParameter::Base64UrlEncodePayload => "b64",
        }
    }
}
