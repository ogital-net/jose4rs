/// Represents the header parameter names as defined in various RFCs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HeaderParameter {
    /// `alg` -- the algorithm used to secure the JWS or JWE (RFC 7515/7516).
    Algorithm,
    /// `enc` -- the content encryption algorithm for a JWE (RFC 7516).
    EncryptionMethod,
    /// `kid` -- a hint identifying the key used (RFC 7515).
    KeyId,
    /// `typ` -- the media type of the JWS/JWE object itself (RFC 7515).
    Type,
    /// `cty` -- the media type of the payload (RFC 7515); required to be `JWT`
    /// for nested JWTs (RFC 7519).
    ContentType,
    /// `jku` -- a URI referencing a JWKS (RFC 7515).
    JwkSetUrl,
    /// `jwk` -- the public key corresponding to the signing key (RFC 7515).
    Jwk,
    /// `x5c` -- the X.509 certificate chain (RFC 7515).
    X509CertificateChain,
    /// `x5t` -- the SHA-1 X.509 certificate thumbprint (RFC 7515).
    X509CertificateThumbprint,
    /// `x5t#S256` -- the SHA-256 X.509 certificate thumbprint (RFC 7515).
    X509CertificateSha256Thumbprint,
    /// `x5u` -- a URI referencing an X.509 certificate or chain (RFC 7515).
    X509Url,
    /// `epk` -- the ephemeral public key for ECDH key agreement (RFC 7518).
    EphemeralPublicKey,
    /// `apu` -- `PartyUInfo` for the Concat KDF in ECDH-ES (RFC 7518).
    AgreementPartyUInfo,
    /// `apv` -- `PartyVInfo` for the Concat KDF in ECDH-ES (RFC 7518).
    AgreementPartyVInfo,
    /// `zip` -- the compression applied to the plaintext before encryption
    /// (RFC 7516).
    Zip,
    /// `p2s` -- the salt input for PBES2 key management (RFC 7518).
    Pbes2SaltInput,
    /// `p2c` -- the iteration count for PBES2 key management (RFC 7518).
    Pbes2IterationCount,
    /// `iv` -- the initialization vector, e.g. for AES-GCM key wrap (RFC 7518).
    InitializationVector,
    /// `tag` -- the authentication tag, e.g. for AES-GCM key wrap (RFC 7518).
    AuthenticationTag,
    /// `crit` -- header parameters that must be understood (RFC 7515).
    Critical,
    /// `b64` -- whether the payload is base64url-encoded (RFC 7797).
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
