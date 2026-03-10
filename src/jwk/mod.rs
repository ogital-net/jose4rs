use std::collections::BTreeMap;

use ec::ECJsonWebKey;
use oct::OctetSequenceJsonWebKey;
use okp::OkpJsonWebKey;
use rsa::RsaJsonWebKey;
use simd_json::derived::ValueObjectAccessAsScalar as _;

use crate::{
    crypto::{rand::rand_bytes, Bio, EcCurve, EvpPkey, EvpPkeyType},
    error::JoseError,
    jwe::KeyManagementAlgorithm,
    jws::AlgorithmIdentifier,
};

pub mod ec;
pub mod oct;
pub mod okp;
pub mod rsa;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyUse {
    Signature,
    Encryption,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputControlLevel {
    IncludePrivate,
    IncludeSymmetric,
    PublicOnly,
}

pub enum JsonWebKey {
    EllipticCurve(ECJsonWebKey),
    OctetKeyPair(OkpJsonWebKey),
    Rsa(RsaJsonWebKey),
    Oct(OctetSequenceJsonWebKey),
}

pub(super) trait GetStr {
    fn get(&self, key: &str) -> Option<&str>;
}

impl GetStr for BTreeMap<String, String> {
    fn get(&self, key: &str) -> Option<&str> {
        self.get(key).map(|x| x.as_str())
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

impl JsonWebKey {
    pub fn from_json(json: impl AsRef<[u8]>) -> Result<Self, JoseError> {
        let mut json = json.as_ref().to_vec().into_boxed_slice();

        let value = simd_json::to_borrowed_value(&mut json)?;

        let jwk = match value.get_str("kty") {
            Some(val) => match val {
                "RSA" => JsonWebKey::Rsa(value.try_into()?),
                "EC" => JsonWebKey::EllipticCurve(value.try_into()?),
                "oct" => JsonWebKey::Oct(value.try_into()?),
                "OKP" => JsonWebKey::OctetKeyPair(value.try_into()?),
                _ => {
                    return Err(JoseError::InvalidJson(
                        "'kty' must be one of 'EC', RSA', 'OKP', or 'oct'".into(),
                    ))
                }
            },
            None => return Err(JoseError::InvalidJson("'kty' field missing".into())),
        };

        Ok(jwk)
    }

    pub fn from_value(value: &simd_json::OwnedValue) -> Result<Self, JoseError> {
        let jwk = match value.get_str("kty") {
            Some(val) => match val {
                "RSA" => JsonWebKey::Rsa(value.try_into()?),
                "EC" => JsonWebKey::EllipticCurve(value.try_into()?),
                "oct" => JsonWebKey::Oct(value.try_into()?),
                "OKP" => JsonWebKey::OctetKeyPair(value.try_into()?),
                _ => {
                    return Err(JoseError::InvalidJson(
                        "'kty' must be one of 'EC', RSA', 'OKP', or 'oct'".into(),
                    ))
                }
            },
            None => return Err(JoseError::InvalidJson("'kty' field missing".into())),
        };

        Ok(jwk)
    }

    pub fn from_pem(pem: impl AsRef<str>) -> Result<Self, JoseError> {
        let bytes = pem.as_ref().as_bytes();
        let evp_pkey = match Bio::from_slice(bytes).read_pem_private_key() {
            Some(k) => k,
            None => match Bio::from_slice(bytes).read_pem_public_key() {
                Some(k) => k,
                None => return Err(JoseError::InvalidKey("key not found".into())),
            },
        };

        match evp_pkey.key_type() {
            EvpPkeyType::Rsa => Ok(JsonWebKey::Rsa(RsaJsonWebKey::from_evp_pkey(evp_pkey))),
            EvpPkeyType::RsaPss => Ok(JsonWebKey::Rsa(RsaJsonWebKey::from_evp_pkey(evp_pkey))),
            EvpPkeyType::Ec => Ok(JsonWebKey::EllipticCurve(ECJsonWebKey::from_evp_pkey(
                evp_pkey,
            ))),
            EvpPkeyType::Ed25519 => Ok(JsonWebKey::OctetKeyPair(OkpJsonWebKey::from_evp_pkey(
                evp_pkey,
            ))),
            _ => Err(JoseError::InvalidKey("Unsupported key type".into())),
        }
    }

    pub fn to_der(&self) -> Option<Box<[u8]>> {
        match self {
            JsonWebKey::EllipticCurve(ec) => Some(ec.to_der()),
            JsonWebKey::OctetKeyPair(okp) => Some(okp.to_der()),
            JsonWebKey::Oct(_) => None,
            JsonWebKey::Rsa(rsa) => Some(rsa.to_der()),
        }
    }

    pub fn to_json(&self, level: OutputControlLevel) -> String {
        match self {
            JsonWebKey::EllipticCurve(ec) => ec.to_json(level),
            JsonWebKey::OctetKeyPair(okp) => okp.to_json(level),
            JsonWebKey::Oct(oct) => oct.to_json(level),
            JsonWebKey::Rsa(rsa) => rsa.to_json(level),
        }
    }

    pub fn key_bytes(&self) -> Option<&[u8]> {
        match self {
            JsonWebKey::Oct(oct) => Some(oct.key_bytes()),
            _ => None,
        }
    }

    pub fn key_type(&self) -> &'static str {
        match self {
            JsonWebKey::EllipticCurve(ec) => ec.key_type(),
            JsonWebKey::OctetKeyPair(okp) => okp.key_type(),
            JsonWebKey::Oct(oct) => oct.key_type(),
            JsonWebKey::Rsa(rsa) => rsa.key_type(),
        }
    }
}

pub struct JsonWebKeyGenerator {
    key_mgmt_alg: Option<KeyManagementAlgorithm>,
    sig_alg: Option<AlgorithmIdentifier>,
    key_bits: Option<u16>,
}

impl JsonWebKeyGenerator {
    pub fn for_encryption(alg: KeyManagementAlgorithm) -> Self {
        JsonWebKeyGenerator {
            key_mgmt_alg: Some(alg),
            sig_alg: None,
            key_bits: None,
        }
    }
    pub fn for_signature(alg: AlgorithmIdentifier) -> Self {
        JsonWebKeyGenerator {
            key_mgmt_alg: None,
            sig_alg: Some(alg),
            key_bits: None,
        }
    }

    pub fn with_key_bits(mut self, bits: u16) -> Self {
        self.key_bits = Some(bits);
        self
    }

    pub fn generate(&self) -> Result<JsonWebKey, JoseError> {
        if let Some(alg) = self.key_mgmt_alg {
            match alg {
                KeyManagementAlgorithm::Rsa15 => todo!(),
                KeyManagementAlgorithm::RsaOaep => todo!(),
                KeyManagementAlgorithm::RsaOaep256 => todo!(),
                KeyManagementAlgorithm::EcdhEs => todo!(),
                KeyManagementAlgorithm::EcdhEsA128Kw => todo!(),
                KeyManagementAlgorithm::EcdhEsA192Kw => todo!(),
                KeyManagementAlgorithm::EcdhEsA256Kw => todo!(),
                KeyManagementAlgorithm::A128Kw => todo!(),
                KeyManagementAlgorithm::A192Kw => todo!(),
                KeyManagementAlgorithm::A256Kw => todo!(),
                KeyManagementAlgorithm::A128GcmKw => todo!(),
                KeyManagementAlgorithm::A192GcmKw => todo!(),
                KeyManagementAlgorithm::A256GcmKw => todo!(),
                KeyManagementAlgorithm::Direct => {
                    let key_bytes = match self.key_bits {
                        Some(bits) => bits as usize / 8,
                        None => 32, // Default to 256 bits
                    };
                    let key = rand_bytes(key_bytes);
                    Ok(JsonWebKey::Oct(OctetSequenceJsonWebKey::new(key, None)))
                }
                _ => Err(JoseError::InvalidAlgorithm(
                    "Unsupported algorithm for key generation".into(),
                )),
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
                        Some(alg),
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
                        Some(alg),
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
                        Some(alg),
                    )))
                }
                AlgorithmIdentifier::RsaUsingSha256 => {
                    let key = EvpPkey::generate_rsa(self.key_bits.unwrap_or(2048));
                    Ok(JsonWebKey::Rsa(RsaJsonWebKey::new(key, Some(alg))))
                }
                AlgorithmIdentifier::RsaUsingSha384 => {
                    let key = EvpPkey::generate_rsa(self.key_bits.unwrap_or(2048));
                    Ok(JsonWebKey::Rsa(RsaJsonWebKey::new(key, Some(alg))))
                }
                AlgorithmIdentifier::RsaUsingSha512 => {
                    let key = EvpPkey::generate_rsa(self.key_bits.unwrap_or(3072));
                    Ok(JsonWebKey::Rsa(RsaJsonWebKey::new(key, Some(alg))))
                }
                AlgorithmIdentifier::EcdsaUsingP256CurveAndSha256 => {
                    let key = EvpPkey::generate_ec(EcCurve::P256);
                    Ok(JsonWebKey::EllipticCurve(ECJsonWebKey::new(key, Some(alg))))
                }
                AlgorithmIdentifier::EcdsaUsingP384CurveAndSha384 => {
                    let key = EvpPkey::generate_ec(EcCurve::P384);
                    Ok(JsonWebKey::EllipticCurve(ECJsonWebKey::new(key, Some(alg))))
                }
                AlgorithmIdentifier::EcdsaUsingP521CurveAndSha512 => {
                    let key = EvpPkey::generate_ec(EcCurve::P521);
                    Ok(JsonWebKey::EllipticCurve(ECJsonWebKey::new(key, Some(alg))))
                }
                #[cfg(not(feature = "boring"))]
                AlgorithmIdentifier::EcdsaUsingSecp256k1CurveAndSha256 => {
                    let key = EvpPkey::generate_ec(EcCurve::Secp256k1);
                    Ok(JsonWebKey::EllipticCurve(ECJsonWebKey::new(key, Some(alg))))
                }
                AlgorithmIdentifier::EdDsa => {
                    let key = EvpPkey::generate_ed25519();
                    Ok(JsonWebKey::OctetKeyPair(OkpJsonWebKey::new(key, Some(alg))))
                }
                AlgorithmIdentifier::RsaPssUsingSha256 => {
                    let key = EvpPkey::generate_rsa(self.key_bits.unwrap_or(2048));
                    Ok(JsonWebKey::Rsa(RsaJsonWebKey::new(key, Some(alg))))
                }
                AlgorithmIdentifier::RsaPssUsingSha384 => {
                    let key = EvpPkey::generate_rsa(self.key_bits.unwrap_or(2048));
                    Ok(JsonWebKey::Rsa(RsaJsonWebKey::new(key, Some(alg))))
                }
                AlgorithmIdentifier::RsaPssUsingSha512 => {
                    let key = EvpPkey::generate_rsa(self.key_bits.unwrap_or(3072));
                    Ok(JsonWebKey::Rsa(RsaJsonWebKey::new(key, Some(alg))))
                }
                _ => {
                    return Err(JoseError::InvalidAlgorithm(
                        "Unsupported algorithm for key generation".into(),
                    ))
                }
            }
        } else {
            Err(JoseError::InvalidAlgorithm("No algorithm specified".into()))
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
}
