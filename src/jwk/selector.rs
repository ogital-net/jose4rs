//! Selects a verification or decryption key from a set of JWKs, based on the
//! header of an inbound JWS or JWE.
//!
//! Mirrors jose4j's `VerificationJwkSelector` / `DecryptionJwkSelector`. The
//! selectors are transport-independent: they take the relevant header values
//! (`kid`, `alg`, and for ECDH-ES the `epk` key type) as plain arguments rather
//! than referencing the JWS/JWE types, so `jwk` does not depend on `jws`/`jwe`.

use super::{JsonWebKey, JwkAlgorithm, KeyUse};
use crate::{error::JoseError, jws::AlgorithmIdentifier};

/// A criterion that a JWK either must have, or may omit.
///
/// Mirrors jose4j's `SimpleJwkFilter` `(expectedValue, noValueOk)` semantics:
/// - `Required`: a key missing the field never matches.
/// - `OmittedOkay`: a key missing the field still matches; a key with the
///   field must equal the expected value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Presence {
    Required,
    OmittedOkay,
}

impl Presence {
    /// Whether a key's field value satisfies this criterion.
    fn meets(self, expected: &str, actual: Option<&str>) -> bool {
        match actual {
            None => self == Presence::OmittedOkay,
            Some(actual) => actual == expected,
        }
    }
}

/// Selects a key for verifying a JWS, from among a set of candidate JWKs.
///
/// Ported from jose4j's `VerificationJwkSelector`. Stateless.
#[derive(Debug, Default, Clone, Copy)]
pub struct VerificationJwkSelector;

impl VerificationJwkSelector {
    /// Create a new selector.
    pub fn new() -> Self {
        Self
    }

    /// Returns the candidate keys, most-preferred first, for a JWS with the
    /// given `kid` and `alg` header values.
    ///
    /// The base filter requires the key type implied by `alg` and an exact
    /// `kid` match (only when the JWS carries a `kid`), and permits omitted
    /// `use`. For `Ed25519` and `EdDSA`, a JWK's `alg` must match if present.
    /// For other algorithms, a matching or omitted `alg` is preferred when
    /// several candidates remain, mirroring jose4j. If the JWS algorithm
    /// specifies a curve, keys on other curves are always excluded.
    pub fn select_list<'k>(
        &self,
        key_id: Option<&str>,
        alg: &str,
        keys: &'k [JsonWebKey],
    ) -> Vec<&'k JsonWebKey> {
        let alg_id = AlgorithmIdentifier::try_from(alg).ok();

        // Base filter: kty is always required (derived from the alg), kid is
        // required only when the JWS has one, use=sig is omitted-okay.
        let mut candidates: Vec<&JsonWebKey> = keys
            .iter()
            .filter(|k| Self::base_filter(k, key_id, alg_id, KeyUse::Signature))
            .collect();

        if matches!(
            alg_id,
            Some(AlgorithmIdentifier::EdDsa | AlgorithmIdentifier::Ed25519)
        ) {
            candidates.retain(|key| Presence::OmittedOkay.meets(alg, key.algorithm()));
        } else if candidates.len() > 1 {
            let narrowed: Vec<&JsonWebKey> = candidates
                .iter()
                .copied()
                .filter(|k| Presence::OmittedOkay.meets(alg, k.algorithm()))
                .collect();
            if !narrowed.is_empty() {
                candidates = narrowed;
            }
        }

        if let Some(crv) = alg_id.and_then(|alg_id| alg_id.ec_curve()) {
            candidates.retain(|k| k.curve_name() == Some(crv));
        }

        candidates
    }

    /// Returns the single most-preferred key, or `None` if no key matches.
    pub fn select<'k>(
        &self,
        key_id: Option<&str>,
        alg: &str,
        keys: &'k [JsonWebKey],
    ) -> Option<&'k JsonWebKey> {
        self.select_list(key_id, alg, keys).into_iter().next()
    }

    /// Returns the only key matching the signature algorithm and optional `kid`.
    ///
    /// Unlike [`Self::select`], this does not rank candidates. An explicit JWK
    /// `alg` must match exactly; an omitted `alg` is allowed. Key type, signing
    /// use, and any required curve must also match. Returns `Ok(None)` when
    /// no key matches or the algorithm is `none`.
    ///
    /// This filters keys, but does not check algorithm policy or verify a
    /// signature.
    ///
    /// # Errors
    ///
    /// Returns [`JoseError::InvalidKey`] if multiple keys match, even if a
    /// `kid` was supplied or some keys have no `alg` metadata.
    pub fn select_unique<'k>(
        &self,
        key_id: Option<&str>,
        alg: AlgorithmIdentifier,
        keys: &'k [JsonWebKey],
    ) -> Result<Option<&'k JsonWebKey>, JoseError> {
        if alg == AlgorithmIdentifier::None {
            return Ok(None);
        }
        let expected_alg = JwkAlgorithm::Jws(alg);
        let curve = if alg == AlgorithmIdentifier::EdDsa {
            Some("Ed25519")
        } else {
            alg.ec_curve()
        };
        let mut candidates = keys.iter().filter(|key| {
            Self::base_filter(key, key_id, Some(alg), KeyUse::Signature)
                && key
                    .jwk_algorithm()
                    .is_none_or(|actual| *actual == expected_alg)
                && curve.is_none_or(|expected| key.curve_name() == Some(expected))
        });
        let selected = candidates.next();
        if candidates.next().is_some() {
            return Err(JoseError::InvalidKey(
                "multiple JWKs match the signature algorithm and key ID".into(),
            ));
        }
        Ok(selected)
    }

    fn base_filter(
        key: &JsonWebKey,
        key_id: Option<&str>,
        alg: Option<AlgorithmIdentifier>,
        want_use: KeyUse,
    ) -> bool {
        // kty is always required, derived from the algorithm's key type.
        if let Some(alg) = alg
            && let Some(kty) = alg.key_type()
            && key.key_type() != kty
        {
            return false;
        }
        // kid: required (exact) only when the JWS carries one.
        if let Some(kid) = key_id
            && !Presence::Required.meets(kid, key.key_id())
        {
            return false;
        }
        // use: match-if-present on the JWK.
        Presence::OmittedOkay.meets(want_use.as_str(), key.key_use().map(|u| u.as_str()))
    }
}

/// Selects a key for decrypting a JWE, from among a set of candidate JWKs.
///
/// Ported from jose4j's `DecryptionJwkSelector`. Unlike verification there is
/// no progressive alg/curve narrowing: the base filter is applied and the
/// first match wins. Stateless.
#[derive(Debug, Default, Clone, Copy)]
pub struct DecryptionJwkSelector;

impl DecryptionJwkSelector {
    /// Create a new selector.
    pub fn new() -> Self {
        Self
    }

    /// Returns the candidate keys, most-preferred first, for a JWE with the
    /// given `kid` and `alg` header values.
    ///
    /// `epk_key_type` is the `kty` of the JWE's `epk` (ephemeral public key)
    /// header, and is only needed for ECDH-ES algorithms: the content key type
    /// is then taken from `epk` rather than from `alg` (so OKP X25519 keys
    /// match ECDH-ES, whose `alg` alone would imply EC). Pass `None` for
    /// non-ECDH algorithms.
    pub fn select_list<'k>(
        &self,
        key_id: Option<&str>,
        alg: &str,
        epk_key_type: Option<&str>,
        keys: &'k [JsonWebKey],
    ) -> Vec<&'k JsonWebKey> {
        // For ECDH-ES the key type comes from the ephemeral key; otherwise
        // from the key-management algorithm.
        let want_kty: Option<&str> = if alg.starts_with("ECDH-ES") {
            epk_key_type
        } else {
            decryption_alg_key_type(alg)
        };

        keys.iter()
            .filter(|k| {
                // kty required.
                if let Some(kty) = want_kty
                    && k.key_type() != kty
                {
                    return false;
                }
                // kid required only when the JWE carries one.
                if let Some(kid) = key_id
                    && !Presence::Required.meets(kid, k.key_id())
                {
                    return false;
                }
                // use=enc is match-if-present.
                Presence::OmittedOkay
                    .meets(KeyUse::Encryption.as_str(), k.key_use().map(|u| u.as_str()))
            })
            .collect()
    }

    /// Returns the single most-preferred key, or `None` if no key matches.
    pub fn select<'k>(
        &self,
        key_id: Option<&str>,
        alg: &str,
        epk_key_type: Option<&str>,
        keys: &'k [JsonWebKey],
    ) -> Option<&'k JsonWebKey> {
        self.select_list(key_id, alg, epk_key_type, keys)
            .into_iter()
            .next()
    }
}

/// The JWK `kty` a key for a JWE key-management algorithm belongs to.
fn decryption_alg_key_type(alg: &str) -> Option<&'static str> {
    use crate::jwe::KeyManagementAlgorithm as K;
    let alg = K::try_from(alg).ok()?;
    match alg {
        K::Rsa15 | K::RsaOaep | K::RsaOaep256 | K::RsaOaep384 | K::RsaOaep512 => Some("RSA"),
        K::EcdhEs | K::EcdhEsA128Kw | K::EcdhEsA192Kw | K::EcdhEsA256Kw => Some("EC"),
        K::A128Kw
        | K::A192Kw
        | K::A256Kw
        | K::A128GcmKw
        | K::A192GcmKw
        | K::A256GcmKw
        | K::Pbes2Hs256A128Kw
        | K::Pbes2Hs384A192Kw
        | K::Pbes2Hs512A256Kw
        | K::Direct => Some("oct"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwk::JsonWebKeySet;

    const EC1: &str = r#"{"kty":"EC","use":"sig","kid":"the key","x":"amuk6RkDZi-48mKrzgBN_zUZ_9qupIwTZHJjM03qL-4","y":"ZOESj6_dpPiZZR-fJ-XVszQta28Cjgti7JudooQJ0co","crv":"P-256"}"#;
    const EC2_NO_KID: &str = r#"{"kty":"EC","use":"sig","x":"eCNZgiEHUpLaCNgYIcvWzfyBlzlaqEaWbt7RFJ4nIBA","y":"UujFME4pNk-nU4B9h4hsetIeSAzhy8DesBgWppiHKPM","crv":"P-256"}"#;

    fn set_with(keys: &[&str]) -> JsonWebKeySet {
        JsonWebKeySet::from_json(format!(r#"{{"keys":[{}]}}"#, keys.join(","))).unwrap()
    }

    #[test]
    fn test_verification_kid_match() {
        let set = set_with(&[EC1, EC2_NO_KID]);
        let keys = set.keys();
        let sel = VerificationJwkSelector::new();

        // kid "the key" matches only EC1 (EC2 has no kid and JWS requires it).
        let found = sel.select(Some("the key"), "ES256", keys).unwrap();
        assert_eq!(found.key_id(), Some("the key"));

        // Unknown kid matches nothing.
        assert!(sel.select(Some("missing"), "ES256", keys).is_none());

        // No kid on the JWS: kty=EC narrows to both EC keys (kid not required).
        let list = sel.select_list(None, "ES256", keys);
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn test_unique_verification_enforces_algorithm_metadata_and_rejects_ambiguity() {
        let selector = VerificationJwkSelector::new();
        let alg = AlgorithmIdentifier::EcdsaUsingP256CurveAndSha256;
        let mismatched = format!(r#"{{"alg":"ES384",{}"#, &EC1[1..]);
        let keys = set_with(&[&mismatched]);
        assert!(selector.select(None, "ES256", keys.keys()).is_some());
        assert!(
            selector
                .select_unique(None, alg, keys.keys())
                .unwrap()
                .is_none()
        );

        let matching = format!(r#"{{"alg":"ES256",{}"#, &EC1[1..]);
        let keys = set_with(&[&matching, EC2_NO_KID]);
        assert!(matches!(
            selector.select_unique(None, alg, keys.keys()),
            Err(JoseError::InvalidKey(_))
        ));
        assert_eq!(
            selector
                .select_unique(Some("the key"), alg, keys.keys())
                .unwrap()
                .unwrap()
                .key_id(),
            Some("the key")
        );
    }

    #[test]
    fn test_verification_kty_from_alg() {
        // A set with an EC and (synthetically) the EC key can't be RSA, so use
        // two EC keys; the kty filter excludes non-EC. Build a mixed set.
        let oct = r#"{"kty":"oct","kid":"sym","k":"Fdh9u8rINxfivbrianbbVT1u232VQBZYKx1HGAGPt2I"}"#;
        let set = set_with(&[EC1, oct]);
        let keys = set.keys();
        let sel = VerificationJwkSelector::new();

        // ES256 requires kty=EC, so the oct key is excluded even without kid.
        let list = sel.select_list(None, "ES256", keys);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].key_type(), "EC");

        // HS256 requires kty=oct.
        let list = sel.select_list(None, "HS256", keys);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].key_type(), "oct");
    }

    #[test]
    fn test_verification_use_filter() {
        // An "enc"-use EC key must not match a signature verification.
        let ec_enc = r#"{"kty":"EC","use":"enc","kid":"e","x":"amuk6RkDZi-48mKrzgBN_zUZ_9qupIwTZHJjM03qL-4","y":"ZOESj6_dpPiZZR-fJ-XVszQta28Cjgti7JudooQJ0co","crv":"P-256"}"#;
        let set = set_with(&[EC1, ec_enc]);
        let keys = set.keys();
        let sel = VerificationJwkSelector::new();
        let list = sel.select_list(None, "ES256", keys);
        // Only the "sig" key survives (use is match-if-present; "enc" != "sig").
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].key_use(), Some(KeyUse::Signature));
    }

    #[test]
    fn test_verification_curve_disambiguation() {
        // Two EC keys with no kid on the JWS, one P-256 and one P-384: the
        // alg's implied curve (ES256 -> P-256) disambiguates. Use a generated
        // P-384 key (no fabricated coordinates).
        let p384 = crate::jwk::JsonWebKeyGenerator::for_signature(
            AlgorithmIdentifier::EcdsaUsingP384CurveAndSha384,
        )
        .generate()
        .unwrap();
        let p384_json = p384.to_json(crate::jwk::OutputControlLevel::PublicOnly);

        let set = set_with(&[EC1, &p384_json]);
        let keys = set.keys();
        let sel = VerificationJwkSelector::new();
        let list = sel.select_list(None, "ES256", keys);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].curve_name(), Some("P-256"));

        // ES384 -> P-384.
        let list = sel.select_list(None, "ES384", keys);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].curve_name(), Some("P-384"));
    }

    /// Regression: a JWKS holding a single EC key whose curve does NOT match
    /// the algorithm must yield no candidate (curve narrowing is not skipped
    /// for single-key sets).
    #[test]
    fn test_verification_curve_narrowing_single_key() {
        // A lone P-384 key, but the JWS uses ES256 (P-256).
        let p384 = crate::jwk::JsonWebKeyGenerator::for_signature(
            AlgorithmIdentifier::EcdsaUsingP384CurveAndSha384,
        )
        .generate()
        .unwrap();
        let p384_json = p384.to_json(crate::jwk::OutputControlLevel::PublicOnly);

        let set = set_with(&[&p384_json]);
        let keys = set.keys();
        let sel = VerificationJwkSelector::new();

        // ES256 requires P-256; the only key is P-384, so nothing is selected.
        assert!(sel.select_list(None, "ES256", keys).is_empty());
        assert!(sel.select(None, "ES256", keys).is_none());

        // The matching algorithm still selects it.
        let list = sel.select_list(None, "ES384", keys);
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn test_verification_ed25519_selection() {
        let ed25519 = r#"{"kty":"OKP","crv":"Ed25519","alg":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#;
        let legacy = r#"{"kty":"OKP","crv":"Ed25519","alg":"EdDSA","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#;
        let untagged =
            r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#;
        let x25519 =
            r#"{"kty":"OKP","crv":"X25519","x":"hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo"}"#;
        let selector = VerificationJwkSelector::new();
        for (alg, matching, mismatched) in
            [("Ed25519", ed25519, legacy), ("EdDSA", legacy, ed25519)]
        {
            let keys = set_with(&[mismatched]);
            assert!(selector.select(None, alg, keys.keys()).is_none());

            let keys = set_with(&[mismatched, matching, untagged]);
            let selected = selector.select_list(None, alg, keys.keys());
            assert_eq!(selected.len(), 2);
            assert_eq!(selected[0].algorithm(), Some(alg));
            assert_eq!(selected[1].algorithm(), None);
        }

        let keys = set_with(&[x25519]);
        assert!(selector.select(None, "Ed25519", keys.keys()).is_none());
        assert!(
            selector
                .select_unique(None, AlgorithmIdentifier::EdDsa, keys.keys())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn test_decryption_kid_and_kty() {
        let oct = r#"{"kty":"oct","use":"enc","kid":"sym","k":"Fdh9u8rINxfivbrianbbVT1u232VQBZYKx1HGAGPt2I"}"#;
        let set = set_with(&[EC1, oct]);
        let keys = set.keys();
        let sel = DecryptionJwkSelector::new();

        // dir -> oct; kid "sym" selects the oct key.
        let found = sel.select(Some("sym"), "dir", None, keys).unwrap();
        assert_eq!(found.key_type(), "oct");

        // EC1 is use=sig so it's excluded from an enc selection.
        let list = sel.select_list(None, "dir", None, keys);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].key_id(), Some("sym"));
    }

    #[test]
    fn test_decryption_ecdh_es_uses_epk_kty() {
        // ECDH-ES takes its kty from the epk header, so an OKP X25519 key
        // matches when epk kty is OKP.
        let x25519 = r#"{"kty":"OKP","use":"enc","kid":"x","crv":"X25519","x":"QfjAvWo5cahODIFx0AB9lzYyHQMVApVjVFkL-GXSQwk"}"#;
        let set = set_with(&[x25519]);
        let keys = set.keys();
        let sel = DecryptionJwkSelector::new();

        // With epk kty = OKP, the OKP key matches ECDH-ES.
        let found = sel.select(Some("x"), "ECDH-ES", Some("OKP"), keys).unwrap();
        assert_eq!(found.key_type(), "OKP");

        // With epk kty = EC, the OKP key does not match.
        assert!(
            sel.select_list(Some("x"), "ECDH-ES", Some("EC"), keys)
                .is_empty()
        );
    }
}
