//! A JSON Web Key Set (JWKS) -- a collection of [`JsonWebKey`]s.
//!
//! Mirrors jose4j's `JsonWebKeySet`. Parsing is tolerant: a document with a
//! missing `"keys"` member is an error, but an individual key that fails to
//! parse is silently skipped (so a JWKS advertising algorithms or key types
//! this crate doesn't support still yields the usable keys).

use simd_json::prelude::*;

use super::{JsonWebKey, KeyUse};
use crate::error::JoseError;

/// A set of JSON Web Keys, as defined by RFC 7517.
#[derive(Clone, Default)]
pub struct JsonWebKeySet {
    keys: Vec<JsonWebKey>,
}

impl JsonWebKeySet {
    /// Parses a JWKS JSON document (`{"keys":[...]}`).
    ///
    /// # Errors
    ///
    /// Returns an error if the JSON is malformed or has no `"keys"` member.
    /// Individual keys that fail to parse are skipped, not treated as errors,
    /// so the resulting set may be empty (or smaller than the source array).
    pub fn from_json(json: impl AsRef<[u8]>) -> Result<Self, JoseError> {
        let mut buf = json.as_ref().to_vec();
        let value = simd_json::to_owned_value(&mut buf).map_err(JoseError::json)?;

        let keys_value = value
            .get("keys")
            .ok_or_else(|| JoseError::InvalidJson("JWKS has no \"keys\" member".into()))?;

        let mut keys = Vec::new();
        if let Some(arr) = keys_value.as_array() {
            for key_value in arr {
                // Tolerate individual unparseable keys: skip them rather than
                // failing the whole set (jose4j behavior).
                if let Ok(jwk) = JsonWebKey::from_value(key_value) {
                    keys.push(jwk);
                }
            }
        }

        Ok(Self { keys })
    }

    /// Creates a set from existing keys.
    pub fn from_keys(keys: Vec<JsonWebKey>) -> Self {
        Self { keys }
    }

    /// Adds a key to the set.
    pub fn add_key(&mut self, key: JsonWebKey) {
        self.keys.push(key);
    }

    /// All keys in the set, in insertion order.
    pub fn keys(&self) -> &[JsonWebKey] {
        &self.keys
    }

    /// Returns an iterator over the keys in insertion order.
    pub fn iter(&self) -> std::slice::Iter<'_, JsonWebKey> {
        self.keys.as_slice().iter()
    }

    /// Consumes the set, returning the keys.
    pub fn into_keys(self) -> Vec<JsonWebKey> {
        self.keys
    }

    /// Returns `true` if the set contains no keys.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// The number of keys in the set.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Finds the first key matching all non-`None` criteria.
    ///
    /// A criterion that is `None` is ignored; a criterion that is `Some` must
    /// equal the key's corresponding field exactly (a key missing that field
    /// never matches a `Some` criterion). This mirrors jose4j's
    /// `JsonWebKeySet.findJsonWebKey`.
    ///
    /// # When to use this vs. `VerificationJwkSelector`
    ///
    /// `find_key` is a **strict equality match** -- it does *not* verify that
    /// the key type (`kty`) is compatible with any algorithm, that the key is
    /// declared for signature use, or that the curve matches. It is suitable
    /// for ad-hoc inspection of a JWKS and for low-level filtering where you
    /// already know what you're looking for.
    ///
    /// For **verifying a JWS signature against a JWKS** (the common OIDC
    /// ID-token case), use [`super::VerificationJwkSelector`] instead:
    ///
    /// ```no_run
    /// # use jose4rs::jwk::{JsonWebKeySet, VerificationJwkSelector};
    /// # let jwks: JsonWebKeySet = unreachable!();
    /// # let jws_kid: Option<&str> = None;
    /// # let jws_alg: &str = "RS256";
    /// let selector = VerificationJwkSelector::new();
    /// if let Some(jwk) = selector.select(jws_kid, jws_alg, jwks.keys()) {
    ///     // pass `jwk.public_key()` to the JWS verifier
    /// }
    /// ```
    ///
    /// `VerificationJwkSelector` enforces that the key's `kty` matches the
    /// algorithm's required key type (the algorithm-confusion defense),
    /// narrows by curve for EC keys, and matches `use: "sig"` if the JWK
    /// declares one. It does **not** by itself try-verify to disambiguate
    /// when multiple keys share a `kid`; rely on
    /// `JsonWebSignature::verify_signature` for the final go/no-go.
    pub fn find_key(
        &self,
        key_id: Option<&str>,
        key_type: Option<&str>,
        key_use: Option<KeyUse>,
        algorithm: Option<&str>,
    ) -> Option<&JsonWebKey> {
        self.keys
            .iter()
            .find(|k| Self::matches(k, key_id, key_type, key_use, algorithm))
    }

    /// Finds all keys matching the criteria (see [`find_key`](Self::find_key)).
    pub fn find_keys(
        &self,
        key_id: Option<&str>,
        key_type: Option<&str>,
        key_use: Option<KeyUse>,
        algorithm: Option<&str>,
    ) -> Vec<&JsonWebKey> {
        self.keys
            .iter()
            .filter(|k| Self::matches(k, key_id, key_type, key_use, algorithm))
            .collect()
    }

    fn matches(
        key: &JsonWebKey,
        key_id: Option<&str>,
        key_type: Option<&str>,
        key_use: Option<KeyUse>,
        algorithm: Option<&str>,
    ) -> bool {
        if let Some(want) = key_id
            && key.key_id() != Some(want)
        {
            return false;
        }
        if let Some(want) = key_type
            && key.key_type() != want
        {
            return false;
        }
        if let Some(want) = key_use
            && key.key_use() != Some(want)
        {
            return false;
        }
        if let Some(want) = algorithm
            && key.algorithm() != Some(want)
        {
            return false;
        }
        true
    }

    /// Serializes the set to a JWKS JSON document. Keys are emitted at the
    /// given output control level.
    pub fn to_json(&self, level: super::OutputControlLevel) -> String {
        let mut out = String::from("{\"keys\":[");
        for (i, key) in self.keys.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str(&key.to_json(level));
        }
        out.push_str("]}");
        out
    }
}

impl std::fmt::Debug for JsonWebKeySet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JsonWebKeySet")
            .field("len", &self.keys.len())
            .finish()
    }
}

impl<'a> IntoIterator for &'a JsonWebKeySet {
    type Item = &'a JsonWebKey;
    type IntoIter = std::slice::Iter<'a, JsonWebKey>;

    fn into_iter(self) -> Self::IntoIter {
        self.keys.as_slice().iter()
    }
}

impl IntoIterator for JsonWebKeySet {
    type Item = JsonWebKey;
    type IntoIter = std::vec::IntoIter<JsonWebKey>;

    fn into_iter(self) -> Self::IntoIter {
        self.keys.into_iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The two EC P-256 public keys from the JWS cookbook (RFC 7515 apparatus).
    const EC1: &str = r#"{"kty":"EC","use":"sig","kid":"the key","x":"amuk6RkDZi-48mKrzgBN_zUZ_9qupIwTZHJjM03qL-4","y":"ZOESj6_dpPiZZR-fJ-XVszQta28Cjgti7JudooQJ0co","crv":"P-256"}"#;
    const EC2: &str = r#"{"kty":"EC","use":"sig","kid":"other key","x":"eCNZgiEHUpLaCNgYIcvWzfyBlzlaqEaWbt7RFJ4nIBA","y":"UujFME4pNk-nU4B9h4hsetIeSAzhy8DesBgWppiHKPM","crv":"P-256"}"#;

    fn jwks() -> String {
        format!(r#"{{"keys":[{EC1},{EC2}]}}"#)
    }

    #[test]
    fn test_parse_and_find() {
        let set = JsonWebKeySet::from_json(jwks()).unwrap();
        assert_eq!(set.len(), 2);

        // kid lookup.
        let k = set.find_key(Some("the key"), None, None, None).unwrap();
        assert_eq!(k.key_id(), Some("the key"));
        let k = set.find_key(Some("other key"), None, None, None).unwrap();
        assert_eq!(k.key_id(), Some("other key"));
        assert!(set.find_key(Some("nope"), None, None, None).is_none());

        // kty filter.
        assert_eq!(set.find_keys(None, Some("EC"), None, None).len(), 2);
        assert_eq!(set.find_keys(None, Some("RSA"), None, None).len(), 0);

        // use filter (both are "sig").
        assert_eq!(
            set.find_keys(None, None, Some(KeyUse::Signature), None)
                .len(),
            2
        );
        assert_eq!(
            set.find_keys(None, None, Some(KeyUse::Encryption), None)
                .len(),
            0
        );

        // Combined criteria.
        assert!(
            set.find_key(Some("the key"), Some("EC"), Some(KeyUse::Signature), None)
                .is_some()
        );
        assert!(
            set.find_key(Some("the key"), Some("RSA"), None, None)
                .is_none()
        );
    }

    #[test]
    fn test_tolerates_bad_keys() {
        // A JWKS with one good key, one with an unsupported kty, and one
        // malformed entry yields just the good key.
        let json = format!(
            r#"{{"keys":[{EC1},{{"kty":"OKP","crv":"Ed448","x":"dGVzdA"}},{{"not":"a key"}}]}}"#
        );
        let set = JsonWebKeySet::from_json(json).unwrap();
        assert_eq!(set.len(), 1);
        assert_eq!(set.keys()[0].key_id(), Some("the key"));
    }

    #[test]
    fn retains_symmetric_keys_with_jwe_algorithm_metadata() {
        let json = r#"{"keys":[{"kty":"oct","k":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","alg":"A256GCMKW","kid":"enc"}]}"#;
        let set = JsonWebKeySet::from_json(json).unwrap();

        assert_eq!(set.len(), 1);
        assert_eq!(set.keys()[0].algorithm(), Some("A256GCMKW"));
        let serialized = set.to_json(super::super::OutputControlLevel::IncludeSymmetric);
        let reparsed = JsonWebKeySet::from_json(serialized).unwrap();
        assert_eq!(reparsed.len(), 1);
        assert_eq!(reparsed.keys()[0].algorithm(), Some("A256GCMKW"));
    }

    #[test]
    fn test_missing_keys_member_is_error() {
        assert!(JsonWebKeySet::from_json(r#"{"notkeys":[]}"#).is_err());
        assert!(JsonWebKeySet::from_json("not json").is_err());
    }

    #[test]
    fn test_empty_keys_is_ok() {
        let set = JsonWebKeySet::from_json(r#"{"keys":[]}"#).unwrap();
        assert!(set.is_empty());
    }

    #[test]
    fn test_to_json_round_trip() {
        let set = JsonWebKeySet::from_json(jwks()).unwrap();
        let json = set.to_json(super::super::OutputControlLevel::PublicOnly);
        let reparsed = JsonWebKeySet::from_json(&json).unwrap();
        assert_eq!(reparsed.len(), 2);
        assert!(
            reparsed
                .find_key(Some("the key"), None, None, None)
                .is_some()
        );
        assert!(
            reparsed
                .find_key(Some("other key"), None, None, None)
                .is_some()
        );
    }
}
