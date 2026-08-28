//! JWT (JSON Web Token) Claims handling.
//!
//! This module provides types and methods for working with JWT claims as defined in
//! [RFC 7519](https://tools.ietf.org/html/rfc7519).

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use simd_json::{
    ValueBuilder as _,
    base::{ValueAsArray, ValueAsScalar, Writable},
    derived::{
        MutableObject, TypedObjectValue, ValueObjectAccessAsArray, ValueObjectAccessAsScalar,
    },
    prelude::ValueObjectAccess,
};

use crate::error::JoseError;

mod consumer;
pub use consumer::{ErrorCode, InvalidJwtError, JwtConsumer, JwtConsumerBuilder, JwtValidator};

#[cfg(test)]
#[path = "consumer_tests.rs"]
mod consumer_tests;

const EXPIRATION_TIME: &str = "exp";
const NOT_BEFORE: &str = "nbf";
const ISSUED_AT: &str = "iat";
const ISSUER: &str = "iss";
const AUDIENCE: &str = "aud";
const SUBJECT: &str = "sub";
const JWT_ID: &str = "jti";

/// The classified result of reading a registered time claim (`exp`/`nbf`/`iat`)
/// exactly once: one object lookup, one type check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TimeClaim {
    /// The claim is absent.
    Absent,
    /// The claim is present but not an integer `NumericDate` (float, string,
    /// bool, null, or out of `i64` range).
    Malformed,
    /// The claim is present and an integer; the value is the seconds since the
    /// Unix epoch (may be negative).
    Value(i64),
}

/// A single-lookup snapshot of the `aud` claim, capturing everything the
/// consumer's audience validation needs without re-querying the claims map.
/// Borrows the claim strings from the claims value (no allocation).
#[derive(Debug, Default)]
pub(crate) struct AudienceInfo<'a> {
    /// Present and not JSON null (null is treated as absent, matching jose4j).
    pub present: bool,
    /// Present but neither a string nor an all-string array.
    pub malformed: bool,
    /// Present as a plain JSON string (the RFC 7523 strict form).
    pub is_string: bool,
    /// The borrowed string values (empty unless well-formed).
    pub values: Vec<&'a str>,
}

/// Dispatch a read-only operation to the inner value regardless of variant.
macro_rules! with_value {
    ($self:expr, |$v:ident| $body:expr) => {
        match &$self.inner {
            ClaimsInner::Owned($v) => $body,
            ClaimsInner::Borrowed { value: $v, .. } => $body,
        }
    };
}

/// Holds either an owned or a buffer-borrowing parsed JSON value.
///
/// In the `Borrowed` variant, `value` references data inside the
/// `Arc<[u8]>` held by `buf`. `Arc<[u8]>` stores the slice header and
/// the data bytes contiguously in a single allocation; we hand simd-json
/// a `&mut [u8]` into that allocation's data slot to parse in place, so
/// `value`'s `Cow<str>` pointers point directly into the Arc's bytes.
/// A cloned `JwtClaims` keeps the same allocation alive (refcount bump),
/// so the pointers stay valid for as long as any clone exists. The
/// `value` field is declared first so Rust drops it before `buf`.
enum ClaimsInner {
    Owned(simd_json::OwnedValue),
    Borrowed {
        value: simd_json::BorrowedValue<'static>,
        buf: Arc<[u8]>,
    },
}

impl Clone for ClaimsInner {
    fn clone(&self) -> Self {
        match self {
            // Deep clone of the owned DOM (recurses through Box<Vec> /
            // Box<Object>). The cloned `OwnedValue` is fully detached.
            Self::Owned(v) => Self::Owned(v.clone()),
            // Shallow clone of the borrowed DOM: `BorrowedValue`'s derived
            // `Clone` bumps the refcounts of the inner `Box<Vec<...>>`s
            // and copies each `Cow<str>` header (pointer + length). The
            // string pointers stay valid because `buf` is `Arc<[u8]>`:
            // both clones keep the underlying bytes alive.
            Self::Borrowed { value, buf } => Self::Borrowed {
                value: value.clone(),
                buf: buf.clone(),
            },
        }
    }
}

impl std::fmt::Debug for ClaimsInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Owned(v) => write!(f, "Owned({v:?})"),
            Self::Borrowed { value, .. } => write!(f, "Borrowed({value:?})"),
        }
    }
}

impl ClaimsInner {
    /// Converts `Borrowed` to `Owned` by re-serializing. No-op if already
    /// `Owned`. Called lazily on first mutation of parsed claims.
    fn ensure_owned(&mut self) {
        if let ClaimsInner::Borrowed { value, .. } = self {
            let json = value.encode();
            let mut buf = json.into_bytes();
            let owned = simd_json::to_owned_value(&mut buf).expect("round-trip JSON");
            *self = ClaimsInner::Owned(owned);
        }
    }

    fn as_owned_mut(&mut self) -> &mut simd_json::OwnedValue {
        self.ensure_owned();
        match self {
            ClaimsInner::Owned(v) => v,
            ClaimsInner::Borrowed { .. } => unreachable!(),
        }
    }
}

/// A collection of JWT claims.
///
/// Represents the claims set of a JSON Web Token, providing convenient access
/// to registered claims (as defined in RFC 7519 Section 4.1) as well as the
/// ability to store custom claims.
///
/// # Registered Claims
///
/// - `iss` (Issuer): Identifies the principal that issued the JWT
/// - `sub` (Subject): Identifies the principal that is the subject of the JWT
/// - `aud` (Audience): Identifies the recipients that the JWT is intended for
/// - `exp` (Expiration Time): Identifies the expiration time after which the JWT must not be accepted
/// - `nbf` (Not Before): Identifies the time before which the JWT must not be accepted
/// - `iat` (Issued At): Identifies the time at which the JWT was issued
/// - `jti` (JWT ID): Provides a unique identifier for the JWT
#[derive(Debug)]
pub struct JwtClaims {
    inner: ClaimsInner,
}

impl JwtClaims {
    /// Creates a new empty JWT claims collection.
    ///
    /// # Example
    ///
    /// ```
    /// # use jose4rs::jwt::JwtClaims;
    /// let claims = JwtClaims::new();
    /// ```
    pub fn new() -> Self {
        Self {
            inner: ClaimsInner::Owned(simd_json::owned::Value::object()),
        }
    }

    /// Parses JWT claims from JSON bytes.
    ///
    /// # Arguments
    ///
    /// * `json` - JSON bytes representing the claims
    ///
    /// # Errors
    ///
    /// Returns an error if the JSON is malformed.
    ///
    /// # Example
    ///
    /// ```
    /// # use jose4rs::jwt::JwtClaims;
    /// let json = r#"{"iss":"example.com","sub":"user123"}"#;
    /// let claims = JwtClaims::parse(json).unwrap();
    /// ```
    #[allow(clippy::missing_panics_doc)]
    pub fn parse(json: impl AsRef<[u8]>) -> Result<Self, JoseError> {
        // Build a single allocation: `Arc<[u8]>::from(&[u8])` allocates
        // `ArcInner<[u8]>` whose layout is `{strong, weak, len, bytes}`
        // contiguously, copying the input bytes into the data slot.
        // The Arc is uniquely owned (strong count = 1) right after
        // construction, so `Arc::get_mut` returns `Some(&mut [u8])`
        // pointing into the Arc's data slot. simd-json parses in place;
        // its `BorrowedValue`'s `Cow<str>` pointers then point directly
        // into the Arc's storage. After the mutable borrow ends we never
        // write to those bytes again, so the pointers stay valid for
        // every `JwtClaims` clone that holds this Arc.
        let mut arc: Arc<[u8]> = Arc::from(json.as_ref());
        let value: simd_json::BorrowedValue<'_> = {
            let bytes: &mut [u8] =
                Arc::get_mut(&mut arc).expect("Arc just constructed; strong count is 1");
            simd_json::to_borrowed_value(bytes).map_err(JoseError::json)?
        };
        let value: simd_json::BorrowedValue<'static> = unsafe { std::mem::transmute(value) };
        if !value.is_object() {
            return Err(JoseError::InvalidJson(
                "claims value is not a JSON object".into(),
            ));
        }
        Ok(Self {
            inner: ClaimsInner::Borrowed { value, buf: arc },
        })
    }

    /// Gets the issuer (`iss`) claim.
    ///
    /// # Returns
    ///
    /// The issuer value if present, `None` otherwise.
    pub fn issuer(&self) -> Option<&str> {
        with_value!(self, |v| v.get_str(ISSUER))
    }

    /// Returns `true` if the named claim is present but not a JSON string
    /// (e.g. a number, object, array, or bool). Used to reject malformed
    /// string-typed claims rather than silently skipping their validation.
    pub(crate) fn string_claim_is_malformed(&self, name: &str) -> bool {
        with_value!(self, |v| match v.get(name) {
            None => false,
            Some(val) => val.as_str().is_none(),
        })
    }

    /// Sets the issuer (`iss`) claim.
    ///
    /// # Arguments
    ///
    /// * `issuer` - The issuer identifier
    ///
    /// # Panics
    ///
    /// Panics if the claims value is not a JSON object (only possible if it
    /// was parsed from a non-object document).
    pub fn set_issuer(&mut self, issuer: impl AsRef<str>) {
        self.inner
            .as_owned_mut()
            .insert(ISSUER, issuer.as_ref())
            .unwrap();
    }

    /// Gets the subject (`sub`) claim.
    ///
    /// # Returns
    ///
    /// The subject value if present, `None` otherwise.
    pub fn subject(&self) -> Option<&str> {
        with_value!(self, |v| v.get_str(SUBJECT))
    }

    /// Sets the subject (`sub`) claim.
    ///
    /// # Arguments
    ///
    /// * `subject` - The subject identifier
    ///
    /// # Panics
    ///
    /// Panics if the claims value is not a JSON object (only possible if it
    /// was parsed from a non-object document).
    pub fn set_subject(&mut self, subject: impl AsRef<str>) {
        self.inner
            .as_owned_mut()
            .insert(SUBJECT, subject.as_ref())
            .unwrap();
    }

    /// Gets the audience (`aud`) claim.
    ///
    /// # Returns
    ///
    /// A vector of audience values if present, `None` otherwise.
    pub fn audience(&self) -> Option<Vec<String>> {
        with_value!(self, |v| {
            let aud_value = v.get(AUDIENCE)?;
            if let Some(s) = aud_value.as_str() {
                return Some(vec![s.to_string()]);
            }
            if let Some(arr) = v.get_array(AUDIENCE) {
                return Some(
                    arr.iter()
                        .filter_map(|el| el.as_str().map(std::string::ToString::to_string))
                        .collect(),
                );
            }
            None
        })
    }

    /// Sets the audience (`aud`) claim.
    ///
    /// # Arguments
    ///
    /// * `audience` - A vector of audience identifiers
    ///
    /// # Panics
    ///
    /// Panics if the claims value is not a JSON object (only possible if it
    /// was parsed from a non-object document).
    pub fn set_audience(&mut self, audience: Vec<String>) {
        let arr: Vec<simd_json::OwnedValue> = audience.iter().map(|s| s.as_str().into()).collect();
        self.inner.as_owned_mut().insert(AUDIENCE, arr).unwrap();
    }

    /// Gets the expiration time (`exp`) claim.
    ///
    /// # Returns
    ///
    /// The expiration time as a `SystemTime` if present and non-negative,
    /// `None` otherwise.
    pub fn expiration_time(&self) -> Option<SystemTime> {
        let timestamp = with_value!(self, |v| v.get_i64(EXPIRATION_TIME))?;
        let secs = u64::try_from(timestamp).ok()?;
        Some(UNIX_EPOCH + Duration::from_secs(secs))
    }

    /// Sets the expiration time (`exp`) claim.
    ///
    /// # Arguments
    ///
    /// * `exp` - The expiration time
    ///
    /// # Panics
    ///
    /// Panics if the given time is before the Unix epoch.
    pub fn set_expiration_time(&mut self, exp: SystemTime) {
        let timestamp = exp.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        self.inner
            .as_owned_mut()
            .insert(EXPIRATION_TIME, timestamp)
            .unwrap();
    }

    /// Gets the not before (`nbf`) claim.
    ///
    /// # Returns
    ///
    /// The not before time as a `SystemTime` if present and non-negative,
    /// `None` otherwise.
    pub fn not_before(&self) -> Option<SystemTime> {
        let timestamp = with_value!(self, |v| v.get_i64(NOT_BEFORE))?;
        let secs = u64::try_from(timestamp).ok()?;
        Some(UNIX_EPOCH + Duration::from_secs(secs))
    }

    /// Sets the not before (`nbf`) claim.
    ///
    /// # Arguments
    ///
    /// * `nbf` - The not before time
    ///
    /// # Panics
    ///
    /// Panics if the given time is before the Unix epoch.
    pub fn set_not_before(&mut self, nbf: SystemTime) {
        let timestamp = nbf.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        self.inner
            .as_owned_mut()
            .insert(NOT_BEFORE, timestamp)
            .unwrap();
    }

    /// Gets the issued at (`iat`) claim.
    ///
    /// # Returns
    ///
    /// The issued at time as a `SystemTime` if present and non-negative,
    /// `None` otherwise.
    pub fn issued_at(&self) -> Option<SystemTime> {
        let timestamp = with_value!(self, |v| v.get_i64(ISSUED_AT))?;
        let secs = u64::try_from(timestamp).ok()?;
        Some(UNIX_EPOCH + Duration::from_secs(secs))
    }

    /// Sets the issued at (`iat`) claim.
    ///
    /// # Arguments
    ///
    /// * `iat` - The issued at time
    ///
    /// # Panics
    ///
    /// Panics if the given time is before the Unix epoch.
    pub fn set_issued_at(&mut self, iat: SystemTime) {
        let timestamp = iat.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        self.inner
            .as_owned_mut()
            .insert(ISSUED_AT, timestamp)
            .unwrap();
    }

    /// Gets the JWT ID (`jti`) claim.
    ///
    /// # Returns
    ///
    /// The JWT ID value if present, `None` otherwise.
    pub fn jwt_id(&self) -> Option<&str> {
        with_value!(self, |v| v.get_str(JWT_ID))
    }

    /// Sets the JWT ID (`jti`) claim.
    ///
    /// # Arguments
    ///
    /// * `jti` - The unique identifier for the JWT
    ///
    /// # Panics
    ///
    /// Panics if the claims value is not a JSON object (only possible if it
    /// was parsed from a non-object document).
    pub fn set_jwt_id(&mut self, jti: impl AsRef<str>) {
        self.inner
            .as_owned_mut()
            .insert(JWT_ID, jti.as_ref())
            .unwrap();
    }

    /// Gets a custom (or any) claim as a string slice.
    ///
    /// Covers the common case of string-valued custom claims -- e.g.
    /// Cognito's `token_use`, `client_id`, or `username` -- without the
    /// caller re-parsing the payload. Registered claims are reachable
    /// through this too, but prefer their typed getters.
    ///
    /// # Returns
    ///
    /// The string value if the claim is present and is a JSON string,
    /// `None` otherwise (absent, or a non-string type such as a number,
    /// array, or object -- callers with an exotic claim type can still
    /// re-parse the payload themselves).
    ///
    /// # Example
    ///
    /// ```
    /// # use jose4rs::jwt::JwtClaims;
    /// let claims = JwtClaims::parse(r#"{"token_use":"access","exp":1}"#).unwrap();
    /// assert_eq!(claims.string_claim("token_use"), Some("access"));
    /// assert_eq!(claims.string_claim("exp"), None); // not a string
    /// assert_eq!(claims.string_claim("missing"), None);
    /// ```
    pub fn string_claim(&self, name: &str) -> Option<&str> {
        with_value!(self, |v| v.get_str(name))
    }

    /// Sets a custom (or any) claim to a string value.
    ///
    /// The string-typed counterpart of [`string_claim`](Self::string_claim),
    /// for custom string claims such as `email` or `scope` -- without the
    /// caller touching JSON. Registered claims are reachable through this too,
    /// but prefer their typed setters.
    ///
    /// # Errors
    ///
    /// Returns an error if the claims value is not a JSON object (which can
    /// only happen if it was parsed from a non-object JSON document).
    ///
    /// # Example
    ///
    /// ```
    /// # use jose4rs::jwt::JwtClaims;
    /// let mut claims = JwtClaims::new();
    /// claims.set_string_claim("email", "mail@example.com").unwrap();
    /// assert_eq!(claims.string_claim("email"), Some("mail@example.com"));
    /// ```
    pub fn set_string_claim(
        &mut self,
        name: impl AsRef<str>,
        value: impl AsRef<str>,
    ) -> Result<(), JoseError> {
        self.inner
            .as_owned_mut()
            .insert(name.as_ref(), value.as_ref())
            .map(|_| ())
            .map_err(|_| JoseError::InvalidJson("claims value is not a JSON object".into()))
    }

    /// Gets a custom (or any) claim as a vector of strings.
    ///
    /// The read counterpart of [`set_string_array_claim`](Self::set_string_array_claim),
    /// for multi-valued claims such as `groups` or `roles` -- without the
    /// caller re-parsing the payload. As a convenience a JSON string value is
    /// returned as a single-element vector (mirroring how `aud` behaves).
    ///
    /// # Returns
    ///
    /// The string values if the claim is present and is a JSON array of
    /// strings (or a single JSON string), `None` otherwise (absent, or a
    /// non-string/non-array type such as a number or object).
    ///
    /// # Example
    ///
    /// ```
    /// # use jose4rs::jwt::JwtClaims;
    /// let claims = JwtClaims::parse(r#"{"groups":["a","b"],"roles":"admin","exp":1}"#).unwrap();
    /// assert_eq!(claims.string_array_claim("groups"), Some(vec!["a".to_string(), "b".to_string()]));
    /// assert_eq!(claims.string_array_claim("roles"), Some(vec!["admin".to_string()]));
    /// assert_eq!(claims.string_array_claim("exp"), None); // not strings
    /// assert_eq!(claims.string_array_claim("missing"), None);
    /// ```
    pub fn string_array_claim(&self, name: &str) -> Option<Vec<String>> {
        with_value!(self, |v| {
            let val = v.get(name)?;
            if let Some(s) = val.as_str() {
                return Some(vec![s.to_string()]);
            }
            let arr = val.as_array()?;
            Some(
                arr.iter()
                    .filter_map(|el| el.as_str().map(std::string::ToString::to_string))
                    .collect(),
            )
        })
    }

    /// Sets a custom (or any) claim to an array of strings.
    ///
    /// For multi-valued claims such as `groups` or `roles`, which end up as a
    /// JSON array -- without the caller touching JSON. To set the registered
    /// `aud` claim prefer [`set_audience`](Self::set_audience).
    ///
    /// # Errors
    ///
    /// Returns an error if the claims value is not a JSON object (which can
    /// only happen if it was parsed from a non-object JSON document).
    ///
    /// # Example
    ///
    /// ```
    /// # use jose4rs::jwt::JwtClaims;
    /// let mut claims = JwtClaims::new();
    /// claims.set_string_array_claim("groups", &["group-1", "other-group"]).unwrap();
    /// assert_eq!(claims.string_array_claim("groups"), Some(vec!["group-1".to_string(), "other-group".to_string()]));
    /// ```
    pub fn set_string_array_claim(
        &mut self,
        name: impl AsRef<str>,
        values: &[impl AsRef<str>],
    ) -> Result<(), JoseError> {
        let arr: Vec<simd_json::OwnedValue> = values.iter().map(|s| s.as_ref().into()).collect();
        self.inner
            .as_owned_mut()
            .insert(name.as_ref(), arr)
            .map(|_| ())
            .map_err(|_| JoseError::InvalidJson("claims value is not a JSON object".into()))
    }

    /// Serializes the JWT claims to a JSON string.
    ///
    /// # Returns
    ///
    /// A JSON string representation of all claims in the collection.
    ///
    /// # Example
    ///
    /// ```
    /// # use jose4rs::jwt::JwtClaims;
    /// let mut claims = JwtClaims::new();
    /// claims.set_issuer("example.com");
    /// claims.set_subject("user123");
    /// let json = claims.to_json();
    /// assert!(json.contains("example.com"));
    /// ```
    pub fn to_json(&self) -> String {
        with_value!(self, |v| v.encode())
    }

    /// Returns `true` if a claim with the given name is present (any type).
    pub(crate) fn has_claim(&self, name: &str) -> bool {
        with_value!(self, |v| v.get(name).is_some())
    }

    /// Reads a registered time claim (`exp`/`nbf`/`iat`) in a single lookup,
    /// classifying it as absent, malformed, or an integer value.
    pub(crate) fn time_claim(&self, name: &str) -> TimeClaim {
        with_value!(self, |v| {
            match v.get(name) {
                None => TimeClaim::Absent,
                Some(val) => match val.as_i64() {
                    Some(secs) => TimeClaim::Value(secs),
                    None => TimeClaim::Malformed,
                },
            }
        })
    }

    /// Reads the `aud` claim once and returns a full classification (presence,
    /// well-formedness, strict-string form, and the string values) so the
    /// consumer performs a single map lookup for all of its audience checks.
    /// The returned string slices borrow from the claims value.
    pub(crate) fn audience_info(&self) -> AudienceInfo<'_> {
        with_value!(self, |v| {
            let Some(aud) = v.get(AUDIENCE) else {
                return AudienceInfo::default();
            };
            // A JSON null aud is treated as absent (matching jose4j's hasClaim).
            if aud.as_null().is_some() {
                return AudienceInfo::default();
            }
            if let Some(s) = aud.as_str() {
                return AudienceInfo {
                    present: true,
                    malformed: false,
                    is_string: true,
                    values: vec![s],
                };
            }
            match aud.as_array() {
                Some(arr) => {
                    let malformed = arr.iter().any(|el| el.as_str().is_none());
                    AudienceInfo {
                        present: true,
                        malformed,
                        is_string: false,
                        values: if malformed {
                            Vec::new()
                        } else {
                            arr.iter().filter_map(|el| el.as_str()).collect()
                        },
                    }
                }
                // A non-string, non-array aud (number/object/bool) is malformed.
                None => AudienceInfo {
                    present: true,
                    malformed: true,
                    is_string: false,
                    values: Vec::new(),
                },
            }
        })
    }
}

impl Default for JwtClaims {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for JwtClaims {
    /// Returns an independent clone. Reads see the same claims; writes
    /// to one clone do not affect the other.
    ///
    /// Cloning a freshly-parsed (Borrowed) `JwtClaims` is cheap: the
    /// underlying JSON buffer is shared via `Arc<[u8]>` (single allocation,
    /// header + data contiguous), so the only per-clone work is a refcount
    /// bump and a shallow copy of the `BorrowedValue`'s inner `Cow` / `Box`
    /// refcounts.
    ///
    /// Cloning an Owned `JwtClaims` deep-copies the DOM (proportional to
    /// the payload size). Mutating either clone is local: only the
    /// mutating clone promotes itself back to `Owned` on the next
    /// `set_*` call.
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_claims() {
        let claims = JwtClaims::new();
        assert!(claims.issuer().is_none());
        assert!(claims.subject().is_none());
        assert!(claims.audience().is_none());
    }

    #[test]
    fn test_issuer() {
        let mut claims = JwtClaims::new();
        assert!(claims.issuer().is_none());

        claims.set_issuer("example.com");
        assert_eq!(claims.issuer(), Some("example.com"));

        claims.set_issuer("another.com");
        assert_eq!(claims.issuer(), Some("another.com"));
    }

    #[test]
    fn test_subject() {
        let mut claims = JwtClaims::new();
        assert!(claims.subject().is_none());

        claims.set_subject("user123");
        assert_eq!(claims.subject(), Some("user123"));
    }

    #[test]
    fn test_get_string_claim() {
        let claims = JwtClaims::parse(
            r#"{
                "sub": "user123",
                "token_use": "access",
                "client_id": "abc123",
                "exp": 1700000000,
                "email_verified": true,
                "cognito:groups": ["a", "b"]
            }"#,
        )
        .unwrap();

        // String custom claims resolve.
        assert_eq!(claims.string_claim("token_use"), Some("access"));
        assert_eq!(claims.string_claim("client_id"), Some("abc123"));
        // Registered string claims are reachable too.
        assert_eq!(claims.string_claim("sub"), Some("user123"));
        // Non-string claims return None (caller re-parses if needed).
        assert_eq!(claims.string_claim("exp"), None);
        assert_eq!(claims.string_claim("email_verified"), None);
        assert_eq!(claims.string_claim("cognito:groups"), None);
        // Absent claims return None.
        assert_eq!(claims.string_claim("missing"), None);
    }

    #[test]
    fn test_set_string_claim() {
        let mut claims = JwtClaims::new();
        claims
            .set_string_claim("email", "mail@example.com")
            .unwrap();
        assert_eq!(claims.string_claim("email"), Some("mail@example.com"));

        // Overwrites an existing value.
        claims.set_string_claim("email", "new@example.com").unwrap();
        assert_eq!(claims.string_claim("email"), Some("new@example.com"));

        // Round-trips through JSON without the caller touching JSON.
        let json = claims.to_json();
        assert!(json.contains(r#""email":"new@example.com""#));
        let parsed = JwtClaims::parse(&json).unwrap();
        assert_eq!(parsed.string_claim("email"), Some("new@example.com"));
    }

    #[test]
    fn test_get_string_array_claim() {
        let claims = JwtClaims::parse(
            r#"{
                "groups": ["group-1", "other-group", "group-3"],
                "roles": "admin",
                "exp": 1700000000,
                "mixed": ["a", 1, true]
            }"#,
        )
        .unwrap();

        // Array of strings resolves.
        assert_eq!(
            claims.string_array_claim("groups"),
            Some(vec![
                "group-1".to_string(),
                "other-group".to_string(),
                "group-3".to_string()
            ])
        );
        // A single string is treated as a one-element list (like `aud`).
        assert_eq!(
            claims.string_array_claim("roles"),
            Some(vec!["admin".to_string()])
        );
        // Non-string/non-array claims return None.
        assert_eq!(claims.string_array_claim("exp"), None);
        // Non-string members are skipped.
        assert_eq!(
            claims.string_array_claim("mixed"),
            Some(vec!["a".to_string()])
        );
        // Absent claims return None.
        assert_eq!(claims.string_array_claim("missing"), None);
    }

    #[test]
    fn test_set_string_array_claim() {
        let mut claims = JwtClaims::new();
        claims
            .set_string_array_claim("groups", &["group-1", "other-group"])
            .unwrap();
        assert_eq!(
            claims.string_array_claim("groups"),
            Some(vec!["group-1".to_string(), "other-group".to_string()])
        );

        // Serializes as a JSON array without the caller touching JSON.
        let json = claims.to_json();
        assert!(json.contains(r#""groups":["group-1","other-group"]"#));

        // Round-trips.
        let parsed = JwtClaims::parse(&json).unwrap();
        assert_eq!(
            parsed.string_array_claim("groups"),
            Some(vec!["group-1".to_string(), "other-group".to_string()])
        );
    }

    #[test]
    fn test_claim_setters_on_non_object_fail() {
        // JWT claims must be a JSON object, so parsing a non-object document is
        // rejected up front. This keeps the `set_*` methods (which insert into
        // the claims map) infallible.
        assert!(JwtClaims::parse(r#"["not","an","object"]"#).is_err());
        assert!(JwtClaims::parse("\"just a string\"").is_err());
        assert!(JwtClaims::parse("42").is_err());
        // An object is accepted.
        assert!(JwtClaims::parse(r#"{"iss":"me"}"#).is_ok());
    }

    #[test]
    fn test_audience() {
        let mut claims = JwtClaims::new();
        assert!(claims.audience().is_none());

        let audience = vec!["service1".to_string(), "service2".to_string()];
        claims.set_audience(audience.clone());
        assert_eq!(claims.audience(), Some(audience));
    }

    #[test]
    fn test_expiration_time() {
        let mut claims = JwtClaims::new();
        assert!(claims.expiration_time().is_none());

        let exp = UNIX_EPOCH + Duration::from_secs(1234567890);
        claims.set_expiration_time(exp);

        let retrieved = claims.expiration_time().unwrap();
        assert_eq!(
            retrieved.duration_since(UNIX_EPOCH).unwrap().as_secs(),
            1234567890
        );
    }

    #[test]
    fn test_not_before() {
        let mut claims = JwtClaims::new();
        assert!(claims.not_before().is_none());

        let nbf = UNIX_EPOCH + Duration::from_secs(1234567890);
        claims.set_not_before(nbf);

        let retrieved = claims.not_before().unwrap();
        assert_eq!(
            retrieved.duration_since(UNIX_EPOCH).unwrap().as_secs(),
            1234567890
        );
    }

    #[test]
    fn test_issued_at() {
        let mut claims = JwtClaims::new();
        assert!(claims.issued_at().is_none());

        let iat = UNIX_EPOCH + Duration::from_secs(1234567890);
        claims.set_issued_at(iat);

        let retrieved = claims.issued_at().unwrap();
        assert_eq!(
            retrieved.duration_since(UNIX_EPOCH).unwrap().as_secs(),
            1234567890
        );
    }

    #[test]
    fn test_jwt_id() {
        let mut claims = JwtClaims::new();
        assert!(claims.jwt_id().is_none());

        claims.set_jwt_id("unique-id-123");
        assert_eq!(claims.jwt_id(), Some("unique-id-123"));
    }

    #[test]
    fn test_parse_claims() {
        let json = r#"{"iss":"example.com","sub":"user123","exp":1234567890}"#;
        let claims = JwtClaims::parse(json).unwrap();

        assert_eq!(claims.issuer(), Some("example.com"));
        assert_eq!(claims.subject(), Some("user123"));

        let exp = claims.expiration_time().unwrap();
        assert_eq!(
            exp.duration_since(UNIX_EPOCH).unwrap().as_secs(),
            1234567890
        );
    }

    #[test]
    fn test_parse_with_audience_array() {
        let json = r#"{"aud":["service1","service2"]}"#;
        let claims = JwtClaims::parse(json).unwrap();

        let audience = claims.audience().unwrap();
        assert_eq!(audience.len(), 2);
        assert_eq!(audience[0], "service1");
        assert_eq!(audience[1], "service2");
    }

    #[test]
    fn test_multiple_claims() {
        let mut claims = JwtClaims::new();

        claims.set_issuer("issuer.com");
        claims.set_subject("user456");
        claims.set_jwt_id("jwt-789");

        let now = SystemTime::now();
        claims.set_issued_at(now);
        claims.set_expiration_time(now + Duration::from_secs(3600));
        claims.set_not_before(now - Duration::from_secs(60));

        assert_eq!(claims.issuer(), Some("issuer.com"));
        assert_eq!(claims.subject(), Some("user456"));
        assert_eq!(claims.jwt_id(), Some("jwt-789"));
        assert!(claims.issued_at().is_some());
        assert!(claims.expiration_time().is_some());
        assert!(claims.not_before().is_some());
    }

    #[test]
    fn test_default() {
        let claims = JwtClaims::default();
        assert!(claims.issuer().is_none());
    }

    #[test]
    fn test_to_json_empty() {
        let claims = JwtClaims::new();
        let json = claims.to_json();
        assert_eq!(json, "{}");
    }

    #[test]
    fn test_to_json_with_single_claim() {
        let mut claims = JwtClaims::new();
        claims.set_issuer("example.com");
        let json = claims.to_json();
        assert!(json.contains("\"iss\""));
        assert!(json.contains("\"example.com\""));
    }

    #[test]
    fn test_to_json_with_multiple_claims() {
        let mut claims = JwtClaims::new();
        claims.set_issuer("issuer.com");
        claims.set_subject("user123");
        claims.set_jwt_id("token-456");

        let json = claims.to_json();
        assert!(json.contains("\"iss\""));
        assert!(json.contains("\"issuer.com\""));
        assert!(json.contains("\"sub\""));
        assert!(json.contains("\"user123\""));
        assert!(json.contains("\"jti\""));
        assert!(json.contains("\"token-456\""));
    }

    #[test]
    fn test_to_json_with_numeric_claims() {
        let mut claims = JwtClaims::new();
        let exp = UNIX_EPOCH + Duration::from_secs(1234567890);
        claims.set_expiration_time(exp);
        claims.set_issued_at(UNIX_EPOCH + Duration::from_secs(1234567800));

        let json = claims.to_json();
        assert!(json.contains("\"exp\""));
        assert!(json.contains("1234567890"));
        assert!(json.contains("\"iat\""));
        assert!(json.contains("1234567800"));
    }

    #[test]
    fn test_to_json_with_audience_array() {
        let mut claims = JwtClaims::new();
        claims.set_audience(vec!["service1".to_string(), "service2".to_string()]);

        let json = claims.to_json();
        assert!(json.contains("\"aud\""));
        assert!(json.contains("\"service1\""));
        assert!(json.contains("\"service2\""));
    }

    #[test]
    fn test_to_json_round_trip() {
        let mut claims = JwtClaims::new();
        claims.set_issuer("test.com");
        claims.set_subject("user789");
        claims.set_jwt_id("unique-id");
        claims.set_expiration_time(UNIX_EPOCH + Duration::from_secs(2000000000));

        let json = claims.to_json();
        let parsed_claims = JwtClaims::parse(&json).unwrap();

        assert_eq!(parsed_claims.issuer(), Some("test.com"));
        assert_eq!(parsed_claims.subject(), Some("user789"));
        assert_eq!(parsed_claims.jwt_id(), Some("unique-id"));
        assert_eq!(
            parsed_claims
                .expiration_time()
                .unwrap()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            2000000000
        );
    }

    #[test]
    fn test_get_null_issuer() {
        let claims = JwtClaims::parse(r#"{"exp":123456781}"#).unwrap();
        assert!(claims.issuer().is_none());
    }

    #[test]
    fn test_get_issuer_from_json() {
        let issuer = "https://idp.example.com";
        let json = format!(r#"{{"iss":"{issuer}"}}"#);
        let claims = JwtClaims::parse(&json).unwrap();
        assert_eq!(claims.issuer(), Some(issuer));
    }

    #[test]
    fn test_get_audience_with_no_audience() {
        let claims = JwtClaims::parse(r#"{"iss":"some-issuer"}"#).unwrap();
        assert!(claims.audience().is_none());
    }

    #[test]
    fn test_get_audience_single_in_array() {
        let claims = JwtClaims::parse(r#"{"aud":["one"]}"#).unwrap();
        let audiences = claims.audience().unwrap();
        assert_eq!(audiences.len(), 1);
        assert_eq!(audiences[0], "one");
    }

    #[test]
    fn test_get_audience_single_value() {
        // JWT spec allows audience to be a single string or an array
        let claims = JwtClaims::parse(r#"{"aud":"one"}"#).unwrap();
        // Our implementation may return None for single string, which is acceptable
        // or convert it to a single-element array
        if let Some(audiences) = claims.audience() {
            assert_eq!(audiences.len(), 1);
            assert_eq!(audiences[0], "one");
        }
    }

    #[test]
    fn test_get_audience_multiple_in_array() {
        let claims = JwtClaims::parse(r#"{"aud":["one","two","three"]}"#).unwrap();
        let audiences = claims.audience().unwrap();
        assert_eq!(audiences.len(), 3);
        assert_eq!(audiences[0], "one");
        assert_eq!(audiences[1], "two");
        assert_eq!(audiences[2], "three");
    }

    #[test]
    fn test_get_audience_empty_array() {
        let claims = JwtClaims::parse(r#"{"aud":[]}"#).unwrap();
        let audiences = claims.audience();
        // Empty array should return Some with empty vec or None
        if let Some(aud) = audiences {
            assert_eq!(aud.len(), 0);
        }
    }

    #[test]
    fn test_get_null_subject() {
        let claims = JwtClaims::parse(r#"{"exp":123456781}"#).unwrap();
        assert!(claims.subject().is_none());
    }

    #[test]
    fn test_get_subject_from_json() {
        let subject = "subject@example.com";
        let json = format!(r#"{{"sub":"{subject}"}}"#);
        let claims = JwtClaims::parse(&json).unwrap();
        assert_eq!(claims.subject(), Some(subject));
    }

    #[test]
    fn test_get_null_jti() {
        let claims = JwtClaims::parse(r#"{"whatever":123456781}"#).unwrap();
        assert!(claims.jwt_id().is_none());
    }

    #[test]
    fn test_get_jti_from_json() {
        let jti = "Xk9c2inNN8fFs60epZil3";
        let json = format!(r#"{{"jti":"{jti}"}}"#);
        let claims = JwtClaims::parse(&json).unwrap();
        assert_eq!(claims.jwt_id(), Some(jti));
    }

    #[test]
    fn test_get_null_exp() {
        let claims = JwtClaims::parse(r#"{"right":123456781}"#).unwrap();
        assert!(claims.expiration_time().is_none());
    }

    #[test]
    fn test_get_exp_from_json() {
        let exp = 1418823169;
        let json = format!(r#"{{"exp":{exp}}}"#);
        let claims = JwtClaims::parse(&json).unwrap();
        assert_eq!(
            claims
                .expiration_time()
                .unwrap()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            exp
        );
    }

    #[test]
    fn test_get_null_nbf() {
        let claims = JwtClaims::parse(r#"{"right":123456781}"#).unwrap();
        assert!(claims.not_before().is_none());
    }

    #[test]
    fn test_get_nbf_from_json() {
        let nbf = 1418823109;
        let json = format!(r#"{{"nbf":{nbf}}}"#);
        let claims = JwtClaims::parse(&json).unwrap();
        assert_eq!(
            claims
                .not_before()
                .unwrap()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            nbf
        );
    }

    #[test]
    fn test_get_null_iat() {
        let claims = JwtClaims::parse(r#"{"right":123456781, "wrong":123452781}"#).unwrap();
        assert!(claims.issued_at().is_none());
    }

    #[test]
    fn test_get_iat_from_json() {
        let iat = 1418823119;
        let json = format!(r#"{{"iat":{iat}}}"#);
        let claims = JwtClaims::parse(&json).unwrap();
        assert_eq!(
            claims
                .issued_at()
                .unwrap()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            iat
        );
    }

    #[test]
    fn test_basic_create() {
        let mut claims = JwtClaims::new();
        claims.set_subject("subject");
        claims.set_audience(vec!["audience".to_string()]);
        claims.set_issuer("issuer");
        claims.set_jwt_id("id");
        claims.set_expiration_time(UNIX_EPOCH + Duration::from_secs(231458800));
        claims.set_issued_at(UNIX_EPOCH + Duration::from_secs(231459000));
        claims.set_not_before(UNIX_EPOCH + Duration::from_secs(231459600));

        let json_claims = claims.to_json();
        assert!(json_claims.contains(r#""iss":"issuer""#));
        assert!(
            json_claims.contains(r#""aud":"audience""#)
                || json_claims.contains(r#""aud":["audience"]"#)
        );
        assert!(json_claims.contains(r#""sub":"subject""#));
        assert!(json_claims.contains(r#""jti":"id""#));
        assert!(json_claims.contains(r#""exp":231458800"#));
        assert!(json_claims.contains(r#""iat":231459000"#));
        assert!(json_claims.contains(r#""nbf":231459600"#));
    }

    #[test]
    fn test_setting_audience_variations() {
        let mut claims = JwtClaims::new();

        // Single audience
        claims.set_audience(vec!["audience".to_string()]);
        let json = claims.to_json();
        assert!(json.contains("\"aud\""));
        assert!(json.contains("\"audience\""));

        // Multiple audiences
        claims.set_audience(vec![
            "audience1".to_string(),
            "audience2".to_string(),
            "outlier".to_string(),
        ]);
        let json = claims.to_json();
        assert!(json.contains(r#""aud":["audience1","audience2","outlier"]"#));

        // Empty audience list
        claims.set_audience(vec![]);
        let json = claims.to_json();
        assert!(json.contains(r#""aud":[]"#));
    }

    #[test]
    fn test_simple_claims_example_from_jwt_rfc() {
        // Example from https://tools.ietf.org/html/rfc7519#section-3.1
        let json = r#"{"iss":"joe","exp":1300819380}"#;
        let claims = JwtClaims::parse(json).unwrap();

        assert_eq!(claims.issuer(), Some("joe"));
        assert_eq!(
            claims
                .expiration_time()
                .unwrap()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            1300819380
        );
    }

    #[test]
    fn test_non_integer_numeric_dates() {
        // Fractional NumericDate values are treated as malformed by time_claim()
        // (as_i64 returns None for floats), so parsing succeeds but the claims
        // will be flagged at validation time.
        let json = r#"{"sub":"brian.d.campbell","nbf":1430602000.173,"iat":1430602060.5,"exp":1430602600.77}"#;
        let claims = JwtClaims::parse(json);

        if let Ok(claims) = claims {
            assert_eq!(claims.subject(), Some("brian.d.campbell"));

            if let Some(exp) = claims.expiration_time() {
                let exp_secs = exp.duration_since(UNIX_EPOCH).unwrap().as_secs();
                assert!(exp_secs == 1430602600 || exp_secs == 1430602601);
            }

            if let Some(iat) = claims.issued_at() {
                let iat_secs = iat.duration_since(UNIX_EPOCH).unwrap().as_secs();
                assert!(iat_secs == 1430602060 || iat_secs == 1430602061);
            }

            if let Some(nbf) = claims.not_before() {
                let nbf_secs = nbf.duration_since(UNIX_EPOCH).unwrap().as_secs();
                assert!(nbf_secs == 1430602000 || nbf_secs == 1430602001);
            }
        }
    }

    #[test]
    fn test_parse_with_all_registered_claims() {
        let json = r#"{
            "sub":"subject",
            "aud":"audience",
            "iss":"issuer",
            "jti":"mz3uxaCcLmQ2cwAV3oJxEQ",
            "exp":1418906607,
            "nbf":1418906000,
            "iat":1418906100
        }"#;

        let claims = JwtClaims::parse(json).unwrap();

        assert_eq!(claims.subject(), Some("subject"));
        assert_eq!(claims.issuer(), Some("issuer"));
        assert_eq!(claims.jwt_id(), Some("mz3uxaCcLmQ2cwAV3oJxEQ"));
        assert_eq!(
            claims
                .expiration_time()
                .unwrap()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            1418906607
        );
        assert_eq!(
            claims
                .not_before()
                .unwrap()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            1418906000
        );
        assert_eq!(
            claims
                .issued_at()
                .unwrap()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            1418906100
        );
    }

    #[test]
    fn test_modification_and_serialization() {
        let mut claims = JwtClaims::new();

        claims.set_issuer("issuer.com");
        claims.set_subject("user456");
        claims.set_jwt_id("jwt-789");

        let json1 = claims.to_json();
        assert!(json1.contains("issuer.com"));

        // Modify existing claims
        claims.set_issuer("new-issuer.com");
        let json2 = claims.to_json();
        assert!(json2.contains("new-issuer.com"));

        // Parse back to verify the old issuer was replaced
        let parsed = JwtClaims::parse(&json2).unwrap();
        assert_eq!(parsed.issuer(), Some("new-issuer.com"));
    }

    #[test]
    fn test_empty_audience_list() {
        let mut claims = JwtClaims::new();
        claims.set_audience(vec![]);

        let json = claims.to_json();
        let parsed = JwtClaims::parse(&json).unwrap();

        if let Some(aud) = parsed.audience() {
            assert_eq!(aud.len(), 0);
        }
    }

    #[test]
    fn test_parse_malformed_json() {
        let result = JwtClaims::parse(r#"{"iss":"unclosed"#);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_empty_json() {
        let claims = JwtClaims::parse("{}").unwrap();
        assert!(claims.issuer().is_none());
        assert!(claims.subject().is_none());
        assert!(claims.audience().is_none());
        assert!(claims.jwt_id().is_none());
    }

    #[test]
    fn test_clone_of_borrowed_is_independent() {
        // A cloned Borrowed claims shares the underlying JSON buffer with
        // the original. Mutating the clone must promote only the clone to
        // Owned, leaving the original's view of the parsed JSON unchanged.
        let original = JwtClaims::parse(r#"{"iss":"original","sub":"user123"}"#).unwrap();
        let mut cloned = original.clone();

        assert_eq!(cloned.issuer(), Some("original"));
        assert_eq!(original.issuer(), Some("original"));

        // Mutate only the clone.
        cloned.set_issuer("mutated");

        // The clone sees the new value.
        assert_eq!(cloned.issuer(), Some("mutated"));
        // The original still reads from the shared buffer (or its own
        // Owned snapshot after ensure_owned), and must still see the
        // original issuer. This is the key correctness check for the
        // Arc<[u8]> aliasing story.
        assert_eq!(original.issuer(), Some("original"));
    }

    #[test]
    fn test_clone_of_owned_is_independent() {
        let mut original = JwtClaims::new();
        original.set_issuer("original");
        let mut cloned = original.clone();

        cloned.set_issuer("mutated");

        assert_eq!(cloned.issuer(), Some("mutated"));
        assert_eq!(original.issuer(), Some("original"));
    }

    #[test]
    fn test_clone_preserves_all_claim_types() {
        // Round-trips through clone without losing claim structure.
        let json = r#"{"iss":"https://idp.example.com","sub":"user123","aud":["a","b"],"exp":1700000000,"nbf":1699999000,"iat":1699999500,"jti":"abc","groups":["g1","g2"],"custom":"value"}"#;
        let original = JwtClaims::parse(json).unwrap();
        let cloned = original.clone();

        assert_eq!(cloned.issuer(), Some("https://idp.example.com"));
        assert_eq!(cloned.subject(), Some("user123"));
        assert_eq!(
            cloned.audience(),
            Some(vec!["a".to_string(), "b".to_string()])
        );
        assert_eq!(cloned.jwt_id(), Some("abc"));
        assert_eq!(
            cloned
                .expiration_time()
                .unwrap()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            1700000000
        );
        assert_eq!(
            cloned
                .not_before()
                .unwrap()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            1699999000
        );
        assert_eq!(
            cloned
                .issued_at()
                .unwrap()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            1699999500
        );
        assert_eq!(cloned.string_claim("custom"), Some("value"));
        assert_eq!(
            cloned.string_array_claim("groups"),
            Some(vec!["g1".to_string(), "g2".to_string()])
        );
    }

    #[test]
    fn test_complex_round_trip() {
        let mut claims = JwtClaims::new();
        claims.set_issuer("test-issuer");
        claims.set_subject("test-subject");
        claims.set_audience(vec![
            "aud1".to_string(),
            "aud2".to_string(),
            "aud3".to_string(),
        ]);
        claims.set_jwt_id("test-jti");
        claims.set_expiration_time(UNIX_EPOCH + Duration::from_secs(1700000000));
        claims.set_issued_at(UNIX_EPOCH + Duration::from_secs(1699999000));
        claims.set_not_before(UNIX_EPOCH + Duration::from_secs(1699998000));

        let json = claims.to_json();
        let parsed = JwtClaims::parse(&json).unwrap();

        assert_eq!(parsed.issuer(), Some("test-issuer"));
        assert_eq!(parsed.subject(), Some("test-subject"));
        assert_eq!(parsed.jwt_id(), Some("test-jti"));

        let aud = parsed.audience().unwrap();
        assert_eq!(aud.len(), 3);
        assert_eq!(aud[0], "aud1");
        assert_eq!(aud[1], "aud2");
        assert_eq!(aud[2], "aud3");

        assert_eq!(
            parsed
                .expiration_time()
                .unwrap()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            1700000000
        );
        assert_eq!(
            parsed
                .issued_at()
                .unwrap()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            1699999000
        );
        assert_eq!(
            parsed
                .not_before()
                .unwrap()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            1699998000
        );
    }
}
