//! JWT (JSON Web Token) Claims handling.
//!
//! This module provides types and methods for working with JWT claims as defined in
//! [RFC 7519](https://tools.ietf.org/html/rfc7519).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use simd_json::{
    base::ValueAsScalar,
    derived::{MutableObject, ValueObjectAccessAsArray, ValueObjectAccessAsScalar},
    ValueBuilder as _,
};

use crate::error::JoseError;

const EXPIRATION_TIME: &str = "exp";
const NOT_BEFORE: &str = "nbf";
const ISSUED_AT: &str = "iat";
const ISSUER: &str = "iss";
const AUDIENCE: &str = "aud";
const SUBJECT: &str = "sub";
const JWT_ID: &str = "jti";

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
pub struct JwtClaims {
    claims_map: simd_json::OwnedValue,
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
            claims_map: simd_json::owned::Value::object(),
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
    pub fn parse(json: impl AsRef<[u8]>) -> Result<Self, JoseError> {
        let mut buf = Box::from(json.as_ref());

        let claims_map = simd_json::to_owned_value(&mut buf)?;
        Ok(Self { claims_map })
    }

    /// Gets the issuer (`iss`) claim.
    ///
    /// # Returns
    ///
    /// The issuer value if present, `None` otherwise.
    pub fn get_issuer(&self) -> Option<&str> {
        self.claims_map.get_str(ISSUER)
    }

    /// Sets the issuer (`iss`) claim.
    ///
    /// # Arguments
    ///
    /// * `issuer` - The issuer identifier
    pub fn set_issuer(&mut self, issuer: impl AsRef<str>) {
        self.claims_map.insert(ISSUER, issuer.as_ref()).unwrap();
    }

    /// Gets the subject (`sub`) claim.
    ///
    /// # Returns
    ///
    /// The subject value if present, `None` otherwise.
    pub fn get_subject(&self) -> Option<&str> {
        self.claims_map.get_str(SUBJECT)
    }

    /// Sets the subject (`sub`) claim.
    ///
    /// # Arguments
    ///
    /// * `subject` - The subject identifier
    pub fn set_subject(&mut self, subject: impl AsRef<str>) {
        self.claims_map.insert(SUBJECT, subject.as_ref()).unwrap();
    }

    /// Gets the audience (`aud`) claim.
    ///
    /// # Returns
    ///
    /// A vector of audience values if present, `None` otherwise.
    pub fn get_audience(&self) -> Option<Vec<String>> {
        self.claims_map.get_array(AUDIENCE).map(|arr| {
            arr.iter()
                .map(|v| v.as_str().unwrap().to_string())
                .collect()
        })
    }

    /// Sets the audience (`aud`) claim.
    ///
    /// # Arguments
    ///
    /// * `audience` - A vector of audience identifiers
    pub fn set_audience(&mut self, audience: Vec<String>) {
        let arr: Vec<simd_json::OwnedValue> = audience.iter().map(|s| s.as_str().into()).collect();
        self.claims_map.insert(AUDIENCE, arr).unwrap();
    }

    /// Gets the expiration time (`exp`) claim.
    ///
    /// # Returns
    ///
    /// The expiration time as a `SystemTime` if present, `None` otherwise.
    pub fn get_expiration_time(&self) -> Option<SystemTime> {
        let timestamp = self.claims_map.get_i64(EXPIRATION_TIME)?;
        Some(UNIX_EPOCH + Duration::from_secs(timestamp as u64))
    }

    /// Sets the expiration time (`exp`) claim.
    ///
    /// # Arguments
    ///
    /// * `exp` - The expiration time
    pub fn set_expiration_time(&mut self, exp: SystemTime) {
        let timestamp = exp.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        self.claims_map.insert(EXPIRATION_TIME, timestamp).unwrap();
    }

    /// Gets the not before (`nbf`) claim.
    ///
    /// # Returns
    ///
    /// The not before time as a `SystemTime` if present, `None` otherwise.
    pub fn get_not_before(&self) -> Option<SystemTime> {
        let timestamp = self.claims_map.get_i64(NOT_BEFORE)?;
        Some(UNIX_EPOCH + Duration::from_secs(timestamp as u64))
    }

    /// Sets the not before (`nbf`) claim.
    ///
    /// # Arguments
    ///
    /// * `nbf` - The not before time
    pub fn set_not_before(&mut self, nbf: SystemTime) {
        let timestamp = nbf.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        self.claims_map.insert(NOT_BEFORE, timestamp).unwrap();
    }

    /// Gets the issued at (`iat`) claim.
    ///
    /// # Returns
    ///
    /// The issued at time as a `SystemTime` if present, `None` otherwise.
    pub fn get_issued_at(&self) -> Option<SystemTime> {
        let timestamp = self.claims_map.get_i64(ISSUED_AT)?;
        Some(UNIX_EPOCH + Duration::from_secs(timestamp as u64))
    }

    /// Sets the issued at (`iat`) claim.
    ///
    /// # Arguments
    ///
    /// * `iat` - The issued at time
    pub fn set_issued_at(&mut self, iat: SystemTime) {
        let timestamp = iat.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        self.claims_map.insert(ISSUED_AT, timestamp).unwrap();
    }

    /// Gets the JWT ID (`jti`) claim.
    ///
    /// # Returns
    ///
    /// The JWT ID value if present, `None` otherwise.
    pub fn get_jwt_id(&self) -> Option<&str> {
        self.claims_map.get_str(JWT_ID)
    }

    /// Sets the JWT ID (`jti`) claim.
    ///
    /// # Arguments
    ///
    /// * `jti` - The unique identifier for the JWT
    pub fn set_jwt_id(&mut self, jti: impl AsRef<str>) {
        self.claims_map.insert(JWT_ID, jti.as_ref()).unwrap();
    }
}

impl Default for JwtClaims {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_claims() {
        let claims = JwtClaims::new();
        assert!(claims.get_issuer().is_none());
        assert!(claims.get_subject().is_none());
        assert!(claims.get_audience().is_none());
    }

    #[test]
    fn test_issuer() {
        let mut claims = JwtClaims::new();
        assert!(claims.get_issuer().is_none());
        
        claims.set_issuer("example.com");
        assert_eq!(claims.get_issuer(), Some("example.com"));
        
        claims.set_issuer("another.com");
        assert_eq!(claims.get_issuer(), Some("another.com"));
    }

    #[test]
    fn test_subject() {
        let mut claims = JwtClaims::new();
        assert!(claims.get_subject().is_none());
        
        claims.set_subject("user123");
        assert_eq!(claims.get_subject(), Some("user123"));
    }

    #[test]
    fn test_audience() {
        let mut claims = JwtClaims::new();
        assert!(claims.get_audience().is_none());
        
        let audience = vec!["service1".to_string(), "service2".to_string()];
        claims.set_audience(audience.clone());
        assert_eq!(claims.get_audience(), Some(audience));
    }

    #[test]
    fn test_expiration_time() {
        let mut claims = JwtClaims::new();
        assert!(claims.get_expiration_time().is_none());
        
        let exp = UNIX_EPOCH + Duration::from_secs(1234567890);
        claims.set_expiration_time(exp);
        
        let retrieved = claims.get_expiration_time().unwrap();
        assert_eq!(retrieved.duration_since(UNIX_EPOCH).unwrap().as_secs(), 1234567890);
    }

    #[test]
    fn test_not_before() {
        let mut claims = JwtClaims::new();
        assert!(claims.get_not_before().is_none());
        
        let nbf = UNIX_EPOCH + Duration::from_secs(1234567890);
        claims.set_not_before(nbf);
        
        let retrieved = claims.get_not_before().unwrap();
        assert_eq!(retrieved.duration_since(UNIX_EPOCH).unwrap().as_secs(), 1234567890);
    }

    #[test]
    fn test_issued_at() {
        let mut claims = JwtClaims::new();
        assert!(claims.get_issued_at().is_none());
        
        let iat = UNIX_EPOCH + Duration::from_secs(1234567890);
        claims.set_issued_at(iat);
        
        let retrieved = claims.get_issued_at().unwrap();
        assert_eq!(retrieved.duration_since(UNIX_EPOCH).unwrap().as_secs(), 1234567890);
    }

    #[test]
    fn test_jwt_id() {
        let mut claims = JwtClaims::new();
        assert!(claims.get_jwt_id().is_none());
        
        claims.set_jwt_id("unique-id-123");
        assert_eq!(claims.get_jwt_id(), Some("unique-id-123"));
    }

    #[test]
    fn test_parse_claims() {
        let json = r#"{"iss":"example.com","sub":"user123","exp":1234567890}"#;
        let claims = JwtClaims::parse(json).unwrap();
        
        assert_eq!(claims.get_issuer(), Some("example.com"));
        assert_eq!(claims.get_subject(), Some("user123"));
        
        let exp = claims.get_expiration_time().unwrap();
        assert_eq!(exp.duration_since(UNIX_EPOCH).unwrap().as_secs(), 1234567890);
    }

    #[test]
    fn test_parse_with_audience_array() {
        let json = r#"{"aud":["service1","service2"]}"#;
        let claims = JwtClaims::parse(json).unwrap();
        
        let audience = claims.get_audience().unwrap();
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
        
        assert_eq!(claims.get_issuer(), Some("issuer.com"));
        assert_eq!(claims.get_subject(), Some("user456"));
        assert_eq!(claims.get_jwt_id(), Some("jwt-789"));
        assert!(claims.get_issued_at().is_some());
        assert!(claims.get_expiration_time().is_some());
        assert!(claims.get_not_before().is_some());
    }

    #[test]
    fn test_default() {
        let claims = JwtClaims::default();
        assert!(claims.get_issuer().is_none());
    }
}
