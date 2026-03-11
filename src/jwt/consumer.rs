// JWT Consumer for validating and processing JWTs

use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::error::JoseError;
use crate::jwt::JwtClaims;

/// Error codes for JWT validation failures
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    /// JWT signature is invalid
    SignatureInvalid = 1,
    /// JWT signature is missing when required
    SignatureMissing = 2,
    /// JWT encryption is missing when required
    EncryptionMissing = 3,
    /// Integrity protection is missing
    IntegrityMissing = 4,
    /// JWT has expired
    Expired = 5,
    /// JWT is not yet valid (nbf claim)
    NotYetValid = 6,
    /// Audience claim is missing
    AudienceMissing = 7,
    /// Audience claim is invalid
    AudienceInvalid = 8,
    /// Issuer claim is missing
    IssuerMissing = 9,
    /// Issuer claim is invalid
    IssuerInvalid = 10,
    /// Subject claim is missing
    SubjectMissing = 11,
    /// Subject claim is invalid
    SubjectInvalid = 12,
    /// JWT ID claim is missing
    JwtIdMissing = 13,
    /// Expiration time claim is malformed
    MalformedClaim = 14,
    /// Expiration time is too far in the future
    ExpirationTooFarInFuture = 15,
    /// Issued at time is invalid (too far in future)
    IssuedAtInvalidFuture = 16,
    /// Issued at time is invalid (too far in past)
    IssuedAtInvalidPast = 17,
    /// Miscellaneous error
    Miscellaneous = 99,
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Error type for invalid JWT validation
#[derive(Debug)]
pub struct InvalidJwtError {
    message: String,
    error_codes: Vec<ErrorCode>,
}

impl InvalidJwtError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            error_codes: Vec::new(),
        }
    }

    pub fn with_error_code(message: impl Into<String>, error_code: ErrorCode) -> Self {
        Self {
            message: message.into(),
            error_codes: vec![error_code],
        }
    }

    pub fn with_error_codes(message: impl Into<String>, error_codes: Vec<ErrorCode>) -> Self {
        Self {
            message: message.into(),
            error_codes,
        }
    }

    /// Check if this error contains a specific error code
    pub fn has_error_code(&self, error_code: ErrorCode) -> bool {
        self.error_codes.contains(&error_code)
    }

    /// Check if the JWT has expired
    pub fn has_expired(&self) -> bool {
        self.has_error_code(ErrorCode::Expired)
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn error_codes(&self) -> &[ErrorCode] {
        &self.error_codes
    }
}

impl fmt::Display for InvalidJwtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for InvalidJwtError {}

impl From<JoseError> for InvalidJwtError {
    fn from(err: JoseError) -> Self {
        InvalidJwtError::new(format!("JWT processing failed: {}", err))
    }
}

/// Builder for creating a JWT Consumer with specific validation requirements
#[derive(Default)]
pub struct JwtConsumerBuilder {
    expected_issuers: Option<Vec<String>>,
    require_issuer: bool,
    expected_audiences: Option<Vec<String>>,
    require_audience: bool,
    strict_audience: bool,
    skip_default_audience_validation: bool,
    expected_subject: Option<String>,
    require_subject: bool,
    require_jwt_id: bool,
    require_expiration: bool,
    require_not_before: bool,
    require_issued_at: bool,
    evaluation_time: Option<SystemTime>,
    allowed_clock_skew: Duration,
    max_future_validity: Option<Duration>,
    iat_allowed_secs_in_future: Option<i64>,
    iat_allowed_secs_in_past: Option<i64>,
    skip_all_validators: bool,
    skip_all_default_validators: bool,
}

impl JwtConsumerBuilder {
    /// Create a new JWT Consumer Builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the expected issuer(s) for the JWT
    ///
    /// # Arguments
    /// * `require_issuer` - Whether the issuer claim is required
    /// * `issuers` - Expected issuer value(s)
    pub fn set_expected_issuers(mut self, require_issuer: bool, issuers: &[&str]) -> Self {
        self.expected_issuers = Some(issuers.iter().map(|s| s.to_string()).collect());
        self.require_issuer = require_issuer;
        self
    }

    /// Set the expected issuer for the JWT (convenience method)
    pub fn set_expected_issuer(self, issuer: &str) -> Self {
        self.set_expected_issuers(true, &[issuer])
    }

    /// Set the expected audience(s) for the JWT
    ///
    /// # Arguments
    /// * `require_audience` - Whether the audience claim is required
    /// * `strict` - If true, audience must be a single string value
    /// * `audiences` - Expected audience value(s)
    pub fn set_expected_audience(
        mut self,
        require_audience: bool,
        strict: bool,
        audiences: &[&str],
    ) -> Self {
        self.expected_audiences = Some(audiences.iter().map(|s| s.to_string()).collect());
        self.require_audience = require_audience;
        self.strict_audience = strict;
        self
    }

    /// Skip default audience validation
    pub fn set_skip_default_audience_validation(mut self) -> Self {
        self.skip_default_audience_validation = true;
        self
    }

    /// Set the expected subject for the JWT
    pub fn set_expected_subject(mut self, subject: &str) -> Self {
        self.expected_subject = Some(subject.to_string());
        self.require_subject = true;
        self
    }

    /// Require that a subject claim be present
    pub fn set_require_subject(mut self) -> Self {
        self.require_subject = true;
        self
    }

    /// Require that a JWT ID claim be present
    pub fn set_require_jwt_id(mut self) -> Self {
        self.require_jwt_id = true;
        self
    }

    /// Require that an expiration time claim be present
    pub fn set_require_expiration_time(mut self) -> Self {
        self.require_expiration = true;
        self
    }

    /// Require that a not before time claim be present
    pub fn set_require_not_before(mut self) -> Self {
        self.require_not_before = true;
        self
    }

    /// Require that an issued at time claim be present
    pub fn set_require_issued_at(mut self) -> Self {
        self.require_issued_at = true;
        self
    }

    /// Set the time to use when validating time-based claims
    pub fn set_evaluation_time_from_seconds(mut self, seconds: i64) -> Self {
        self.evaluation_time = Some(UNIX_EPOCH + Duration::from_secs(seconds as u64));
        self
    }

    /// Set the amount of clock skew to allow for time-based validations
    pub fn set_allowed_clock_skew(mut self, duration: Duration) -> Self {
        self.allowed_clock_skew = duration;
        self
    }

    /// Set the maximum on how far in the future the exp claim can be
    pub fn set_max_future_validity(mut self, duration: Duration) -> Self {
        self.max_future_validity = Some(duration);
        self
    }

    /// Set restrictions on how far from evaluation time the iat claim can be
    pub fn set_issued_at_restrictions(
        mut self,
        allowed_secs_in_future: i64,
        allowed_secs_in_past: i64,
    ) -> Self {
        self.iat_allowed_secs_in_future = Some(allowed_secs_in_future);
        self.iat_allowed_secs_in_past = Some(allowed_secs_in_past);
        self
    }

    /// Skip all claim validators
    pub fn set_skip_all_validators(mut self) -> Self {
        self.skip_all_validators = true;
        self
    }

    /// Skip all default claim validators (but not custom ones)
    pub fn set_skip_all_default_validators(mut self) -> Self {
        self.skip_all_default_validators = true;
        self
    }

    /// Build the JWT Consumer
    pub fn build(self) -> JwtConsumer {
        JwtConsumer {
            expected_issuers: self.expected_issuers,
            require_issuer: self.require_issuer,
            expected_audiences: self.expected_audiences,
            require_audience: self.require_audience,
            strict_audience: self.strict_audience,
            skip_default_audience_validation: self.skip_default_audience_validation,
            expected_subject: self.expected_subject,
            require_subject: self.require_subject,
            require_jwt_id: self.require_jwt_id,
            require_expiration: self.require_expiration,
            require_not_before: self.require_not_before,
            require_issued_at: self.require_issued_at,
            evaluation_time: self.evaluation_time,
            allowed_clock_skew: self.allowed_clock_skew,
            max_future_validity: self.max_future_validity,
            iat_allowed_secs_in_future: self.iat_allowed_secs_in_future,
            iat_allowed_secs_in_past: self.iat_allowed_secs_in_past,
            skip_all_validators: self.skip_all_validators,
            skip_all_default_validators: self.skip_all_default_validators,
        }
    }
}

/// JWT Consumer for validating JWT claims
pub struct JwtConsumer {
    expected_issuers: Option<Vec<String>>,
    require_issuer: bool,
    expected_audiences: Option<Vec<String>>,
    require_audience: bool,
    strict_audience: bool,
    skip_default_audience_validation: bool,
    expected_subject: Option<String>,
    require_subject: bool,
    require_jwt_id: bool,
    require_expiration: bool,
    require_not_before: bool,
    require_issued_at: bool,
    evaluation_time: Option<SystemTime>,
    allowed_clock_skew: Duration,
    max_future_validity: Option<Duration>,
    iat_allowed_secs_in_future: Option<i64>,
    iat_allowed_secs_in_past: Option<i64>,
    skip_all_validators: bool,
    skip_all_default_validators: bool,
}

impl JwtConsumer {
    /// Process JWT claims and validate them
    pub fn process_to_claims(&self, claims: &str) -> Result<JwtClaims, InvalidJwtError> {
        let claims = JwtClaims::parse(claims)?;
        if self.skip_all_validators {
            return Ok(claims);
        }

        let mut errors = Vec::new();

        if !self.skip_all_default_validators {
            // Validate issuer
            if let Err(e) = self.validate_issuer(&claims) {
                errors.extend(e.error_codes);
            }

            // Validate audience
            if !self.skip_default_audience_validation {
                if let Err(e) = self.validate_audience(&claims) {
                    errors.extend(e.error_codes);
                }
            }

            // Validate subject
            if let Err(e) = self.validate_subject(&claims) {
                errors.extend(e.error_codes);
            }

            // Validate JWT ID
            if let Err(e) = self.validate_jwt_id(&claims) {
                errors.extend(e.error_codes);
            }

            // Validate time claims
            if let Err(e) = self.validate_time_claims(&claims) {
                errors.extend(e.error_codes);
            }
        }

        if errors.is_empty() {
            Ok(claims)
        } else {
            Err(InvalidJwtError::with_error_codes(
                "JWT validation failed",
                errors,
            ))
        }
    }

    fn validate_issuer(&self, claims: &JwtClaims) -> Result<(), InvalidJwtError> {
        let issuer = claims.get_issuer();

        if self.require_issuer && issuer.is_none() {
            return Err(InvalidJwtError::with_error_code(
                "Issuer claim is required but missing",
                ErrorCode::IssuerMissing,
            ));
        }

        if let Some(expected_issuers) = &self.expected_issuers {
            if let Some(issuer) = issuer {
                if !expected_issuers.is_empty() && !expected_issuers.contains(&issuer.to_string()) {
                    return Err(InvalidJwtError::with_error_code(
                        format!("Issuer '{}' is not expected", issuer),
                        ErrorCode::IssuerInvalid,
                    ));
                }
            } else if self.require_issuer {
                return Err(InvalidJwtError::with_error_code(
                    "Issuer claim is required but missing",
                    ErrorCode::IssuerMissing,
                ));
            }
        }

        Ok(())
    }

    fn validate_audience(&self, claims: &JwtClaims) -> Result<(), InvalidJwtError> {
        let audience = claims.get_audience();

        if self.require_audience && audience.is_none() {
            return Err(InvalidJwtError::with_error_code(
                "Audience claim is required but missing",
                ErrorCode::AudienceMissing,
            ));
        }

        if let Some(expected_audiences) = &self.expected_audiences {
            if let Some(audience) = audience {
                // Check if strict validation is required
                if self.strict_audience && audience.len() > 1 {
                    return Err(InvalidJwtError::with_error_code(
                        "Audience must be a single string value in strict mode",
                        ErrorCode::AudienceInvalid,
                    ));
                }

                // Check if any expected audience matches
                if !expected_audiences.is_empty() {
                    let has_match = audience.iter().any(|aud| expected_audiences.contains(aud));
                    if !has_match {
                        return Err(InvalidJwtError::with_error_code(
                            "No expected audience found in JWT",
                            ErrorCode::AudienceInvalid,
                        ));
                    }
                }
            } else if self.require_audience {
                return Err(InvalidJwtError::with_error_code(
                    "Audience claim is required but missing",
                    ErrorCode::AudienceMissing,
                ));
            }
        } else if !self.skip_default_audience_validation && audience.is_some() {
            // Default behavior: if audience is present but no expected audience configured, fail
            return Err(InvalidJwtError::with_error_code(
                "No expected audience has been configured",
                ErrorCode::AudienceMissing,
            ));
        }

        Ok(())
    }

    fn validate_subject(&self, claims: &JwtClaims) -> Result<(), InvalidJwtError> {
        let subject = claims.get_subject();

        if self.require_subject && subject.is_none() {
            return Err(InvalidJwtError::with_error_code(
                "Subject claim is required but missing",
                ErrorCode::SubjectMissing,
            ));
        }

        if let Some(expected_subject) = &self.expected_subject {
            if let Some(subject) = subject {
                if subject != expected_subject {
                    return Err(InvalidJwtError::with_error_code(
                        format!(
                            "Subject '{}' does not match expected '{}'",
                            subject, expected_subject
                        ),
                        ErrorCode::SubjectInvalid,
                    ));
                }
            } else {
                return Err(InvalidJwtError::with_error_code(
                    "Subject claim is required but missing",
                    ErrorCode::SubjectMissing,
                ));
            }
        }

        Ok(())
    }

    fn validate_jwt_id(&self, claims: &JwtClaims) -> Result<(), InvalidJwtError> {
        if self.require_jwt_id && claims.get_jwt_id().is_none() {
            return Err(InvalidJwtError::with_error_code(
                "JWT ID claim is required but missing",
                ErrorCode::JwtIdMissing,
            ));
        }
        Ok(())
    }

    fn validate_time_claims(&self, claims: &JwtClaims) -> Result<(), InvalidJwtError> {
        let eval_time = self.evaluation_time.unwrap_or_else(SystemTime::now);
        let eval_secs = eval_time.duration_since(UNIX_EPOCH).unwrap().as_secs();

        let mut errors = Vec::new();

        // Validate expiration time
        if let Some(exp) = claims.get_expiration_time() {
            let exp_secs = exp.duration_since(UNIX_EPOCH).unwrap().as_secs();

            // Check if expired (token is expired at or after the exp time)
            if exp_secs + self.allowed_clock_skew.as_secs() <= eval_secs {
                errors.push(ErrorCode::Expired);
            }

            // Check if expiration is too far in the future
            if let Some(max_future_validity) = self.max_future_validity {
                let max_exp = eval_secs + max_future_validity.as_secs();
                if exp_secs > max_exp + self.allowed_clock_skew.as_secs() {
                    errors.push(ErrorCode::ExpirationTooFarInFuture);
                }
            }
        } else if self.require_expiration {
            errors.push(ErrorCode::MalformedClaim);
        }

        // Validate not before time
        if let Some(nbf) = claims.get_not_before() {
            let nbf_secs = nbf.duration_since(UNIX_EPOCH).unwrap().as_secs();

            if nbf_secs > eval_secs + self.allowed_clock_skew.as_secs() {
                errors.push(ErrorCode::NotYetValid);
            }
        } else if self.require_not_before {
            errors.push(ErrorCode::MalformedClaim);
        }

        // Validate issued at time
        if let Some(iat) = claims.get_issued_at() {
            let iat_secs = iat.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;

            // Check if issued at is too far in the future
            if let Some(allowed_future) = self.iat_allowed_secs_in_future {
                if iat_secs > eval_secs as i64 + allowed_future {
                    errors.push(ErrorCode::IssuedAtInvalidFuture);
                }
            }

            // Check if issued at is too far in the past
            if let Some(allowed_past) = self.iat_allowed_secs_in_past {
                if iat_secs < eval_secs as i64 - allowed_past {
                    errors.push(ErrorCode::IssuedAtInvalidPast);
                }
            }
        } else if self.require_issued_at {
            errors.push(ErrorCode::MalformedClaim);
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(InvalidJwtError::with_error_codes(
                "Time-based validation failed",
                errors,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_validation_success() {
        let mut claims = JwtClaims::new();
        claims.set_issuer("test-issuer");
        claims.set_audience(vec!["test-audience".to_string()]);
        claims.set_subject("test-subject");
        claims.set_expiration_time(SystemTime::now() + Duration::from_secs(3600));
        let claims = claims.to_json();

        let consumer = JwtConsumerBuilder::new()
            .set_expected_issuer("test-issuer")
            .set_expected_audience(true, false, &["test-audience"])
            .set_expected_subject("test-subject")
            .set_require_expiration_time()
            .build();

        assert!(consumer.process_to_claims(&claims).is_ok());
    }

    #[test]
    fn test_missing_issuer() {
        let claims = JwtClaims::new().to_json();

        let consumer = JwtConsumerBuilder::new()
            .set_expected_issuer("test-issuer")
            .build();

        let result = consumer.process_to_claims(&claims);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.has_error_code(ErrorCode::IssuerMissing));
    }

    #[test]
    fn test_invalid_issuer() {
        let mut claims = JwtClaims::new();
        claims.set_issuer("wrong-issuer");
        let claims = claims.to_json();

        let consumer = JwtConsumerBuilder::new()
            .set_expected_issuer("test-issuer")
            .build();

        let result = consumer.process_to_claims(&claims);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.has_error_code(ErrorCode::IssuerInvalid));
    }

    #[test]
    fn test_missing_audience() {
        let claims = JwtClaims::new();
        let claims = claims.to_json();

        let consumer = JwtConsumerBuilder::new()
            .set_expected_audience(true, false, &["test-audience"])
            .build();

        let result = consumer.process_to_claims(&claims);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.has_error_code(ErrorCode::AudienceMissing));
    }

    #[test]
    fn test_invalid_audience() {
        let mut claims = JwtClaims::new();
        claims.set_audience(vec!["wrong-audience".to_string()]);
        let claims = claims.to_json();

        let consumer = JwtConsumerBuilder::new()
            .set_expected_audience(true, false, &["test-audience"])
            .build();

        let result = consumer.process_to_claims(&claims);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.has_error_code(ErrorCode::AudienceInvalid));
    }

    #[test]
    fn test_expired_token() {
        let mut claims = JwtClaims::new();
        claims.set_expiration_time(UNIX_EPOCH + Duration::from_secs(1000));
        let claims = claims.to_json();

        let consumer = JwtConsumerBuilder::new()
            .set_evaluation_time_from_seconds(2000)
            .build();

        let result = consumer.process_to_claims(&claims);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.has_expired());
        assert!(err.has_error_code(ErrorCode::Expired));
    }

    #[test]
    fn test_not_yet_valid() {
        let mut claims = JwtClaims::new();
        claims.set_not_before(UNIX_EPOCH + Duration::from_secs(2000));
        let claims = claims.to_json();

        let consumer = JwtConsumerBuilder::new()
            .set_evaluation_time_from_seconds(1000)
            .build();

        let result = consumer.process_to_claims(&claims);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.has_error_code(ErrorCode::NotYetValid));
    }

    #[test]
    fn test_clock_skew_allows_expired() {
        let mut claims = JwtClaims::new();
        claims.set_expiration_time(UNIX_EPOCH + Duration::from_secs(1000));
        let claims = claims.to_json();

        let consumer = JwtConsumerBuilder::new()
            .set_evaluation_time_from_seconds(1005)
            .set_allowed_clock_skew(Duration::from_secs(10))
            .build();

        // Should pass because clock skew allows for 10 seconds
        assert!(consumer.process_to_claims(&claims).is_ok());
    }

    #[test]
    fn test_skip_all_validators() {
        let mut claims = JwtClaims::new();
        claims.set_issuer("wrong-issuer");
        claims.set_expiration_time(UNIX_EPOCH + Duration::from_secs(1000));
        let claims = claims.to_json();

        let consumer = JwtConsumerBuilder::new()
            .set_expected_issuer("test-issuer")
            .set_evaluation_time_from_seconds(2000)
            .set_skip_all_validators()
            .build();

        // Should pass even though issuer is wrong and token is expired
        assert!(consumer.process_to_claims(&claims).is_ok());
    }

    #[test]
    fn test_multiple_issuers() {
        let mut claims = JwtClaims::new();
        claims.set_issuer("accounts.google.com");
        let claims = claims.to_json();

        let consumer = JwtConsumerBuilder::new()
            .set_expected_issuers(
                true,
                &["https://accounts.google.com", "accounts.google.com"],
            )
            .build();

        assert!(consumer.process_to_claims(&claims).is_ok());
    }

    #[test]
    fn test_strict_audience_validation() {
        let mut claims = JwtClaims::new();
        claims.set_audience(vec!["aud1".to_string(), "aud2".to_string()]);
        let claims = claims.to_json();

        let consumer = JwtConsumerBuilder::new()
            .set_expected_audience(true, true, &["aud1"])
            .build();

        let result = consumer.process_to_claims(&claims);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.has_error_code(ErrorCode::AudienceInvalid));
    }

    #[test]
    fn test_max_future_validity() {
        let mut claims = JwtClaims::new();
        claims.set_expiration_time(UNIX_EPOCH + Duration::from_secs(1000 + 20 * 60));
        let claims = claims.to_json();

        let consumer = JwtConsumerBuilder::new()
            .set_evaluation_time_from_seconds(1000)
            .set_max_future_validity(Duration::from_mins(10))
            .build();

        let result = consumer.process_to_claims(&claims);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.has_error_code(ErrorCode::ExpirationTooFarInFuture));
    }

    #[test]
    fn test_issued_at_restrictions() {
        let mut claims = JwtClaims::new();
        claims.set_issued_at(UNIX_EPOCH + Duration::from_secs(500));
        let claims = claims.to_json();

        let consumer = JwtConsumerBuilder::new()
            .set_evaluation_time_from_seconds(1000)
            .set_require_issued_at()
            .set_issued_at_restrictions(10, 100)
            .build();

        let result = consumer.process_to_claims(&claims);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.has_error_code(ErrorCode::IssuedAtInvalidPast));
    }
}
