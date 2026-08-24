// JWT Consumer for validating and processing JWTs

use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::error::JoseError;
use crate::jwt::{JwtClaims, TimeClaim};

/// Error codes for JWT validation failures
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    /// JWT signature is invalid
    SignatureInvalid,
    /// JWT signature is missing when required
    SignatureMissing,
    /// JWT encryption is missing when required
    EncryptionMissing,
    /// Integrity protection is missing
    IntegrityMissing,
    /// JWT has expired
    Expired,
    /// JWT is not yet valid (nbf claim)
    NotYetValid,
    /// Audience claim is missing
    AudienceMissing,
    /// Audience claim is invalid
    AudienceInvalid,
    /// Issuer claim is missing
    IssuerMissing,
    /// Issuer claim is invalid
    IssuerInvalid,
    /// Subject claim is missing
    SubjectMissing,
    /// Subject claim is invalid
    SubjectInvalid,
    /// JWT ID claim is missing
    JwtIdMissing,
    /// Expiration time claim is malformed
    MalformedClaim,
    /// Expiration time is too far in the future
    ExpirationTooFarInFuture,
    /// Issued at time is invalid (too far in future)
    IssuedAtInvalidFuture,
    /// Issued at time is invalid (too far in past)
    IssuedAtInvalidPast,
    /// Expiration time claim is required but missing
    ExpirationMissing,
    /// Not before time claim is required but missing
    NotBeforeMissing,
    /// Issued at time claim is required but missing
    IssuedAtMissing,
    /// Expiration time is before the issued at time (inconsistent claims)
    ExpirationBeforeIssuedAt,
    /// Expiration time is before the not before time (inconsistent claims)
    ExpirationBeforeNotBefore,
    /// A prohibited claim is present
    ProhibitedClaim,
    /// Miscellaneous error
    Miscellaneous,
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Error type for invalid JWT validation
#[derive(Debug)]
pub struct InvalidJwtError {
    message: String,
    error_codes: Vec<ErrorCode>,
}

impl InvalidJwtError {
    /// Create an error with no associated error codes.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            error_codes: Vec::new(),
        }
    }

    /// Create an error carrying a single error code.
    pub fn with_error_code(message: impl Into<String>, error_code: ErrorCode) -> Self {
        Self {
            message: message.into(),
            error_codes: vec![error_code],
        }
    }

    /// Create an error carrying multiple error codes.
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

    /// The human-readable failure message.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// All error codes carried by this error, in insertion order.
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
        InvalidJwtError::new(format!("JWT processing failed: {err}"))
    }
}

/// Builder for creating a JWT Consumer with specific validation requirements
#[derive(Debug, Default)]
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
    prohibited_claims: Vec<String>,
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
        self.expected_issuers = Some(
            issuers
                .iter()
                .map(std::string::ToString::to_string)
                .collect(),
        );
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
        self.expected_audiences = Some(
            audiences
                .iter()
                .map(std::string::ToString::to_string)
                .collect(),
        );
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

    /// Set claims that must NOT be present in the JWT.
    ///
    /// Useful to prevent cross-JWT confusion in situations where explicit
    /// typing via the `typ` header is not used -- e.g. rejecting an access
    /// token that carries a claim only ID tokens should have.
    pub fn set_prohibited_claims(mut self, claims: &[&str]) -> Self {
        self.prohibited_claims = claims
            .iter()
            .map(std::string::ToString::to_string)
            .collect();
        self
    }

    /// Set the time to use when validating time-based claims.
    ///
    /// A negative value denotes a pre-epoch time (before 1970-01-01), matching
    /// jose4j's `NumericDate.fromSeconds`.
    pub fn set_evaluation_time_from_seconds(mut self, seconds: i64) -> Self {
        self.evaluation_time = Some(if seconds >= 0 {
            UNIX_EPOCH + Duration::from_secs(seconds as u64)
        } else {
            // Negative values are pre-epoch; magnitude fits u64 for any i64::MIN
            // via unsigned_abs.
            UNIX_EPOCH - Duration::from_secs(seconds.unsigned_abs())
        });
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
            prohibited_claims: self.prohibited_claims,
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
#[derive(Debug)]
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
    prohibited_claims: Vec<String>,
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
    ///
    /// # Errors
    ///
    /// Returns an error if the claims cannot be parsed or fail validation.
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

            // Validate prohibited claims
            if let Err(e) = self.validate_prohibited_claims(&claims) {
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
        let issuer = claims.issuer();

        // A present-but-non-string iss is malformed, not missing; reject it
        // (before the missing check, which would otherwise mask it) when the
        // caller has configured expected issuers.
        if let Some(expected_issuers) = &self.expected_issuers {
            if !expected_issuers.is_empty() && claims.string_claim_is_malformed("iss") {
                return Err(InvalidJwtError::with_error_code(
                    "issuer claim is malformed (must be a string)",
                    ErrorCode::IssuerInvalid,
                ));
            }
        }

        if self.require_issuer && issuer.is_none() {
            return Err(InvalidJwtError::with_error_code(
                "issuer claim is required but missing",
                ErrorCode::IssuerMissing,
            ));
        }

        if let Some(expected_issuers) = &self.expected_issuers {
            if let Some(issuer) = issuer {
                if !expected_issuers.is_empty()
                    && !expected_issuers.iter().any(|exp| exp.as_str() == issuer)
                {
                    return Err(InvalidJwtError::with_error_code(
                        format!("issuer '{issuer}' is not expected"),
                        ErrorCode::IssuerInvalid,
                    ));
                }
            } else if self.require_issuer {
                return Err(InvalidJwtError::with_error_code(
                    "issuer claim is required but missing",
                    ErrorCode::IssuerMissing,
                ));
            }
        }

        Ok(())
    }

    fn validate_audience(&self, claims: &JwtClaims) -> Result<(), InvalidJwtError> {
        // Read the aud claim exactly once: presence, well-formedness, strict
        // string form, and the string values all come from a single lookup.
        let aud = claims.audience_info();

        // A present-but-malformed aud (non-string member, or not a string/array)
        // is rejected outright rather than silently filtered (jose4j
        // MalformedClaimException on `getAudience`).
        if aud.malformed {
            return Err(InvalidJwtError::with_error_code(
                "audience claim is malformed (must be a string or an array of strings)",
                ErrorCode::AudienceInvalid,
            ));
        }

        let has_aud = aud.present;

        if self.require_audience && !has_aud {
            return Err(InvalidJwtError::with_error_code(
                "audience claim is required but missing",
                ErrorCode::AudienceMissing,
            ));
        }

        if let Some(expected_audiences) = &self.expected_audiences {
            if has_aud {
                // Strict mode (RFC 7523 client assertions) requires the raw aud
                // to be a single string, not an array.
                if self.strict_audience && !aud.is_string {
                    return Err(InvalidJwtError::with_error_code(
                        "audience must be a single string value in strict mode",
                        ErrorCode::AudienceInvalid,
                    ));
                }

                let matches = aud
                    .values
                    .iter()
                    .any(|a| expected_audiences.iter().any(|e| e.as_str() == *a));
                if !expected_audiences.is_empty() && !matches {
                    return Err(InvalidJwtError::with_error_code(
                        "no expected audience found in JWT",
                        ErrorCode::AudienceInvalid,
                    ));
                }
            } else if self.require_audience {
                return Err(InvalidJwtError::with_error_code(
                    "audience claim is required but missing",
                    ErrorCode::AudienceMissing,
                ));
            }
        } else if !self.skip_default_audience_validation && has_aud {
            return Err(InvalidJwtError::with_error_code(
                "no expected audience has been configured",
                ErrorCode::AudienceMissing,
            ));
        }

        Ok(())
    }

    fn validate_subject(&self, claims: &JwtClaims) -> Result<(), InvalidJwtError> {
        let subject = claims.subject();

        if self.require_subject && subject.is_none() {
            return Err(InvalidJwtError::with_error_code(
                "subject claim is required but missing",
                ErrorCode::SubjectMissing,
            ));
        }

        if let Some(expected_subject) = &self.expected_subject {
            if let Some(subject) = subject {
                if subject != expected_subject.as_str() {
                    return Err(InvalidJwtError::with_error_code(
                        format!("subject '{subject}' does not match expected '{expected_subject}'"),
                        ErrorCode::SubjectInvalid,
                    ));
                }
            } else {
                return Err(InvalidJwtError::with_error_code(
                    "subject claim is required but missing",
                    ErrorCode::SubjectMissing,
                ));
            }
        }

        Ok(())
    }

    fn validate_jwt_id(&self, claims: &JwtClaims) -> Result<(), InvalidJwtError> {
        if self.require_jwt_id && claims.jwt_id().is_none() {
            return Err(InvalidJwtError::with_error_code(
                "JWT ID claim is required but missing",
                ErrorCode::JwtIdMissing,
            ));
        }
        Ok(())
    }

    fn validate_prohibited_claims(&self, claims: &JwtClaims) -> Result<(), InvalidJwtError> {
        let present: Vec<&str> = self
            .prohibited_claims
            .iter()
            .filter(|name| claims.has_claim(name))
            .map(String::as_str)
            .collect();
        if !present.is_empty() {
            return Err(InvalidJwtError::with_error_code(
                format!("JWT has prohibited claims: {}", present.join(", ")),
                ErrorCode::ProhibitedClaim,
            ));
        }
        Ok(())
    }

    fn validate_time_claims(&self, claims: &JwtClaims) -> Result<(), InvalidJwtError> {
        let eval_time = self.evaluation_time.unwrap_or_else(SystemTime::now);
        // Signed seconds since the epoch; negative for pre-epoch times so the
        // claim comparisons (all in i64) work for any evaluation time.
        let eval_secs = match eval_time.duration_since(UNIX_EPOCH) {
            Ok(d) => d.as_secs() as i64,
            Err(e) => -(e.duration().as_secs() as i64),
        };
        let clock_skew_secs = self.allowed_clock_skew.as_secs() as i64;

        // Read each time claim exactly once: a single map lookup per claim both
        // classifies it (absent / malformed / integer) and yields the value.
        let exp = claims.time_claim("exp");
        let nbf = claims.time_claim("nbf");
        let iat = claims.time_claim("iat");

        let mut errors = Vec::new();

        // A present-but-non-integer NumericDate (float, string, out-of-range)
        // is malformed, not absent (RFC 7519 Section 2, jose4j MalformedClaimException).
        for claim in [exp, nbf, iat] {
            if claim == TimeClaim::Malformed {
                errors.push(ErrorCode::MalformedClaim);
            }
        }

        // Validate expiration time
        if let TimeClaim::Value(exp_secs) = exp {
            // Check if expired (token is expired at or after the exp time).
            // Negative values are long past and thus expired; the comparison
            // `exp + skew <= eval` handles them naturally in i64.
            if exp_secs
                .checked_add(clock_skew_secs)
                .is_none_or(|e| e <= eval_secs)
            {
                errors.push(ErrorCode::Expired);
            }

            // exp cannot precede iat (inconsistent claims)
            if let TimeClaim::Value(iat_secs) = iat {
                if exp_secs < iat_secs {
                    errors.push(ErrorCode::ExpirationBeforeIssuedAt);
                }
            }

            // exp cannot precede nbf (inconsistent claims)
            if let TimeClaim::Value(nbf_secs) = nbf {
                if exp_secs < nbf_secs {
                    errors.push(ErrorCode::ExpirationBeforeNotBefore);
                }
            }

            // Check if expiration is too far in the future
            if let Some(max_future_validity) = self.max_future_validity {
                let max_validity_secs = max_future_validity.as_secs() as i64;
                let too_far = match eval_secs
                    .checked_add(max_validity_secs)
                    .and_then(|m| m.checked_add(clock_skew_secs))
                {
                    // exp beyond (eval + max_validity + skew) is too far.
                    Some(max_exp) => exp_secs > max_exp,
                    // eval+max+skew overflowed i64; only i64::MAX exp exceeds it.
                    None => false,
                };
                if too_far {
                    errors.push(ErrorCode::ExpirationTooFarInFuture);
                }
            }
        } else if self.require_expiration && exp == TimeClaim::Absent {
            errors.push(ErrorCode::ExpirationMissing);
        }

        // Validate not before time
        if let TimeClaim::Value(nbf_secs) = nbf {
            // Not yet valid when nbf is after (eval + skew). Negative nbf is in
            // the past and therefore already valid.
            let not_yet = match eval_secs.checked_add(clock_skew_secs) {
                Some(latest) => nbf_secs > latest,
                None => false, // eval+skew overflowed; nothing can be after it
            };
            if not_yet {
                errors.push(ErrorCode::NotYetValid);
            }
        } else if self.require_not_before && nbf == TimeClaim::Absent {
            errors.push(ErrorCode::NotBeforeMissing);
        }

        // Validate issued at time
        if let TimeClaim::Value(iat_secs) = iat {
            // Check if issued at is too far in the future
            if let Some(allowed_future) = self.iat_allowed_secs_in_future {
                let too_new = match eval_secs.checked_add(allowed_future) {
                    Some(latest) => iat_secs > latest,
                    None => false,
                };
                if too_new {
                    errors.push(ErrorCode::IssuedAtInvalidFuture);
                }
            }

            // Check if issued at is too far in the past
            if let Some(allowed_past) = self.iat_allowed_secs_in_past {
                let too_old = match eval_secs.checked_sub(allowed_past) {
                    Some(earliest) => iat_secs < earliest,
                    None => false,
                };
                if too_old {
                    errors.push(ErrorCode::IssuedAtInvalidPast);
                }
            }
        } else if self.require_issued_at && iat == TimeClaim::Absent {
            errors.push(ErrorCode::IssuedAtMissing);
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(InvalidJwtError::with_error_codes(
                "time-based validation failed",
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

    #[test]
    fn test_prohibited_claims() {
        let claims = JwtClaims::parse(r#"{"iss":"i","token_use":"id","sub":"s"}"#)
            .unwrap()
            .to_json();

        let consumer = JwtConsumerBuilder::new()
            .set_prohibited_claims(&["token_use"])
            .build();

        let result = consumer.process_to_claims(&claims);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.has_error_code(ErrorCode::ProhibitedClaim));

        // Not present -> passes
        let consumer = JwtConsumerBuilder::new()
            .set_prohibited_claims(&["nonce", "at_hash"])
            .build();
        assert!(consumer.process_to_claims(&claims).is_ok());
    }
}
