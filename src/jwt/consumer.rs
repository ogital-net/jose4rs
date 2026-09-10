// JWT Consumer for validating and processing JWTs

use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::error::JoseError;
use crate::jwt::{JwtClaims, TimeClaim};

/// Stable, typed identifier for a JWT validation failure.
///
/// `ErrorCode` is a thin newtype around `i32` with two regions of the integer
/// space:
///
/// * **Library-defined codes** (positive integers, 1..=N) are exposed as
///   `pub const` items on this type. Some are produced by the default
///   validation pipeline ([`JwtConsumer::process_to_claims`]); the rest are
///   stable identifiers available for use by custom validators
///   ([`JwtValidator`]) that want a recognizable code name in their
///   [`InvalidJwtError`] (e.g. a JWS-aware validator may re-emit
///   `SIGNATURE_INVALID` for a recognizable failure surface).
/// * **Consumer-defined codes** (negative integers) are created via
///   [`ErrorCode::custom`]. They let callers attach protocol-specific
///   failure identifiers (e.g. an OIDC `nonce` mismatch, an RFC 9700
///   `c_hash` mismatch, a `cnf.jkt` mismatch in a `DPoP` proof)
///   without the library needing to grow a variant per protocol.
///
/// The split is enforced at the API edge: `ErrorCode::custom` requires a
/// negative integer and panics otherwise, so a positive integer can never
/// collide with a library-defined code by accident.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ErrorCode(i32);

impl ErrorCode {
    // --- Library-defined codes. Emitted by the default validation    ---
    // --- pipeline when applicable; the rest are stable identifiers  ---
    // --- for use by custom validators that want a recognizable      ---
    // --- code name in their `InvalidJwtError`.                      ---

    /// JWT has expired (`exp` claim identified a time in the past).
    pub const EXPIRED: ErrorCode = ErrorCode(1);
    /// `exp` claim was required but missing.
    pub const EXPIRATION_MISSING: ErrorCode = ErrorCode(2);
    /// `iat` claim was required but missing.
    pub const ISSUED_AT_MISSING: ErrorCode = ErrorCode(3);
    /// `nbf` claim was required but missing.
    pub const NOT_BEFORE_MISSING: ErrorCode = ErrorCode(4);
    /// `exp` claim was too far in the future.
    pub const EXPIRATION_TOO_FAR_IN_FUTURE: ErrorCode = ErrorCode(5);
    /// JWT is not yet valid (`nbf` claim).
    pub const NOT_YET_VALID: ErrorCode = ErrorCode(6);
    /// `aud` claim was required but missing.
    pub const AUDIENCE_MISSING: ErrorCode = ErrorCode(7);
    /// `aud` claim did not match any expected audience.
    pub const AUDIENCE_INVALID: ErrorCode = ErrorCode(8);
    /// JWS signature did not verify. Not produced by the default claims
    /// pipeline (signature verification is handled by `JsonWebSignature`
    /// before claims reach `JwtConsumer`).
    pub const SIGNATURE_INVALID: ErrorCode = ErrorCode(9);
    /// JWS signature was required but missing. Not produced by the default
    /// claims pipeline; see [`Self::SIGNATURE_INVALID`].
    pub const SIGNATURE_MISSING: ErrorCode = ErrorCode(10);
    /// `iss` claim was required but missing.
    pub const ISSUER_MISSING: ErrorCode = ErrorCode(11);
    /// `iss` claim did not match any expected issuer.
    pub const ISSUER_INVALID: ErrorCode = ErrorCode(12);
    /// `jti` claim was required but missing.
    pub const JWT_ID_MISSING: ErrorCode = ErrorCode(13);
    /// `sub` claim was required but missing.
    pub const SUBJECT_MISSING: ErrorCode = ErrorCode(14);
    /// `sub` claim did not match the expected subject.
    pub const SUBJECT_INVALID: ErrorCode = ErrorCode(15);
    /// JWT claims could not be parsed as JSON. Produced when
    /// [`crate::error::JoseError::InvalidJson`] is converted into an
    /// [`InvalidJwtError`] via the `From<JoseError>` impl.
    pub const JSON_INVALID: ErrorCode = ErrorCode(16);
    /// Catch-all for failures that don't fit a more specific code.
    pub const MISCELLANEOUS: ErrorCode = ErrorCode(17);
    /// A registered time claim (`exp`/`nbf`/`iat`) was present but not an
    /// integer `NumericDate` (float, string, bool, null, or out of range).
    pub const MALFORMED_CLAIM: ErrorCode = ErrorCode(18);
    /// JWE encryption was required but missing. Not produced by the default
    /// claims pipeline (JWE is handled by `JsonWebEncryption` before claims
    /// reach `JwtConsumer`).
    pub const ENCRYPTION_MISSING: ErrorCode = ErrorCode(19);
    /// Integrity protection was missing when required. Not produced by the
    /// default claims pipeline; see [`Self::SIGNATURE_INVALID`].
    pub const INTEGRITY_MISSING: ErrorCode = ErrorCode(20);
    /// A configured prohibited claim was present.
    pub const PROHIBITED_CLAIM: ErrorCode = ErrorCode(21);
    /// `exp` precedes `iat` (inconsistent claims).
    pub const EXPIRATION_BEFORE_ISSUED_AT: ErrorCode = ErrorCode(22);
    /// `exp` precedes `nbf` (inconsistent claims).
    pub const EXPIRATION_BEFORE_NOT_BEFORE: ErrorCode = ErrorCode(23);
    /// `iat` is too far in the future.
    pub const ISSUED_AT_INVALID_FUTURE: ErrorCode = ErrorCode(24);
    /// `iat` is too far in the past.
    pub const ISSUED_AT_INVALID_PAST: ErrorCode = ErrorCode(25);
    /// `typ` header was required but missing. Not produced by the default
    /// claims pipeline (the `typ` header is on the JWS protected header,
    /// which `process_to_claims` does not see).
    pub const TYPE_MISSING: ErrorCode = ErrorCode(26);
    /// `typ` header did not match the expected value. Not produced by the
    /// default claims pipeline; see [`Self::TYPE_MISSING`].
    pub const TYPE_INVALID: ErrorCode = ErrorCode(27);

    /// Create a consumer-defined error code.
    ///
    /// `code` must be negative. Positive values are reserved for
    /// library-defined codes and cause a panic -- passing one is almost
    /// certainly a collision with a built-in failure and is rejected
    /// at the API edge so it can't silently mask a built-in check.
    ///
    /// Convention: define one `const` per protocol-specific failure in
    /// your crate, with a stable negative integer, and pass it to
    /// [`InvalidJwtError::with_error_code`] from a custom validator:
    ///
    /// ```ignore
    /// use jose4rs::jwt::{ErrorCode, InvalidJwtError, JwtClaims};
    /// const NONCE_MISSING: ErrorCode = ErrorCode::custom(-1001);
    /// const NONCE_MISMATCH: ErrorCode = ErrorCode::custom(-1002);
    ///
    /// let expected = "abc".to_string();
    /// let _v = move |claims: &JwtClaims| match claims.string_claim("nonce") {
    ///     Some(n) if n == expected => Ok(()),
    ///     Some(_) => Err(InvalidJwtError::with_error_code(
    ///         "nonce does not match expected value", NONCE_MISMATCH,
    ///     )),
    ///     None => Err(InvalidJwtError::with_error_code(
    ///         "nonce claim is required but missing", NONCE_MISSING,
    ///     )),
    /// };
    /// ```
    ///
    /// # Panics
    ///
    /// Panics if `code` is non-negative. Use this only with a literal
    /// negative integer or a `const` you've already validated.
    #[track_caller]
    pub const fn custom(code: i32) -> Self {
        // const fn: simple `assert!` is allowed (no `format!`).
        assert!(
            code < 0,
            "ErrorCode::custom requires a negative i32 (positive values are reserved for library-defined codes)"
        );
        ErrorCode(code)
    }

    /// The raw integer value. Library codes are positive; custom codes
    /// are negative.
    pub const fn code(self) -> i32 {
        self.0
    }

    /// `true` if this is a consumer-defined code (negative integer).
    pub const fn is_custom(self) -> bool {
        self.0 < 0
    }

    /// Library-code name used by [`Debug`](fmt::Debug) and
    /// [`Display`](fmt::Display). Falls back to `"UNKNOWN"` for
    /// positive integers we don't recognize, which can happen if a
    /// caller hand-rolled an `ErrorCode(<positive>)` without going
    /// through one of the `pub const` items above.
    const fn name(self) -> &'static str {
        match self.0 {
            1 => "EXPIRED",
            2 => "EXPIRATION_MISSING",
            3 => "ISSUED_AT_MISSING",
            4 => "NOT_BEFORE_MISSING",
            5 => "EXPIRATION_TOO_FAR_IN_FUTURE",
            6 => "NOT_YET_VALID",
            7 => "AUDIENCE_MISSING",
            8 => "AUDIENCE_INVALID",
            9 => "SIGNATURE_INVALID",
            10 => "SIGNATURE_MISSING",
            11 => "ISSUER_MISSING",
            12 => "ISSUER_INVALID",
            13 => "JWT_ID_MISSING",
            14 => "SUBJECT_MISSING",
            15 => "SUBJECT_INVALID",
            16 => "JSON_INVALID",
            17 => "MISCELLANEOUS",
            18 => "MALFORMED_CLAIM",
            19 => "ENCRYPTION_MISSING",
            20 => "INTEGRITY_MISSING",
            21 => "PROHIBITED_CLAIM",
            22 => "EXPIRATION_BEFORE_ISSUED_AT",
            23 => "EXPIRATION_BEFORE_NOT_BEFORE",
            24 => "ISSUED_AT_INVALID_FUTURE",
            25 => "ISSUED_AT_INVALID_PAST",
            26 => "TYPE_MISSING",
            27 => "TYPE_INVALID",
            _ => "UNKNOWN",
        }
    }
}

impl fmt::Debug for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0 < 0 {
            write!(f, "ErrorCode::custom({})", self.0)
        } else {
            f.write_str(self.name())
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0 < 0 {
            write!(f, "CUSTOM({})", self.0)
        } else {
            f.write_str(self.name())
        }
    }
}

/// Error type for invalid JWT validation.
///
/// Carries a human-readable message plus a set of [`ErrorCode`]s
/// (library-defined *and* consumer-defined) that describe why the JWT
/// failed. Multiple codes are accumulated when several checks fail in the
/// same pass.
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
    pub fn with_error_codes(
        message: impl Into<String>,
        error_codes: impl IntoIterator<Item = ErrorCode>,
    ) -> Self {
        Self {
            message: message.into(),
            error_codes: error_codes.into_iter().collect(),
        }
    }

    /// Check if this error contains a specific error code.
    pub fn has_error_code(&self, error_code: ErrorCode) -> bool {
        self.error_codes.contains(&error_code)
    }

    /// Check if the JWT has expired.
    pub fn has_expired(&self) -> bool {
        self.has_error_code(ErrorCode::EXPIRED)
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
        // JSON parse failures are the most common JoseError surfaced
        // through this impl (everything else is either programmer-error
        // preconditions or JWS/JWE failures that callers handle at the
        // JOSE layer before reaching the claims consumer). Surface those
        // as `JSON_INVALID` so the code is recoverable from the error.
        if let JoseError::InvalidJson(_) = &err {
            return InvalidJwtError::with_error_code(
                format!("JWT processing failed: {err}"),
                ErrorCode::JSON_INVALID,
            );
        }
        InvalidJwtError::new(format!("JWT processing failed: {err}"))
    }
}

/// Packed boolean switches for JWT validation.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
struct ValidationFlags(u16);

// `1 << 0` keeps the bit positions uniform across the constants.
#[allow(clippy::identity_op)]
impl ValidationFlags {
    const REQUIRE_ISSUER: Self = Self(1 << 0);
    const REQUIRE_AUDIENCE: Self = Self(1 << 1);
    const STRICT_AUDIENCE: Self = Self(1 << 2);
    const SKIP_DEFAULT_AUDIENCE_VALIDATION: Self = Self(1 << 3);
    const REQUIRE_SUBJECT: Self = Self(1 << 4);
    const REQUIRE_JWT_ID: Self = Self(1 << 5);
    const REQUIRE_EXPIRATION: Self = Self(1 << 6);
    const REQUIRE_NOT_BEFORE: Self = Self(1 << 7);
    const REQUIRE_ISSUED_AT: Self = Self(1 << 8);
    const SKIP_ALL_VALIDATORS: Self = Self(1 << 9);
    const SKIP_ALL_DEFAULT_VALIDATORS: Self = Self(1 << 10);

    /// `true` if `flag` is set.
    #[inline]
    const fn contains(self, flag: Self) -> bool {
        self.0 & flag.0 != 0
    }

    /// Set or clear `flag` according to `on`.
    #[inline]
    fn set(&mut self, flag: Self, on: bool) {
        if on {
            self.0 |= flag.0;
        } else {
            self.0 &= !flag.0;
        }
    }
}

impl fmt::Debug for ValidationFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use ValidationFlags as VF;
        const NAMES: [(ValidationFlags, &str); 11] = [
            (VF::REQUIRE_ISSUER, "REQUIRE_ISSUER"),
            (VF::REQUIRE_AUDIENCE, "REQUIRE_AUDIENCE"),
            (VF::STRICT_AUDIENCE, "STRICT_AUDIENCE"),
            (
                VF::SKIP_DEFAULT_AUDIENCE_VALIDATION,
                "SKIP_DEFAULT_AUDIENCE_VALIDATION",
            ),
            (VF::REQUIRE_SUBJECT, "REQUIRE_SUBJECT"),
            (VF::REQUIRE_JWT_ID, "REQUIRE_JWT_ID"),
            (VF::REQUIRE_EXPIRATION, "REQUIRE_EXPIRATION"),
            (VF::REQUIRE_NOT_BEFORE, "REQUIRE_NOT_BEFORE"),
            (VF::REQUIRE_ISSUED_AT, "REQUIRE_ISSUED_AT"),
            (VF::SKIP_ALL_VALIDATORS, "SKIP_ALL_VALIDATORS"),
            (
                VF::SKIP_ALL_DEFAULT_VALIDATORS,
                "SKIP_ALL_DEFAULT_VALIDATORS",
            ),
        ];
        f.write_str("ValidationFlags(")?;
        let mut wrote_any = false;
        for (flag, name) in NAMES {
            if self.contains(flag) {
                if wrote_any {
                    f.write_str(" | ")?;
                }
                f.write_str(name)?;
                wrote_any = true;
            }
        }
        if !wrote_any {
            f.write_str("(empty)")?;
        }
        f.write_str(")")
    }
}

/// Builder for creating a JWT Consumer with specific validation requirements.
#[derive(Default)]
pub struct JwtConsumerBuilder<'a> {
    expected_issuers: Option<Vec<&'a str>>,
    expected_audiences: Option<Vec<&'a str>>,
    expected_subject: Option<&'a str>,
    prohibited_claims: Vec<&'a str>,
    evaluation_time: Option<SystemTime>,
    allowed_clock_skew: Duration,
    max_future_validity: Option<Duration>,
    iat_allowed_secs_in_future: Option<i64>,
    iat_allowed_secs_in_past: Option<i64>,
    flags: ValidationFlags,
    custom_validators: Vec<Box<dyn JwtValidator + 'a>>,
}

impl fmt::Debug for JwtConsumerBuilder<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JwtConsumerBuilder")
            .field("expected_issuers", &self.expected_issuers)
            .field("expected_audiences", &self.expected_audiences)
            .field("expected_subject", &self.expected_subject)
            .field("prohibited_claims", &self.prohibited_claims)
            .field("evaluation_time", &self.evaluation_time)
            .field("allowed_clock_skew", &self.allowed_clock_skew)
            .field("max_future_validity", &self.max_future_validity)
            .field(
                "iat_allowed_secs_in_future",
                &self.iat_allowed_secs_in_future,
            )
            .field("iat_allowed_secs_in_past", &self.iat_allowed_secs_in_past)
            .field("flags", &self.flags)
            .field("custom_validators", &self.custom_validators.len())
            .finish()
    }
}

/// Validation hook for custom claim checks.
///
/// Runs as part of [`JwtConsumer::process_to_claims`] alongside the
/// built-in validators. Errors are accumulated into the resulting
/// [`InvalidJwtError`] (via [`InvalidJwtError::with_error_code`] or
/// [`InvalidJwtError::with_error_codes`]), matching how every other
/// validator behaves.
///
/// Custom validators run *after* the built-in defaults (issuer,
/// audience, subject, jti, prohibited claims, time claims). They are
/// skipped under [`JwtConsumerBuilder::set_skip_all_validators`] but
/// still run under
/// [`JwtConsumerBuilder::set_skip_all_default_validators`].
pub trait JwtValidator: Send + Sync {
    /// Validate the parsed JWT `claims`. Return `Ok(())` if the JWT
    /// passes this validator's checks, or an `Err(InvalidJwtError)`
    /// carrying one or more [`ErrorCode`]s.
    ///
    /// # Errors
    ///
    /// Return an [`InvalidJwtError`] to signal a validation failure.
    /// The error's [`ErrorCode`]s are accumulated with those from the
    /// built-in validators and any other custom validators into the
    /// single `InvalidJwtError` produced by
    /// [`JwtConsumer::process_to_claims`].
    fn validate(&self, claims: &JwtClaims) -> Result<(), InvalidJwtError>;
}

// Blanket impl: closures and `fn` pointers work directly. Saves callers
// from wrapping every closure in a struct just to satisfy the trait.
impl<F> JwtValidator for F
where
    F: Fn(&JwtClaims) -> Result<(), InvalidJwtError> + Send + Sync,
{
    fn validate(&self, claims: &JwtClaims) -> Result<(), InvalidJwtError> {
        self(claims)
    }
}

impl fmt::Debug for dyn JwtValidator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<JwtValidator>")
    }
}

impl<'a> JwtConsumerBuilder<'a> {
    /// Create a new JWT Consumer Builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the expected issuer(s) for the JWT
    ///
    /// # Arguments
    /// * `require_issuer` - Whether the issuer claim is required
    /// * `issuers` - Expected issuer value(s)
    pub fn set_expected_issuers(mut self, require_issuer: bool, issuers: &[&'a str]) -> Self {
        self.expected_issuers = Some(issuers.to_vec());
        self.flags
            .set(ValidationFlags::REQUIRE_ISSUER, require_issuer);
        self
    }

    /// Set the expected issuer for the JWT (convenience method)
    pub fn set_expected_issuer(mut self, issuer: &'a str) -> Self {
        self.expected_issuers = Some(vec![issuer]);
        self.flags.set(ValidationFlags::REQUIRE_ISSUER, true);
        self
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
        audiences: &[&'a str],
    ) -> Self {
        self.expected_audiences = Some(audiences.to_vec());
        self.flags
            .set(ValidationFlags::REQUIRE_AUDIENCE, require_audience);
        self.flags.set(ValidationFlags::STRICT_AUDIENCE, strict);
        self
    }

    /// Skip default audience validation
    pub fn set_skip_default_audience_validation(mut self) -> Self {
        self.flags
            .set(ValidationFlags::SKIP_DEFAULT_AUDIENCE_VALIDATION, true);
        self
    }

    /// Set the expected subject for the JWT
    pub fn set_expected_subject(mut self, subject: &'a str) -> Self {
        self.expected_subject = Some(subject);
        self.flags.set(ValidationFlags::REQUIRE_SUBJECT, true);
        self
    }

    /// Require that a subject claim be present
    pub fn set_require_subject(mut self) -> Self {
        self.flags.set(ValidationFlags::REQUIRE_SUBJECT, true);
        self
    }

    /// Require that a JWT ID claim be present
    pub fn set_require_jwt_id(mut self) -> Self {
        self.flags.set(ValidationFlags::REQUIRE_JWT_ID, true);
        self
    }

    /// Require that an expiration time claim be present
    pub fn set_require_expiration_time(mut self) -> Self {
        self.flags.set(ValidationFlags::REQUIRE_EXPIRATION, true);
        self
    }

    /// Require that a not before time claim be present
    pub fn set_require_not_before(mut self) -> Self {
        self.flags.set(ValidationFlags::REQUIRE_NOT_BEFORE, true);
        self
    }

    /// Require that an issued at time claim be present
    pub fn set_require_issued_at(mut self) -> Self {
        self.flags.set(ValidationFlags::REQUIRE_ISSUED_AT, true);
        self
    }

    /// Set claims that must NOT be present in the JWT.
    ///
    /// Useful to prevent cross-JWT confusion in situations where explicit
    /// typing via the `typ` header is not used -- e.g. rejecting an access
    /// token that carries a claim only ID tokens should have.
    pub fn set_prohibited_claims(mut self, claims: &[&'a str]) -> Self {
        self.prohibited_claims = claims.to_vec();
        self
    }

    /// Set the time to use when validating time-based claims.
    ///
    /// A negative value denotes a pre-epoch time (before 1970-01-01).
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
        self.flags.set(ValidationFlags::SKIP_ALL_VALIDATORS, true);
        self
    }

    /// Skip all default claim validators (but not custom ones)
    pub fn set_skip_all_default_validators(mut self) -> Self {
        self.flags
            .set(ValidationFlags::SKIP_ALL_DEFAULT_VALIDATORS, true);
        self
    }

    /// Register a custom validator that runs as part of
    /// [`JwtConsumer::process_to_claims`].
    ///
    /// Custom validators run after every built-in default (issuer,
    /// audience, subject, jti, prohibited claims, time claims). They do
    /// **not** run when [`set_skip_all_validators`](Self::set_skip_all_validators)
    /// is set; they **do** run when
    /// [`set_skip_all_default_validators`](Self::set_skip_all_default_validators)
    /// is set.
    ///
    /// Errors are accumulated: a validator failure does not stop later
    /// validators, but its [`ErrorCode`]s are merged into the final
    /// [`InvalidJwtError`].
    ///
    /// Use [`ErrorCode::custom`] to mint consumer-defined codes so the
    /// library doesn't need to grow a variant per protocol:
    ///
    /// ```
    /// # use jose4rs::jwt::{
    /// #     ErrorCode, InvalidJwtError, JwtClaims, JwtConsumerBuilder,
    /// #     JwtValidator,
    /// # };
    /// const NONCE_MISMATCH: ErrorCode = ErrorCode::custom(-1001);
    ///
    /// let expected = "abc123".to_string();
    /// let consumer = JwtConsumerBuilder::new()
    ///     .register_validator(move |claims: &JwtClaims| {
    ///         match claims.string_claim("nonce") {
    ///             Some(n) if n == expected => Ok(()),
    ///             Some(_) => Err(InvalidJwtError::with_error_code(
    ///                 "nonce does not match expected value",
    ///                 NONCE_MISMATCH,
    ///             )),
    ///             None => Err(InvalidJwtError::with_error_code(
    ///                 "nonce claim is required but missing",
    ///                 NONCE_MISMATCH,
    ///             )),
    ///         }
    ///     })
    ///     .build();
    /// let _ = consumer;
    /// ```
    ///
    /// [`ErrorCode`]: crate::jwt::ErrorCode
    /// [`InvalidJwtError`]: crate::jwt::InvalidJwtError
    pub fn register_validator<V>(mut self, validator: V) -> Self
    where
        V: JwtValidator + 'a,
    {
        self.custom_validators.push(Box::new(validator));
        self
    }

    /// Build the JWT Consumer
    pub fn build(self) -> JwtConsumer<'a> {
        JwtConsumer {
            expected_issuers: self.expected_issuers,
            expected_audiences: self.expected_audiences,
            expected_subject: self.expected_subject,
            prohibited_claims: self.prohibited_claims,
            evaluation_time: self.evaluation_time,
            allowed_clock_skew: self.allowed_clock_skew,
            max_future_validity: self.max_future_validity,
            iat_allowed_secs_in_future: self.iat_allowed_secs_in_future,
            iat_allowed_secs_in_past: self.iat_allowed_secs_in_past,
            flags: self.flags,
            custom_validators: self.custom_validators,
        }
    }
}

/// JWT Consumer for validating JWT claims.
pub struct JwtConsumer<'a> {
    expected_issuers: Option<Vec<&'a str>>,
    expected_audiences: Option<Vec<&'a str>>,
    expected_subject: Option<&'a str>,
    prohibited_claims: Vec<&'a str>,
    evaluation_time: Option<SystemTime>,
    allowed_clock_skew: Duration,
    max_future_validity: Option<Duration>,
    iat_allowed_secs_in_future: Option<i64>,
    iat_allowed_secs_in_past: Option<i64>,
    flags: ValidationFlags,
    custom_validators: Vec<Box<dyn JwtValidator + 'a>>,
}

impl fmt::Debug for JwtConsumer<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JwtConsumer")
            .field("expected_issuers", &self.expected_issuers)
            .field("expected_audiences", &self.expected_audiences)
            .field("expected_subject", &self.expected_subject)
            .field("prohibited_claims", &self.prohibited_claims)
            .field("evaluation_time", &self.evaluation_time)
            .field("allowed_clock_skew", &self.allowed_clock_skew)
            .field("max_future_validity", &self.max_future_validity)
            .field(
                "iat_allowed_secs_in_future",
                &self.iat_allowed_secs_in_future,
            )
            .field("iat_allowed_secs_in_past", &self.iat_allowed_secs_in_past)
            .field("flags", &self.flags)
            .field("custom_validators", &self.custom_validators.len())
            .finish()
    }
}

impl JwtConsumer<'_> {
    /// Process JWT claims and validate them
    ///
    /// # Errors
    ///
    /// Returns an error if the claims cannot be parsed or fail validation.
    pub fn process_to_claims(&self, claims: &str) -> Result<JwtClaims, InvalidJwtError> {
        let claims = JwtClaims::parse(claims)?;
        self.validate(&claims)?;
        Ok(claims)
    }

    /// Validate already-parsed claims without copying or reparsing them.
    ///
    /// Runs the same default and custom validators as
    /// [`process_to_claims`](Self::process_to_claims), including the configured
    /// skip flags. Useful when applying multiple validation policies to the
    /// same claims or inspecting claims before selecting a policy.
    ///
    /// This validates claims only; it does not verify a JWS signature or
    /// decrypt a JWE. Authenticate the corresponding token before trusting
    /// these claims. Mutating claims after validation requires revalidation.
    ///
    /// # Errors
    ///
    /// Returns an error if the claims fail validation.
    pub fn validate(&self, claims: &JwtClaims) -> Result<(), InvalidJwtError> {
        if self.flags.contains(ValidationFlags::SKIP_ALL_VALIDATORS) {
            return Ok(());
        }

        let mut errors: Vec<ErrorCode> = Vec::new();

        if !self
            .flags
            .contains(ValidationFlags::SKIP_ALL_DEFAULT_VALIDATORS)
        {
            // Validate issuer
            errors.extend(self.validate_issuer(claims));

            // Validate audience
            if !self
                .flags
                .contains(ValidationFlags::SKIP_DEFAULT_AUDIENCE_VALIDATION)
            {
                errors.extend(self.validate_audience(claims));
            }

            // Validate subject
            errors.extend(self.validate_subject(claims));

            // Validate JWT ID
            errors.extend(self.validate_jwt_id(claims));

            // Validate prohibited claims
            errors.extend(self.validate_prohibited_claims(claims));

            // Validate time claims
            self.validate_time_claims(claims, &mut errors);
        }

        // Custom validators run regardless of `skip_all_default_validators`;
        // only `skip_all_validators` (handled above) short-circuits past
        // them.
        for validator in &self.custom_validators {
            if let Err(e) = validator.validate(claims) {
                errors.extend(e.error_codes);
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(InvalidJwtError::with_error_codes(
                "JWT validation failed",
                errors,
            ))
        }
    }

    // Built-ins only contribute codes to the final error; do not allocate
    // temporary messages/vectors that the caller would immediately discard.
    fn validate_issuer(&self, claims: &JwtClaims) -> Option<ErrorCode> {
        let require_issuer = self.flags.contains(ValidationFlags::REQUIRE_ISSUER);
        let expected_issuers = self.expected_issuers.as_deref().unwrap_or_default();
        if !require_issuer && expected_issuers.is_empty() {
            return None;
        }
        let issuer = claims.issuer();

        // A present-but-non-string iss is malformed, not missing; reject it
        // (before the missing check, which would otherwise mask it) when the
        // caller has configured expected issuers.
        if issuer.is_none() && !expected_issuers.is_empty() && claims.has_claim("iss") {
            return Some(ErrorCode::ISSUER_INVALID);
        }

        if require_issuer && issuer.is_none() {
            return Some(ErrorCode::ISSUER_MISSING);
        }

        if let Some(issuer) = issuer
            && !expected_issuers.is_empty()
            && !expected_issuers.contains(&issuer)
        {
            return Some(ErrorCode::ISSUER_INVALID);
        }

        None
    }

    fn validate_audience(&self, claims: &JwtClaims) -> Option<ErrorCode> {
        // Read the aud claim exactly once: presence, well-formedness, strict
        // string form, and the string values all come from a single lookup.
        let aud = claims.audience_info(self.expected_audiences.as_deref().unwrap_or_default());

        // A present-but-malformed aud (non-string member, or not a string/array)
        // is rejected outright rather than silently filtered (RFC 7519
        // requires the claim shape to be honoured).
        if aud.malformed {
            return Some(ErrorCode::AUDIENCE_INVALID);
        }

        let has_aud = aud.present;

        if self.flags.contains(ValidationFlags::REQUIRE_AUDIENCE) && !has_aud {
            return Some(ErrorCode::AUDIENCE_MISSING);
        }

        if let Some(expected_audiences) = &self.expected_audiences {
            if has_aud {
                // Strict mode (RFC 7523 client assertions) requires the raw aud
                // to be a single string, not an array.
                if self.flags.contains(ValidationFlags::STRICT_AUDIENCE) && !aud.is_string {
                    return Some(ErrorCode::AUDIENCE_INVALID);
                }

                if !expected_audiences.is_empty() && !aud.matches_expected {
                    return Some(ErrorCode::AUDIENCE_INVALID);
                }
            }
        } else if has_aud {
            return Some(ErrorCode::AUDIENCE_MISSING);
        }

        None
    }

    fn validate_subject(&self, claims: &JwtClaims) -> Option<ErrorCode> {
        if !self.flags.contains(ValidationFlags::REQUIRE_SUBJECT) && self.expected_subject.is_none()
        {
            return None;
        }
        let subject = claims.subject();

        if self.flags.contains(ValidationFlags::REQUIRE_SUBJECT) && subject.is_none() {
            return Some(ErrorCode::SUBJECT_MISSING);
        }

        if let Some(expected_subject) = &self.expected_subject {
            if let Some(subject) = subject {
                if subject != *expected_subject {
                    return Some(ErrorCode::SUBJECT_INVALID);
                }
            } else {
                return Some(ErrorCode::SUBJECT_MISSING);
            }
        }

        None
    }

    fn validate_jwt_id(&self, claims: &JwtClaims) -> Option<ErrorCode> {
        if self.flags.contains(ValidationFlags::REQUIRE_JWT_ID) && claims.jwt_id().is_none() {
            return Some(ErrorCode::JWT_ID_MISSING);
        }
        None
    }

    fn validate_prohibited_claims(&self, claims: &JwtClaims) -> Option<ErrorCode> {
        self.prohibited_claims
            .iter()
            .any(|name| claims.has_claim(name))
            .then_some(ErrorCode::PROHIBITED_CLAIM)
    }

    fn validate_time_claims(&self, claims: &JwtClaims, errors: &mut Vec<ErrorCode>) {
        // Read each time claim exactly once: a single map lookup per claim both
        // classifies it (absent / malformed / integer) and yields the value.
        let exp = claims.time_claim("exp");
        let nbf = claims.time_claim("nbf");
        let iat = claims.time_claim("iat");

        // No comparisons require the wall clock when all time claims are
        // absent. Still enforce required claims, in the usual error order.
        if [exp, nbf, iat] == [TimeClaim::Absent; 3] {
            for (flag, code) in [
                (
                    ValidationFlags::REQUIRE_EXPIRATION,
                    ErrorCode::EXPIRATION_MISSING,
                ),
                (
                    ValidationFlags::REQUIRE_NOT_BEFORE,
                    ErrorCode::NOT_BEFORE_MISSING,
                ),
                (
                    ValidationFlags::REQUIRE_ISSUED_AT,
                    ErrorCode::ISSUED_AT_MISSING,
                ),
            ] {
                if self.flags.contains(flag) {
                    errors.push(code);
                }
            }
            return;
        }

        let eval_time = self.evaluation_time.unwrap_or_else(SystemTime::now);
        // Signed seconds since the epoch; negative for pre-epoch times so the
        // claim comparisons (all in i64) work for any evaluation time.
        let eval_secs = match eval_time.duration_since(UNIX_EPOCH) {
            Ok(d) => d.as_secs() as i64,
            Err(e) => -(e.duration().as_secs() as i64),
        };
        let clock_skew_secs = self.allowed_clock_skew.as_secs() as i64;

        // A present-but-non-integer NumericDate (float, string, out-of-range)
        // is malformed, not absent (RFC 7519 Section 2).
        for claim in [exp, nbf, iat] {
            if claim == TimeClaim::Malformed {
                errors.push(ErrorCode::MALFORMED_CLAIM);
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
                errors.push(ErrorCode::EXPIRED);
            }

            // exp cannot precede iat (inconsistent claims)
            if let TimeClaim::Value(iat_secs) = iat
                && exp_secs < iat_secs
            {
                errors.push(ErrorCode::EXPIRATION_BEFORE_ISSUED_AT);
            }

            // exp cannot precede nbf (inconsistent claims)
            if let TimeClaim::Value(nbf_secs) = nbf
                && exp_secs < nbf_secs
            {
                errors.push(ErrorCode::EXPIRATION_BEFORE_NOT_BEFORE);
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
                    errors.push(ErrorCode::EXPIRATION_TOO_FAR_IN_FUTURE);
                }
            }
        } else if self.flags.contains(ValidationFlags::REQUIRE_EXPIRATION)
            && exp == TimeClaim::Absent
        {
            errors.push(ErrorCode::EXPIRATION_MISSING);
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
                errors.push(ErrorCode::NOT_YET_VALID);
            }
        } else if self.flags.contains(ValidationFlags::REQUIRE_NOT_BEFORE)
            && nbf == TimeClaim::Absent
        {
            errors.push(ErrorCode::NOT_BEFORE_MISSING);
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
                    errors.push(ErrorCode::ISSUED_AT_INVALID_FUTURE);
                }
            }

            // Check if issued at is too far in the past
            if let Some(allowed_past) = self.iat_allowed_secs_in_past {
                let too_old = match eval_secs.checked_sub(allowed_past) {
                    Some(earliest) => iat_secs < earliest,
                    None => false,
                };
                if too_old {
                    errors.push(ErrorCode::ISSUED_AT_INVALID_PAST);
                }
            }
        } else if self.flags.contains(ValidationFlags::REQUIRE_ISSUED_AT)
            && iat == TimeClaim::Absent
        {
            errors.push(ErrorCode::ISSUED_AT_MISSING);
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
        assert!(err.has_error_code(ErrorCode::ISSUER_MISSING));
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
        assert!(err.has_error_code(ErrorCode::ISSUER_INVALID));
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
        assert!(err.has_error_code(ErrorCode::AUDIENCE_MISSING));
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
        assert!(err.has_error_code(ErrorCode::AUDIENCE_INVALID));
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
        assert!(err.has_error_code(ErrorCode::EXPIRED));
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
        assert!(err.has_error_code(ErrorCode::NOT_YET_VALID));
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
        assert!(err.has_error_code(ErrorCode::AUDIENCE_INVALID));
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
        assert!(err.has_error_code(ErrorCode::EXPIRATION_TOO_FAR_IN_FUTURE));
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
        assert!(err.has_error_code(ErrorCode::ISSUED_AT_INVALID_PAST));
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
        assert!(err.has_error_code(ErrorCode::PROHIBITED_CLAIM));

        // Not present -> passes
        let consumer = JwtConsumerBuilder::new()
            .set_prohibited_claims(&["nonce", "at_hash"])
            .build();
        assert!(consumer.process_to_claims(&claims).is_ok());
    }
}
