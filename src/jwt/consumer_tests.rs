// Comprehensive tests for JwtConsumer and ErrorCode behaviour.

#[cfg(test)]
mod jwt_consumer_tests {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use crate::jwt::consumer::ErrorCode;
    use crate::jwt::{InvalidJwtError, JwtClaims, JwtConsumerBuilder};

    /// Test basic audience validation with single value
    #[test]
    fn some_basic_aud_checks() {
        // Test with single audience string
        let claims = r#"{"aud":"example.com"}"#;

        let consumer = JwtConsumerBuilder::new().build();
        // Should fail without expected audience set
        assert!(consumer.process_to_claims(claims).is_err());

        let consumer = JwtConsumerBuilder::new()
            .set_expected_audience(true, false, &["example.com"])
            .build();
        assert!(consumer.process_to_claims(claims).is_ok());

        let consumer = JwtConsumerBuilder::new()
            .set_expected_audience(true, false, &["example.org", "example.com", "k8HiI26Y7"])
            .build();
        assert!(consumer.process_to_claims(claims).is_ok());

        let consumer = JwtConsumerBuilder::new()
            .set_expected_audience(true, false, &["example.org"])
            .build();
        assert!(consumer.process_to_claims(claims).is_err());

        // Test with no audience in claims
        let claims = r#"{"sub":"subject"}"#;
        let consumer = JwtConsumerBuilder::new()
            .set_expected_audience(false, false, &["example.org", "www.example.org"])
            .build();
        assert!(consumer.process_to_claims(claims).is_ok());

        let consumer = JwtConsumerBuilder::new()
            .set_expected_audience(true, false, &["example.org", "www.example.org"])
            .build();
        assert!(consumer.process_to_claims(claims).is_err());

        // Test with array of audiences
        let claims = r#"{"aud":["example.com","usa.org","ca.ca"]}"#;
        let consumer = JwtConsumerBuilder::new()
            .set_expected_audience(true, false, &["example.org"])
            .build();
        assert!(consumer.process_to_claims(claims).is_err());

        let consumer = JwtConsumerBuilder::new()
            .set_expected_audience(true, false, &["usa.org"])
            .build();
        assert!(consumer.process_to_claims(claims).is_ok());

        let consumer = JwtConsumerBuilder::new()
            .set_expected_audience(true, false, &["ca.ca"])
            .build();
        assert!(consumer.process_to_claims(claims).is_ok());

        let consumer = JwtConsumerBuilder::new()
            .set_expected_audience(true, false, &["usa.org", "ca.ca"])
            .build();
        assert!(consumer.process_to_claims(claims).is_ok());
    }

    /// Test basic issuer validation
    #[test]
    fn some_basic_iss_checks() {
        let claims = r#"{"iss":"issuer.example.com"}"#;

        let consumer = JwtConsumerBuilder::new().build();
        assert!(consumer.process_to_claims(claims).is_ok());

        let consumer = JwtConsumerBuilder::new()
            .set_expected_issuer("issuer.example.com")
            .build();
        assert!(consumer.process_to_claims(claims).is_ok());

        let consumer = JwtConsumerBuilder::new()
            .set_expected_issuer("nope.example.com")
            .build();
        assert!(consumer.process_to_claims(claims).is_err());

        // Test with no issuer
        let claims = r#"{"sub":"subject"}"#;
        let consumer = JwtConsumerBuilder::new()
            .set_expected_issuer("issuer.example.com")
            .build();
        assert!(consumer.process_to_claims(claims).is_err());

        let consumer = JwtConsumerBuilder::new()
            .set_expected_issuers(false, &["issuer.example.com"])
            .build();
        assert!(consumer.process_to_claims(claims).is_ok());

        // Test with multiple expected issuers (like Google ID tokens)
        let claims = r#"{"iss":"accounts.google.com"}"#;
        let consumer = JwtConsumerBuilder::new()
            .set_expected_issuers(
                true,
                &["https://accounts.google.com", "accounts.google.com"],
            )
            .build();
        assert!(consumer.process_to_claims(claims).is_ok());

        let claims = r#"{"iss":"https://accounts.google.com"}"#;
        assert!(consumer.process_to_claims(claims).is_ok());

        let consumer = JwtConsumerBuilder::new()
            .set_expected_issuers(true, &["https://fake.google.com", "nope.google.com"])
            .build();
        assert!(consumer.process_to_claims(claims).is_err());
    }

    /// Test basic subject validation
    #[test]
    fn some_basic_sub_checks() {
        let claims = r#"{"sub":"brian.d.campbell"}"#;

        let consumer = JwtConsumerBuilder::new().build();
        assert!(consumer.process_to_claims(claims).is_ok());

        let consumer = JwtConsumerBuilder::new().set_require_subject().build();
        assert!(consumer.process_to_claims(claims).is_ok());

        // Missing subject
        let claims = r#"{"name":"brian.d.campbell"}"#;
        let consumer = JwtConsumerBuilder::new().set_require_subject().build();
        assert!(consumer.process_to_claims(claims).is_err());

        let consumer = JwtConsumerBuilder::new().build();
        assert!(consumer.process_to_claims(claims).is_ok());
    }

    /// Test basic JWT ID validation
    #[test]
    fn some_basic_jti_checks() {
        let claims = r#"{"jti":"1Y5iLSQfNgcSGt0A4is29"}"#;

        let consumer = JwtConsumerBuilder::new().build();
        assert!(consumer.process_to_claims(claims).is_ok());

        let consumer = JwtConsumerBuilder::new().set_require_jwt_id().build();
        assert!(consumer.process_to_claims(claims).is_ok());

        // Missing JTI
        let claims = r#"{"notjti":"lbZ_mLS6w3xBSlvW6ULmkV-uLCk"}"#;
        let consumer = JwtConsumerBuilder::new().set_require_jwt_id().build();
        assert!(consumer.process_to_claims(claims).is_err());

        let consumer = JwtConsumerBuilder::new().build();
        assert!(consumer.process_to_claims(claims).is_ok());
    }

    /// Test time-based validation
    #[test]
    fn some_basic_time_checks() {
        // Basic claims with no time claims
        let claims = r#"{"sub":"brian.d.campbell"}"#;
        let consumer = JwtConsumerBuilder::new().build();
        assert!(consumer.process_to_claims(claims).is_ok());

        let consumer = JwtConsumerBuilder::new()
            .set_require_expiration_time()
            .build();
        assert!(consumer.process_to_claims(claims).is_err());

        let consumer = JwtConsumerBuilder::new().set_require_issued_at().build();
        assert!(consumer.process_to_claims(claims).is_err());

        let consumer = JwtConsumerBuilder::new().set_require_not_before().build();
        assert!(consumer.process_to_claims(claims).is_err());

        // Test with expiration exactly at evaluation time
        let claims = r#"{"sub":"brian.d.campbell","exp":1430602000}"#;
        let consumer = JwtConsumerBuilder::new()
            .set_require_expiration_time()
            .set_evaluation_time_from_seconds(1430602000)
            .build();
        assert!(consumer.process_to_claims(claims).is_err()); // Expired

        // With clock skew
        let consumer = JwtConsumerBuilder::new()
            .set_require_expiration_time()
            .set_evaluation_time_from_seconds(1430602000)
            .set_allowed_clock_skew(Duration::from_secs(10))
            .build();
        assert!(consumer.process_to_claims(claims).is_ok());

        // Before expiration
        let consumer = JwtConsumerBuilder::new()
            .set_evaluation_time_from_seconds(1430601000)
            .build();
        assert!(consumer.process_to_claims(claims).is_ok());

        // After expiration
        let consumer = JwtConsumerBuilder::new()
            .set_evaluation_time_from_seconds(1430602002)
            .build();
        assert!(consumer.process_to_claims(claims).is_err());

        // Test nbf (not before)
        let claims = r#"{"sub":"brian.d.campbell","nbf":1430602000}"#;
        let consumer = JwtConsumerBuilder::new()
            .set_evaluation_time_from_seconds(1430602000)
            .build();
        assert!(consumer.process_to_claims(claims).is_ok());

        let consumer = JwtConsumerBuilder::new()
            .set_evaluation_time_from_seconds(1430601999)
            .build();
        assert!(consumer.process_to_claims(claims).is_err()); // Not yet valid

        // With clock skew
        let consumer = JwtConsumerBuilder::new()
            .set_evaluation_time_from_seconds(1430601983)
            .set_allowed_clock_skew(Duration::from_secs(30))
            .build();
        assert!(consumer.process_to_claims(claims).is_ok());

        // Test combination of all time claims
        let claims =
            r#"{"sub":"brian.d.campbell","nbf":1430602000,"iat":1430602060,"exp":1430602600}"#;
        let consumer = JwtConsumerBuilder::new()
            .set_require_expiration_time()
            .set_require_not_before()
            .set_require_issued_at()
            .set_evaluation_time_from_seconds(1430602002)
            .build();
        assert!(consumer.process_to_claims(claims).is_ok());

        // Test expiration too far in future
        let claims = r#"{"sub":"brian.d.campbell","exp":1430607201}"#;
        let consumer = JwtConsumerBuilder::new()
            .set_require_expiration_time()
            .set_evaluation_time_from_seconds(1430600000)
            .build();
        assert!(consumer.process_to_claims(claims).is_ok());

        let consumer = JwtConsumerBuilder::new()
            .set_require_expiration_time()
            .set_evaluation_time_from_seconds(1430600000)
            .set_max_future_validity(Duration::from_mins(90))
            .build();
        assert!(consumer.process_to_claims(claims).is_err());

        let consumer = JwtConsumerBuilder::new()
            .set_require_expiration_time()
            .set_evaluation_time_from_seconds(1430600000)
            .set_max_future_validity(Duration::from_mins(120))
            .build();
        assert!(consumer.process_to_claims(claims).is_err());

        let consumer = JwtConsumerBuilder::new()
            .set_require_expiration_time()
            .set_evaluation_time_from_seconds(1430600000)
            .set_max_future_validity(Duration::from_mins(120))
            .set_allowed_clock_skew(Duration::from_secs(20))
            .build();
        assert!(consumer.process_to_claims(claims).is_ok());
    }

    /// Missing required time claims use specific error codes, and exp cannot
    /// precede iat/nbf (consistency checks on time claims).
    #[test]
    fn time_claim_missing_codes_and_consistency() {
        let claims = r#"{"sub":"x"}"#;

        let consumer = JwtConsumerBuilder::new()
            .set_require_expiration_time()
            .build();
        let err = consumer.process_to_claims(claims).unwrap_err();
        assert!(err.has_error_code(ErrorCode::EXPIRATION_MISSING));

        let consumer = JwtConsumerBuilder::new().set_require_not_before().build();
        let err = consumer.process_to_claims(claims).unwrap_err();
        assert!(err.has_error_code(ErrorCode::NOT_BEFORE_MISSING));

        let consumer = JwtConsumerBuilder::new().set_require_issued_at().build();
        let err = consumer.process_to_claims(claims).unwrap_err();
        assert!(err.has_error_code(ErrorCode::ISSUED_AT_MISSING));

        // exp before iat
        let consumer = JwtConsumerBuilder::new()
            .set_evaluation_time_from_seconds(1430601000)
            .build();
        let err = consumer
            .process_to_claims(r#"{"iat":1430602000,"exp":1430601500}"#)
            .unwrap_err();
        assert!(err.has_error_code(ErrorCode::EXPIRATION_BEFORE_ISSUED_AT));

        // exp before nbf
        let err = consumer
            .process_to_claims(r#"{"nbf":1430602000,"exp":1430601500}"#)
            .unwrap_err();
        assert!(err.has_error_code(ErrorCode::EXPIRATION_BEFORE_NOT_BEFORE));

        // consistent exp >= iat and nbf passes
        assert!(
            consumer
                .process_to_claims(r#"{"nbf":1430601000,"iat":1430601000,"exp":1430602000}"#)
                .is_ok()
        );
    }

    /// Test issued at (iat) reasonableness checks
    #[test]
    fn iat_reasonableness() {
        let consumer = JwtConsumerBuilder::new()
            .set_require_issued_at()
            .set_issued_at_restrictions(0, 60)
            .set_evaluation_time_from_seconds(1571322100)
            .build();

        // Valid iat at evaluation time
        let claims = r#"{"iat":1571322100}"#;
        assert!(consumer.process_to_claims(claims).is_ok());

        // Valid iat 1 second in past
        let claims = r#"{"iat":1571322099}"#;
        assert!(consumer.process_to_claims(claims).is_ok());

        // Valid iat within allowed past
        let claims = r#"{"iat":1571322043}"#;
        assert!(consumer.process_to_claims(claims).is_ok());

        let claims = r#"{"iat":1571322040}"#;
        assert!(consumer.process_to_claims(claims).is_ok());

        // Too far in past
        let claims = r#"{"iat":1571322039}"#;
        assert!(consumer.process_to_claims(claims).is_err());

        let claims = r#"{"iat":1570321001}"#;
        assert!(consumer.process_to_claims(claims).is_err());

        // Too far in future
        let claims = r#"{"iat":1571322101}"#;
        assert!(consumer.process_to_claims(claims).is_err());

        let claims = r#"{"iat":1571322177}"#;
        assert!(consumer.process_to_claims(claims).is_err());

        // Test with different restrictions
        let consumer = JwtConsumerBuilder::new()
            .set_require_issued_at()
            .set_issued_at_restrictions(10, 120)
            .set_evaluation_time_from_seconds(1571322100)
            .build();

        let claims = r#"{"iat":1571322100}"#;
        assert!(consumer.process_to_claims(claims).is_ok());

        // 120 seconds in past
        let claims = r#"{"iat":1571321980}"#;
        assert!(consumer.process_to_claims(claims).is_ok());

        // 121 seconds in past
        let claims = r#"{"iat":1571321979}"#;
        assert!(consumer.process_to_claims(claims).is_err());

        // 5 seconds in future
        let claims = r#"{"iat":1571322105}"#;
        assert!(consumer.process_to_claims(claims).is_ok());

        // 10 seconds in future
        let claims = r#"{"iat":1571322110}"#;
        assert!(consumer.process_to_claims(claims).is_ok());

        // 11 seconds in future
        let claims = r#"{"iat":1571322111}"#;
        assert!(consumer.process_to_claims(claims).is_err());
    }

    /// Test validation for various combined scenarios
    #[test]
    fn some_basic_checks() {
        let claims = r#"{"sub":"subject","iss":"issuer","aud":"audience"}"#;

        let consumer = JwtConsumerBuilder::new()
            .set_expected_audience(true, false, &["audience"])
            .set_expected_issuer("issuer")
            .build();
        assert!(consumer.process_to_claims(claims).is_ok());

        // Multiple failures
        let consumer = JwtConsumerBuilder::new()
            .set_expected_audience(true, false, &["nope"])
            .set_expected_issuer("no way")
            .set_require_subject()
            .set_require_jwt_id()
            .build();
        let result = consumer.process_to_claims(claims);
        assert!(result.is_err());
        // Should have multiple error codes
        let err = result.unwrap_err();
        assert!(!err.error_codes().is_empty());
    }

    /// Test that iat before nbf is acceptable
    #[test]
    fn iat_before_nbf_should_be_okay() {
        let mut claims = JwtClaims::new();
        claims.set_subject("me");
        // nbf is 1 minute in past
        claims.set_not_before(UNIX_EPOCH + Duration::from_secs(1571322040));
        // exp is 10 minutes in future from nbf
        claims.set_expiration_time(UNIX_EPOCH + Duration::from_secs(1571322640));
        // iat is 2 minutes before nbf
        claims.set_issued_at(UNIX_EPOCH + Duration::from_secs(1571321920));
        claims.set_audience(vec!["audience".to_string()]);
        claims.set_issuer("issuer");
        let claims = claims.to_json();

        let consumer = JwtConsumerBuilder::new()
            .set_expected_audience(true, false, &["audience"])
            .set_expected_issuer("issuer")
            .set_require_expiration_time()
            .set_require_not_before()
            .set_require_issued_at()
            .set_evaluation_time_from_seconds(1571322100)
            .build();

        assert!(consumer.process_to_claims(&claims).is_ok());
    }

    /// Test skip validators
    #[test]
    fn skip_validators() {
        let mut claims = JwtClaims::new();
        claims.set_issuer("wrong-issuer");
        claims.set_expiration_time(UNIX_EPOCH + Duration::from_secs(1000));
        let claims = claims.to_json();

        // Should fail with normal validation
        let consumer = JwtConsumerBuilder::new()
            .set_expected_issuer("test-issuer")
            .set_evaluation_time_from_seconds(2000)
            .build();
        assert!(consumer.process_to_claims(&claims).is_err());

        // Should pass with skip all validators
        let consumer = JwtConsumerBuilder::new()
            .set_expected_issuer("test-issuer")
            .set_evaluation_time_from_seconds(2000)
            .set_skip_all_validators()
            .build();
        assert!(consumer.process_to_claims(&claims).is_ok());

        // Should pass with skip all default validators
        let consumer = JwtConsumerBuilder::new()
            .set_expected_issuer("test-issuer")
            .set_evaluation_time_from_seconds(2000)
            .set_skip_all_default_validators()
            .build();
        assert!(consumer.process_to_claims(&claims).is_ok());
    }

    /// Test error codes are correctly set
    #[test]
    fn error_code_validation() {
        // Test expired error
        let mut claims = JwtClaims::new();
        claims.set_expiration_time(UNIX_EPOCH + Duration::from_secs(1000));
        claims.set_issuer("ISS");
        claims.set_audience(vec!["AUD".to_string()]);
        claims.set_subject("SUB");
        let claims = claims.to_json();

        let consumer = JwtConsumerBuilder::new()
            .set_expected_audience(true, false, &["AUD"])
            .set_expected_issuer("ISS")
            .set_require_expiration_time()
            .set_evaluation_time_from_seconds(2000)
            .build();

        let result = consumer.process_to_claims(&claims);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.has_expired());

        // Test audience invalid
        let mut claims = JwtClaims::new();
        claims.set_expiration_time(SystemTime::now() + Duration::from_secs(3600));
        claims.set_issuer("ISS");
        claims.set_audience(vec!["AUD".to_string()]);
        claims.set_subject("SUB");
        let claims = claims.to_json();

        let consumer = JwtConsumerBuilder::new()
            .set_expected_audience(true, false, &["nope"])
            .set_expected_issuer("ISS")
            .set_require_expiration_time()
            .build();

        let result = consumer.process_to_claims(&claims);
        assert!(result.is_err());
        let err = result.unwrap_err();
        use crate::jwt::consumer::ErrorCode;
        assert!(err.has_error_code(ErrorCode::AUDIENCE_INVALID));

        // Test issuer invalid
        let mut claims = JwtClaims::new();
        claims.set_expiration_time(SystemTime::now() + Duration::from_secs(3600));
        claims.set_issuer("wrong");
        claims.set_audience(vec!["AUD".to_string()]);
        claims.set_subject("SUB");
        let claims = claims.to_json();

        let consumer = JwtConsumerBuilder::new()
            .set_expected_audience(true, false, &["AUD"])
            .set_expected_issuer("ISS")
            .set_require_expiration_time()
            .build();

        let result = consumer.process_to_claims(&claims);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.has_error_code(ErrorCode::ISSUER_INVALID));

        // Test multiple errors
        let mut claims = JwtClaims::new();
        claims.set_expiration_time(SystemTime::now() + Duration::from_secs(3600));
        claims.set_issuer("wrong");
        claims.set_audience(vec!["wrong-aud".to_string()]);
        claims.set_subject("SUB");
        let claims = claims.to_json();

        let consumer = JwtConsumerBuilder::new()
            .set_expected_audience(true, false, &["AUD"])
            .set_expected_issuer("ISS")
            .set_max_future_validity(Duration::from_mins(5))
            .set_require_expiration_time()
            .build();

        let result = consumer.process_to_claims(&claims);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.has_error_code(ErrorCode::ISSUER_INVALID));
        assert!(err.has_error_code(ErrorCode::AUDIENCE_INVALID));
        assert!(err.has_error_code(ErrorCode::EXPIRATION_TOO_FAR_IN_FUTURE));
    }

    /// Negative `exp` must be treated as expired, not wrapped to a far-future time.
    #[test]
    fn negative_exp_is_expired() {
        let claims = r#"{"sub":"x","exp":-1}"#;
        let consumer = JwtConsumerBuilder::new()
            .set_evaluation_time_from_seconds(1430602000)
            .build();
        let err = consumer.process_to_claims(claims).unwrap_err();
        assert!(err.has_error_code(ErrorCode::EXPIRED));
    }

    /// A non-integer `exp`/`nbf`/`iat` (float, string, oversized)
    /// must be rejected as malformed, not silently treated as absent.
    #[test]
    fn non_integer_time_claims_are_malformed() {
        for claims in [
            r#"{"exp":1.9}"#,
            r#"{"exp":"9999999999"}"#,
            r#"{"exp":18446744073709551615}"#, // > i64::MAX
            r#"{"nbf":1.5}"#,
            r#"{"iat":"now"}"#,
        ] {
            let consumer = JwtConsumerBuilder::new()
                .set_evaluation_time_from_seconds(1430602000)
                .build();
            let err = consumer
                .process_to_claims(claims)
                .expect_err("expected rejection");
            assert!(
                err.has_error_code(ErrorCode::MALFORMED_CLAIM),
                "expected MalformedClaim for {claims}, got {:?}",
                err.error_codes()
            );
        }
    }

    /// Claims that fail to parse as JSON must surface `JSON_INVALID`
    /// (the `From<JoseError>` impl translates `JoseError::InvalidJson`
    /// into an `InvalidJwtError` carrying the recognisable code).
    #[test]
    fn invalid_json_surfaces_json_invalid_code() {
        let consumer = JwtConsumerBuilder::new().build();

        for malformed in [
            "not json at all",
            r#"{"unterminated":"string"#,
            r"[1, 2, 3]",      // not a JSON object
            r#"{"exp": NaN}"#, // bare identifier
        ] {
            let err = consumer
                .process_to_claims(malformed)
                .expect_err("expected JSON parse failure");
            assert!(
                err.has_error_code(ErrorCode::JSON_INVALID),
                "expected JSON_INVALID for {malformed:?}, got {:?}",
                err.error_codes()
            );
        }
    }

    /// Huge `exp` values must not overflow the checked arithmetic
    /// (exp + skew, eval + `max_validity` + skew).
    #[test]
    fn huge_exp_does_not_overflow() {
        let claims = r#"{"sub":"x","exp":9223372036854775807}"#; // i64::MAX
        let consumer = JwtConsumerBuilder::new()
            .set_evaluation_time_from_seconds(1430602000)
            .set_max_future_validity(Duration::from_secs(60))
            .set_allowed_clock_skew(Duration::from_secs(30))
            .build();
        let err = consumer.process_to_claims(claims).unwrap_err();
        assert!(err.has_error_code(ErrorCode::EXPIRATION_TOO_FAR_IN_FUTURE));
    }

    /// `aud` with non-string members or a wrong type is malformed,
    /// not silently filtered.
    #[test]
    fn malformed_audience_rejected() {
        for claims in [
            r#"{"aud":[123,"expected"]}"#,
            r#"{"aud":123}"#,
            r#"{"aud":{"x":1}}"#,
            r#"{"aud":[true]}"#,
        ] {
            let consumer = JwtConsumerBuilder::new()
                .set_expected_audience(true, false, &["expected"])
                .build();
            let err = consumer
                .process_to_claims(claims)
                .expect_err("expected rejection");
            assert!(
                err.has_error_code(ErrorCode::AUDIENCE_INVALID),
                "expected AudienceInvalid for {claims}, got {:?}",
                err.error_codes()
            );
        }
    }

    /// `aud: null` counts as absent, so `require_audience` rejects it.
    #[test]
    fn null_audience_is_absent() {
        let claims = r#"{"aud":null}"#;
        let consumer = JwtConsumerBuilder::new()
            .set_expected_audience(true, false, &["expected"])
            .build();
        let err = consumer.process_to_claims(claims).unwrap_err();
        assert!(err.has_error_code(ErrorCode::AUDIENCE_MISSING));
    }

    /// Strict audience mode requires a raw string, not a single-element array.
    #[test]
    fn strict_audience_rejects_single_element_array() {
        let claims = r#"{"aud":["expected"]}"#;
        let consumer = JwtConsumerBuilder::new()
            .set_expected_audience(true, true, &["expected"])
            .build();
        let err = consumer.process_to_claims(claims).unwrap_err();
        assert!(err.has_error_code(ErrorCode::AUDIENCE_INVALID));

        // ...but a plain string passes strict mode.
        let claims = r#"{"aud":"expected"}"#;
        assert!(consumer.process_to_claims(claims).is_ok());
    }

    /// A negative evaluation time (pre-epoch) must not panic.
    #[test]
    fn negative_evaluation_time_does_not_panic() {
        let claims = r#"{"sub":"x","exp":1000}"#;
        let consumer = JwtConsumerBuilder::new()
            .set_evaluation_time_from_seconds(-100)
            .build();
        // exp=1000 is after a pre-epoch eval time, so the token is not expired.
        assert!(consumer.process_to_claims(claims).is_ok());

        // And an exp after the (pre-epoch) eval time but a tiny exp before it.
        let consumer = JwtConsumerBuilder::new()
            .set_evaluation_time_from_seconds(-100)
            .build();
        let claims = r#"{"sub":"x","exp":-200}"#;
        let err = consumer.process_to_claims(claims).unwrap_err();
        assert!(err.has_error_code(ErrorCode::EXPIRED));
    }

    /// A present-but-non-string `iss` is rejected as malformed when
    /// expected issuers are configured.
    #[test]
    fn non_string_issuer_rejected_when_expected() {
        let claims = r#"{"iss":123}"#;
        let consumer = JwtConsumerBuilder::new()
            .set_expected_issuer("issuer.example.com")
            .build();
        let err = consumer.process_to_claims(claims).unwrap_err();
        assert!(err.has_error_code(ErrorCode::ISSUER_INVALID));
    }

    // ---------------------------------------------------------------
    // register_validator / JwtValidator tests
    // ---------------------------------------------------------------

    /// Closure-as-validator: a custom validator using `ErrorCode::custom`
    /// can enforce a protocol-specific claim (here: OIDC-style `nonce`
    /// equality) and the consumer surfaces the code via `has_error_code`.
    #[test]
    fn register_validator_closure_matches_nonce() {
        const NONCE_MISSING: ErrorCode = ErrorCode::custom(-1001);
        const NONCE_MISMATCH: ErrorCode = ErrorCode::custom(-1002);

        let expected = "abc123".to_string();

        let consumer = JwtConsumerBuilder::new()
            .register_validator(
                move |claims: &JwtClaims| match claims.string_claim("nonce") {
                    Some(n) if n == expected => Ok(()),
                    Some(_) => Err(InvalidJwtError::with_error_code(
                        "nonce does not match expected value",
                        NONCE_MISMATCH,
                    )),
                    None => Err(InvalidJwtError::with_error_code(
                        "nonce claim is required but missing",
                        NONCE_MISSING,
                    )),
                },
            )
            .build();

        // Nonce matches -> Ok
        assert!(consumer.process_to_claims(r#"{"nonce":"abc123"}"#).is_ok());

        // Nonce present but wrong -> custom mismatch code
        let err = consumer
            .process_to_claims(r#"{"nonce":"wrong"}"#)
            .unwrap_err();
        assert!(err.has_error_code(NONCE_MISMATCH));
        assert!(!err.has_error_code(NONCE_MISSING));

        // Nonce absent -> custom missing code
        let err = consumer.process_to_claims(r#"{"sub":"x"}"#).unwrap_err();
        assert!(err.has_error_code(NONCE_MISSING));
        assert!(!err.has_error_code(NONCE_MISMATCH));
    }

    /// A custom validator's failure coexists with a built-in validator's
    /// failure in the same `InvalidJwtError` — the codes are accumulated,
    /// not short-circuited.
    #[test]
    fn register_validator_accumulates_with_default_failures() {
        const CUSTOM: ErrorCode = ErrorCode::custom(-2001);

        let consumer = JwtConsumerBuilder::new()
            .set_expected_issuer("real-issuer")
            .set_require_expiration_time()
            .register_validator(|claims: &JwtClaims| {
                if claims.string_claim("c_hash").is_some() {
                    Ok(())
                } else {
                    Err(InvalidJwtError::with_error_code(
                        "c_hash claim is required",
                        CUSTOM,
                    ))
                }
            })
            .build();

        let err = consumer
            .process_to_claims(r#"{"iss":"wrong"}"#)
            .unwrap_err();
        // Default issuer failure surfaces alongside the custom c_hash failure.
        assert!(err.has_error_code(ErrorCode::ISSUER_INVALID));
        assert!(err.has_error_code(ErrorCode::EXPIRATION_MISSING));
        assert!(err.has_error_code(CUSTOM));
    }

    /// `skip_all_default_validators` does NOT skip custom validators;
    /// only `skip_all_validators` short-circuits past them.
    #[test]
    fn skip_all_default_validators_still_runs_custom_validators() {
        const CUSTOM: ErrorCode = ErrorCode::custom(-3001);

        let consumer = JwtConsumerBuilder::new()
            .set_expected_issuer("real-issuer")
            .set_skip_all_default_validators()
            .register_validator(|_: &JwtClaims| {
                Err(InvalidJwtError::with_error_code("custom failed", CUSTOM))
            })
            .build();

        let err = consumer.process_to_claims(r"{}").unwrap_err();
        assert!(err.has_error_code(CUSTOM));
        // Default issuer failure did not surface because defaults were skipped.
        assert!(!err.has_error_code(ErrorCode::ISSUER_INVALID));
    }

    /// `skip_all_validators` DOES skip custom validators too (they are
    /// validators after all).
    #[test]
    fn skip_all_validators_skips_custom_validators() {
        const CUSTOM: ErrorCode = ErrorCode::custom(-4001);

        let consumer = JwtConsumerBuilder::new()
            .set_expected_issuer("real-issuer")
            .set_skip_all_validators()
            .register_validator(|_: &JwtClaims| {
                Err(InvalidJwtError::with_error_code("custom failed", CUSTOM))
            })
            .build();

        assert!(consumer.process_to_claims(r#"{"iss":"wrong"}"#).is_ok());
    }

    /// `ErrorCode::custom` enforces the negative-integer convention at
    /// the API edge.
    #[test]
    #[should_panic(expected = "ErrorCode::custom requires a negative i32")]
    fn error_code_custom_rejects_positive() {
        let _ = ErrorCode::custom(42);
    }

    /// A `Box<dyn JwtValidator>` (named impl) works alongside closures.
    /// Confirms the trait is object-safe and the blanket impl isn't the
    /// only path.
    #[test]
    fn register_validator_trait_object_works() {
        let consumer = JwtConsumerBuilder::new()
            .register_validator(RequireCHash)
            .build();
        assert!(consumer.process_to_claims(r#"{"c_hash":"abc"}"#).is_ok());

        let err = consumer.process_to_claims(r"{}").unwrap_err();
        assert!(err.has_error_code(ErrorCode::custom(-5001)));
    }

    /// Named `JwtValidator` impl used by
    /// `register_validator_trait_object_works` to confirm trait-object
    /// dispatch works alongside the closure blanket impl.
    struct RequireCHash;

    impl crate::jwt::JwtValidator for RequireCHash {
        fn validate(&self, claims: &JwtClaims) -> Result<(), InvalidJwtError> {
            match claims.string_claim("c_hash") {
                Some(_) => Ok(()),
                None => Err(InvalidJwtError::with_error_code(
                    "c_hash is required",
                    ErrorCode::custom(-5001),
                )),
            }
        }
    }
}
