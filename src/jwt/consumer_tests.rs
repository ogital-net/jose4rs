// Comprehensive tests ported from jose4j JwtConsumerTest.java

#[cfg(test)]
mod jwt_consumer_tests {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use crate::jwt::{JwtClaims, JwtConsumerBuilder};

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
        assert!(err.has_error_code(ErrorCode::AudienceInvalid));

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
        assert!(err.has_error_code(ErrorCode::IssuerInvalid));

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
        assert!(err.has_error_code(ErrorCode::IssuerInvalid));
        assert!(err.has_error_code(ErrorCode::AudienceInvalid));
        assert!(err.has_error_code(ErrorCode::ExpirationTooFarInFuture));
    }
}
