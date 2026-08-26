//! An example of building verification keys from PEM and X.509 inputs.
//!
//! jose4j exposes `KeyUtil` / `X509Util` helper classes for turning PEM keys
//! and X.509 certificates into keys usable for JOSE. jose4rs instead puts
//! `from_pem` / `from_x509_pem` / `from_x509_der` / `to_pem` directly on the
//! JWK types.
//!
//! This mirrors the X.509 part of jose4j's `ExamplesTest.jwtRoundTripExample`:
//! a certificate arrives out-of-band and its public key is used to verify a
//! JWS. (jose4rs does not yet have an `X509VerificationKeyResolver` that
//! selects among several certificates by x5t/x5t#S256 thumbprint.)

use jose4rs::jwa::{AlgorithmConstraints, ConstraintType};
use jose4rs::jwk::rsa::RsaJsonWebKey;
use jose4rs::jwk::JsonWebKeyGenerator;
use jose4rs::jwk::{JsonWebKey, OutputControlLevel};
use jose4rs::jws::{AlgorithmIdentifier, JsonWebSignature};
use jose4rs::jwx::JsonWebStructure;

// --- X.509: extract a public key from a certificate ---
// (Self-signed example cert; only the public key is used, the certificate
// is neither retained nor chain-validated.)
const CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
    MIICojCCAYoCCQDjFCGvXJ6aRzANBgkqhkiG9w0BAQsFADATMREwDwYDVQQDDAh0\n\
    ZXN0LXJzYTAeFw0yNjA4MjAyMTA3MThaFw0yNzA4MjAyMTA3MThaMBMxETAPBgNV\n\
    BAMMCHRlc3QtcnNhMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqgZj\n\
    rugNDwxBcIvQXHv/76ifyuQvJfuJfdPAjDM9A9XoUdYfUPWtim8Ra4kmpiLPzezJ\n\
    x62XcLDvcIOzrINPInqs67ZteoTLSVCOHDPAA3YSk8uhQ2lAOH0wW4798qIKE8j9\n\
    RmebRct3dbLgtDyzjEKL+R72hCbFrqoM9qwkq8LQH3I/C/qxv8qmo98hE1Cm9C38\n\
    TL8AulZFGm+Jdkhq3fyAtxqfBsh2cFVhaFbZNQB1hyDhwJWeZAlJZLoeJXAQzw0O\n\
    TreK2uBUg3FdtQ9salM9dGzo2Enes/1NvHD56p0HiJ5Z9sEyGNGcobHK2+B6YAQb\n\
    B5KKW4jLcqIvhfQgBwIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQAr5jDlaVZ8dquC\n\
    +ovj3dFUELe1IUb5mQTG5fSE23FnOYJzxqk6kNOh/b76OP4SRAmk1YC2Fek93wl+\n\
    N1xJbT34cBrV8WTvrevwUnFTpUwQiZARy1UuoXok7S4mGjFFjkSe1vWS6SRiwuY6\n\
    WCg0TQ/Q4YKneIxwW+zGxCJFy/X1yU+F3fYQ1xgdoK36y9ViSrG7v2TYpylEV2IZ\n\
    X77BPJaM6Ipl29ejeiaqQxdi+lDW8NwQFd8A99CKxvBjcuXvn1xezOSkxif0iknT\n\
    i8uB/Gr41bm3vCtbfccScCfayb87HP0ZHeVnwCTd5AlhqVH5i4t4Z024TGt6PwXj\n\
    0Sn/VO7U\n\
    -----END CERTIFICATE-----";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // --- Producing side: sign with a key, export it as PEM ---
    let signing_jwk =
        JsonWebKeyGenerator::for_signature(AlgorithmIdentifier::RsaUsingSha256).generate()?;

    let mut jws = JsonWebSignature::new();
    jws.set_payload("Payload verified with a key from a PEM round trip.");
    jws.set_algorithm(AlgorithmIdentifier::RsaUsingSha256);
    let compact = jws.compact_serialization(&signing_jwk)?;
    println!("JWS: {compact}");

    // Export the public key as a PEM (SubjectPublicKeyInfo). This is what a
    // signer would publish out-of-band.
    let public_pem = signing_jwk.to_pem(OutputControlLevel::PublicOnly)?;
    println!("Public key PEM:\n{public_pem}");

    // --- Consuming side: rebuild the verification key from the PEM ---
    let verification_jwk = RsaJsonWebKey::from_pem(&public_pem)?;

    let constraints = AlgorithmConstraints::new(
        ConstraintType::Permit,
        [AlgorithmIdentifier::RsaUsingSha256],
    );
    let mut verifier = JsonWebSignature::new();
    verifier.set_algorithm_constraints(&constraints);
    verifier.set_compact_serialization(&compact)?;
    let verification_jwk = JsonWebKey::Rsa(verification_jwk);

    let verified = verifier.verify_signature(&verification_jwk)?;
    println!("JWS signature valid (key from PEM): {verified}");
    assert!(verified);

    let cert_jwk = RsaJsonWebKey::from_x509_pem(CERT_PEM)?;
    println!(
        "Extracted {}-bit RSA key from X.509 certificate",
        cert_jwk.key_size_bits()
    );
    // The certificate's thumbprints are captured on the resulting JWK, so you
    // can match it against a JWS x5t/x5t#S256 header later.
    println!("x5t:       {}", cert_jwk.x5t().unwrap_or("<none>"));
    println!("x5t#S256:  {}", cert_jwk.x5t_s256().unwrap_or("<none>"));
    println!(
        "As JWK: {}",
        cert_jwk.to_json(OutputControlLevel::PublicOnly)
    );

    Ok(())
}
