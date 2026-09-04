//! End-to-end JWKS verification flow against a real local HTTP server.
//!
//! Requires the `jwks-https` feature:
//! `cargo run --example jwks_https --features jwks-https`.
//!
//! The crate owns the cache/refresh policy (Cache-Control / Expires / Age parsing,
//! refresh single-flighting, retain-stale-on-error) but not the transport:
//! you supply a [`JwksFetcher`] over whatever HTTP client your application
//! already uses. This example wires up [`reqwest::blocking::Client`] for the
//! fetch and [`wiremock`] for the endpoint, so the full path -- real socket,
//! real `Cache-Control` headers, real selector round-trip -- is exercised
//! without a network.
//!
//! Run with `cargo run --example jwks_https --features jwks-https`.

use std::sync::Arc;
use std::time::Duration;

use jose4rs::error::JoseError;
use jose4rs::jwk::{FetchResponse, HttpsJwks, JwksFetcher};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A single JWKS body containing one ES256 signing key.
const JWKS_BODY: &str = r#"{"keys":[
    {"kty":"EC","use":"sig","kid":"the key",
     "x":"amuk6RkDZi-48mKrzgBN_zUZ_9qupIwTZHJjM03qL-4",
     "y":"ZOESj6_dpPiZZR-fJ-XVszQta28Cjgti7JudooQJ0co","crv":"P-256"}
]}"#;

/// Adapts a blocking `reqwest::Client` to the [`JwksFetcher`] trait.
struct ReqwestFetcher(reqwest::blocking::Client);

impl JwksFetcher for ReqwestFetcher {
    fn fetch(&self, url: &str) -> Result<FetchResponse, JoseError> {
        let resp = self
            .0
            .get(url)
            .send()
            .map_err(|e| JoseError::JwksFetch(e.to_string()))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(JoseError::JwksFetch(format!("HTTP {status}")));
        }
        let cache_control = resp
            .headers()
            .get(reqwest::header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let expires = resp
            .headers()
            .get(reqwest::header::EXPIRES)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let age = resp
            .headers()
            .get(reqwest::header::AGE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse().ok())
            .map(Duration::from_secs);
        let body = resp
            .bytes()
            .map_err(|e| JoseError::JwksFetch(e.to_string()))?
            .to_vec();
        Ok(FetchResponse {
            body,
            cache_control,
            expires,
            age,
        })
    }
}

/// Builds a reqwest blocking client with redirects disabled.
///
/// A JWKS endpoint must never redirect: an attacker controlling a redirect
/// target could exfiltrate a Bearer token or substitute their own keys.
/// Returning a redirect as an error forces the operator to configure the
/// endpoint correctly.
fn build_blocking_client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("build reqwest blocking client")
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // wiremock's server lifecycle is async, so we drive it on a single-threaded
    // tokio runtime *just for setup*. The actual JWKS fetches below go through
    // `reqwest::blocking::Client` -- no async runtime needed for the application
    // code under test. The `MockServer` MUST outlive the example: its `Drop`
    // shuts down the background server (and runs request-count verification),
    // so we keep it alive until end of `main`.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let server = rt.block_on(async {
        let server = MockServer::start().await;

        // Mount a single GET /jwks responder with a 5-minute cache directive.
        // We expect exactly 3 hits across the demo: the initial cold fetch,
        // the forced `refresh()` call, and the kid-miss refresh. A warm-cache
        // call must NOT hit the server; if it does, the mock's `.expect(3)`
        // verification at shutdown will panic.
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("cache-control", "public, max-age=300")
                    .set_body_string(JWKS_BODY),
            )
            .expect(3)
            .mount(&server)
            .await;

        server
    });

    let verify_uri = format!("{}/jwks", server.uri());
    let client = build_blocking_client();
    let fetcher: Arc<dyn JwksFetcher> = Arc::new(ReqwestFetcher(client));
    let jwks = HttpsJwks::new(&verify_uri, fetcher);

    println!("JWKS endpoint: {verify_uri}");

    // ---- 1. Cache lifecycle ------------------------------------------------

    println!("\n[1] Cache lifecycle");
    let keys = jwks.keys()?;
    println!(
        "  keys()    -> {} key(s) (cold: should hit network)",
        keys.len()
    );

    let keys = jwks.keys()?;
    println!(
        "  keys()    -> {} key(s) (warm: must NOT hit network)",
        keys.len()
    );

    let keys = jwks.refresh()?;
    println!(
        "  refresh() -> {} key(s) (forced: must hit network)",
        keys.len()
    );

    // ---- 2. OIDC-style verify-key selection -------------------------------

    println!("\n[2] select_verification_key -- the OIDC ID-token path");

    // (kid matches, alg matches ES256 / EC P-256) -> Some
    let selected = jwks.select_verification_key(Some("the key"), "ES256")?;
    println!(
        "  kid='the key', alg=ES256 -> {}",
        match &selected {
            Some(k) => format!("Some(kid={:?})", k.key_id()),
            None => "None".into(),
        }
    );
    assert_eq!(selected.as_ref().and_then(|k| k.key_id()), Some("the key"));

    // (kid matches, alg mismatch: RS256 vs EC key) -> None (algorithm-confusion defense)
    let wrong_alg = jwks.select_verification_key(Some("the key"), "RS256")?;
    println!(
        "  kid='the key', alg=RS256 -> {} (expected None -- kty guard)",
        if wrong_alg.is_some() { "Some" } else { "None" }
    );
    assert!(wrong_alg.is_none());

    // (no kid) -> falls back to alg-filtered selection over the whole set
    let no_kid = jwks.select_verification_key(None, "ES256")?;
    println!(
        "  kid=None,    alg=ES256 -> {}",
        match &no_kid {
            Some(k) => format!("Some(kid={:?})", k.key_id()),
            None => "None".into(),
        }
    );
    assert!(no_kid.is_some());

    // ---- 3. kid-miss refresh ----------------------------------------------

    println!("\n[3] kid-miss refresh (key rotation)");
    // The JWKS only has 'the key'; ask for one that isn't there. This should
    // trigger exactly one extra HTTP fetch (the kid-miss refresh path), taking
    // the total hit count to 3.
    let rotated = jwks.select_verification_key(Some("rotated-key"), "ES256")?;
    println!(
        "  kid='rotated-key', alg=ES256 -> {} (expected None, but fetched once)",
        if rotated.is_some() { "Some" } else { "None" }
    );
    assert!(rotated.is_none());

    println!(
        "\nAll assertions passed. wiremock will verify the expected request count at shutdown."
    );
    // `server` is dropped here; wiremock verifies `.expect(3)` matches the
    // recorded call count, panicking on mismatch.
    Ok(())
}
