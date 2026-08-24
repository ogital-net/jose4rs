//! Fetching and caching a JWKS from an HTTPS endpoint.
//!
//! Requires the `jwks-https` feature: `cargo run --example jwks_https --features jwks-https`.
//!
//! The crate owns the cache/refresh policy (Cache-Control / Expires handling,
//! refresh single-flighting, retain-stale-on-error) but not the transport:
//! you supply a [`JwksFetcher`] over whatever HTTP client your application
//! already uses. This example uses a mock fetcher so it runs without network;
//! swap in a real client (ureq, reqwest-blocking, a tokio bridge, ...) for
//! production.

use std::sync::Arc;

use jose4rs::error::JoseError;
use jose4rs::jwk::{FetchResponse, HttpsJwks, JwksFetcher};

/// A stand-in for a real HTTP client. Returns a fixed JWKS with a
/// `Cache-Control: max-age` directive the cache will honor.
struct MockFetcher;

impl JwksFetcher for MockFetcher {
    fn fetch(&self, _url: &str) -> Result<FetchResponse, JoseError> {
        println!("  (fetcher: HTTP GET performed)");
        let body = br#"{"keys":[
            {"kty":"EC","use":"sig","kid":"the key",
             "x":"amuk6RkDZi-48mKrzgBN_zUZ_9qupIwTZHJjM03qL-4",
             "y":"ZOESj6_dpPiZZR-fJ-XVszQta28Cjgti7JudooQJ0co","crv":"P-256"}
        ]}"#
        .to_vec();
        Ok(FetchResponse::new(body).with_cache_control("public, max-age=300"))
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The HttpsJwks retrieves and caches keys from the given HTTPS endpoint.
    // Because it retains the JWKs after fetching them, it should be reused to
    // improve efficiency by reducing outbound calls to the endpoint.
    let fetcher: Arc<dyn JwksFetcher> = Arc::new(MockFetcher);
    let jwks = HttpsJwks::new("https://example.com/jwks", fetcher);

    println!("First call (cache is empty, fetches):");
    let keys = jwks.keys()?;
    println!("  got {} key(s)", keys.len());

    println!("Second call (cache is fresh, no fetch):");
    let keys = jwks.keys()?;
    println!("  got {} key(s)", keys.len());

    println!("After forcing a refresh:");
    let keys = jwks.refresh()?;
    println!("  got {} key(s)", keys.len());

    // In a real consumer you'd hand `jwks.keys()?` to a VerificationJwkSelector
    // (see the jwks_verify_jws example) to pick the verification key for an
    // inbound JWS by its kid/alg headers.

    Ok(())
}
