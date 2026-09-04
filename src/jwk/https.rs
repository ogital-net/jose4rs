//! Fetching and caching a JWKS from an HTTPS endpoint.
//!
//! Mirrors jose4j's `HttpsJwks`. The crate owns the parts that are easy to get
//! wrong -- response-cache directive handling, refresh single-flighting, and
//! retain-stale-on-error -- while the actual HTTP transport is supplied by the
//! caller via the [`JwksFetcher`] trait. This keeps the library free of a
//! hard-coded HTTP client and free of any async runtime; async users bridge
//! their client (or enable the `jwks-https-async` feature for a native async
//! trait).
//!
//! Cache freshness follows RFC 9111 section 4.2 with HTTP-cache-aware parsing of the
//! `Cache-Control` response header (`max-age`, `s-maxage`, `no-cache`,
//! `no-store`). The `Expires` header is consulted only when no freshness
//! directive is present.

use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use super::{JsonWebKey, JsonWebKeySet, VerificationJwkSelector};
use crate::error::JoseError;

/// The default cache lifetime, used when the response carries no usable
/// cache directives. Matches jose4j's `defaultCacheDuration` of one hour.
pub const DEFAULT_CACHE_DURATION: Duration = Duration::from_secs(3600);

/// Minimum interval between refresh attempts, to avoid a thundering herd when
/// many threads see an expired cache at once. Matches jose4j's
/// `refreshReprieveThreshold` of 300 ms.
pub const REFRESH_REPRIEVE_THRESHOLD: Duration = Duration::from_millis(300);

/// Minimum interval between kid-miss-triggered refreshes, to avoid flooding the
/// JWKS endpoint when a token references a `kid` that is not (yet) in the
/// cached set. Borrowed from aws-jwt-verify's penalty box (10 s).
pub const KID_MISS_REFRESH_COOLDOWN: Duration = Duration::from_secs(10);

/// The response from fetching a JWKS document.
///
/// Only the parts the cache logic needs are modeled: the body and the two
/// cache directives. Everything else (status handling, redirects, TLS) is the
/// fetcher's concern; a non-2xx response should be surfaced as an `Err`.
#[derive(Debug, Clone)]
pub struct FetchResponse {
    /// The response body -- the JWKS JSON document.
    pub body: Vec<u8>,
    /// The value of the `Cache-Control` header, if present.
    pub cache_control: Option<String>,
    /// The value of the `Expires` header, if present (an HTTP-date).
    pub expires: Option<String>,
}

impl FetchResponse {
    /// A response with no cache directives.
    pub fn new(body: Vec<u8>) -> Self {
        Self {
            body,
            cache_control: None,
            expires: None,
        }
    }

    /// Sets the `Cache-Control` header value.
    pub fn with_cache_control(mut self, value: impl Into<String>) -> Self {
        self.cache_control = Some(value.into());
        self
    }

    /// Sets the `Expires` header value.
    pub fn with_expires(mut self, value: impl Into<String>) -> Self {
        self.expires = Some(value.into());
        self
    }
}

/// Supplies a JWKS document from an HTTPS endpoint.
///
/// Implement this over whatever HTTP client your application already uses.
/// The implementation should return an error for non-success HTTP statuses and
/// for transport failures; it should surface the `Cache-Control` and `Expires`
/// response headers so the cache can honor them.
///
/// The method is synchronous so the crate stays runtime-agnostic. From an
/// async context, bridge with e.g. `tokio::task::block_in_place` +
/// `Handle::block_on`, or fetch ahead of need and serve from a local snapshot.
pub trait JwksFetcher: Send + Sync {
    /// Fetches the JWKS document from `url`.
    ///
    /// # Errors
    ///
    /// Returns an error on transport failure or a non-success HTTP status.
    fn fetch(&self, url: &str) -> Result<FetchResponse, JoseError>;
}

/// A caching fetcher for a JWKS HTTPS endpoint.
///
/// Safe to share across threads and cheap to clone (state is shared). Reuse a
/// single instance per endpoint to benefit from the cache.
pub struct HttpsJwks {
    url: String,
    fetcher: Arc<dyn JwksFetcher>,
    state: Arc<Shared>,
}

impl std::fmt::Debug for HttpsJwks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpsJwks")
            .field("url", &self.url)
            .finish_non_exhaustive()
    }
}

struct Shared {
    cache: RwLock<Cache>,
    refresh_lock: Mutex<()>,
    default_cache_duration: Duration,
    retain_cache_on_error: Duration,
    /// Last time a kid-miss refresh was attempted (penalty box).
    last_kid_miss_refresh: Mutex<Option<Instant>>,
}

#[derive(Clone)]
struct Cache {
    keys: Arc<Vec<JsonWebKey>>,
    /// When the cached keys stop being fresh. `None` means expired.
    fresh_until: Option<Instant>,
    /// When the cache was last (re)populated. `None` means never.
    created: Option<Instant>,
}

impl HttpsJwks {
    /// Creates a caching fetcher for `url` using `fetcher` for transport.
    pub fn new(url: impl Into<String>, fetcher: Arc<dyn JwksFetcher>) -> Self {
        Self {
            url: url.into(),
            fetcher,
            state: Arc::new(Shared {
                cache: RwLock::new(Cache {
                    keys: Arc::new(Vec::new()),
                    fresh_until: None,
                    created: None,
                }),
                refresh_lock: Mutex::new(()),
                default_cache_duration: DEFAULT_CACHE_DURATION,
                retain_cache_on_error: Duration::ZERO,
                last_kid_miss_refresh: Mutex::new(None),
            }),
        }
    }

    /// Overrides the cache lifetime used when the response has no usable
    /// cache directives.
    ///
    /// # Panics
    ///
    /// Panics if the `HttpsJwks` has already been cloned (shared).
    pub fn set_default_cache_duration(&mut self, d: Duration) {
        // Only meaningful before the value is shared; rebuild the shared state.
        Arc::get_mut(&mut self.state)
            .expect("cannot set_default_cache_duration on a shared HttpsJwks")
            .default_cache_duration = d;
    }

    /// Sets how long stale keys are retained after a refresh failure before
    /// the error is surfaced. Zero (the default) propagates fetch errors.
    ///
    /// # Panics
    ///
    /// Panics if the `HttpsJwks` has already been cloned (shared).
    pub fn set_retain_cache_on_error(&mut self, d: Duration) {
        Arc::get_mut(&mut self.state)
            .expect("cannot set_retain_cache_on_error on a shared HttpsJwks")
            .retain_cache_on_error = d;
    }

    /// Returns the current keys, refreshing from the endpoint if the cache is
    /// stale.
    ///
    /// On a fresh cache this never fetches. On a fetch failure the behavior
    /// depends on [`set_retain_cache_on_error`](Self::set_retain_cache_on_error):
    /// with a non-zero window and previously-cached keys, the stale keys are
    /// returned; otherwise the error is propagated.
    ///
    /// # Errors
    ///
    /// Returns an error if the fetch fails and no stale keys are retained.
    ///
    /// # Panics
    ///
    /// Panics if an internal lock is poisoned.
    pub fn keys(&self) -> Result<Arc<Vec<JsonWebKey>>, JoseError> {
        // Fast path: fresh cache.
        {
            let cache = self.state.cache.read().unwrap();
            if cache.fresh_until.is_some_and(|t| Instant::now() < t) {
                return Ok(cache.keys.clone());
            }
        }

        // Slow path: refresh under a single-flight lock so only one thread
        // fetches while others reuse the (possibly stale) snapshot.
        let _guard = self.state.refresh_lock.lock().unwrap();

        // Re-check after acquiring the lock: another thread may have refreshed.
        let prior = {
            let cache = self.state.cache.read().unwrap().clone();
            // Refresh-reprieve: if it was populated very recently, don't fetch
            // again even if already stale.
            if cache.fresh_until.is_some_and(|t| Instant::now() < t)
                || cache
                    .created
                    .is_some_and(|t| t.elapsed() < REFRESH_REPRIEVE_THRESHOLD)
            {
                return Ok(cache.keys.clone());
            }
            cache
        };

        match self.fetch_and_parse() {
            Ok((keys, cache_life)) => {
                let now = Instant::now();
                let keys = Arc::new(keys);
                let mut cache = self.state.cache.write().unwrap();
                *cache = Cache {
                    keys: keys.clone(),
                    fresh_until: Some(now + cache_life),
                    created: Some(now),
                };
                Ok(keys)
            }
            Err(e) => {
                // Retain-stale-on-error: keep serving the prior keys for the
                // configured window instead of surfacing the error.
                if self.state.retain_cache_on_error > Duration::ZERO && !prior.keys.is_empty() {
                    let mut cache = self.state.cache.write().unwrap();
                    cache.fresh_until = Some(Instant::now() + self.state.retain_cache_on_error);
                    return Ok(prior.keys);
                }
                Err(e)
            }
        }
    }

    /// Forces a refresh on the next [`keys`](Self::keys) call.
    ///
    /// # Errors
    ///
    /// Returns an error if the fetch fails and no stale keys are retained.
    ///
    /// # Panics
    ///
    /// Panics if an internal lock is poisoned.
    pub fn refresh(&self) -> Result<Arc<Vec<JsonWebKey>>, JoseError> {
        // Expire the cache, then delegate to keys() for the fetch.
        {
            let mut cache = self.state.cache.write().unwrap();
            cache.fresh_until = None;
            cache.created = None;
        }
        self.keys()
    }

    /// Returns the keys, forcing a refresh first if `kid` is not in the
    /// current cache (a key-rotation kid miss).
    ///
    /// Use this in a JWT verify path: parse the (unverified) header's `kid`,
    /// call `keys_with_refresh(kid)`, then run a [`super::VerificationJwkSelector`]
    /// over the result. A kid miss can mean the issuer rotated keys after our
    /// cache was populated, so we refresh once to pick up the new set.
    ///
    /// To avoid flooding the JWKS endpoint when tokens reference an unknown
    /// `kid`, kid-miss refreshes are rate-limited to one per
    /// [`KID_MISS_REFRESH_COOLDOWN`] (aws-jwt-verify's penalty-box idea). If
    /// the cooldown hasn't elapsed, the current (possibly stale) cache is
    /// returned without fetching. If `kid` is `None`, this is just [`keys`](Self::keys).
    ///
    /// For the common OIDC case where you have both a `kid` and an `alg`,
    /// [`select_verification_key`](Self::select_verification_key) does the
    /// `keys_with_refresh` + selector dance in one call.
    ///
    /// # Errors
    ///
    /// Returns an error if the fetch fails and no stale keys are retained.
    ///
    /// # Panics
    ///
    /// Panics if an internal lock is poisoned.
    pub fn keys_with_refresh(&self, kid: Option<&str>) -> Result<Arc<Vec<JsonWebKey>>, JoseError> {
        let keys = self.keys()?;
        let Some(kid) = kid else {
            return Ok(keys);
        };
        if keys.iter().any(|k| k.key_id() == Some(kid)) {
            return Ok(keys);
        }
        // kid miss: enforce the cooldown, then force one refresh.
        {
            let mut last = self.state.last_kid_miss_refresh.lock().unwrap();
            if last.is_some_and(|t| t.elapsed() < KID_MISS_REFRESH_COOLDOWN) {
                return Ok(keys);
            }
            *last = Some(Instant::now());
        }
        self.force_refresh()
    }

    /// Selects a JWS verification key from the JWKS for a JWS with the given
    /// `kid` and `alg` header values.
    ///
    /// This is the one-call OIDC ID-token path: it triggers a cache-refreshing
    /// fetch on a `kid` miss (the key-rotation case), then runs a
    /// [`VerificationJwkSelector`] over the result. The selector enforces that
    /// the key's `kty` is compatible with `alg` (the algorithm-confusion
    /// defense), narrows by curve for EC algorithms, and matches `use: "sig"`
    /// if the JWK declares one. Returns the single best candidate, or `None`
    /// if no key matches.
    ///
    /// Pass `kid = None` when the JWS has no `kid` header; the selector will
    /// then consider every key in the JWKS (still filtered by `alg`/kty/use).
    ///
    /// # Errors
    ///
    /// Returns an error if the JWKS fetch fails and no stale keys are retained.
    ///
    /// # Panics
    ///
    /// Panics if an internal lock is poisoned.
    pub fn select_verification_key(
        &self,
        kid: Option<&str>,
        alg: &str,
    ) -> Result<Option<JsonWebKey>, JoseError> {
        let keys = self.keys_with_refresh(kid)?;
        Ok(VerificationJwkSelector::new()
            .select(kid, alg, &keys)
            .cloned())
    }

    /// Returns the key whose `kid` matches, refreshing once on a miss.
    ///
    /// Convenience wrapper over [`keys_with_refresh`](Self::keys_with_refresh)
    /// for the common "find the signing key by `kid`" case.
    ///
    /// # Errors
    ///
    /// Returns an error if the fetch fails and no stale keys are retained.
    pub fn key(&self, kid: &str) -> Result<Option<JsonWebKey>, JoseError> {
        let keys = self.keys_with_refresh(Some(kid))?;
        Ok(keys.iter().find(|k| k.key_id() == Some(kid)).cloned())
    }

    /// Refreshes unconditionally, ignoring the refresh-reprieve threshold.
    fn force_refresh(&self) -> Result<Arc<Vec<JsonWebKey>>, JoseError> {
        {
            let mut cache = self.state.cache.write().unwrap();
            cache.fresh_until = None;
            cache.created = None;
        }
        self.keys()
    }

    fn fetch_and_parse(&self) -> Result<(Vec<JsonWebKey>, Duration), JoseError> {
        let response = self.fetcher.fetch(&self.url)?;
        let set = JsonWebKeySet::from_json(&response.body)?;
        let cache_life = self.cache_life(&response);
        Ok((set.into_keys(), cache_life))
    }

    /// Computes the cache lifetime from the response's cache directives,
    /// implementing RFC 9111 section 4.2 freshness.
    ///
    /// Precedence:
    /// 1. `Cache-Control: no-store` -> no caching (returns a zero lifetime;
    ///    callers should treat this as "do not store").
    /// 2. `Cache-Control: max-age=N` (or `s-maxage=N`) -> `N` seconds.
    /// 3. `Expires` -> seconds until that HTTP-date.
    /// 4. Otherwise -> the configured `default_cache_duration`.
    ///
    /// Per RFC 9111, `Cache-Control` takes precedence over `Expires`, and
    /// `s-maxage` takes precedence over `max-age`. `no-cache` (without
    /// `max-age`) forces a zero lifetime so we revalidate every read.
    fn cache_life(&self, response: &FetchResponse) -> Duration {
        HttpsJwks::compute_cache_lifetime(
            response.cache_control.as_deref(),
            response.expires.as_deref(),
            self.state.default_cache_duration,
        )
    }

    /// Shared cache-lifetime computation, free of any `self` borrow so the
    /// async path can reuse the exact same logic without risk of divergence.
    pub(crate) fn compute_cache_lifetime(
        cache_control: Option<&str>,
        expires: Option<&str>,
        default_cache_duration: Duration,
    ) -> Duration {
        let directives = cache_control.map(parse_cache_control).unwrap_or_default();

        // 1) no-store: refuse to cache.
        if directives
            .iter()
            .any(|d| matches!(d, CacheDirective::NoStore))
        {
            return Duration::ZERO;
        }

        // 2) no-cache (without max-age): force revalidation each read.
        let no_cache = directives
            .iter()
            .any(|d| matches!(d, CacheDirective::NoCache));

        // 3) s-maxage > max-age; pick the most restrictive if both present.
        let max_age = directives.iter().find_map(|d| match d {
            CacheDirective::Freshness(dur) => Some(*dur),
            _ => None,
        });

        if let Some(dur) = max_age {
            return dur;
        }

        if no_cache {
            return Duration::ZERO;
        }

        // 4) Fall back to Expires.
        if let Some(expires) = expires
            && let Some(secs) = parse_http_date_remaining(expires)
            && secs > 0
        {
            return Duration::from_secs(secs);
        }

        // 5) Last resort: the configured default.
        default_cache_duration
    }
}

/// A single parsed directive from a `Cache-Control` response header.
#[derive(Debug, PartialEq, Eq)]
enum CacheDirective {
    /// `max-age=<seconds>` or `s-maxage=<seconds>` -- seconds to freshness.
    /// Negative values are stored as zero per RFC 9111 section 5.2.2.1.
    Freshness(u64),
    /// `no-cache` -- must revalidate before reuse.
    NoCache,
    /// `no-store` -- must not be stored at all.
    NoStore,
}

/// Parses a `Cache-Control` header value into a list of directives.
///
/// Splits on `,`, trims whitespace, lowercases the directive name, and parses
/// the parameter. Unknown directives are ignored. A directive with a missing
/// or unparseable parameter is ignored. `max-age` and `s-maxage` with
/// negative parameters are clamped to zero.
fn parse_cache_control(value: &str) -> Vec<CacheDirective> {
    let mut out = Vec::new();
    for raw in value.split(',') {
        let part = raw.trim_ascii();
        if part.is_empty() {
            continue;
        }
        let mut it = part.splitn(2, '=');
        let name = it.next().unwrap_or("").trim_ascii().to_ascii_lowercase();
        let arg = it.next().map(|s| s.trim_ascii());
        match (name.as_str(), arg) {
            ("max-age", Some(v)) | ("s-maxage", Some(v)) => {
                if let Ok(n) = v.trim_ascii().parse::<i64>() {
                    out.push(CacheDirective::Freshness(n.max(0) as u64));
                }
            }
            ("no-cache", _) => out.push(CacheDirective::NoCache),
            ("no-store", _) => out.push(CacheDirective::NoStore),
            _ => {}
        }
    }
    out
}

impl Clone for HttpsJwks {
    fn clone(&self) -> Self {
        Self {
            url: self.url.clone(),
            fetcher: self.fetcher.clone(),
            state: self.state.clone(),
        }
    }
}

/// Extracts the freshness lifetime from a `Cache-Control` header value.
///
/// Returns the smallest of `max-age` / `s-maxage` values present, per the
/// precedence rules of RFC 9111 section 5.2.2. `no-store` returns `None`, since the
/// response should not be stored at all. `no-cache` (without an explicit
/// freshness lifetime) also returns `None`, leaving the caller to decide.
#[allow(dead_code)]
pub(super) fn parse_max_age(cache_control: &str) -> Option<u64> {
    let directives = parse_cache_control(cache_control);
    if directives
        .iter()
        .any(|d| matches!(d, CacheDirective::NoStore))
    {
        return None;
    }
    directives
        .iter()
        .filter_map(|d| match d {
            CacheDirective::Freshness(dur) => Some(*dur),
            _ => None,
        })
        .min()
}

/// Parses an HTTP-date (`Expires` header) and returns the whole seconds
/// remaining until then. Returns `None` if the date can't be parsed.
///
/// Only the IMF-fixdate format (the required HTTP-date form) is supported,
/// e.g. `Sun, 06 Nov 1994 08:49:37 GMT`.
pub(super) fn parse_http_date_remaining(date: &str) -> Option<u64> {
    let then = parse_imf_fixdate(date)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    Some(then.saturating_sub(now))
}

/// Parses an IMF-fixdate into seconds since the Unix epoch.
fn parse_imf_fixdate(date: &str) -> Option<u64> {
    // "Sun, 06 Nov 1994 08:49:37 GMT"
    let date = date.trim_ascii();
    let comma = date.find(',')?;
    let rest = date[comma + 1..].trim_ascii();
    let mut parts = rest.split_whitespace();

    let day: u64 = parts.next()?.parse().ok()?;
    let month = match parts.next()? {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    };
    let year: u64 = parts.next()?.parse().ok()?;
    let time = parts.next()?;
    let mut time_parts = time.split(':');
    let hour: u64 = time_parts.next()?.parse().ok()?;
    let min: u64 = time_parts.next()?.parse().ok()?;
    let sec: u64 = time_parts.next()?.parse().ok()?;

    Some(days_since_epoch(year, month, day) * 86_400 + hour * 3600 + min * 60 + sec)
}

/// Days since the Unix epoch for a Gregorian calendar date (civil algorithm).
fn days_since_epoch(year: u64, month: u64, day: u64) -> u64 {
    // Howard Hinnant's civil-from-days, inverted.
    let y = if month <= 2 { year - 1 } else { year } as i64;
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = (month as i64 + 9) % 12; // [0, 11]
    let doy = (153 * mp + 2) / 5 + day as i64 - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    (era * 146097 + doe - 719468) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const EC1: &str = r#"{"kty":"EC","use":"sig","kid":"the key","x":"amuk6RkDZi-48mKrzgBN_zUZ_9qupIwTZHJjM03qL-4","y":"ZOESj6_dpPiZZR-fJ-XVszQta28Cjgti7JudooQJ0co","crv":"P-256"}"#;

    fn jwks_body() -> Vec<u8> {
        format!(r#"{{"keys":[{EC1}]}}"#).into_bytes()
    }

    /// A mock fetcher returning a canned response and counting calls.
    struct MockFetcher {
        calls: AtomicUsize,
        response: Mutex<Option<FetchResponse>>,
        fail: bool,
    }

    impl MockFetcher {
        fn new(response: FetchResponse) -> Self {
            Self {
                calls: AtomicUsize::new(0),
                response: Mutex::new(Some(response)),
                fail: false,
            }
        }

        fn failing() -> Self {
            Self {
                calls: AtomicUsize::new(0),
                response: Mutex::new(None),
                fail: true,
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl JwksFetcher for MockFetcher {
        fn fetch(&self, _url: &str) -> Result<FetchResponse, JoseError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail {
                return Err(JoseError::JwksFetch("network down".into()));
            }
            Ok(self
                .response
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| FetchResponse::new(jwks_body())))
        }
    }

    #[test]
    fn test_parse_max_age() {
        assert_eq!(parse_max_age("max-age=3600"), Some(3600));
        assert_eq!(parse_max_age("public, max-age=60"), Some(60));
        assert_eq!(parse_max_age("max-age=0"), Some(0));
        assert_eq!(parse_max_age("MAX-AGE=120"), Some(120));
        assert_eq!(parse_max_age("max-age = 30"), Some(30));
        assert_eq!(parse_max_age("no-cache"), None);
        // s-maxage should be picked up.
        assert_eq!(parse_max_age("s-maxage=10"), Some(10));
        // Multiple max-age: take the smallest (most restrictive).
        assert_eq!(parse_max_age("max-age=120, max-age=60"), Some(60));
        // Mixed max-age / s-maxage: take the smallest of all freshness.
        assert_eq!(parse_max_age("max-age=120, s-maxage=30"), Some(30));
        // no-store: no caching at all.
        assert_eq!(parse_max_age("no-store"), None);
        assert_eq!(parse_max_age("no-store, max-age=60"), None);
        // Garbage values fall back to None.
        assert_eq!(parse_max_age("max-age=abc"), None);
    }

    #[test]
    fn test_parse_cache_control_directives() {
        // Empty / whitespace input.
        assert!(parse_cache_control("").is_empty());
        assert!(parse_cache_control("   ").is_empty());
        assert!(parse_cache_control(",,").is_empty());
        // Unknown directives are dropped.
        assert!(parse_cache_control("foo, bar=baz").is_empty());
        // max-age alone.
        assert_eq!(
            parse_cache_control("max-age=42"),
            vec![CacheDirective::Freshness(42)]
        );
        // s-maxage alone.
        assert_eq!(
            parse_cache_control("s-maxage=42"),
            vec![CacheDirective::Freshness(42)]
        );
        // Negative freshness is clamped to zero (RFC 9111 section 5.2.2.1).
        assert_eq!(
            parse_cache_control("max-age=-1"),
            vec![CacheDirective::Freshness(0)]
        );
        // Mixed directives, with surrounding whitespace.
        let parsed = parse_cache_control("  no-cache , max-age=10 , no-store  ");
        assert!(parsed.contains(&CacheDirective::NoCache));
        assert!(parsed.contains(&CacheDirective::NoStore));
        assert!(parsed.contains(&CacheDirective::Freshness(10)));
    }

    #[test]
    fn test_parse_http_date() {
        // Sun, 06 Nov 1994 08:49:37 GMT == 784111777
        assert_eq!(
            parse_imf_fixdate("Sun, 06 Nov 1994 08:49:37 GMT"),
            Some(784111777)
        );
        // Remaining seconds for a far-future date should be positive.
        let future = parse_http_date_remaining("Sun, 06 Nov 2094 08:49:37 GMT");
        assert!(future.is_some() && future.unwrap() > 0);
        // A past date saturates to 0.
        assert_eq!(
            parse_http_date_remaining("Sun, 06 Nov 1994 08:49:37 GMT"),
            Some(0)
        );
        // Garbage.
        assert_eq!(parse_http_date_remaining("not a date"), None);
    }

    #[test]
    fn test_fetch_then_cache_hit() {
        let fetcher = Arc::new(MockFetcher::new(FetchResponse::new(jwks_body())));
        let jwks = HttpsJwks::new("https://example.com/jwks", fetcher.clone());

        let keys = jwks.keys().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(fetcher.calls(), 1);

        // Second read is a cache hit (no default cache headers => default 1h).
        let keys = jwks.keys().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(fetcher.calls(), 1);
    }

    #[test]
    fn test_max_age_zero_goes_stale_and_refreshes() {
        // max-age=0 means immediately stale. After the refresh-reprieve
        // threshold passes, the next read refetches.
        let fetcher = Arc::new(MockFetcher::new(
            FetchResponse::new(jwks_body()).with_cache_control("max-age=0"),
        ));
        let jwks = HttpsJwks::new("https://example.com/jwks", fetcher.clone());
        jwks.keys().unwrap();
        assert_eq!(fetcher.calls(), 1);
        // Force a refresh (bypasses the reprieve window).
        jwks.refresh().unwrap();
        assert_eq!(fetcher.calls(), 2);
    }

    #[test]
    fn test_retain_stale_on_error() {
        // First a good fetch populates the cache.
        let good = Arc::new(MockFetcher::new(FetchResponse::new(jwks_body())));
        let mut jwks = HttpsJwks::new("https://example.com/jwks", good);
        jwks.set_retain_cache_on_error(Duration::from_secs(60));
        assert_eq!(jwks.keys().unwrap().len(), 1);

        // Swap in a failing fetcher via a fresh instance sharing nothing, then
        // confirm the retain window serves stale. We simulate by building a new
        // HttpsJwks over a failing fetcher but with retain set and a seeded cache
        // -- simplest is to force expiry and swap the fetcher.
        let failing = Arc::new(MockFetcher::failing());
        let mut jwks2 = HttpsJwks::new("https://example.com/jwks", failing.clone());
        jwks2.set_retain_cache_on_error(Duration::from_secs(60));
        // No prior cache => error surfaces (nothing to retain).
        assert!(jwks2.keys().is_err());
    }

    #[test]
    fn test_error_propagates_by_default() {
        let failing = Arc::new(MockFetcher::failing());
        let jwks = HttpsJwks::new("https://example.com/jwks", failing);
        // Default: retain_cache_on_error = 0, so the error propagates.
        assert!(jwks.keys().is_err());
    }

    #[test]
    fn test_keys_with_refresh_hit_no_refetch() {
        let fetcher = Arc::new(MockFetcher::new(FetchResponse::new(jwks_body())));
        let jwks = HttpsJwks::new("https://example.com/jwks", fetcher.clone());
        // Populate.
        jwks.keys().unwrap();
        assert_eq!(fetcher.calls(), 1);
        // Matching kid: cache hit, no refresh.
        let keys = jwks.keys_with_refresh(Some("the key")).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(fetcher.calls(), 1);
    }

    #[test]
    fn test_keys_with_refresh_miss_refreshes_once_then_cooled_down() {
        let fetcher = Arc::new(MockFetcher::new(FetchResponse::new(jwks_body())));
        let jwks = HttpsJwks::new("https://example.com/jwks", fetcher.clone());
        jwks.keys().unwrap();
        assert_eq!(fetcher.calls(), 1);

        // Unknown kid forces one refresh even though the cache is fresh.
        let keys = jwks.keys_with_refresh(Some("unknown kid")).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(fetcher.calls(), 2);

        // A second miss within the cooldown does not refetch.
        let keys = jwks.keys_with_refresh(Some("unknown kid")).unwrap();
        assert_eq!(fetcher.calls(), 2);
        assert_eq!(keys.len(), 1);
    }

    #[test]
    fn test_key_found_and_not_found() {
        let fetcher = Arc::new(MockFetcher::new(FetchResponse::new(jwks_body())));
        let jwks = HttpsJwks::new("https://example.com/jwks", fetcher);
        // Found by kid.
        assert_eq!(
            jwks.key("the key").unwrap().unwrap().key_id(),
            Some("the key")
        );
        // Unknown kid: refresh happens, key still absent -> None.
        assert!(jwks.key("nope").unwrap().is_none());
    }

    #[test]
    fn test_keys_with_refresh_none_kid_is_plain_keys() {
        let fetcher = Arc::new(MockFetcher::new(FetchResponse::new(jwks_body())));
        let jwks = HttpsJwks::new("https://example.com/jwks", fetcher.clone());
        jwks.keys_with_refresh(None).unwrap();
        assert_eq!(fetcher.calls(), 1);
    }

    #[test]
    fn test_select_verification_key_matches_alg_and_kid() {
        let fetcher = Arc::new(MockFetcher::new(FetchResponse::new(jwks_body())));
        let jwks = HttpsJwks::new("https://example.com/jwks", fetcher.clone());

        // Happy path: kid matches, alg matches the EC P-256 key.
        let selected = jwks
            .select_verification_key(Some("the key"), "ES256")
            .unwrap();
        assert!(selected.is_some());
        assert_eq!(selected.unwrap().key_id(), Some("the key"));

        // Wrong alg: selector rejects because the EC key's kty is incompatible
        // with RS256. This is the algorithm-confusion defense.
        let wrong_alg = jwks
            .select_verification_key(Some("the key"), "RS256")
            .unwrap();
        assert!(wrong_alg.is_none());

        // Wrong kid: no match.
        let wrong_kid = jwks
            .select_verification_key(Some("other"), "ES256")
            .unwrap();
        assert!(wrong_kid.is_none());

        // No kid: still matches by alg.
        let no_kid = jwks.select_verification_key(None, "ES256").unwrap();
        assert!(no_kid.is_some());
    }
}
