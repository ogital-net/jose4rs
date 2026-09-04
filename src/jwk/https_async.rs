//! Async JWKS fetching for async runtimes (e.g. tokio).
//!
//! Enabled by the `jwks-https-async` feature. Provides a native-async
//! counterpart to the blocking [`JwksFetcher`](super::JwksFetcher) so async
//! applications don't have to bridge a blocking call into their runtime. The
//! cache-directive handling is identical to [`HttpsJwks`](super::HttpsJwks);
//! only the transport is async.
//!
//! The cache lock is a plain `std::sync::RwLock` held only for the brief
//! read/write of the in-memory snapshot -- never across an `.await` -- so this
//! stays runtime-agnostic (no tokio dependency) and safe to use from any
//! executor.

use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use super::https::{
    DEFAULT_CACHE_DURATION, DEFAULT_MINIMUM_CACHE_DURATION, FetchResponse,
    KID_MISS_REFRESH_COOLDOWN, REFRESH_REPRIEVE_THRESHOLD,
};
use super::{JsonWebKey, JsonWebKeySet};
use crate::error::JoseError;

/// A boxed future returned by [`AsyncJwksFetcher::fetch`].
///
/// Native `async fn` in a `dyn`-compatible trait isn't object-safe to call, so
/// the trait returns an explicit boxed future instead. This is exactly what the
/// `async-trait` crate expands to, but with no dependency. Implementors write a
/// normal `async fn` and box it: `Box::pin(async move { ... })`.
pub type FetchFuture<'a> = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<FetchResponse, JoseError>> + Send + 'a>,
>;

/// Async variant of [`JwksFetcher`](super::JwksFetcher).
///
/// Implement this over your async HTTP client (reqwest, hyper, etc.). Return
/// an error for non-success statuses and surface the `Cache-Control` /
/// `Expires` / `Age` headers so the cache can honor them.
///
/// # Example
///
/// ```ignore
/// # use jose4rs::jwk::{AsyncJwksFetcher, FetchFuture, FetchResponse};
/// # use jose4rs::error::JoseError;
/// struct MyFetcher { client: reqwest::Client }
/// impl AsyncJwksFetcher for MyFetcher {
///     fn fetch<'a>(&'a self, url: &'a str) -> FetchFuture<'a> {
///         Box::pin(async move {
///             let resp = self.client.get(url).send().await.map_err(|e| JoseError::JwksFetch(e.to_string()))?;
///             let cache_control = resp.headers().get("cache-control")
///                 .and_then(|v| v.to_str().ok()).map(str::to_owned);
///             let expires = resp.headers().get("expires")
///                 .and_then(|v| v.to_str().ok()).map(str::to_owned);
///             let age = resp.headers().get("age").and_then(|v| v.to_str().ok())
///                 .and_then(|v| v.parse().ok()).map(std::time::Duration::from_secs);
///             let body = resp.bytes().await.map_err(|e| JoseError::JwksFetch(e.to_string()))?.to_vec();
///             Ok(FetchResponse { body, cache_control, expires, age })
///         })
///     }
/// }
/// ```
pub trait AsyncJwksFetcher: Send + Sync {
    /// Fetches the JWKS document from `url`.
    fn fetch<'a>(&'a self, url: &'a str) -> FetchFuture<'a>;
}

/// A caching async JWKS fetcher.
///
/// Cheap to clone (state is shared). Concurrent stale reads share one refresh;
/// subsequent readers reuse the refreshed entry.
pub struct AsyncHttpsJwks {
    url: String,
    fetcher: Arc<dyn AsyncJwksFetcher>,
    state: Arc<AsyncShared>,
}

impl std::fmt::Debug for AsyncHttpsJwks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AsyncHttpsJwks")
            .field("url", &self.url)
            .finish_non_exhaustive()
    }
}

struct AsyncShared {
    cache: RwLock<AsyncCache>,
    refresh_lock: futures_util::lock::Mutex<()>,
    default_cache_duration: Duration,
    minimum_cache_duration: Duration,
    retain_cache_on_error: Duration,
    /// Last time a kid-miss refresh was attempted (penalty box).
    last_kid_miss_refresh: Mutex<Option<Instant>>,
}

#[derive(Clone)]
struct AsyncCache {
    keys: Arc<Vec<JsonWebKey>>,
    fresh_until: Option<Instant>,
    stale_until: Option<Instant>,
    retry_after: Option<Instant>,
    generation: u64,
}

impl AsyncCache {
    fn empty() -> Self {
        Self {
            keys: Arc::new(Vec::new()),
            fresh_until: None,
            stale_until: None,
            retry_after: None,
            generation: 0,
        }
    }
}

impl AsyncHttpsJwks {
    /// Creates a caching async fetcher for `url` using `fetcher` for transport.
    pub fn new(url: impl Into<String>, fetcher: Arc<dyn AsyncJwksFetcher>) -> Self {
        Self {
            url: url.into(),
            fetcher,
            state: Arc::new(AsyncShared {
                cache: RwLock::new(AsyncCache::empty()),
                refresh_lock: futures_util::lock::Mutex::new(()),
                default_cache_duration: DEFAULT_CACHE_DURATION,
                minimum_cache_duration: DEFAULT_MINIMUM_CACHE_DURATION,
                retain_cache_on_error: Duration::ZERO,
                last_kid_miss_refresh: Mutex::new(None),
            }),
        }
    }

    /// Sets the cache lifetime used when the response has no cache directives.
    ///
    /// # Panics
    ///
    /// Panics if the `AsyncHttpsJwks` has already been cloned (shared).
    pub fn set_default_cache_duration(&mut self, d: Duration) {
        Arc::get_mut(&mut self.state)
            .expect("cannot set_default_cache_duration on a shared AsyncHttpsJwks")
            .default_cache_duration = d;
    }

    /// Sets the minimum time a successfully fetched JWKS is reused.
    ///
    /// The default is [`DEFAULT_MINIMUM_CACHE_DURATION`]. This floor prevents
    /// strict response directives from causing a fetch for every token. A
    /// `kid` miss and [`refresh`](Self::refresh) still bypass it. Set this to
    /// zero to honor `no-cache`, `no-store`, and zero lifetimes strictly.
    ///
    /// # Panics
    ///
    /// Panics if the `AsyncHttpsJwks` has already been cloned (shared).
    pub fn set_minimum_cache_duration(&mut self, d: Duration) {
        Arc::get_mut(&mut self.state)
            .expect("cannot set_minimum_cache_duration on a shared AsyncHttpsJwks")
            .minimum_cache_duration = d;
    }

    /// Sets how long keys may remain usable after freshness expires when a
    /// refresh fails. Zero (the default) propagates fetch errors.
    ///
    /// # Panics
    ///
    /// Panics if the `AsyncHttpsJwks` has already been cloned (shared).
    pub fn set_retain_cache_on_error(&mut self, d: Duration) {
        Arc::get_mut(&mut self.state)
            .expect("cannot set_retain_cache_on_error on a shared AsyncHttpsJwks")
            .retain_cache_on_error = d;
    }

    /// Pre-seeds the cache with the given keys, valid for `ttl`.
    ///
    /// On the next [`keys`](Self::keys) call within `ttl`, no HTTP fetch is
    /// performed. Useful when the consumer (e.g. an OIDC client) has already
    /// obtained the JWKS via discovery and wants to skip a redundant fetch.
    ///
    /// `seed` always overwrites any existing cache entry.
    ///
    /// # Panics
    ///
    /// Panics if an internal lock is poisoned.
    pub fn seed(&self, keys: Vec<JsonWebKey>, ttl: Duration) {
        let now = Instant::now();
        let keys = Arc::new(keys);
        let mut cache = self.state.cache.write().unwrap();
        let fresh_until = now.checked_add(ttl);
        *cache = AsyncCache {
            keys,
            fresh_until,
            stale_until: fresh_until
                .and_then(|fresh| fresh.checked_add(self.state.retain_cache_on_error)),
            retry_after: None,
            generation: cache.generation.wrapping_add(1),
        };
    }

    /// Convenience wrapper over [`seed`](Self::seed) that parses a raw JWKS
    /// JSON document and seeds the cache with the default TTL.
    ///
    /// # Errors
    ///
    /// Returns an error if the JSON is malformed or has no `"keys"` member.
    pub fn seed_from_json(&self, body: impl AsRef<[u8]>) -> Result<(), JoseError> {
        let set = JsonWebKeySet::from_json(body)?;
        let keys = set.into_keys();
        self.seed(keys, self.state.default_cache_duration);
        Ok(())
    }

    /// Returns the current keys, refreshing from the endpoint if stale.
    ///
    /// # Errors
    ///
    /// Returns an error if the fetch fails and no stale keys are retained.
    ///
    /// # Panics
    ///
    /// Panics if an internal lock is poisoned.
    pub async fn keys(&self) -> Result<Arc<Vec<JsonWebKey>>, JoseError> {
        // Fast path before acquiring the async single-flight lock.
        {
            let cache = self.state.cache.read().unwrap();
            let now = Instant::now();
            if cache.fresh_until.is_some_and(|t| now < t)
                || cache.retry_after.is_some_and(|t| now < t)
            {
                return Ok(cache.keys.clone());
            }
        }

        let _guard = self.state.refresh_lock.lock().await;

        // Re-check after acquiring the lock: another task may have refreshed.
        let prior = {
            let cache = self.state.cache.read().unwrap().clone();
            let now = Instant::now();
            if cache.fresh_until.is_some_and(|t| now < t)
                || cache.retry_after.is_some_and(|t| now < t)
            {
                return Ok(cache.keys.clone());
            }
            cache
        };

        match self.fetch_and_parse().await {
            Ok((keys, cache_policy)) => {
                let now = Instant::now();
                let keys = Arc::new(keys);
                let mut cache = self.state.cache.write().unwrap();
                if cache.generation != prior.generation {
                    return Ok(cache.keys.clone());
                }
                let generation = cache.generation.wrapping_add(1);
                *cache = match cache_policy {
                    super::cache::CachePolicy::CacheFor {
                        lifetime,
                        must_revalidate,
                    } => {
                        let fresh_until = now.checked_add(lifetime);
                        AsyncCache {
                            keys: keys.clone(),
                            fresh_until,
                            stale_until: (!must_revalidate)
                                .then_some(fresh_until)
                                .flatten()
                                .and_then(|fresh| {
                                    fresh.checked_add(self.state.retain_cache_on_error)
                                }),
                            retry_after: None,
                            generation,
                        }
                    }
                    super::cache::CachePolicy::Revalidate
                    | super::cache::CachePolicy::DoNotStore => AsyncCache {
                        keys: Arc::new(Vec::new()),
                        fresh_until: None,
                        stale_until: None,
                        retry_after: None,
                        generation,
                    },
                };
                Ok(keys)
            }
            Err(e) => {
                let now = Instant::now();
                let mut cache = self.state.cache.write().unwrap();
                if cache.generation != prior.generation {
                    return Ok(cache.keys.clone());
                }
                if !prior.keys.is_empty() && prior.stale_until.is_some_and(|until| now < until) {
                    cache.retry_after = now
                        .checked_add(REFRESH_REPRIEVE_THRESHOLD)
                        .map(|retry| retry.min(prior.stale_until.unwrap()));
                    return Ok(cache.keys.clone());
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
    pub async fn refresh(&self) -> Result<Arc<Vec<JsonWebKey>>, JoseError> {
        {
            let mut cache = self.state.cache.write().unwrap();
            cache.fresh_until = None;
            cache.retry_after = None;
        }
        self.keys().await
    }

    /// Returns the keys, forcing a refresh first if `kid` is not in the
    /// current cache (a key-rotation kid miss).
    ///
    /// Use this in a JWT verify path: parse the (unverified) header's `kid`,
    /// call `keys_with_refresh(kid)`, then run a [`super::VerificationJwkSelector`]
    /// over the result. Kid-miss refreshes are rate-limited to one per
    /// [`KID_MISS_REFRESH_COOLDOWN`] to avoid flooding the endpoint when a
    /// token references an unknown `kid`.
    ///
    /// # Errors
    ///
    /// Returns an error if the fetch fails and no stale keys are retained.
    ///
    /// # Panics
    ///
    /// Panics if an internal lock is poisoned.
    pub async fn keys_with_refresh(
        &self,
        kid: Option<&str>,
    ) -> Result<Arc<Vec<JsonWebKey>>, JoseError> {
        let keys = self.keys().await?;
        let Some(kid) = kid else {
            return Ok(keys);
        };
        if keys.iter().any(|k| k.key_id() == Some(kid)) {
            return Ok(keys);
        }
        {
            let mut last = self.state.last_kid_miss_refresh.lock().unwrap();
            if last.is_some_and(|t| t.elapsed() < KID_MISS_REFRESH_COOLDOWN) {
                return Ok(keys);
            }
            *last = Some(Instant::now());
        }
        self.force_refresh().await
    }

    /// Returns the key whose `kid` matches, refreshing once on a miss.
    ///
    /// # Errors
    ///
    /// Returns an error if the fetch fails and no stale keys are retained.
    pub async fn key(&self, kid: &str) -> Result<Option<JsonWebKey>, JoseError> {
        let keys = self.keys_with_refresh(Some(kid)).await?;
        Ok(keys.iter().find(|k| k.key_id() == Some(kid)).cloned())
    }

    /// Selects a JWS verification key from the JWKS for a JWS with the given
    /// `kid` and `alg` header values.
    ///
    /// This is the one-call OIDC ID-token path: it triggers a cache-refreshing
    /// fetch on a `kid` miss (the key-rotation case), then runs a
    /// [`super::VerificationJwkSelector`] over the result. The selector
    /// enforces that the key's `kty` is compatible with `alg` (the
    /// algorithm-confusion defense), narrows by curve for EC algorithms, and
    /// matches `use: "sig"` if the JWK declares one. Returns the single best
    /// candidate, or `None` if no key matches.
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
    pub async fn select_verification_key(
        &self,
        kid: Option<&str>,
        alg: &str,
    ) -> Result<Option<JsonWebKey>, JoseError> {
        let keys = self.keys_with_refresh(kid).await?;
        Ok(super::VerificationJwkSelector::new()
            .select(kid, alg, &keys)
            .cloned())
    }

    /// Refreshes unconditionally, ignoring the refresh-reprieve threshold.
    async fn force_refresh(&self) -> Result<Arc<Vec<JsonWebKey>>, JoseError> {
        {
            let mut cache = self.state.cache.write().unwrap();
            cache.fresh_until = None;
            cache.retry_after = None;
        }
        self.keys().await
    }

    async fn fetch_and_parse(
        &self,
    ) -> Result<(Vec<JsonWebKey>, super::cache::CachePolicy), JoseError> {
        let response = self.fetcher.fetch(&self.url).await?;
        let set = JsonWebKeySet::from_json(&response.body)?;
        let policy = super::cache::compute_cache_policy(
            response.cache_control.as_deref(),
            response.expires.as_deref(),
            response.age,
            self.state.default_cache_duration,
        );
        Ok((
            set.into_keys(),
            super::cache::apply_minimum_cache_duration(policy, self.state.minimum_cache_duration),
        ))
    }
}

impl Clone for AsyncHttpsJwks {
    fn clone(&self) -> Self {
        Self {
            url: self.url.clone(),
            fetcher: self.fetcher.clone(),
            state: self.state.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Barrier, mpsc};
    use std::task::{Context, Poll, Waker};

    const EC1: &str = r#"{"kty":"EC","use":"sig","kid":"the key","x":"amuk6RkDZi-48mKrzgBN_zUZ_9qupIwTZHJjM03qL-4","y":"ZOESj6_dpPiZZR-fJ-XVszQta28Cjgti7JudooQJ0co","crv":"P-256"}"#;

    fn jwks_body() -> Vec<u8> {
        format!(r#"{{"keys":[{EC1}]}}"#).into_bytes()
    }

    /// A minimal `block_on` for driving ready-immediately futures in tests, so
    /// the async cache can be exercised without pulling in a runtime.
    fn block_on<F: std::future::Future>(mut fut: F) -> F::Output {
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut fut = unsafe { std::pin::Pin::new_unchecked(&mut fut) };
        loop {
            match fut.as_mut().poll(&mut cx) {
                Poll::Ready(v) => return v,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    struct MockAsyncFetcher {
        calls: AtomicUsize,
    }

    impl AsyncJwksFetcher for MockAsyncFetcher {
        fn fetch<'a>(&'a self, _url: &'a str) -> FetchFuture<'a> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                Ok(FetchResponse::new(jwks_body()).with_cache_control("max-age=300"))
            })
        }
    }

    struct DirectiveAsyncFetcher {
        calls: AtomicUsize,
        cache_control: &'static str,
    }

    impl AsyncJwksFetcher for DirectiveAsyncFetcher {
        fn fetch<'a>(&'a self, _url: &'a str) -> FetchFuture<'a> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                Ok(FetchResponse::new(jwks_body()).with_cache_control(self.cache_control))
            })
        }
    }

    struct SequenceAsyncFetcher {
        responses: Mutex<VecDeque<Result<FetchResponse, JoseError>>>,
    }

    impl AsyncJwksFetcher for SequenceAsyncFetcher {
        fn fetch<'a>(&'a self, _url: &'a str) -> FetchFuture<'a> {
            let response = self
                .responses
                .lock()
                .unwrap()
                .pop_front()
                .expect("unexpected fetch");
            Box::pin(async move { response })
        }
    }

    #[test]
    fn test_async_fetch_and_cache_hit() {
        let fetcher = Arc::new(MockAsyncFetcher {
            calls: AtomicUsize::new(0),
        });
        let jwks = AsyncHttpsJwks::new("https://example.com/jwks", fetcher.clone());

        let keys = block_on(jwks.keys()).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(fetcher.calls.load(Ordering::SeqCst), 1);

        // Fresh cache: no second fetch.
        let keys = block_on(jwks.keys()).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(fetcher.calls.load(Ordering::SeqCst), 1);

        // Forced refresh fetches again.
        let keys = block_on(jwks.refresh()).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(fetcher.calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn test_async_minimum_cache_duration_prevents_fetch_per_verification() {
        for directive in ["no-store", "no-cache, max-age=300"] {
            let fetcher = Arc::new(DirectiveAsyncFetcher {
                calls: AtomicUsize::new(0),
                cache_control: directive,
            });
            let jwks = AsyncHttpsJwks::new("https://example.com/jwks", fetcher.clone());

            block_on(jwks.keys()).unwrap();
            block_on(jwks.keys()).unwrap();

            assert_eq!(fetcher.calls.load(Ordering::SeqCst), 1, "{directive}");
        }
    }

    #[test]
    fn test_async_zero_minimum_honors_strict_directives() {
        for directive in ["no-store", "no-cache, max-age=300"] {
            let fetcher = Arc::new(DirectiveAsyncFetcher {
                calls: AtomicUsize::new(0),
                cache_control: directive,
            });
            let mut jwks = AsyncHttpsJwks::new("https://example.com/jwks", fetcher.clone());
            jwks.set_minimum_cache_duration(Duration::ZERO);

            block_on(jwks.keys()).unwrap();
            block_on(jwks.keys()).unwrap();

            assert_eq!(fetcher.calls.load(Ordering::SeqCst), 2, "{directive}");
        }
    }

    #[test]
    fn test_async_must_revalidate_disables_stale_fallback() {
        let fetcher = Arc::new(SequenceAsyncFetcher {
            responses: Mutex::new(
                vec![
                    Ok(FetchResponse::new(jwks_body())
                        .with_cache_control("max-age=0, must-revalidate")),
                    Err(JoseError::JwksFetch("network down".into())),
                ]
                .into(),
            ),
        });
        let mut jwks = AsyncHttpsJwks::new("https://example.com/jwks", fetcher);
        jwks.set_retain_cache_on_error(Duration::from_secs(60));

        block_on(jwks.keys()).unwrap();
        assert!(block_on(jwks.refresh()).is_err());
    }

    #[test]
    fn test_async_refresh_is_single_flight_and_seed_wins() {
        struct BlockingAsyncFetcher {
            calls: AtomicUsize,
            started: mpsc::SyncSender<()>,
            release: Mutex<mpsc::Receiver<()>>,
        }

        impl AsyncJwksFetcher for BlockingAsyncFetcher {
            fn fetch<'a>(&'a self, _url: &'a str) -> FetchFuture<'a> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                Box::pin(async move {
                    self.started.send(()).unwrap();
                    self.release.lock().unwrap().recv().unwrap();
                    Ok(FetchResponse::new(jwks_body()).with_cache_control("max-age=300"))
                })
            }
        }

        let (started_tx, started_rx) = mpsc::sync_channel(0);
        let (release_tx, release_rx) = mpsc::sync_channel(0);
        let fetcher = Arc::new(BlockingAsyncFetcher {
            calls: AtomicUsize::new(0),
            started: started_tx,
            release: Mutex::new(release_rx),
        });
        let jwks = AsyncHttpsJwks::new("https://example.com/jwks", fetcher.clone());
        let barrier = Arc::new(Barrier::new(3));
        let mut handles = Vec::new();
        for _ in 0..2 {
            let fetching = jwks.clone();
            let barrier = barrier.clone();
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                block_on(fetching.keys())
            }));
        }

        barrier.wait();
        started_rx.recv().unwrap();
        let seeded = JsonWebKey::from_json(single_jwk_json("seeded")).unwrap();
        jwks.seed(vec![seeded], Duration::from_secs(60));
        release_tx.send(()).unwrap();

        for handle in handles {
            let keys = handle.join().unwrap().unwrap();
            assert_eq!(keys[0].key_id(), Some("seeded"));
        }
        assert_eq!(fetcher.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_async_kid_miss_refresh_and_cooldown() {
        let fetcher = Arc::new(MockAsyncFetcher {
            calls: AtomicUsize::new(0),
        });
        let jwks = AsyncHttpsJwks::new("https://example.com/jwks", fetcher.clone());
        block_on(jwks.keys()).unwrap();
        assert_eq!(fetcher.calls.load(Ordering::SeqCst), 1);

        // Matching kid: no refresh.
        block_on(jwks.keys_with_refresh(Some("the key"))).unwrap();
        assert_eq!(fetcher.calls.load(Ordering::SeqCst), 1);

        // Unknown kid: one refresh, then cooled down.
        block_on(jwks.keys_with_refresh(Some("unknown"))).unwrap();
        assert_eq!(fetcher.calls.load(Ordering::SeqCst), 2);
        block_on(jwks.keys_with_refresh(Some("unknown"))).unwrap();
        assert_eq!(fetcher.calls.load(Ordering::SeqCst), 2);

        // key() convenience: found and not-found.
        assert_eq!(
            block_on(jwks.key("the key")).unwrap().unwrap().key_id(),
            Some("the key")
        );
        assert!(block_on(jwks.key("nope")).unwrap().is_none());
    }

    #[test]
    fn test_async_select_verification_key_matches_alg_and_kid() {
        let fetcher = Arc::new(MockAsyncFetcher {
            calls: AtomicUsize::new(0),
        });
        let jwks = AsyncHttpsJwks::new("https://example.com/jwks", fetcher.clone());

        // Happy path: kid matches, alg matches the EC P-256 key.
        let selected = block_on(jwks.select_verification_key(Some("the key"), "ES256")).unwrap();
        assert!(selected.is_some());
        assert_eq!(selected.unwrap().key_id(), Some("the key"));

        // Wrong alg: selector rejects because the EC key's kty is incompatible
        // with RS256. This is the algorithm-confusion defense.
        let wrong_alg = block_on(jwks.select_verification_key(Some("the key"), "RS256")).unwrap();
        assert!(wrong_alg.is_none());

        // Wrong kid: no match (and a kid-miss refresh fires once).
        let wrong_kid = block_on(jwks.select_verification_key(Some("other"), "ES256")).unwrap();
        assert!(wrong_kid.is_none());
        assert_eq!(fetcher.calls.load(Ordering::SeqCst), 2);

        // No kid: still matches by alg.
        let no_kid = block_on(jwks.select_verification_key(None, "ES256")).unwrap();
        assert!(no_kid.is_some());
    }

    // ---------- seed / seed_from_json tests ----------

    fn single_jwk_json(kid: &str) -> Vec<u8> {
        // Minimal valid single JWK (no JWKS wrapper), suitable for
        // `JsonWebKey::from_json` / `seed()`.
        format!(
            r#"{{"kty":"EC","kid":"{kid}","crv":"P-256","x":"amuk6RkDZi-48mKrzgBN_zUZ_9qupIwTZHJjM03qL-4","y":"ZOESj6_dpPiZZR-fJ-XVszQta28Cjgti7JudooQJ0co"}}"#
        )
        .into_bytes()
    }

    /// A fetcher whose `fetch` errors if invoked. Used to prove that a seeded
    /// cache short-circuits network access entirely.
    struct FailingAsyncFetcher;
    impl AsyncJwksFetcher for FailingAsyncFetcher {
        fn fetch<'a>(&'a self, _url: &'a str) -> FetchFuture<'a> {
            Box::pin(async { Err(JoseError::JwksFetch("fetcher should not be called".into())) })
        }
    }

    #[test]
    fn test_seed_populates_cache_without_calling_fetcher() {
        let jwks = AsyncHttpsJwks::new("https://example.com/jwks", Arc::new(FailingAsyncFetcher));
        let key = JsonWebKey::from_json(single_jwk_json("seeded")).unwrap();
        jwks.seed(vec![key], Duration::from_secs(60));

        let keys = block_on(jwks.keys()).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].key_id(), Some("seeded"));
    }

    #[test]
    fn test_seed_overwrites_prior_fetched_entry() {
        // First response: 1 key with kid "the key". Second: kid "seeded".
        // The mock always returns the same canned body, so we can't observe
        // "fetcher not called" here -- instead, assert that seed() overwrites
        // by checking the returned kid.
        let fetcher = Arc::new(MockAsyncFetcher {
            calls: AtomicUsize::new(0),
        });
        let jwks = AsyncHttpsJwks::new("https://example.com/jwks", fetcher.clone());

        // Prime the cache.
        let first_keys = block_on(jwks.keys()).unwrap();
        assert_eq!(first_keys[0].key_id(), Some("the key"));
        let calls_after_prime = fetcher.calls.load(Ordering::SeqCst);

        // Seed with a different key.
        let seeded_key = JsonWebKey::from_json(single_jwk_json("seeded")).unwrap();
        jwks.seed(vec![seeded_key], Duration::from_secs(60));

        // The next read must come from the cache (the seeded entry), and must
        // not have triggered a fetch.
        let keys = block_on(jwks.keys()).unwrap();
        assert_eq!(keys[0].key_id(), Some("seeded"));
        assert_eq!(
            fetcher.calls.load(Ordering::SeqCst),
            calls_after_prime,
            "seed() must not call the fetcher"
        );
    }

    #[test]
    fn test_seed_resets_freshness_window() {
        let fetcher = Arc::new(MockAsyncFetcher {
            calls: AtomicUsize::new(0),
        });
        let jwks = AsyncHttpsJwks::new("https://example.com/jwks", fetcher.clone());

        // Prime the cache.
        block_on(jwks.keys()).unwrap();
        assert_eq!(fetcher.calls.load(Ordering::SeqCst), 1);

        // Seed with a long TTL.
        let seeded_key = JsonWebKey::from_json(single_jwk_json("seeded")).unwrap();
        jwks.seed(vec![seeded_key], Duration::from_secs(3600));

        // A second read returns the seeded entry, no fetch.
        let keys = block_on(jwks.keys()).unwrap();
        assert_eq!(keys[0].key_id(), Some("seeded"));
        assert_eq!(fetcher.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_seed_from_json_succeeds() {
        let jwks = AsyncHttpsJwks::new("https://example.com/jwks", Arc::new(FailingAsyncFetcher));
        jwks.seed_from_json(jwks_body()).unwrap();

        let keys = block_on(jwks.keys()).unwrap();
        assert_eq!(keys[0].key_id(), Some("the key"));
    }

    #[test]
    fn test_seed_from_json_rejects_invalid_json() {
        let jwks = AsyncHttpsJwks::new("https://example.com/jwks", Arc::new(FailingAsyncFetcher));
        let err = jwks.seed_from_json(b"not json at all").unwrap_err();
        let _ = format!("{err}");
    }

    #[test]
    fn test_seed_from_json_rejects_missing_keys_member() {
        let jwks = AsyncHttpsJwks::new("https://example.com/jwks", Arc::new(FailingAsyncFetcher));
        let err = jwks.seed_from_json(br#"{"other":"value"}"#).unwrap_err();
        let _ = format!("{err}");
    }
}
