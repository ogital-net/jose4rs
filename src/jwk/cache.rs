//! Shared cache-directive parsing for the sync and async JWKS fetchers.
//!
//! Compiled when either `jwks-https` or `jwks-https-async` is enabled, since
//! both fetchers need to interpret the same `Cache-Control` / `Expires`
//! headers.

use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CachePolicy {
    CacheFor {
        lifetime: Duration,
        must_revalidate: bool,
    },
    Revalidate,
    DoNotStore,
}

pub(crate) fn apply_minimum_cache_duration(
    policy: CachePolicy,
    minimum_cache_duration: Duration,
) -> CachePolicy {
    if minimum_cache_duration.is_zero() {
        return policy;
    }

    match policy {
        CachePolicy::CacheFor {
            lifetime,
            must_revalidate,
        } => CachePolicy::CacheFor {
            lifetime: lifetime.max(minimum_cache_duration),
            must_revalidate,
        },
        CachePolicy::Revalidate | CachePolicy::DoNotStore => CachePolicy::CacheFor {
            lifetime: minimum_cache_duration,
            must_revalidate: true,
        },
    }
}

pub(crate) fn compute_cache_policy(
    cache_control: Option<&str>,
    expires: Option<&str>,
    age: Option<Duration>,
    default_cache_duration: Duration,
) -> CachePolicy {
    let directives = cache_control.map(parse_cache_control).unwrap_or_default();

    // 1) no-store: refuse to cache.
    if directives
        .iter()
        .any(|d| matches!(d, CacheDirective::NoStore))
    {
        return CachePolicy::DoNotStore;
    }

    // 2) no-cache: force revalidation each read, even with max-age present.
    let no_cache = directives
        .iter()
        .any(|d| matches!(d, CacheDirective::NoCache));
    if no_cache {
        return CachePolicy::Revalidate;
    }

    let must_revalidate = directives
        .iter()
        .any(|d| matches!(d, CacheDirective::MustRevalidate));

    // 3) This is a private application cache, so s-maxage does not apply.
    let freshness = directives
        .iter()
        .filter_map(|d| match d {
            CacheDirective::Freshness(dur) => Some(*dur),
            _ => None,
        })
        .min();

    if let Some(dur) = freshness {
        return CachePolicy::CacheFor {
            lifetime: Duration::from_secs(dur).saturating_sub(age.unwrap_or_default()),
            must_revalidate,
        };
    }

    // 4) Fall back to Expires.
    if let Some(expires) = expires {
        return CachePolicy::CacheFor {
            // RFC 9111 section 5.3 requires invalid Expires values to be
            // interpreted as already expired.
            lifetime: Duration::from_secs(parse_http_date_remaining(expires).unwrap_or(0)),
            must_revalidate,
        };
    }

    // 5) Last resort: the configured default.
    CachePolicy::CacheFor {
        lifetime: default_cache_duration.saturating_sub(age.unwrap_or_default()),
        must_revalidate,
    }
}

/// A single parsed directive from a `Cache-Control` response header.
#[derive(Debug, PartialEq, Eq)]
enum CacheDirective {
    /// `max-age=<seconds>` -- seconds to freshness.
    Freshness(u64),
    /// `no-cache` -- must revalidate before reuse.
    NoCache,
    /// `no-store` -- must not be stored at all.
    NoStore,
    /// `must-revalidate` -- stale responses must not be reused.
    MustRevalidate,
}

/// Parses a `Cache-Control` header value into a list of directives.
///
/// Splits on `,`, trims whitespace, lowercases the directive name, and parses
/// the parameter. Unknown directives are ignored. A directive with a missing
/// or unparseable parameter is ignored. Invalid `max-age` values are treated
/// as zero, and values larger than RFC 9111's delta-seconds limit are capped.
fn parse_cache_control(value: &str) -> Vec<CacheDirective> {
    let mut out = Vec::new();
    for raw in value.split(',') {
        let part = raw.trim_ascii();
        if part.is_empty() {
            continue;
        }
        let mut it = part.splitn(2, '=');
        let name = it.next().unwrap_or("").trim_ascii().to_ascii_lowercase();
        let arg = it.next().map(str::trim_ascii);
        match (name.as_str(), arg) {
            ("max-age", Some(v)) => out.push(CacheDirective::Freshness(parse_delta_seconds(v))),
            ("no-cache", _) => out.push(CacheDirective::NoCache),
            ("no-store", _) => out.push(CacheDirective::NoStore),
            ("must-revalidate", _) => out.push(CacheDirective::MustRevalidate),
            _ => {}
        }
    }
    out
}

fn parse_delta_seconds(value: &str) -> u64 {
    const MAX_DELTA_SECONDS: u64 = 2_147_483_648;

    value
        .trim_matches('"')
        .parse::<u128>()
        .map_or(0, |seconds| seconds.min(MAX_DELTA_SECONDS.into()) as u64)
}

/// Parses an HTTP-date (`Expires` header) and returns the whole seconds
/// remaining until then. Returns `None` if the date can't be parsed.
///
/// Only the IMF-fixdate format (the required HTTP-date form) is supported,
/// e.g. `Sun, 06 Nov 1994 08:49:37 GMT`.
pub(super) fn parse_http_date_remaining(date: &str) -> Option<u64> {
    let then = httpdate::parse_http_date(date).ok()?;
    Some(
        then.duration_since(std::time::SystemTime::now())
            .unwrap_or_default()
            .as_secs(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_max_age() {
        assert_eq!(
            compute_cache_policy(Some("max-age=3600"), None, None, Duration::from_secs(60)),
            CachePolicy::CacheFor {
                lifetime: Duration::from_secs(3600),
                must_revalidate: false
            }
        );
        assert_eq!(
            compute_cache_policy(
                Some("public, max-age=60"),
                None,
                None,
                Duration::from_secs(60)
            ),
            CachePolicy::CacheFor {
                lifetime: Duration::from_secs(60),
                must_revalidate: false
            }
        );
        assert_eq!(
            compute_cache_policy(Some("max-age=0"), None, None, Duration::from_secs(60)),
            CachePolicy::CacheFor {
                lifetime: Duration::ZERO,
                must_revalidate: false
            }
        );
        assert_eq!(
            compute_cache_policy(Some("MAX-AGE=120"), None, None, Duration::from_secs(60)),
            CachePolicy::CacheFor {
                lifetime: Duration::from_secs(120),
                must_revalidate: false
            }
        );
        assert_eq!(
            compute_cache_policy(Some("max-age = 30"), None, None, Duration::from_secs(60)),
            CachePolicy::CacheFor {
                lifetime: Duration::from_secs(30),
                must_revalidate: false
            }
        );
        // no-cache means must-revalidate on next read, even with max-age.
        assert_eq!(
            compute_cache_policy(Some("no-cache"), None, None, Duration::from_secs(60)),
            CachePolicy::Revalidate
        );
        assert_eq!(
            compute_cache_policy(
                Some("no-cache, max-age=300"),
                None,
                None,
                Duration::from_secs(60)
            ),
            CachePolicy::Revalidate
        );
        // s-maxage applies only to shared caches and is ignored here.
        assert_eq!(
            compute_cache_policy(Some("s-maxage=10"), None, None, Duration::from_secs(60)),
            CachePolicy::CacheFor {
                lifetime: Duration::from_secs(60),
                must_revalidate: false
            }
        );
        // Multiple max-age: take the smallest (most restrictive).
        assert_eq!(
            compute_cache_policy(
                Some("max-age=120, max-age=60"),
                None,
                None,
                Duration::from_secs(60)
            ),
            CachePolicy::CacheFor {
                lifetime: Duration::from_secs(60),
                must_revalidate: false
            }
        );
        // max-age controls private caches when s-maxage is also present.
        assert_eq!(
            compute_cache_policy(
                Some("max-age=120, s-maxage=30"),
                None,
                None,
                Duration::from_secs(60)
            ),
            CachePolicy::CacheFor {
                lifetime: Duration::from_secs(120),
                must_revalidate: false
            }
        );
        // no-store: no caching at all.
        assert_eq!(
            compute_cache_policy(Some("no-store"), None, None, Duration::from_secs(60)),
            CachePolicy::DoNotStore
        );
        assert_eq!(
            compute_cache_policy(
                Some("no-store, max-age=60"),
                None,
                None,
                Duration::from_secs(60)
            ),
            CachePolicy::DoNotStore
        );
        // Garbage values fall back to the default.
        assert_eq!(
            compute_cache_policy(Some("max-age=abc"), None, None, Duration::from_secs(60)),
            CachePolicy::CacheFor {
                lifetime: Duration::ZERO,
                must_revalidate: false
            }
        );
        assert_eq!(
            compute_cache_policy(
                Some("max-age=60, must-revalidate"),
                None,
                Some(Duration::from_secs(10)),
                Duration::from_secs(30)
            ),
            CachePolicy::CacheFor {
                lifetime: Duration::from_secs(50),
                must_revalidate: true
            }
        );
        assert_eq!(
            compute_cache_policy(
                Some("max-age=60"),
                None,
                Some(Duration::from_secs(90)),
                Duration::from_secs(30)
            ),
            CachePolicy::CacheFor {
                lifetime: Duration::ZERO,
                must_revalidate: false
            }
        );
        assert_eq!(
            compute_cache_policy(
                Some("max-age=999999999999999999999"),
                None,
                None,
                Duration::from_secs(30)
            ),
            CachePolicy::CacheFor {
                lifetime: Duration::from_secs(2_147_483_648),
                must_revalidate: false
            }
        );
        for expires in ["Sun, 06 Nov 1994 08:49:37 GMT", "not a date"] {
            assert_eq!(
                compute_cache_policy(None, Some(expires), None, Duration::from_secs(30)),
                CachePolicy::CacheFor {
                    lifetime: Duration::ZERO,
                    must_revalidate: false
                }
            );
        }
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
        // s-maxage applies only to shared caches.
        assert!(parse_cache_control("s-maxage=42").is_empty());
        // Invalid freshness is conservatively considered stale.
        assert_eq!(
            parse_cache_control("max-age=-1"),
            vec![CacheDirective::Freshness(0)]
        );
        // Mixed directives, with surrounding whitespace.
        let parsed = parse_cache_control("  no-cache , max-age=10 , no-store  ");
        assert!(parsed.contains(&CacheDirective::NoCache));
        assert!(parsed.contains(&CacheDirective::NoStore));
        assert!(parsed.contains(&CacheDirective::Freshness(10)));
        assert_eq!(parse_delta_seconds("999999999999999999999"), 2_147_483_648);
    }

    #[test]
    fn test_parse_http_date() {
        // Remaining seconds for a far-future date should be positive.
        let future_date =
            httpdate::fmt_http_date(std::time::SystemTime::now() + Duration::from_secs(3600));
        let future = parse_http_date_remaining(&future_date);
        assert!(future.is_some() && future.unwrap() > 0);
        // A past date saturates to 0.
        assert_eq!(
            parse_http_date_remaining("Sun, 06 Nov 1994 08:49:37 GMT"),
            Some(0)
        );
        // Garbage.
        assert_eq!(parse_http_date_remaining("not a date"), None);
        // Obsolete HTTP-date forms are accepted by HTTP recipients.
        assert_eq!(
            parse_http_date_remaining("Sunday, 06-Nov-94 08:49:37 GMT"),
            Some(0)
        );
    }

    #[test]
    fn test_apply_minimum_cache_duration() {
        let minimum = Duration::from_secs(60);
        for policy in [CachePolicy::Revalidate, CachePolicy::DoNotStore] {
            assert_eq!(
                apply_minimum_cache_duration(policy, minimum),
                CachePolicy::CacheFor {
                    lifetime: minimum,
                    must_revalidate: true
                }
            );
        }
        assert_eq!(
            apply_minimum_cache_duration(
                CachePolicy::CacheFor {
                    lifetime: Duration::ZERO,
                    must_revalidate: false
                },
                minimum
            ),
            CachePolicy::CacheFor {
                lifetime: minimum,
                must_revalidate: false
            }
        );
        assert_eq!(
            apply_minimum_cache_duration(CachePolicy::DoNotStore, Duration::ZERO),
            CachePolicy::DoNotStore
        );
    }
}
