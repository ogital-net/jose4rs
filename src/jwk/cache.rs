//! Shared cache-directive parsing for the sync and async JWKS fetchers.
//!
//! Compiled when either `jwks-https` or `jwks-https-async` is enabled, since
//! both fetchers need to interpret the same `Cache-Control` / `Expires`
//! headers.

use std::time::Duration;

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

    // 3) s-maxage > max-age; per RFC 9111 section 5.2.2, when multiple
    //    freshness lifetimes are present the most restrictive wins.
    let freshness = directives
        .iter()
        .filter_map(|d| match d {
            CacheDirective::Freshness(dur) => Some(*dur),
            _ => None,
        })
        .min();

    if let Some(dur) = freshness {
        return Duration::from_secs(dur);
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

/// Extracts the freshness lifetime from a `Cache-Control` header value.
///
/// Returns the smallest of `max-age` / `s-maxage` values present, per the
/// precedence rules of RFC 9111 section 5.2.2. `no-store` returns `None`,
/// since the response should not be stored at all. `no-cache` (without an
/// explicit freshness lifetime) also returns `None`, leaving the caller to
/// decide.
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

    #[test]
    fn test_parse_max_age() {
        assert_eq!(compute_cache_lifetime(Some("max-age=3600"), None, Duration::from_secs(60)), Duration::from_secs(3600));
        assert_eq!(compute_cache_lifetime(Some("public, max-age=60"), None, Duration::from_secs(60)), Duration::from_secs(60));
        assert_eq!(compute_cache_lifetime(Some("max-age=0"), None, Duration::from_secs(60)), Duration::ZERO);
        assert_eq!(compute_cache_lifetime(Some("MAX-AGE=120"), None, Duration::from_secs(60)), Duration::from_secs(120));
        assert_eq!(compute_cache_lifetime(Some("max-age = 30"), None, Duration::from_secs(60)), Duration::from_secs(30));
        // no-cache (without max-age) means must-revalidate on next read: zero.
        assert_eq!(compute_cache_lifetime(Some("no-cache"), None, Duration::from_secs(60)), Duration::ZERO);
        // s-maxage should be picked up.
        assert_eq!(compute_cache_lifetime(Some("s-maxage=10"), None, Duration::from_secs(60)), Duration::from_secs(10));
        // Multiple max-age: take the smallest (most restrictive).
        assert_eq!(compute_cache_lifetime(Some("max-age=120, max-age=60"), None, Duration::from_secs(60)), Duration::from_secs(60));
        // Mixed max-age / s-maxage: take the smallest of all freshness.
        assert_eq!(compute_cache_lifetime(Some("max-age=120, s-maxage=30"), None, Duration::from_secs(60)), Duration::from_secs(30));
        // no-store: no caching at all.
        assert_eq!(compute_cache_lifetime(Some("no-store"), None, Duration::from_secs(60)), Duration::ZERO);
        assert_eq!(compute_cache_lifetime(Some("no-store, max-age=60"), None, Duration::from_secs(60)), Duration::ZERO);
        // Garbage values fall back to the default.
        assert_eq!(compute_cache_lifetime(Some("max-age=abc"), None, Duration::from_secs(60)), Duration::from_secs(60));
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
}
