use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::RwLock;
use std::time::Instant;

use crate::error::ApiError;

/// Extract the real client IP from proxy headers.
/// Prefers x-envoy-external-address (set by Scaleway/Envoy), falls back to
/// the first entry in X-Forwarded-For (the original client).
pub fn xff_client_ip(headers: &[(String, String)]) -> Option<String> {
    // x-envoy-external-address is the most reliable on Envoy-based platforms
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("x-envoy-external-address") {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    // Fallback: first entry in XFF is the original client
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("x-forwarded-for") {
            return value.split(',').next().map(|s| s.trim().to_string());
        }
    }
    None
}

/// Extract client IP using XFF (only when trusted_proxy is set) with ConnectInfo fallback.
pub fn client_ip(
    headers: &[(String, String)],
    connect_info: Option<SocketAddr>,
    trusted_proxy: bool,
) -> Option<String> {
    if trusted_proxy {
        if let Some(ip) = xff_client_ip(headers) {
            return Some(ip);
        }
    }
    connect_info.map(|addr| addr.ip().to_string())
}

/// Same as client_ip but returns "unknown" instead of None.
pub fn client_ip_safe(
    headers: &[(String, String)],
    connect_info: Option<SocketAddr>,
    trusted_proxy: bool,
) -> String {
    client_ip(headers, connect_info, trusted_proxy).unwrap_or_else(|| "unknown".to_string())
}

/// Generic rate-limiter: allows `max` requests per `window_secs` per key.
/// Uses std RwLock (not tokio) so it works in both sync and async contexts.
pub fn check_rate_limit(
    limiter: &RwLock<HashMap<String, (u32, Instant)>>,
    key: &str,
    max: u32,
    window_secs: u64,
) -> Result<(), ApiError> {
    // Skip rate limiting in dev mode
    if std::env::var("DEV_MODE").is_ok() {
        return Ok(());
    }
    let now = Instant::now();
    let mut map = limiter.write().unwrap();
    if map.len() >= 100_000 {
        return Err(ApiError::TooManyRequests);
    }
    let entry = map.entry(key.to_string()).or_insert((0, now));
    if now.duration_since(entry.1).as_secs() >= window_secs {
        *entry = (1, now);
    } else {
        entry.0 += 1;
        if entry.0 > max {
            return Err(ApiError::TooManyRequests);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn socket(ip: [u8; 4]) -> Option<SocketAddr> {
        Some(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])),
            12345,
        ))
    }

    fn headers(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn xff_prefers_envoy_header() {
        let h = headers(&[
            ("x-envoy-external-address", "1.2.3.4"),
            ("x-forwarded-for", "5.6.7.8, 9.10.11.12"),
        ]);
        assert_eq!(xff_client_ip(&h), Some("1.2.3.4".to_string()));
    }

    #[test]
    fn xff_falls_back_to_forwarded_for() {
        let h = headers(&[("x-forwarded-for", "5.6.7.8, 9.10.11.12")]);
        assert_eq!(xff_client_ip(&h), Some("5.6.7.8".to_string()));
    }

    #[test]
    fn xff_returns_none_when_no_headers() {
        assert_eq!(xff_client_ip(&[]), None);
    }

    #[test]
    fn xff_ignores_empty_envoy_header() {
        let h = headers(&[
            ("x-envoy-external-address", "  "),
            ("x-forwarded-for", "5.6.7.8"),
        ]);
        assert_eq!(xff_client_ip(&h), Some("5.6.7.8".to_string()));
    }

    #[test]
    fn xff_trims_whitespace() {
        let h = headers(&[("x-envoy-external-address", "  1.2.3.4  ")]);
        assert_eq!(xff_client_ip(&h), Some("1.2.3.4".to_string()));
    }

    #[test]
    fn client_ip_trusted_proxy_uses_xff() {
        let h = headers(&[("x-forwarded-for", "10.0.0.1")]);
        assert_eq!(
            client_ip(&h, socket([192, 168, 1, 1]), true),
            Some("10.0.0.1".to_string()),
        );
    }

    #[test]
    fn client_ip_untrusted_proxy_ignores_xff() {
        let h = headers(&[("x-forwarded-for", "10.0.0.1")]);
        assert_eq!(
            client_ip(&h, socket([192, 168, 1, 1]), false),
            Some("192.168.1.1".to_string()),
        );
    }

    #[test]
    fn client_ip_falls_back_to_connect_info() {
        assert_eq!(
            client_ip(&[], socket([127, 0, 0, 1]), true),
            Some("127.0.0.1".to_string()),
        );
    }

    #[test]
    fn client_ip_returns_none_when_nothing_available() {
        assert_eq!(client_ip(&[], None, false), None);
    }

    #[test]
    fn client_ip_safe_returns_unknown_when_none() {
        assert_eq!(client_ip_safe(&[], None, false), "unknown");
    }

    #[test]
    fn client_ip_safe_returns_ip_when_available() {
        assert_eq!(
            client_ip_safe(&[], socket([10, 0, 0, 1]), false),
            "10.0.0.1",
        );
    }

    #[test]
    fn rate_limit_allows_within_limit() {
        std::env::remove_var("DEV_MODE");
        let limiter = RwLock::new(HashMap::new());
        for _ in 0..5 {
            assert!(check_rate_limit(&limiter, "key1", 5, 60).is_ok());
        }
    }

    #[test]
    fn rate_limit_blocks_over_limit() {
        std::env::remove_var("DEV_MODE");
        let limiter = RwLock::new(HashMap::new());
        for _ in 0..5 {
            check_rate_limit(&limiter, "key1", 5, 60).unwrap();
        }
        assert!(check_rate_limit(&limiter, "key1", 5, 60).is_err());
    }

    #[test]
    fn rate_limit_different_keys_independent() {
        std::env::remove_var("DEV_MODE");
        let limiter = RwLock::new(HashMap::new());
        for _ in 0..5 {
            check_rate_limit(&limiter, "key1", 5, 60).unwrap();
        }
        assert!(check_rate_limit(&limiter, "key2", 5, 60).is_ok());
    }
}
