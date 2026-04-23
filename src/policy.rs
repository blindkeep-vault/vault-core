use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_views: Option<i32>,
    #[serde(default = "default_allowed_ops")]
    pub allowed_ops: Vec<String>,
    #[serde(default)]
    pub notify_on_access: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_allowlist: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub one_shot: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub notarize_on_use: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

fn default_allowed_ops() -> Vec<String> {
    vec!["view".to_string(), "download".to_string()]
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            expires_at: None,
            ttl_seconds: None,
            max_views: None,
            allowed_ops: default_allowed_ops(),
            notify_on_access: false,
            ip_allowlist: None,
            one_shot: false,
            notarize_on_use: false,
        }
    }
}

impl Policy {
    /// Check whether access is currently allowed given the current time,
    /// view count, the time of first access, and the requested operation.
    /// Returns true if the grant is permanently expired due to time or view
    /// count limits. These conditions cannot be reversed by a different request.
    pub fn is_expired(
        &self,
        now: DateTime<Utc>,
        view_count: i32,
        first_accessed_at: Option<DateTime<Utc>>,
    ) -> bool {
        if let Some(expires_at) = self.expires_at {
            if now >= expires_at {
                return true;
            }
        }

        if let (Some(ttl), Some(first)) = (self.ttl_seconds, first_accessed_at) {
            let deadline = first + chrono::Duration::seconds(ttl);
            if now >= deadline {
                return true;
            }
        }

        if let Some(max) = self.max_views {
            if view_count >= max {
                return true;
            }
        }

        false
    }

    /// Check whether access is currently allowed given the current time,
    /// view count, the time of first access, and the requested operation.
    pub fn is_access_allowed(
        &self,
        now: DateTime<Utc>,
        view_count: i32,
        first_accessed_at: Option<DateTime<Utc>>,
        operation: &str,
        client_ip: Option<&str>,
    ) -> bool {
        // Check permanent expiry conditions
        if self.is_expired(now, view_count, first_accessed_at) {
            return false;
        }

        // Check allowed operations
        if !self.allowed_ops.contains(&operation.to_string()) {
            return false;
        }

        // Check IP allowlist (supports exact IPs and CIDR notation)
        if let Some(ref allowlist) = self.ip_allowlist {
            match client_ip {
                Some(ip) => {
                    if !ip_matches_allowlist(ip, allowlist) {
                        return false;
                    }
                }
                None => return false,
            }
        }

        true
    }
}

fn ip_matches_allowlist(client_ip: &str, allowlist: &[String]) -> bool {
    let addr: IpAddr = match client_ip.parse() {
        Ok(a) => a,
        Err(_) => return false,
    };

    allowlist.iter().any(|entry| {
        if let Some((network, prefix_str)) = entry.split_once('/') {
            // CIDR notation: e.g. "10.0.0.0/24" or "fd00::/64"
            let net_addr: IpAddr = match network.parse() {
                Ok(a) => a,
                Err(_) => return false,
            };
            let prefix_len: u32 = match prefix_str.parse() {
                Ok(p) => p,
                Err(_) => return false,
            };
            ip_in_cidr(addr, net_addr, prefix_len)
        } else {
            // Exact IP match
            entry.parse::<IpAddr>() == Ok(addr)
        }
    })
}

fn ip_in_cidr(addr: IpAddr, network: IpAddr, prefix_len: u32) -> bool {
    match (addr, network) {
        (IpAddr::V4(a), IpAddr::V4(n)) => {
            if prefix_len > 32 {
                return false;
            }
            let mask = if prefix_len == 0 {
                0u32
            } else {
                u32::MAX << (32 - prefix_len)
            };
            u32::from(a) & mask == u32::from(n) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(n)) => {
            if prefix_len > 128 {
                return false;
            }
            let mask = if prefix_len == 0 {
                0u128
            } else {
                u128::MAX << (128 - prefix_len)
            };
            u128::from(a) & mask == u128::from(n) & mask
        }
        _ => false, // v4 vs v6 mismatch
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn test_unlimited_policy_allows_access() {
        let policy = Policy {
            expires_at: None,
            ttl_seconds: None,
            max_views: None,
            allowed_ops: vec!["view".into(), "download".into()],
            notify_on_access: false,
            ip_allowlist: None,
            one_shot: false,
            notarize_on_use: false,
        };
        assert!(policy.is_access_allowed(Utc::now(), 0, None, "view", None));
        assert!(policy.is_access_allowed(Utc::now(), 100, None, "download", None));
    }

    #[test]
    fn test_expired_policy_denies() {
        let policy = Policy {
            expires_at: Some(Utc::now() - Duration::hours(1)),
            ttl_seconds: None,
            max_views: None,
            allowed_ops: vec!["view".into()],
            notify_on_access: false,
            ip_allowlist: None,
            one_shot: false,
            notarize_on_use: false,
        };
        assert!(!policy.is_access_allowed(Utc::now(), 0, None, "view", None));
    }

    #[test]
    fn test_max_views_enforced() {
        let policy = Policy {
            expires_at: None,
            ttl_seconds: None,
            max_views: Some(3),
            allowed_ops: vec!["view".into()],
            notify_on_access: false,
            ip_allowlist: None,
            one_shot: false,
            notarize_on_use: false,
        };
        assert!(policy.is_access_allowed(Utc::now(), 2, None, "view", None));
        assert!(!policy.is_access_allowed(Utc::now(), 3, None, "view", None));
    }

    #[test]
    fn test_disallowed_operation() {
        let policy = Policy {
            expires_at: None,
            ttl_seconds: None,
            max_views: None,
            allowed_ops: vec!["view".into()],
            notify_on_access: false,
            ip_allowlist: None,
            one_shot: false,
            notarize_on_use: false,
        };
        assert!(!policy.is_access_allowed(Utc::now(), 0, None, "download", None));
    }

    #[test]
    fn test_ttl_from_first_access() {
        let first = Utc::now() - Duration::seconds(3600);
        let policy = Policy {
            expires_at: None,
            ttl_seconds: Some(1800), // 30 minutes
            max_views: None,
            allowed_ops: vec!["view".into()],
            notify_on_access: false,
            ip_allowlist: None,
            one_shot: false,
            notarize_on_use: false,
        };
        // 1 hour since first access, TTL is 30 min → denied
        assert!(!policy.is_access_allowed(Utc::now(), 0, Some(first), "view", None));
    }

    #[test]
    fn test_ip_allowlist_allows_listed_ip() {
        let policy = Policy {
            expires_at: None,
            ttl_seconds: None,
            max_views: None,
            allowed_ops: vec!["view".into()],
            notify_on_access: false,
            ip_allowlist: Some(vec!["10.0.0.1".into(), "192.168.1.100".into()]),
            one_shot: false,
            notarize_on_use: false,
        };
        assert!(policy.is_access_allowed(Utc::now(), 0, None, "view", Some("10.0.0.1")));
        assert!(policy.is_access_allowed(Utc::now(), 0, None, "view", Some("192.168.1.100")));
    }

    #[test]
    fn test_ip_allowlist_denies_unlisted_ip() {
        let policy = Policy {
            expires_at: None,
            ttl_seconds: None,
            max_views: None,
            allowed_ops: vec!["view".into()],
            notify_on_access: false,
            ip_allowlist: Some(vec!["10.0.0.1".into()]),
            one_shot: false,
            notarize_on_use: false,
        };
        assert!(!policy.is_access_allowed(Utc::now(), 0, None, "view", Some("10.0.0.2")));
    }

    #[test]
    fn test_ip_allowlist_denies_when_no_client_ip() {
        let policy = Policy {
            expires_at: None,
            ttl_seconds: None,
            max_views: None,
            allowed_ops: vec!["view".into()],
            notify_on_access: false,
            ip_allowlist: Some(vec!["10.0.0.1".into()]),
            one_shot: false,
            notarize_on_use: false,
        };
        assert!(!policy.is_access_allowed(Utc::now(), 0, None, "view", None));
    }

    #[test]
    fn test_no_ip_allowlist_allows_any_ip() {
        let policy = Policy {
            expires_at: None,
            ttl_seconds: None,
            max_views: None,
            allowed_ops: vec!["view".into()],
            notify_on_access: false,
            ip_allowlist: None,
            one_shot: false,
            notarize_on_use: false,
        };
        assert!(policy.is_access_allowed(Utc::now(), 0, None, "view", Some("1.2.3.4")));
        assert!(policy.is_access_allowed(Utc::now(), 0, None, "view", None));
    }

    #[test]
    fn test_ip_cidr_v4_match() {
        let policy = Policy {
            expires_at: None,
            ttl_seconds: None,
            max_views: None,
            allowed_ops: vec!["view".into()],
            notify_on_access: false,
            ip_allowlist: Some(vec!["10.0.0.0/24".into()]),
            one_shot: false,
            notarize_on_use: false,
        };
        assert!(policy.is_access_allowed(Utc::now(), 0, None, "view", Some("10.0.0.1")));
        assert!(policy.is_access_allowed(Utc::now(), 0, None, "view", Some("10.0.0.254")));
        assert!(!policy.is_access_allowed(Utc::now(), 0, None, "view", Some("10.0.1.1")));
        assert!(!policy.is_access_allowed(Utc::now(), 0, None, "view", Some("192.168.0.1")));
    }

    #[test]
    fn test_ip_cidr_v4_wide() {
        let policy = Policy {
            expires_at: None,
            ttl_seconds: None,
            max_views: None,
            allowed_ops: vec!["view".into()],
            notify_on_access: false,
            ip_allowlist: Some(vec!["10.0.0.0/8".into()]),
            one_shot: false,
            notarize_on_use: false,
        };
        assert!(policy.is_access_allowed(Utc::now(), 0, None, "view", Some("10.255.255.255")));
        assert!(!policy.is_access_allowed(Utc::now(), 0, None, "view", Some("11.0.0.1")));
    }

    #[test]
    fn test_ip_cidr_v6() {
        let policy = Policy {
            expires_at: None,
            ttl_seconds: None,
            max_views: None,
            allowed_ops: vec!["view".into()],
            notify_on_access: false,
            ip_allowlist: Some(vec!["fd00::/16".into()]),
            one_shot: false,
            notarize_on_use: false,
        };
        assert!(policy.is_access_allowed(Utc::now(), 0, None, "view", Some("fd00::1")));
        assert!(policy.is_access_allowed(Utc::now(), 0, None, "view", Some("fd00:abcd::1")));
        assert!(!policy.is_access_allowed(Utc::now(), 0, None, "view", Some("fe80::1")));
    }

    #[test]
    fn test_one_shot_defaults_false_when_absent_in_json() {
        let policy: Policy = serde_json::from_str("{}").unwrap();
        assert!(!policy.one_shot);
        assert!(!policy.notarize_on_use);
    }

    #[test]
    fn test_one_shot_round_trip() {
        let policy = Policy {
            one_shot: true,
            notarize_on_use: true,
            ..Default::default()
        };
        let json = serde_json::to_string(&policy).unwrap();
        assert!(json.contains("\"one_shot\":true"));
        assert!(json.contains("\"notarize_on_use\":true"));
        let back: Policy = serde_json::from_str(&json).unwrap();
        assert!(back.one_shot);
        assert!(back.notarize_on_use);
    }

    #[test]
    fn test_false_flags_omitted_from_json() {
        let policy = Policy::default();
        let json = serde_json::to_string(&policy).unwrap();
        assert!(!json.contains("one_shot"));
        assert!(!json.contains("notarize_on_use"));
    }

    #[test]
    fn test_ip_mixed_exact_and_cidr() {
        let policy = Policy {
            expires_at: None,
            ttl_seconds: None,
            max_views: None,
            allowed_ops: vec!["view".into()],
            notify_on_access: false,
            ip_allowlist: Some(vec!["192.168.1.50".into(), "10.0.0.0/24".into()]),
            one_shot: false,
            notarize_on_use: false,
        };
        assert!(policy.is_access_allowed(Utc::now(), 0, None, "view", Some("192.168.1.50")));
        assert!(policy.is_access_allowed(Utc::now(), 0, None, "view", Some("10.0.0.42")));
        assert!(!policy.is_access_allowed(Utc::now(), 0, None, "view", Some("192.168.1.51")));
    }
}
