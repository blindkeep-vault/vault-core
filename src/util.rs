//! Shared utility functions used across clients and servers.
//!
//! These are pure helpers with no I/O, no network, no storage.

/// Convert a JSON array of numbers to a byte vector.
///
/// Returns an empty vec if the value is not an array.
/// Each element is read as `u64` and truncated to `u8`.
pub fn json_to_bytes(val: &serde_json::Value) -> Vec<u8> {
    match val.as_array() {
        Some(a) => a.iter().map(|v| v.as_u64().unwrap_or(0) as u8).collect(),
        None => Vec::new(),
    }
}

/// Convert a JSON array of numbers to a fixed 32-byte array.
///
/// Returns `None` if the value is not a 32-element array.
pub fn json_to_array32(val: &serde_json::Value) -> Option<[u8; 32]> {
    let bytes = json_to_bytes(val);
    if bytes.len() == 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Some(arr)
    } else {
        None
    }
}

/// Parse a human-readable duration string (e.g. `"24h"`, `"7d"`, `"1y"`).
///
/// Supported suffixes: `h` (hours), `d` (days), `y` (years, as 365 days).
pub fn parse_duration(s: &str) -> Result<chrono::Duration, String> {
    let s = s.trim();
    if let Some(hours) = s.strip_suffix('h') {
        let n: i64 = hours.parse().map_err(|_| "invalid number of hours")?;
        Ok(chrono::Duration::hours(n))
    } else if let Some(days) = s.strip_suffix('d') {
        let n: i64 = days.parse().map_err(|_| "invalid number of days")?;
        Ok(chrono::Duration::days(n))
    } else if let Some(years) = s.strip_suffix('y') {
        let n: i64 = years.parse().map_err(|_| "invalid number of years")?;
        Ok(chrono::Duration::days(n * 365))
    } else {
        Err(format!(
            "invalid expiry format '{}' (use e.g. '24h', '7d', or '1y')",
            s
        ))
    }
}

/// Trim, lowercase, and validate an email address.
///
/// Returns an error if the email is missing `@` or is too short.
pub fn normalize_email(raw: &str) -> Result<String, String> {
    let email = raw.trim().to_lowercase();
    if !email.contains('@') || email.len() < 3 {
        return Err("invalid email".into());
    }
    Ok(email)
}

/// Check that a string is exactly 64 lowercase hex characters (a 32-byte hash).
///
/// Returns `true` if valid, `false` otherwise.
pub fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // --- json_to_bytes ---

    #[test]
    fn json_to_bytes_array() {
        let val = json!([1, 2, 255, 0]);
        assert_eq!(json_to_bytes(&val), vec![1, 2, 255, 0]);
    }

    #[test]
    fn json_to_bytes_null() {
        assert_eq!(json_to_bytes(&json!(null)), Vec::<u8>::new());
    }

    #[test]
    fn json_to_bytes_string() {
        assert_eq!(json_to_bytes(&json!("hello")), Vec::<u8>::new());
    }

    #[test]
    fn json_to_bytes_empty_array() {
        assert_eq!(json_to_bytes(&json!([])), Vec::<u8>::new());
    }

    // --- json_to_array32 ---

    #[test]
    fn json_to_array32_valid() {
        let val = json!((0..32).collect::<Vec<u8>>());
        let arr = json_to_array32(&val).unwrap();
        assert_eq!(arr[0], 0);
        assert_eq!(arr[31], 31);
    }

    #[test]
    fn json_to_array32_wrong_length() {
        assert!(json_to_array32(&json!([1, 2, 3])).is_none());
    }

    #[test]
    fn json_to_array32_null() {
        assert!(json_to_array32(&json!(null)).is_none());
    }

    // --- parse_duration ---

    #[test]
    fn parse_hours() {
        assert_eq!(parse_duration("24h").unwrap(), chrono::Duration::hours(24));
    }

    #[test]
    fn parse_days() {
        assert_eq!(parse_duration("7d").unwrap(), chrono::Duration::days(7));
    }

    #[test]
    fn parse_years() {
        assert_eq!(parse_duration("1y").unwrap(), chrono::Duration::days(365));
    }

    #[test]
    fn parse_duration_with_whitespace() {
        assert_eq!(
            parse_duration("  12h  ").unwrap(),
            chrono::Duration::hours(12)
        );
    }

    #[test]
    fn parse_duration_invalid_suffix() {
        assert!(parse_duration("10m").is_err());
    }

    #[test]
    fn parse_duration_invalid_number() {
        assert!(parse_duration("abch").is_err());
    }

    // --- normalize_email ---

    #[test]
    fn normalize_trims_and_lowercases() {
        assert_eq!(
            normalize_email("  Alice@Example.COM  ").unwrap(),
            "alice@example.com"
        );
    }

    #[test]
    fn normalize_rejects_no_at() {
        assert!(normalize_email("alice").is_err());
    }

    #[test]
    fn normalize_rejects_too_short() {
        assert!(normalize_email("a@").is_err());
    }

    // --- is_hex64 ---

    #[test]
    fn is_hex64_valid() {
        assert!(is_hex64("a".repeat(64).as_str()));
        assert!(is_hex64(
            "0123456789abcdefABCDEF".repeat(3)[..64]
                .to_string()
                .as_str()
        ));
    }

    #[test]
    fn is_hex64_wrong_length() {
        assert!(!is_hex64("abcd"));
        assert!(!is_hex64(&"a".repeat(63)));
        assert!(!is_hex64(&"a".repeat(65)));
    }

    #[test]
    fn is_hex64_non_hex() {
        let mut s = "a".repeat(63);
        s.push('g');
        assert!(!is_hex64(&s));
    }

    #[test]
    fn is_hex64_empty() {
        assert!(!is_hex64(""));
    }
}
