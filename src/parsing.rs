//! URL and input parsing utilities shared across all clients.
//!
//! These functions parse drop URLs, pickup URLs, grant URLs, and BIP39
//! mnemonics from user input. They are pure — no I/O, no network.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

// ---------------------------------------------------------------------------
// Drop input types
// ---------------------------------------------------------------------------

/// Parsed drop input: either a direct UUID + key or a BIP39 mnemonic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DropInput {
    /// Direct drop access via UUID and 32-byte key.
    Direct { drop_id: String, key: [u8; 32] },
    /// Mnemonic-based access (lookup key derived from mnemonic).
    Mnemonic {
        mnemonic: String,
        /// Present if the mnemonic was extracted from a pickup URL that
        /// also contained the drop UUID.
        drop_id: Option<String>,
    },
}

/// Error returned when drop input cannot be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// A UUID was provided without a key.
    UuidWithoutKey,
    /// A base64url key was provided without a UUID.
    KeyWithoutUuid,
    /// A pickup URL with UUID requires a mnemonic instead.
    PickupUuidNeedsMnemonic,
    /// The input could not be recognized.
    Unrecognized,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UuidWithoutKey => {
                write!(
                    f,
                    "drop UUID provided without a key — provide a base64url key as second argument"
                )
            }
            Self::KeyWithoutUuid => {
                write!(f, "base64url key provided without a drop UUID")
            }
            Self::PickupUuidNeedsMnemonic => {
                write!(
                    f,
                    "pickup URL with UUID requires a mnemonic — provide the 12 words instead"
                )
            }
            Self::Unrecognized => {
                write!(
                    f,
                    "could not parse input as a drop URL, BIP39 mnemonic, or UUID + key"
                )
            }
        }
    }
}

impl std::error::Error for ParseError {}

// ---------------------------------------------------------------------------
// Drop input parsing
// ---------------------------------------------------------------------------

/// Parse user input as a drop reference.
///
/// Handles multiple formats:
/// - Drop URL: `https://.../#/drop/{uuid}?key={base64url}`
/// - Pickup slug URL: `https://.../#/pickup/{word1-word2-...word12}`
/// - BIP39 mnemonic (space or hyphen separated, 12 words)
/// - UUID + base64url key (two arguments)
pub fn parse_drop_input(key: &str, key2: Option<&str>) -> Result<DropInput, ParseError> {
    let input = key.trim();

    // Two-argument form: UUID + key or key + UUID
    if let Some(k2) = key2 {
        let k2 = k2.trim();
        if looks_like_uuid(input) {
            if let Some(key_bytes) = try_decode_base64url_key(k2) {
                return Ok(DropInput::Direct {
                    drop_id: input.to_string(),
                    key: key_bytes,
                });
            }
        }
        if looks_like_uuid(k2) {
            if let Some(key_bytes) = try_decode_base64url_key(input) {
                return Ok(DropInput::Direct {
                    drop_id: k2.to_string(),
                    key: key_bytes,
                });
            }
        }
        // Try combining as a mnemonic
        let combined = format!("{} {}", input, k2);
        return parse_drop_input(&combined, None);
    }

    // Drop URL: /drop/{uuid}?key={base64url}
    if let Some((drop_id, key)) = extract_drop_url(input) {
        return Ok(DropInput::Direct { drop_id, key });
    }

    // Pickup slug URL: /pickup/{word1-word2-...}
    if let Some(slug) = extract_pickup_slug(input) {
        let mnemonic = slug.replace('-', " ");
        return Ok(DropInput::Mnemonic {
            mnemonic: crate::drops::normalize_mnemonic(&mnemonic),
            drop_id: None,
        });
    }

    // Pickup UUID URL (not supported without mnemonic)
    if extract_pickup_uuid(input).is_some() {
        return Err(ParseError::PickupUuidNeedsMnemonic);
    }

    // Hyphen-separated 12-word mnemonic
    let hyphen_words: Vec<&str> = input.split('-').collect();
    if hyphen_words.len() == 12
        && hyphen_words
            .iter()
            .all(|w| w.chars().all(|c| c.is_ascii_lowercase()))
    {
        return Ok(DropInput::Mnemonic {
            mnemonic: hyphen_words.join(" "),
            drop_id: None,
        });
    }

    // Space-separated 12-word mnemonic
    let space_words: Vec<&str> = input.split_whitespace().collect();
    if space_words.len() == 12
        && space_words
            .iter()
            .all(|w| w.chars().all(|c| c.is_ascii_alphabetic()))
    {
        return Ok(DropInput::Mnemonic {
            mnemonic: crate::drops::normalize_mnemonic(input),
            drop_id: None,
        });
    }

    // Bare UUID without key
    if looks_like_uuid(input) {
        return Err(ParseError::UuidWithoutKey);
    }

    // Bare base64url key without UUID
    if try_decode_base64url_key(input).is_some() {
        return Err(ParseError::KeyWithoutUuid);
    }

    Err(ParseError::Unrecognized)
}

// ---------------------------------------------------------------------------
// Grant URL parsing
// ---------------------------------------------------------------------------

/// Parsed grant link components.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantLink {
    pub grant_id: String,
    pub claim_key_b64: String,
}

/// Parse a grant-accept URL into its grant ID and claim key.
///
/// Handles URLs of the form: `.../#/grant-accept/{id}/{base64url_claim_key}`
pub fn parse_grant_url(url: &str) -> Option<GrantLink> {
    let idx = url.find("/grant-accept/")?;
    let rest = &url[idx + 14..];
    let parts: Vec<&str> = rest.splitn(3, '/').collect();
    if parts.len() >= 2 && !parts[0].is_empty() && !parts[1].is_empty() {
        let secret = parts[1]
            .split(&['?', '#', '&'][..])
            .next()
            .unwrap_or(parts[1]);
        Some(GrantLink {
            grant_id: parts[0].to_string(),
            claim_key_b64: secret.to_string(),
        })
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Check if a string looks like a UUID.
pub fn looks_like_uuid(s: &str) -> bool {
    uuid::Uuid::parse_str(s).is_ok()
}

/// Try to decode a base64url string as exactly 32 bytes.
pub fn try_decode_base64url_key(s: &str) -> Option<[u8; 32]> {
    let bytes = URL_SAFE_NO_PAD.decode(s).ok()?;
    if bytes.len() == 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Some(arr)
    } else {
        None
    }
}

/// Extract drop UUID and key from a drop URL.
///
/// Format: `.../#/drop/{uuid}?key={base64url}`
pub fn extract_drop_url(s: &str) -> Option<(String, [u8; 32])> {
    let drop_idx = s.find("/drop/")?;
    let rest = &s[drop_idx + 6..];
    let uuid_end = rest.find('?').unwrap_or(rest.len());
    let uuid_str = &rest[..uuid_end];
    if !looks_like_uuid(uuid_str) {
        return None;
    }
    let key_start = rest.find("key=")?;
    let key_str = &rest[key_start + 4..];
    let key_end = key_str.find('&').unwrap_or(key_str.len());
    let key_str = &key_str[..key_end];
    let key = try_decode_base64url_key(key_str)?;
    Some((uuid_str.to_string(), key))
}

/// Extract a 12-word slug from a pickup URL.
///
/// Format: `.../#/pickup/{word1-word2-...-word12}`
pub fn extract_pickup_slug(s: &str) -> Option<String> {
    let idx = s.find("/pickup/")?;
    let rest = &s[idx + 8..];
    let slug = rest
        .split(&['?', '&', '#'][..])
        .next()
        .unwrap_or(rest)
        .trim();
    let words: Vec<&str> = slug.split('-').collect();
    if words.len() == 12
        && words
            .iter()
            .all(|w| w.chars().all(|c| c.is_ascii_lowercase()))
    {
        Some(slug.to_string())
    } else {
        None
    }
}

/// Extract a UUID from a pickup URL (without mnemonic slug).
pub fn extract_pickup_uuid(s: &str) -> Option<String> {
    let idx = s.find("/pickup/")?;
    let rest = &s[idx + 8..];
    let id = rest
        .split(&['?', '&', '#'][..])
        .next()
        .unwrap_or(rest)
        .trim();
    if looks_like_uuid(id) {
        Some(id.to_string())
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_drop_url_format() {
        let url = "https://app.example.com/#/drop/550e8400-e29b-41d4-a716-446655440000?key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let result = parse_drop_input(url, None).unwrap();
        match result {
            DropInput::Direct { drop_id, key } => {
                assert_eq!(drop_id, "550e8400-e29b-41d4-a716-446655440000");
                assert_eq!(key, [0u8; 32]);
            }
            _ => panic!("expected Direct"),
        }
    }

    #[test]
    fn parse_pickup_slug() {
        let url = "https://app.example.com/#/pickup/abandon-ability-able-about-above-absent-absorb-abstract-absurd-abuse-access-accident";
        let result = parse_drop_input(url, None).unwrap();
        match result {
            DropInput::Mnemonic { mnemonic, drop_id } => {
                assert_eq!(
                    mnemonic,
                    "abandon ability able about above absent absorb abstract absurd abuse access accident"
                );
                assert!(drop_id.is_none());
            }
            _ => panic!("expected Mnemonic"),
        }
    }

    #[test]
    fn parse_hyphen_mnemonic() {
        let input =
            "abandon-ability-able-about-above-absent-absorb-abstract-absurd-abuse-access-accident";
        let result = parse_drop_input(input, None).unwrap();
        assert!(matches!(result, DropInput::Mnemonic { .. }));
    }

    #[test]
    fn parse_space_mnemonic() {
        let input =
            "abandon ability able about above absent absorb abstract absurd abuse access accident";
        let result = parse_drop_input(input, None).unwrap();
        assert!(matches!(result, DropInput::Mnemonic { .. }));
    }

    #[test]
    fn parse_uuid_without_key_errors() {
        let result = parse_drop_input("550e8400-e29b-41d4-a716-446655440000", None);
        assert_eq!(result.unwrap_err(), ParseError::UuidWithoutKey);
    }

    #[test]
    fn parse_uuid_plus_key_two_args() {
        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        let key_b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let result = parse_drop_input(uuid, Some(key_b64)).unwrap();
        match result {
            DropInput::Direct { drop_id, key } => {
                assert_eq!(drop_id, uuid);
                assert_eq!(key, [0u8; 32]);
            }
            _ => panic!("expected Direct"),
        }
    }

    #[test]
    fn parse_key_plus_uuid_reversed() {
        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        let key_b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let result = parse_drop_input(key_b64, Some(uuid)).unwrap();
        assert!(matches!(result, DropInput::Direct { .. }));
    }

    #[test]
    fn parse_grant_url_valid() {
        let url =
            "https://app.example.com/#/grant-accept/abc-123/dGVzdC1jbGFpbS1rZXktMTIzNDU2Nzg5MDEy";
        let link = parse_grant_url(url).unwrap();
        assert_eq!(link.grant_id, "abc-123");
        assert_eq!(link.claim_key_b64, "dGVzdC1jbGFpbS1rZXktMTIzNDU2Nzg5MDEy");
    }

    #[test]
    fn parse_grant_url_with_query() {
        let url = "https://app.example.com/#/grant-accept/abc-123/key123?foo=bar";
        let link = parse_grant_url(url).unwrap();
        assert_eq!(link.grant_id, "abc-123");
        assert_eq!(link.claim_key_b64, "key123");
    }

    #[test]
    fn parse_grant_url_missing() {
        assert!(parse_grant_url("https://example.com/foo").is_none());
    }

    #[test]
    fn extract_pickup_uuid_works() {
        let url = "https://app.example.com/#/pickup/550e8400-e29b-41d4-a716-446655440000";
        let result = parse_drop_input(url, None);
        assert_eq!(result.unwrap_err(), ParseError::PickupUuidNeedsMnemonic);
    }
}
