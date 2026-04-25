use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ApiError;

/// Create JWT validation pinned to HS256 algorithm to prevent algorithm confusion attacks.
fn jwt_validation() -> Validation {
    Validation::new(jsonwebtoken::Algorithm::HS256)
}

/// Which tier of access this session represents.
///
/// - `Full` — client has (or can derive) the vault master key: password login,
///   passkey+PRF login, API key auth, legacy tokens.
/// - `Limited` — authenticated via magic link only; the server has no evidence
///   the client holds the vault key. The server's auth middleware enforces a
///   path allow-list for this tier; vault-content routes return 403.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SessionKind {
    #[default]
    Full,
    Limited,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid,
    pub email: String,
    pub email_verified: bool,
    #[serde(default)]
    pub needs_password_setup: bool,
    pub exp: usize,
    #[serde(default)]
    pub iat: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_only: Option<bool>,
    #[serde(default)]
    pub session_kind: SessionKind,
    /// Per-log read whitelist. `None` = no constraint (session JWT or
    /// full-access API key); `Some(vec)` = scoped API key may only read
    /// these log IDs and their entries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_log_read: Option<Vec<Uuid>>,
    /// Per-log write whitelist. `None` = no constraint; `Some(vec)` =
    /// scoped API key may only append to these log IDs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_log_write: Option<Vec<Uuid>>,
}

pub fn encode_jwt(
    user_id: Uuid,
    email: &str,
    email_verified: bool,
    secret: &str,
) -> Result<String, jsonwebtoken::errors::Error> {
    encode_jwt_full(user_id, email, email_verified, false, secret)
}

pub fn encode_jwt_full(
    user_id: Uuid,
    email: &str,
    email_verified: bool,
    needs_password_setup: bool,
    secret: &str,
) -> Result<String, jsonwebtoken::errors::Error> {
    let now = chrono::Utc::now();
    let exp = now
        .checked_add_signed(chrono::Duration::hours(24))
        .expect("valid timestamp")
        .timestamp() as usize;
    let iat = now.timestamp() as usize;

    let claims = Claims {
        sub: user_id,
        email: email.to_owned(),
        email_verified,
        needs_password_setup,
        exp,
        iat,
        api_key_id: None,
        read_only: None,
        session_kind: SessionKind::Full,
        event_log_read: None,
        event_log_write: None,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
}

/// Issue a Limited session JWT (magic-link login: authenticated but vault locked).
///
/// The auth middleware's path allow-list blocks this tier from routes that
/// need the vault master key on the client. The client can swap this for a
/// `Full` JWT via the `/auth/upgrade-session` endpoint by supplying the
/// password-derived `auth_key`.
pub fn encode_jwt_limited(
    user_id: Uuid,
    email: &str,
    needs_password_setup: bool,
    secret: &str,
) -> Result<String, jsonwebtoken::errors::Error> {
    let now = chrono::Utc::now();
    let exp = now
        .checked_add_signed(chrono::Duration::hours(24))
        .expect("valid timestamp")
        .timestamp() as usize;
    let iat = now.timestamp() as usize;

    let claims = Claims {
        sub: user_id,
        email: email.to_owned(),
        email_verified: true,
        needs_password_setup,
        exp,
        iat,
        api_key_id: None,
        read_only: None,
        session_kind: SessionKind::Limited,
        event_log_read: None,
        event_log_write: None,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
}

pub fn encode_jwt_api_key(
    user_id: Uuid,
    email: &str,
    api_key_id: Uuid,
    read_only: bool,
    secret: &str,
) -> Result<String, jsonwebtoken::errors::Error> {
    encode_jwt_api_key_full(user_id, email, api_key_id, read_only, None, None, secret)
}

/// Same as [`encode_jwt_api_key`] but lets the caller pin per-log read and
/// write whitelists into the JWT. Either field set to `None` keeps the
/// legacy "no constraint" behavior (back-compat for keys without the new
/// scope); `Some(vec)` produces a scoped JWT.
#[allow(clippy::too_many_arguments)]
pub fn encode_jwt_api_key_full(
    user_id: Uuid,
    email: &str,
    api_key_id: Uuid,
    read_only: bool,
    event_log_read: Option<Vec<Uuid>>,
    event_log_write: Option<Vec<Uuid>>,
    secret: &str,
) -> Result<String, jsonwebtoken::errors::Error> {
    let now = chrono::Utc::now();
    let exp = now
        .checked_add_signed(chrono::Duration::hours(24))
        .expect("valid timestamp")
        .timestamp() as usize;
    let iat = now.timestamp() as usize;

    let claims = Claims {
        sub: user_id,
        email: email.to_owned(),
        email_verified: true,
        needs_password_setup: false,
        exp,
        iat,
        api_key_id: Some(api_key_id),
        read_only: Some(read_only),
        session_kind: SessionKind::Full,
        event_log_read,
        event_log_write,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
}

pub fn decode_jwt(token: &str, secret: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &jwt_validation(),
    )
    .map(|td| td.claims)
}

pub fn decode_jwt_allow_expired(
    token: &str,
    secret: &str,
) -> Result<Claims, jsonwebtoken::errors::Error> {
    let mut validation = jwt_validation();
    validation.validate_exp = false;
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .map(|td| td.claims)
}

/// Check that the current session is allowed to perform write operations.
/// Returns Forbidden if the session is from a read-only API key.
pub fn check_write_allowed(claims: &Claims) -> Result<(), ApiError> {
    if claims.read_only == Some(true) {
        return Err(ApiError::Forbidden);
    }
    Ok(())
}

/// Check that the current session is allowed to append to the given event log.
///
/// Layered on top of [`check_write_allowed`]: the global `read_only` check
/// runs first, then the per-log whitelist. `event_log_write = None` (session
/// JWTs and unscoped API keys) imposes no per-log constraint — log ownership
/// is checked at the route layer where the log row is loaded.
pub fn check_event_log_write_allowed(claims: &Claims, log_id: Uuid) -> Result<(), ApiError> {
    check_write_allowed(claims)?;
    if let Some(allowed) = &claims.event_log_write {
        if !allowed.contains(&log_id) {
            return Err(ApiError::Forbidden);
        }
    }
    Ok(())
}

/// Check that the current session is allowed to read the given event log
/// (the log row, its entries, and inclusion proofs).
///
/// `event_log_read = None` (session JWTs and unscoped API keys) imposes no
/// per-log constraint; the route layer enforces ownership against the log
/// row's `user_id`. A scoped API key with `event_log_read = Some(vec)` may
/// only see logs whose UUID is in the list.
pub fn check_event_log_read_allowed(claims: &Claims, log_id: Uuid) -> Result<(), ApiError> {
    if let Some(allowed) = &claims.event_log_read {
        if !allowed.contains(&log_id) {
            return Err(ApiError::Forbidden);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SECRET: &str = "test-secret-key-for-jwt-tests";

    fn test_user_id() -> Uuid {
        Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap()
    }

    #[test]
    fn encode_decode_roundtrip() {
        let uid = test_user_id();
        let token = encode_jwt(uid, "user@example.com", true, TEST_SECRET).unwrap();
        let claims = decode_jwt_allow_expired(&token, TEST_SECRET).unwrap();

        assert_eq!(claims.sub, uid);
        assert_eq!(claims.email, "user@example.com");
        assert!(claims.email_verified);
        assert!(!claims.needs_password_setup);
    }

    #[test]
    fn encode_full_with_needs_password_setup() {
        let uid = test_user_id();
        let token = encode_jwt_full(uid, "user@example.com", true, true, TEST_SECRET).unwrap();
        let claims = decode_jwt_allow_expired(&token, TEST_SECRET).unwrap();

        assert!(claims.needs_password_setup);
    }

    #[test]
    fn decode_rejects_wrong_secret() {
        let token = encode_jwt(test_user_id(), "user@example.com", true, TEST_SECRET).unwrap();

        let mut validation = jwt_validation();
        validation.validate_exp = false;
        let result = decode::<Claims>(
            &token,
            &DecodingKey::from_secret(b"wrong-secret"),
            &validation,
        );
        assert!(result.is_err());
    }

    #[test]
    fn decode_rejects_garbage_token() {
        let result = decode_jwt_allow_expired("not-a-jwt", TEST_SECRET);
        assert!(result.is_err());
    }

    #[test]
    fn jwt_expiry_is_in_future() {
        let token = encode_jwt(test_user_id(), "user@example.com", true, TEST_SECRET).unwrap();
        let claims = decode_jwt_allow_expired(&token, TEST_SECRET).unwrap();

        let now = chrono::Utc::now().timestamp() as usize;
        assert!(claims.exp > now);
        assert!(claims.exp <= now + 86401);
        assert!(claims.exp >= now + 86399 - 2);
    }

    #[test]
    fn jwt_validation_pins_hs256() {
        let v = jwt_validation();
        assert_eq!(v.algorithms, vec![jsonwebtoken::Algorithm::HS256]);
    }

    #[test]
    fn decode_jwt_allow_expired_accepts_expired_token() {
        let claims = Claims {
            sub: test_user_id(),
            email: "user@example.com".to_string(),
            email_verified: true,
            needs_password_setup: false,
            exp: 1,
            iat: 0,
            api_key_id: None,
            read_only: None,
            session_kind: SessionKind::Full,
            event_log_read: None,
            event_log_write: None,
        };
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(TEST_SECRET.as_bytes()),
        )
        .unwrap();

        let result = decode_jwt_allow_expired(&token, TEST_SECRET);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().sub, test_user_id());
    }

    #[test]
    fn default_session_kind_is_full() {
        // Tokens issued before the session_kind claim existed must keep working.
        // Construct a minimal JSON payload without the field and confirm it
        // deserializes as Full.
        use serde_json::json;
        let payload = json!({
            "sub": test_user_id().to_string(),
            "email": "user@example.com",
            "email_verified": true,
            "exp": (chrono::Utc::now().timestamp() as usize) + 3600,
        });
        let claims: Claims = serde_json::from_value(payload).unwrap();
        assert_eq!(claims.session_kind, SessionKind::Full);
    }

    #[test]
    fn encode_jwt_limited_roundtrip() {
        let uid = test_user_id();
        let token = encode_jwt_limited(uid, "user@example.com", false, TEST_SECRET).unwrap();
        let claims = decode_jwt_allow_expired(&token, TEST_SECRET).unwrap();

        assert_eq!(claims.sub, uid);
        assert_eq!(claims.session_kind, SessionKind::Limited);
        assert!(claims.email_verified);
        assert!(!claims.needs_password_setup);
    }

    #[test]
    fn encode_jwt_limited_carries_needs_password_setup() {
        let token =
            encode_jwt_limited(test_user_id(), "user@example.com", true, TEST_SECRET).unwrap();
        let claims = decode_jwt_allow_expired(&token, TEST_SECRET).unwrap();
        assert_eq!(claims.session_kind, SessionKind::Limited);
        assert!(claims.needs_password_setup);
    }

    #[test]
    fn regular_jwt_is_full_session() {
        let token = encode_jwt(test_user_id(), "user@example.com", true, TEST_SECRET).unwrap();
        let claims = decode_jwt_allow_expired(&token, TEST_SECRET).unwrap();
        assert_eq!(claims.session_kind, SessionKind::Full);
    }

    #[test]
    fn session_kind_wire_format_is_snake_case() {
        // Guard against a rename that breaks on-the-wire compatibility.
        // The client parses this value directly from the JWT payload.
        let token =
            encode_jwt_limited(test_user_id(), "user@example.com", false, TEST_SECRET).unwrap();
        let payload_b64 = token.split('.').nth(1).unwrap();
        let pad = (4 - payload_b64.len() % 4) % 4;
        let mut padded = payload_b64.to_string();
        padded.extend(std::iter::repeat('=').take(pad));
        let bytes = base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE,
            padded.as_bytes(),
        )
        .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(payload["session_kind"], "limited");

        let token2 = encode_jwt(test_user_id(), "user@example.com", true, TEST_SECRET).unwrap();
        let payload_b64 = token2.split('.').nth(1).unwrap();
        let pad = (4 - payload_b64.len() % 4) % 4;
        let mut padded = payload_b64.to_string();
        padded.extend(std::iter::repeat('=').take(pad));
        let bytes = base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE,
            padded.as_bytes(),
        )
        .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(payload["session_kind"], "full");
    }

    #[test]
    fn claims_email_verified_false_preserved() {
        let token = encode_jwt(test_user_id(), "user@example.com", false, TEST_SECRET).unwrap();
        let claims = decode_jwt_allow_expired(&token, TEST_SECRET).unwrap();
        assert!(!claims.email_verified);
    }

    #[test]
    fn encode_api_key_jwt_sets_fields() {
        let uid = test_user_id();
        let ak_id = Uuid::parse_str("660e8400-e29b-41d4-a716-446655440000").unwrap();
        let token = encode_jwt_api_key(uid, "user@example.com", ak_id, true, TEST_SECRET).unwrap();
        let claims = decode_jwt_allow_expired(&token, TEST_SECRET).unwrap();

        assert_eq!(claims.sub, uid);
        assert_eq!(claims.api_key_id, Some(ak_id));
        assert_eq!(claims.read_only, Some(true));
        assert!(claims.email_verified);
        assert!(!claims.needs_password_setup);
    }

    #[test]
    fn regular_jwt_has_no_api_key_fields() {
        let token = encode_jwt(test_user_id(), "user@example.com", true, TEST_SECRET).unwrap();
        let claims = decode_jwt_allow_expired(&token, TEST_SECRET).unwrap();
        assert_eq!(claims.api_key_id, None);
        assert_eq!(claims.read_only, None);
    }

    #[test]
    fn check_write_allowed_permits_normal_session() {
        let token = encode_jwt(test_user_id(), "user@example.com", true, TEST_SECRET).unwrap();
        let claims = decode_jwt_allow_expired(&token, TEST_SECRET).unwrap();
        assert!(check_write_allowed(&claims).is_ok());
    }

    #[test]
    fn check_write_allowed_blocks_read_only() {
        let ak_id = Uuid::parse_str("660e8400-e29b-41d4-a716-446655440000").unwrap();
        let token =
            encode_jwt_api_key(test_user_id(), "user@example.com", ak_id, true, TEST_SECRET)
                .unwrap();
        let claims = decode_jwt_allow_expired(&token, TEST_SECRET).unwrap();
        assert!(check_write_allowed(&claims).is_err());
    }

    #[test]
    fn check_write_allowed_permits_readwrite_api_key() {
        let ak_id = Uuid::parse_str("660e8400-e29b-41d4-a716-446655440000").unwrap();
        let token = encode_jwt_api_key(
            test_user_id(),
            "user@example.com",
            ak_id,
            false,
            TEST_SECRET,
        )
        .unwrap();
        let claims = decode_jwt_allow_expired(&token, TEST_SECRET).unwrap();
        assert!(check_write_allowed(&claims).is_ok());
    }
}
