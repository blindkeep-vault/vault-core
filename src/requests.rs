//! Shared request/response DTOs for the vault API.
//! Used by both vault-api (Postgres) and vault-cli serve (SQLite).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::types::Classification;

// --- Auth ---

#[derive(Debug, Deserialize)]
pub struct LookupRequest {
    pub email: String,
}

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub auth_key: String,
    pub public_key: Vec<u8>,
    pub encrypted_private_key: Vec<u8>,
    #[serde(default)]
    pub client_salt: Vec<u8>,
    pub encrypted_master_key: Option<Vec<u8>>,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub auth_key: String,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub token: String,
    pub user_id: String,
}

#[derive(Debug, Deserialize)]
pub struct VerifyEmailRequest {
    pub token: String,
}

// --- Items ---

#[derive(Debug, Deserialize)]
pub struct CreateItemRequest {
    pub encrypted_blob: Option<String>,
    /// S3 key for pre-uploaded blob (cloud API only).
    pub s3_key: Option<String>,
    pub wrapped_key: Vec<u8>,
    pub nonce: Vec<u8>,
    pub item_type: String,
    /// Data-handling classification for this item (issue #9). Omitting the
    /// field lands on `Standard`, matching today's behavior. Future slices
    /// enforce handling rules (e.g. `Confidential` requires one-shot grants).
    #[serde(default)]
    pub classification: Classification,
    pub metadata: Option<serde_json::Value>,
    pub size_bytes: Option<i64>,
    pub file_blob_key: Option<String>,
    /// Consume the item on the first direct read via `GET /items/:id` or
    /// `GET /items/:id/blob` (owner JWT or API-key JWT), atomically setting
    /// `consumed_at`; subsequent direct reads return 410 Gone.
    ///
    /// Scope: direct reads ONLY. Grant-based access via `POST /grants/:id/access`
    /// goes through a separate retrieval path whose atomicity is governed by
    /// the grant's own `policy.one_shot` flag. If you need one-shot semantics
    /// for a credential handed off to another user, set `one_shot` on the grant,
    /// not on the underlying item.
    #[serde(default)]
    pub one_shot: bool,
    /// When true, each successful direct read emits a notarized `item.retrieve`
    /// attestation. Same scope caveat as `one_shot`: direct reads only.
    #[serde(default)]
    pub notarize_on_use: bool,
}

/// Reclassify an existing item. `acknowledge_grant_breakage = true` opts the
/// caller into proceeding when the new classification would leave an active
/// grant non-compliant under [`policy::classification::enforce_grant_policy`].
/// Downgrades are always notarized regardless of this flag (issue #9 acceptance
/// gap, #42).
#[derive(Debug, Deserialize)]
pub struct UpdateClassificationRequest {
    pub classification: Classification,
    #[serde(default)]
    pub acknowledge_grant_breakage: bool,
}

// --- Grants ---

#[derive(Debug, Deserialize)]
pub struct CreateGrantRequest {
    pub item_id: Option<Uuid>,
    pub grantee_email: String,
    pub wrapped_key: Vec<u8>,
    pub ephemeral_pubkey: Vec<u8>,
    pub policy: serde_json::Value,
    pub file_wrapped_key: Option<Vec<u8>>,
    pub claim_token_hash: Option<String>,
    pub claim_ciphertext: Option<Vec<u8>>,
    pub group_id: Option<Uuid>,
    pub wrapped_item_keys: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct AccessGrantRequest {
    #[serde(default = "default_operation")]
    pub operation: String,
}

fn default_operation() -> String {
    "view".to_string()
}

// --- API Keys ---

#[derive(Debug, Deserialize)]
pub struct CreateApiKeyRequest {
    pub name: String,
    pub auth_key: String,
    pub key_prefix: String,
    pub wrapped_master_key: Option<Vec<u8>>,
    pub encrypted_private_key: Vec<u8>,
    pub public_key: Option<Vec<u8>>,
    #[serde(default)]
    pub scopes: Option<serde_json::Value>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
pub struct CreateApiKeyResponse {
    pub id: String,
    pub name: String,
    pub key_prefix: String,
    pub public_key: Option<Vec<u8>>,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
pub struct ApiKeyListItem {
    pub id: String,
    pub name: String,
    pub key_prefix: String,
    pub scopes: serde_json::Value,
    pub is_scoped: bool,
    pub public_key: Option<Vec<u8>>,
    pub grant_count: i64,
    pub expires_at: Option<String>,
    pub last_used_at: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
pub struct ApiKeyAuthRequest {
    pub key_prefix: String,
    pub auth_key: String,
}

#[derive(Debug, Serialize)]
pub struct ApiKeyAuthResponse {
    pub token: String,
    pub user_id: String,
    pub api_key_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wrapped_master_key: Option<Vec<u8>>,
    pub encrypted_private_key: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<Vec<u8>>,
}

#[derive(Debug, Deserialize)]
pub struct CreateApiKeyGrantRequest {
    pub item_id: Uuid,
    pub wrapped_key: Vec<u8>,
    pub ephemeral_pubkey: Vec<u8>,
    pub nonce: Vec<u8>,
}

#[derive(Debug, Serialize)]
pub struct ApiKeyGrantItem {
    pub id: String,
    pub item_id: String,
    pub wrapped_key: Vec<u8>,
    pub ephemeral_pubkey: Vec<u8>,
    pub nonce: Vec<u8>,
    pub created_at: String,
}

// --- Users ---

#[derive(Debug, Deserialize)]
pub struct PublicKeyQuery {
    pub email: String,
}

#[derive(Debug, Serialize)]
pub struct PublicKeyResponse {
    pub public_key: Vec<u8>,
}
