//! Shared request/response DTOs for the vault API.
//! Used by both vault-api (Postgres) and vault-cli serve (SQLite).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::types::{Classification, OrgRole};

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

/// One org membership entry surfaced on `POST /auth/login` (issue #84,
/// plan task 3.1). Stripped down from `vault_core::types::Organization`
/// so the login surface doesn't leak billing fields (`billing_email`,
/// `stripe_customer_id`, `closed_at`) — those belong to the
/// `GET /orgs/:id` path, behind an explicit membership check.
#[derive(Debug, Serialize)]
pub struct LoginOrg {
    pub id: Uuid,
    pub name: String,
    pub role: OrgRole,
}

/// Login-specific response shape (plan task 3.1). Adds two fields onto
/// `AuthResponse`:
/// - `orgs`: the user's full membership list at login time, so the
///   client can render an org switcher without a follow-up call.
///   Empty for users with no org rows (legacy or fresh accounts).
/// - `active_org_id`: which org (if any) the just-issued JWT was
///   scoped to. Mirrors the JWT's `active_org_id` claim so a client
///   that doesn't decode JWTs can still display the active org.
///
/// Existing clients that deserialize this response into the older
/// `AuthResponse` shape ignore the additional fields — both are
/// `skip_serializing_if`-elided when empty/None, so the wire format
/// stays byte-identical to today for any user without an org.
#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub user_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub orgs: Vec<LoginOrg>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_org_id: Option<Uuid>,
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
    /// Cascade-revocation tag (issue #7). Validated by
    /// [`crate::types::validate_scope_tag`]. `None` leaves the item unscoped
    /// and outside any future tombstone cascade — preserves today's behavior
    /// for callers that don't opt in.
    #[serde(default)]
    pub scope_tag: Option<String>,
}

/// Reclassify an existing item. `acknowledge_grant_breakage = true` opts the
/// caller into proceeding when the new classification would leave an active
/// grant non-compliant under
/// [`policy::classification::ClassificationPolicy::enforce_grant_policy`].
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
    /// Event-log target arm (issue #94). Mutually exclusive with `item_id`
    /// and `group_id`; the route enforces "exactly one of three". Event
    /// logs carry no encryption material of their own (entries are server-
    /// signed plaintext), so callers send empty `wrapped_key` /
    /// `ephemeral_pubkey` for this arm — same shape as link-secret item
    /// grants today.
    #[serde(default)]
    pub event_log_id: Option<Uuid>,
    /// Cascade-revocation tag (issue #7). Independent from the grantee's
    /// own item scope: e.g. a contractor on scope `acme/pentest-q2` may be
    /// granted access to items outside that scope, but the grant itself
    /// tombstones with the engagement.
    #[serde(default)]
    pub scope_tag: Option<String>,
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
    /// Cascade-revocation tag (issue #7). Not to be confused with the
    /// `scopes` JSONB above, which holds unrelated RBAC-style permissions
    /// (`{"read_only": true}`, …). See [`crate::types::validate_scope_tag`].
    #[serde(default)]
    pub scope_tag: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CreateApiKeyResponse {
    pub id: String,
    pub name: String,
    pub key_prefix: String,
    pub public_key: Option<Vec<u8>>,
    pub created_at: String,
    /// Echo of the tag the server persisted, so the caller can verify
    /// that what landed in storage matches what they sent — important
    /// because a mistyped tag would silently miss the future tombstone
    /// cascade. Absent for unscoped keys (the caller sent no tag), which
    /// also keeps this response byte-identical to the pre-#7 wire format
    /// for the unscoped path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope_tag: Option<String>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope_tag: Option<String>,
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
    /// Phase 2 of #122. Format version of `wrapped_master_key`.
    pub wrapped_master_key_format_version: i16,
    pub encrypted_private_key: Vec<u8>,
    /// Phase 2 of #122. Format version of `encrypted_private_key`.
    pub encrypted_private_key_format_version: i16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<Vec<u8>>,
}

#[derive(Debug, Deserialize)]
pub struct CreateApiKeyGrantRequest {
    pub item_id: Uuid,
    pub wrapped_key: Vec<u8>,
    pub ephemeral_pubkey: Vec<u8>,
    pub nonce: Vec<u8>,
    /// Issue #178 / residual #122 cleanup. `0` = legacy V0 X25519 wrap
    /// (HKDF without key-bound salt, no AAD), `1` = V1 (HKDF salted with
    /// eph_pub‖recipient_pub, AAD = same salt). Defaults to 0 when absent
    /// so an older client that hasn't been updated yet still creates a
    /// readable (V0) grant — consumers fall back to V0 unwrap on
    /// `format_version = 0`.
    #[serde(default)]
    pub format_version: i16,
}

#[derive(Debug, Serialize)]
pub struct ApiKeyGrantItem {
    pub id: String,
    pub item_id: String,
    pub wrapped_key: Vec<u8>,
    pub ephemeral_pubkey: Vec<u8>,
    pub nonce: Vec<u8>,
    pub created_at: String,
    /// Issue #178 / residual #122 cleanup. See [`CreateApiKeyGrantRequest::format_version`].
    pub format_version: i16,
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

// --- Decisions (issue #5) ---

/// Record a notarized approval decision. The encrypted blob holds the
/// rationale (encrypted client-side with the caller's master key, like any
/// other item); the structured fields land plaintext in `decisions` and
/// drive the GET /decisions filter API.
///
/// `approver` defaults to the caller's user-id stringified — pass an
/// explicit value when recording a decision on behalf of an external party
/// (a counterparty signature, an external system's identity).
///
/// `supersedes` chains a follow-up decision onto a prior one; the server
/// enforces that both belong to the same `approver_user_id` to prevent
/// cross-account chain forgery.
#[derive(Debug, Deserialize)]
pub struct RecordDecisionRequest {
    pub encrypted_blob: String,
    pub wrapped_key: Vec<u8>,
    pub nonce: Vec<u8>,
    pub action: String,
    pub target: String,
    #[serde(default)]
    pub approver: Option<String>,
    #[serde(default)]
    pub supersedes: Option<Uuid>,
    /// Caller-supplied decision time, used for backfilling historical
    /// approvals. Defaults to record time on the server.
    #[serde(default)]
    pub decided_at: Option<DateTime<Utc>>,
    /// Per-item handling tag, same as `CreateItemRequest.classification`.
    #[serde(default)]
    pub classification: crate::types::Classification,
}

// --- Scope tombstone (issue #7) ---

/// Tombstone a scope_tag: revoke grants, kill api_keys (and their item
/// grants), freeze items, write a notarized `scope.tombstone` event. One
/// cascade, one ledger row, fully idempotent — a second POST on the same
/// `(user, scope_tag)` returns the existing row unchanged.
///
/// `retention_days` is the retention boundary clients see as `--retention
/// 90d`. `None` defaults to 90 days server-side; explicit values are
/// clamped to a safe range so a stray `0` or an absurd huge value can't
/// bend the retention sweep.
#[derive(Debug, Deserialize)]
pub struct TombstoneScopeRequest {
    pub scope_tag: String,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub retention_days: Option<u32>,
}
