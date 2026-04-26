use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub public_key: Vec<u8>,
    pub email_verified: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ItemType {
    Password,
    Document,
    HealthRecord,
    Key,
}

/// Data-handling classification applied to items. The tag drives the policy
/// layer's decisions on what operations are permitted (see `policy::classification`).
///
/// `Standard` is the default for items created without an explicit classification.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum Classification {
    Public,
    #[default]
    Standard,
    Confidential,
    Restricted,
}

impl Classification {
    /// Canonical snake_case string form, used when binding to the TEXT column
    /// or formatting error messages. Kept in sync with the serde rename via
    /// the `classification_as_str_matches_serde` test.
    pub const fn as_str(self) -> &'static str {
        match self {
            Classification::Public => "public",
            Classification::Standard => "standard",
            Classification::Confidential => "confidential",
            Classification::Restricted => "restricted",
        }
    }
}

/// Maximum length of a validated `scope_tag`. Chosen to fit comfortably inside
/// a Postgres btree index leaf entry alongside a small tuple header, while
/// giving callers enough room for `org/team/workspace`-style nested namespaces.
pub const SCOPE_TAG_MAX_LEN: usize = 64;

/// Validate a `scope_tag` value (issue #7). A valid tag is 1..=64 ASCII
/// characters drawn from `[a-z0-9\-_./]`, starting with `[a-z0-9]`, with no
/// whitespace and no uppercase. The constraint keeps scope tags URL-safe,
/// shell-safe, and log-safe so callers can paste them unescaped into paths,
/// audit entries, and notarized events without a second normalization step.
///
/// Centralized here so server, CLI, and WASM bindings reject the same set.
/// Returns `Ok(())` when the input is valid, `Err(&'static str)` with a short
/// reason otherwise — the API handler maps it to a 400.
pub fn validate_scope_tag(tag: &str) -> Result<(), &'static str> {
    if tag.is_empty() {
        return Err("scope_tag must not be empty");
    }
    if tag.len() > SCOPE_TAG_MAX_LEN {
        return Err("scope_tag exceeds 64 characters");
    }
    let mut chars = tag.chars();
    let first = chars.next().expect("non-empty checked above");
    if !(first.is_ascii_lowercase() || first.is_ascii_digit()) {
        return Err("scope_tag must start with a lowercase letter or digit");
    }
    for c in std::iter::once(first).chain(chars) {
        let ok = c.is_ascii_lowercase()
            || c.is_ascii_digit()
            || c == '-'
            || c == '_'
            || c == '.'
            || c == '/';
        if !ok {
            return Err("scope_tag may only contain [a-z0-9-_./]");
        }
    }
    Ok(())
}

impl std::str::FromStr for Classification {
    type Err = &'static str;

    /// Parse from the canonical snake_case form produced by [`Self::as_str`].
    /// Useful for reading back the value from the `items.classification` TEXT
    /// column. The `CHECK` constraint on that column guarantees only valid
    /// values reach this path; an `Err` here indicates DB corruption or a
    /// schema drift, and callers should surface it as an internal error.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "public" => Ok(Self::Public),
            "standard" => Ok(Self::Standard),
            "confidential" => Ok(Self::Confidential),
            "restricted" => Ok(Self::Restricted),
            _ => Err("unknown classification"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Item {
    pub id: Uuid,
    pub owner_id: Uuid,
    pub encrypted_blob: String,
    pub wrapped_key: Vec<u8>,
    pub nonce: Vec<u8>,
    pub item_type: ItemType,
    #[serde(default)]
    pub classification: Classification,
    pub metadata: serde_json::Value,
    pub storage_backend: String,
    /// Opaque cascade-revocation tag (issue #7). Present when the item was
    /// created inside a named scope (tenant, project, engagement). Unscoped
    /// items carry `None` and are not eligible for scope-wide tombstoning.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope_tag: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GrantStatus {
    Pending,
    Active,
    Revoked,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub id: Uuid,
    pub owner_id: Uuid,
    pub encrypted_blob: String,
    pub wrapped_key: Vec<u8>,
    pub nonce: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Grant {
    pub id: Uuid,
    pub item_id: Option<Uuid>,
    pub group_id: Option<Uuid>,
    /// Event-log target (issue #94). Mutually exclusive with `item_id` and
    /// `group_id`; the server enforces "exactly one of three" via the
    /// `grants_target_xor` CHECK added in migration 046. Optional in the
    /// struct so wire-format roundtrips of pre-#94 grants stay byte-identical
    /// (the field is omitted on serialize when None).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_log_id: Option<Uuid>,
    pub grantor_id: Uuid,
    pub grantee_email: String,
    pub grantee_id: Option<Uuid>,
    pub wrapped_key: Vec<u8>,
    pub ephemeral_pubkey: Vec<u8>,
    pub policy: serde_json::Value,
    pub status: GrantStatus,
    pub view_count: i32,
    /// Opaque cascade-revocation tag (issue #7). See [`Item::scope_tag`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope_tag: Option<String>,
    pub created_at: DateTime<Utc>,
    pub claimed_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

/// Notarized approval-decision (issue #5). Each row pairs 1:1 with an
/// `items` row of the same id — that item carries the encrypted rationale,
/// while the structured fields here (`approver`, `action`, `target`,
/// `supersedes`) stay plaintext to support the GET /decisions filter API.
///
/// `decided_at` is when the approval was made (caller-supplied, defaulting
/// to record time); `created_at` is when the row was persisted. For
/// imported / backfilled decisions the two diverge — the notarization
/// timestamp anchors the latter, not the former.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Decision {
    /// Same value as the underlying `items.id`. Decisions ARE items at the
    /// storage layer; this is the same UUID, surfaced under a friendlier name.
    pub id: Uuid,
    pub approver_user_id: Uuid,
    pub approver: String,
    pub action: String,
    pub target: String,
    pub supersedes: Option<Uuid>,
    pub decided_at: DateTime<Utc>,
    pub notarization_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: Uuid,
    pub actor_id: Uuid,
    pub action: String,
    pub resource_type: String,
    pub resource_id: Uuid,
    pub details: serde_json::Value,
    pub ip_address: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Organization role within an `org_members` row.
///
/// `Owner` may invite, remove members, change roles, and close the org.
/// `BillingAdmin` may manage payment / topup but cannot manage membership
/// or vault content. `Member` has resource access only (no billing). The
/// authorization rule that combines a caller's role with a required role
/// is [`OrgRole::satisfies`].
///
/// Snake-case wire format matches the `org_members.role` CHECK constraint
/// in migration 041 — `role` is bound directly via [`Self::as_str`] and
/// parsed back via [`std::str::FromStr`] at the db layer.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OrgRole {
    Owner,
    BillingAdmin,
    Member,
}

impl OrgRole {
    pub const fn as_str(self) -> &'static str {
        match self {
            OrgRole::Owner => "owner",
            OrgRole::BillingAdmin => "billing_admin",
            OrgRole::Member => "member",
        }
    }

    /// Authorization check: does the caller's role (`self`) authorize an
    /// action that requires `required`?
    ///
    /// `Owner` is a superset of both other roles and satisfies anything.
    /// `BillingAdmin` and `Member` are parallel responsibilities (billing
    /// vs. resource access — see the type-level doc for the split) and do
    /// not cross-elevate: `BillingAdmin` does NOT satisfy `Member`, and
    /// vice versa. This preserves separation of duties — `BillingAdmin`
    /// exists precisely so a finance-only seat can't read vault content;
    /// folding it into `Member` would defeat the role.
    ///
    /// "Any role passes" is expressed at the call site by skipping the
    /// `satisfies` check (e.g. `Option::None` in the resource-authz
    /// helper), not by passing a distinguished value here.
    pub const fn satisfies(self, required: OrgRole) -> bool {
        matches!(
            (self, required),
            (OrgRole::Owner, _)
                | (OrgRole::BillingAdmin, OrgRole::BillingAdmin)
                | (OrgRole::Member, OrgRole::Member)
        )
    }
}

impl std::str::FromStr for OrgRole {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "owner" => Ok(Self::Owner),
            "billing_admin" => Ok(Self::BillingAdmin),
            "member" => Ok(Self::Member),
            _ => Err("unknown org role"),
        }
    }
}

/// Public-facing organization record (issue #82). Server-internal billing
/// fields (`mbhour_balance`, grace timestamps, …) live on the corresponding
/// `OrganizationRow` in `vault-api/src/db/orgs.rs` — the wire shape stays
/// minimal so a member listing doesn't expose another tenant's burn rate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Organization {
    pub id: Uuid,
    pub name: String,
    pub billing_email: String,
    pub stripe_customer_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub closed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OrgMember {
    pub org_id: Uuid,
    pub user_id: Uuid,
    pub role: OrgRole,
    pub joined_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OrgInvitation {
    pub id: Uuid,
    pub org_id: Uuid,
    pub invited_email: String,
    pub role: OrgRole,
    /// SHA-256 hex of the secret token. Server-internal: the hash is the
    /// DB-side handle for an invite (`get_invitation_by_token_hash`) and
    /// must never be serialized into a wire shape — anyone who later
    /// learns a plaintext token (forwarded email, support ticket, etc.)
    /// could otherwise re-derive the hash and confirm which invite it
    /// belonged to without the original holder's cooperation. The
    /// plaintext token is returned exactly once at creation time via
    /// `CreateInvitationResponse::token` (route layer); after that no
    /// API surface should expose either form.
    #[serde(skip)]
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
    pub accepted_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn item_type_serde_roundtrip() {
        for variant in [
            ItemType::Password,
            ItemType::Document,
            ItemType::HealthRecord,
            ItemType::Key,
        ] {
            let json = serde_json::to_string(&variant).unwrap();
            let parsed: ItemType = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, variant);
        }
    }

    #[test]
    fn item_type_snake_case_serialization() {
        assert_eq!(
            serde_json::to_string(&ItemType::Password).unwrap(),
            "\"password\""
        );
        assert_eq!(
            serde_json::to_string(&ItemType::Document).unwrap(),
            "\"document\""
        );
        assert_eq!(
            serde_json::to_string(&ItemType::HealthRecord).unwrap(),
            "\"health_record\""
        );
        assert_eq!(serde_json::to_string(&ItemType::Key).unwrap(), "\"key\"");
    }

    #[test]
    fn grant_status_serde_roundtrip() {
        for variant in [
            GrantStatus::Pending,
            GrantStatus::Active,
            GrantStatus::Revoked,
            GrantStatus::Expired,
        ] {
            let json = serde_json::to_string(&variant).unwrap();
            let parsed: GrantStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, variant);
        }
    }

    #[test]
    fn grant_status_snake_case_serialization() {
        assert_eq!(
            serde_json::to_string(&GrantStatus::Pending).unwrap(),
            "\"pending\""
        );
        assert_eq!(
            serde_json::to_string(&GrantStatus::Active).unwrap(),
            "\"active\""
        );
        assert_eq!(
            serde_json::to_string(&GrantStatus::Revoked).unwrap(),
            "\"revoked\""
        );
        assert_eq!(
            serde_json::to_string(&GrantStatus::Expired).unwrap(),
            "\"expired\""
        );
    }

    #[test]
    fn item_type_rejects_unknown_variant() {
        let result: Result<ItemType, _> = serde_json::from_str("\"unknown\"");
        assert!(result.is_err());
    }

    #[test]
    fn classification_serde_roundtrip() {
        for variant in [
            Classification::Public,
            Classification::Standard,
            Classification::Confidential,
            Classification::Restricted,
        ] {
            let json = serde_json::to_string(&variant).unwrap();
            let parsed: Classification = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, variant);
        }
    }

    #[test]
    fn classification_snake_case_serialization() {
        assert_eq!(
            serde_json::to_string(&Classification::Public).unwrap(),
            "\"public\""
        );
        assert_eq!(
            serde_json::to_string(&Classification::Standard).unwrap(),
            "\"standard\""
        );
        assert_eq!(
            serde_json::to_string(&Classification::Confidential).unwrap(),
            "\"confidential\""
        );
        assert_eq!(
            serde_json::to_string(&Classification::Restricted).unwrap(),
            "\"restricted\""
        );
    }

    #[test]
    fn classification_default_is_standard() {
        assert_eq!(Classification::default(), Classification::Standard);
    }

    #[test]
    fn classification_as_str_matches_serde() {
        // Drift guard: if anyone edits `Classification` or the serde rename,
        // this catches divergence between `as_str()` and the wire format.
        for variant in [
            Classification::Public,
            Classification::Standard,
            Classification::Confidential,
            Classification::Restricted,
        ] {
            let serde_form = serde_json::to_string(&variant).unwrap();
            let quoted = format!("\"{}\"", variant.as_str());
            assert_eq!(serde_form, quoted, "variant {variant:?} drifted");
        }
    }

    #[test]
    fn classification_from_str_roundtrips() {
        use std::str::FromStr;
        for variant in [
            Classification::Public,
            Classification::Standard,
            Classification::Confidential,
            Classification::Restricted,
        ] {
            let parsed = Classification::from_str(variant.as_str()).unwrap();
            assert_eq!(parsed, variant);
        }
    }

    #[test]
    fn classification_from_str_rejects_unknown() {
        use std::str::FromStr;
        assert!(Classification::from_str("top_secret").is_err());
        assert!(Classification::from_str("").is_err());
        assert!(Classification::from_str("Public").is_err()); // case-sensitive
    }

    #[test]
    fn classification_rejects_unknown_variant() {
        let result: Result<Classification, _> = serde_json::from_str("\"top_secret\"");
        assert!(result.is_err());
    }

    #[test]
    fn grant_status_rejects_unknown_variant() {
        let result: Result<GrantStatus, _> = serde_json::from_str("\"deleted\"");
        assert!(result.is_err());
    }

    #[test]
    fn user_serde_roundtrip() {
        let user = User {
            id: Uuid::new_v4(),
            email: "test@example.com".to_string(),
            public_key: vec![1, 2, 3],
            email_verified: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let json = serde_json::to_string(&user).unwrap();
        let parsed: User = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, user.id);
        assert_eq!(parsed.email, user.email);
        assert_eq!(parsed.public_key, user.public_key);
        assert_eq!(parsed.email_verified, user.email_verified);
    }

    #[test]
    fn audit_entry_serde_roundtrip() {
        let entry = AuditEntry {
            id: Uuid::new_v4(),
            actor_id: Uuid::new_v4(),
            action: "create".to_string(),
            resource_type: "item".to_string(),
            resource_id: Uuid::new_v4(),
            details: serde_json::json!({"key": "value"}),
            ip_address: Some("127.0.0.1".to_string()),
            created_at: Utc::now(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: AuditEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, entry.id);
        assert_eq!(parsed.action, "create");
        assert_eq!(parsed.ip_address, Some("127.0.0.1".to_string()));
    }

    #[test]
    fn item_serde_roundtrip_with_classification() {
        let item = Item {
            id: Uuid::new_v4(),
            owner_id: Uuid::new_v4(),
            encrypted_blob: "blob".to_string(),
            wrapped_key: vec![1, 2, 3],
            nonce: vec![4, 5, 6],
            item_type: ItemType::Password,
            classification: Classification::Confidential,
            metadata: serde_json::json!({}),
            storage_backend: "managed".to_string(),
            scope_tag: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let json = serde_json::to_string(&item).unwrap();
        assert!(json.contains("\"classification\":\"confidential\""));
        // Unscoped item serializes without a `scope_tag` key so unscoped rows
        // stay byte-identical to the pre-#7 wire format.
        assert!(!json.contains("scope_tag"));
        let parsed: Item = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.classification, Classification::Confidential);
        assert_eq!(parsed.scope_tag, None);
    }

    #[test]
    fn item_serde_roundtrip_with_scope_tag() {
        let item = Item {
            id: Uuid::new_v4(),
            owner_id: Uuid::new_v4(),
            encrypted_blob: "blob".to_string(),
            wrapped_key: vec![1, 2, 3],
            nonce: vec![4, 5, 6],
            item_type: ItemType::Password,
            classification: Classification::Standard,
            metadata: serde_json::json!({}),
            storage_backend: "managed".to_string(),
            scope_tag: Some("acme/prod".to_string()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let json = serde_json::to_string(&item).unwrap();
        assert!(json.contains("\"scope_tag\":\"acme/prod\""));
        let parsed: Item = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.scope_tag.as_deref(), Some("acme/prod"));
    }

    #[test]
    fn item_deserialize_without_classification_defaults_to_standard() {
        // Forward-compat: payloads written before the field existed must still
        // parse, and must land on `Standard` (the DB migration default), not a
        // deserialization error.
        let json = serde_json::json!({
            "id": Uuid::new_v4(),
            "owner_id": Uuid::new_v4(),
            "encrypted_blob": "blob",
            "wrapped_key": [1, 2, 3],
            "nonce": [4, 5, 6],
            "item_type": "password",
            "metadata": {},
            "storage_backend": "managed",
            "created_at": Utc::now(),
            "updated_at": Utc::now(),
        });
        let parsed: Item = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.classification, Classification::Standard);
    }

    #[test]
    fn validate_scope_tag_accepts_canonical_forms() {
        for tag in [
            "acme",
            "acme-prod",
            "acme_prod",
            "acme.prod",
            "acme/prod",
            "t1/team-a/app_1",
            "0pentest",
            "a",
            &"a".repeat(SCOPE_TAG_MAX_LEN),
        ] {
            assert!(
                validate_scope_tag(tag).is_ok(),
                "expected {tag:?} to validate"
            );
        }
    }

    #[test]
    fn validate_scope_tag_rejects_bad_inputs() {
        for tag in [
            "",
            " acme",          // leading space
            "acme ",          // trailing space
            "Acme",           // uppercase
            "acme!",          // punctuation
            "-acme",          // starts with dash
            "_acme",          // starts with underscore
            "/acme",          // starts with slash
            ".acme",          // starts with dot
            "acme\nprod",     // newline
            "acme\tprod",     // tab
            "acme/prod:read", // colon
            "日本語",         // non-ASCII
        ] {
            assert!(
                validate_scope_tag(tag).is_err(),
                "expected {tag:?} to be rejected"
            );
        }
        // Length cap: 65 chars must fail (boundary one past the limit).
        let too_long = "a".repeat(SCOPE_TAG_MAX_LEN + 1);
        assert!(validate_scope_tag(&too_long).is_err());
    }

    #[test]
    fn group_serde_roundtrip() {
        let group = Group {
            id: Uuid::new_v4(),
            owner_id: Uuid::new_v4(),
            encrypted_blob: "encrypted".to_string(),
            wrapped_key: vec![4, 5, 6],
            nonce: vec![7, 8, 9],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let json = serde_json::to_string(&group).unwrap();
        let parsed: Group = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, group.id);
        assert_eq!(parsed.wrapped_key, group.wrapped_key);
    }

    #[test]
    fn org_role_serde_roundtrip() {
        for variant in [OrgRole::Owner, OrgRole::BillingAdmin, OrgRole::Member] {
            let json = serde_json::to_string(&variant).unwrap();
            let parsed: OrgRole = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, variant);
        }
    }

    #[test]
    fn org_role_snake_case_serialization() {
        assert_eq!(serde_json::to_string(&OrgRole::Owner).unwrap(), "\"owner\"");
        assert_eq!(
            serde_json::to_string(&OrgRole::BillingAdmin).unwrap(),
            "\"billing_admin\""
        );
        assert_eq!(
            serde_json::to_string(&OrgRole::Member).unwrap(),
            "\"member\""
        );
    }

    #[test]
    fn org_role_as_str_matches_serde() {
        // Drift guard: the `org_members.role` CHECK constraint accepts the
        // exact set returned by `as_str()`. If the serde rename and the
        // helper diverge, the db layer would write a value the CHECK
        // rejects (or vice versa).
        for variant in [OrgRole::Owner, OrgRole::BillingAdmin, OrgRole::Member] {
            let serde_form = serde_json::to_string(&variant).unwrap();
            let quoted = format!("\"{}\"", variant.as_str());
            assert_eq!(serde_form, quoted, "variant {variant:?} drifted");
        }
    }

    #[test]
    fn org_role_from_str_roundtrips() {
        use std::str::FromStr;
        for variant in [OrgRole::Owner, OrgRole::BillingAdmin, OrgRole::Member] {
            let parsed = OrgRole::from_str(variant.as_str()).unwrap();
            assert_eq!(parsed, variant);
        }
    }

    #[test]
    fn org_role_from_str_rejects_unknown() {
        use std::str::FromStr;
        assert!(OrgRole::from_str("admin").is_err());
        assert!(OrgRole::from_str("Owner").is_err()); // case-sensitive
        assert!(OrgRole::from_str("").is_err());
    }

    #[test]
    fn org_role_satisfies_full_matrix() {
        // Caller × required matrix. Owner is a superset; BillingAdmin and
        // Member are parallel and do NOT cross-elevate (separation of
        // duties — see the docstring).
        let cases: &[(OrgRole, OrgRole, bool)] = &[
            (OrgRole::Owner, OrgRole::Owner, true),
            (OrgRole::Owner, OrgRole::BillingAdmin, true),
            (OrgRole::Owner, OrgRole::Member, true),
            (OrgRole::BillingAdmin, OrgRole::Owner, false),
            (OrgRole::BillingAdmin, OrgRole::BillingAdmin, true),
            (OrgRole::BillingAdmin, OrgRole::Member, false),
            (OrgRole::Member, OrgRole::Owner, false),
            (OrgRole::Member, OrgRole::BillingAdmin, false),
            (OrgRole::Member, OrgRole::Member, true),
        ];
        for (caller, required, expected) in cases.iter().copied() {
            assert_eq!(
                caller.satisfies(required),
                expected,
                "satisfies({caller:?}, {required:?})",
            );
        }
    }

    #[test]
    fn organization_serde_roundtrip() {
        let org = Organization {
            id: Uuid::new_v4(),
            name: "Acme Inc.".to_string(),
            billing_email: "billing@acme.example".to_string(),
            stripe_customer_id: Some("cus_test123".to_string()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            closed_at: None,
        };
        let json = serde_json::to_string(&org).unwrap();
        let parsed: Organization = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, org);
    }

    #[test]
    fn org_member_serde_roundtrip() {
        let member = OrgMember {
            org_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            role: OrgRole::Owner,
            joined_at: Utc::now(),
        };
        let json = serde_json::to_string(&member).unwrap();
        let parsed: OrgMember = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, member);
    }

    #[test]
    fn org_invitation_serde_roundtrip_drops_token_hash() {
        let invite = OrgInvitation {
            id: Uuid::new_v4(),
            org_id: Uuid::new_v4(),
            invited_email: "alice@example.com".to_string(),
            role: OrgRole::Member,
            token_hash: "deadbeef".to_string(),
            expires_at: Utc::now(),
            accepted_at: None,
            revoked_at: None,
            created_at: Utc::now(),
        };
        let json = serde_json::to_string(&invite).unwrap();

        // `token_hash` is server-internal — it must NOT appear in any
        // serialized form, even alongside the plaintext token at create
        // time. A consumer who learns the token later must not be able
        // to recover the hash from a stored response payload.
        assert!(!json.contains("token_hash"));
        assert!(!json.contains("deadbeef"));

        // Every other field round-trips; token_hash deserializes to its
        // String default ("") because of #[serde(skip)].
        let parsed: OrgInvitation = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, invite.id);
        assert_eq!(parsed.org_id, invite.org_id);
        assert_eq!(parsed.invited_email, invite.invited_email);
        assert_eq!(parsed.role, invite.role);
        assert_eq!(parsed.expires_at, invite.expires_at);
        assert_eq!(parsed.accepted_at, invite.accepted_at);
        assert_eq!(parsed.revoked_at, invite.revoked_at);
        assert_eq!(parsed.created_at, invite.created_at);
        assert_eq!(parsed.token_hash, "");
    }
}
