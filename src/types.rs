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
    pub grantor_id: Uuid,
    pub grantee_email: String,
    pub grantee_id: Option<Uuid>,
    pub wrapped_key: Vec<u8>,
    pub ephemeral_pubkey: Vec<u8>,
    pub policy: serde_json::Value,
    pub status: GrantStatus,
    pub view_count: i32,
    pub created_at: DateTime<Utc>,
    pub claimed_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
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
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let json = serde_json::to_string(&item).unwrap();
        assert!(json.contains("\"classification\":\"confidential\""));
        let parsed: Item = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.classification, Classification::Confidential);
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
}
