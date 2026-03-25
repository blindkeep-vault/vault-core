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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Item {
    pub id: Uuid,
    pub owner_id: Uuid,
    pub encrypted_blob: String,
    pub wrapped_key: Vec<u8>,
    pub nonce: Vec<u8>,
    pub item_type: ItemType,
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
