use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::{decrypt_item, decrypt_item_auto, CryptoError};
use crate::padding::unpad;

/// Encrypted envelope format (compatible with web UI).
/// The `name` field is the display name / secret label.
/// The `content` field holds the secret value.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SecretBlob {
    pub name: String,
    #[serde(default)]
    pub content: Option<String>,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default, alias = "type", alias = "item_type")]
    pub item_type: Option<String>,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_wrapped_key: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_nonce: Option<Vec<u8>>,
}

impl SecretBlob {
    pub fn display_name(&self) -> &str {
        if !self.name.is_empty() {
            &self.name
        } else {
            self.label.as_deref().unwrap_or("Untitled")
        }
    }

    pub fn secret_value(&self) -> Option<&str> {
        self.content.as_deref().or(self.value.as_deref())
    }

    pub fn is_secret(&self) -> bool {
        self.content.is_some() || self.item_type.as_deref() == Some("secret")
    }

    pub fn is_file(&self) -> bool {
        self.item_type.as_deref() == Some("file")
            || (self.item_type.as_deref() == Some("document") && self.filename.is_some())
    }
}

/// Decrypt an encrypted blob (raw bytes, not base64) using V0/V1 auto-detection.
///
/// V1 format: `0x01 + nonce(24) + ciphertext`
/// V0 format: `nonce(24) + ciphertext`
///
/// The `user_id` is used to construct the AAD (`"item:{user_id}"`) for V1 decryption.
/// Pass an empty string for contexts without a user_id.
pub fn decrypt_blob_bytes(
    blob_data: &[u8],
    item_key: &[u8; 32],
    user_id: &str,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if blob_data.len() < 25 {
        return Err(CryptoError::DecryptionFailed);
    }

    let blob_aad = if user_id.is_empty() {
        Vec::new()
    } else {
        format!("item:{}", user_id).into_bytes()
    };

    if blob_data[0] == 0x01 && blob_data.len() > 25 {
        let nonce = &blob_data[1..25];
        let ciphertext = &blob_data[25..];
        decrypt_item_auto(item_key, ciphertext, nonce, &blob_aad).or_else(|_| {
            // Nonce happened to start with 0x01 — treat as V0
            decrypt_item(item_key, &blob_data[24..], &blob_data[..24])
        })
    } else {
        decrypt_item(item_key, &blob_data[24..], &blob_data[..24])
    }
}

/// Decrypt a base64-encoded inline envelope, unpad, and parse as SecretBlob.
///
/// Used for file items where `encrypted_blob` is the metadata envelope.
pub fn decrypt_inline_envelope(
    enc_blob_b64: &str,
    item_key: &[u8; 32],
    user_id: &str,
) -> Option<SecretBlob> {
    use base64::{engine::general_purpose::STANDARD, Engine};

    let blob_data = STANDARD.decode(enc_blob_b64).ok()?;
    let decrypted = decrypt_blob_bytes(&blob_data, item_key, user_id).ok()?;
    let envelope_bytes = unpad(&decrypted);
    let blob: SecretBlob = serde_json::from_slice(envelope_bytes).ok()?;
    if blob.is_secret() || blob.is_file() {
        Some(blob)
    } else {
        None
    }
}

/// Build a binary envelope: `[4-byte BE header_len][JSON metadata][file_data]`.
///
/// This is the inverse of [`parse_envelope`].
pub fn build_envelope(filename: &str, data: &[u8], mime_type: &str) -> Vec<u8> {
    let meta = serde_json::json!({
        "name": filename,
        "type": mime_type,
        "size": data.len(),
    });
    let meta_bytes = serde_json::to_vec(&meta).expect("JSON serialization cannot fail");
    let header_len = meta_bytes.len() as u32;
    let mut out = Vec::with_capacity(4 + meta_bytes.len() + data.len());
    out.extend_from_slice(&header_len.to_be_bytes());
    out.extend_from_slice(&meta_bytes);
    out.extend_from_slice(data);
    out
}

/// Parse a binary envelope: 4-byte BE header length + JSON metadata + file bytes.
/// Returns `(filename, file_data)`. Falls back to a default name if parsing fails.
pub fn parse_envelope<'a>(data: &'a [u8], fallback_id: &str) -> (String, &'a [u8]) {
    if data.len() > 4 {
        let header_len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        if header_len > 0 && header_len < 10240 && 4 + header_len <= data.len() {
            if let Ok(meta_json) = std::str::from_utf8(&data[4..4 + header_len]) {
                if let Ok(meta) = serde_json::from_str::<serde_json::Value>(meta_json) {
                    let short_id = &fallback_id[..fallback_id.len().min(8)];
                    let name = meta["name"]
                        .as_str()
                        .unwrap_or(&format!("drop-{}", short_id))
                        .to_string();
                    return (name, &data[4 + header_len..]);
                }
            }
        }
    }
    let short_id = &fallback_id[..fallback_id.len().min(8)];
    (format!("drop-{}", short_id), data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_blob_display_name() {
        let blob = SecretBlob {
            name: "my-secret".into(),
            content: None,
            label: Some("label".into()),
            item_type: None,
            value: None,
            filename: None,
            mime_type: None,
            file_size: None,
            file_wrapped_key: None,
            file_nonce: None,
        };
        assert_eq!(blob.display_name(), "my-secret");

        let blob2 = SecretBlob {
            name: String::new(),
            label: Some("fallback-label".into()),
            ..blob.clone()
        };
        assert_eq!(blob2.display_name(), "fallback-label");

        let blob3 = SecretBlob {
            name: String::new(),
            label: None,
            ..blob.clone()
        };
        assert_eq!(blob3.display_name(), "Untitled");
    }

    #[test]
    fn secret_blob_secret_value() {
        let blob = SecretBlob {
            name: "test".into(),
            content: Some("content-val".into()),
            label: None,
            item_type: None,
            value: Some("value-val".into()),
            filename: None,
            mime_type: None,
            file_size: None,
            file_wrapped_key: None,
            file_nonce: None,
        };
        assert_eq!(blob.secret_value(), Some("content-val"));

        let blob2 = SecretBlob {
            content: None,
            ..blob.clone()
        };
        assert_eq!(blob2.secret_value(), Some("value-val"));
    }

    #[test]
    fn secret_blob_type_checks() {
        let secret = SecretBlob {
            name: "s".into(),
            content: Some("v".into()),
            label: None,
            item_type: Some("secret".into()),
            value: None,
            filename: None,
            mime_type: None,
            file_size: None,
            file_wrapped_key: None,
            file_nonce: None,
        };
        assert!(secret.is_secret());
        assert!(!secret.is_file());

        let file = SecretBlob {
            content: None,
            item_type: Some("file".into()),
            filename: Some("test.txt".into()),
            ..secret.clone()
        };
        assert!(!file.is_secret());
        assert!(file.is_file());

        let doc_file = SecretBlob {
            item_type: Some("document".into()),
            filename: Some("doc.pdf".into()),
            ..secret.clone()
        };
        assert!(doc_file.is_file());
    }

    #[test]
    fn secret_blob_serde_roundtrip() {
        let blob = SecretBlob {
            name: "test".into(),
            content: Some("secret-value".into()),
            label: None,
            item_type: Some("secret".into()),
            value: None,
            filename: None,
            mime_type: None,
            file_size: None,
            file_wrapped_key: None,
            file_nonce: None,
        };
        let json = serde_json::to_string(&blob).unwrap();
        let recovered: SecretBlob = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.name, "test");
        assert_eq!(recovered.secret_value(), Some("secret-value"));
    }

    #[test]
    fn secret_blob_type_alias() {
        // Web UI sends "type" field, CLI sends "item_type"
        let json_with_type = r#"{"name":"a","type":"secret","content":"v"}"#;
        let blob: SecretBlob = serde_json::from_str(json_with_type).unwrap();
        assert_eq!(blob.item_type.as_deref(), Some("secret"));

        let json_with_item_type = r#"{"name":"b","item_type":"file","filename":"f.txt"}"#;
        let blob2: SecretBlob = serde_json::from_str(json_with_item_type).unwrap();
        assert_eq!(blob2.item_type.as_deref(), Some("file"));
    }

    #[test]
    fn parse_envelope_valid() {
        let meta = br#"{"name":"myfile.txt"}"#;
        let file_data = b"file-contents-here";
        let mut envelope = Vec::new();
        envelope.extend_from_slice(&(meta.len() as u32).to_be_bytes());
        envelope.extend_from_slice(meta);
        envelope.extend_from_slice(file_data);

        let (name, data) = parse_envelope(&envelope, "abc12345");
        assert_eq!(name, "myfile.txt");
        assert_eq!(data, file_data);
    }

    #[test]
    fn parse_envelope_no_name_in_meta() {
        let meta = br#"{"size":42}"#;
        let file_data = b"data";
        let mut envelope = Vec::new();
        envelope.extend_from_slice(&(meta.len() as u32).to_be_bytes());
        envelope.extend_from_slice(meta);
        envelope.extend_from_slice(file_data);

        let (name, data) = parse_envelope(&envelope, "abcdefghij");
        assert_eq!(name, "drop-abcdefgh");
        assert_eq!(data, file_data);
    }

    #[test]
    fn parse_envelope_invalid_fallback() {
        let (name, data) = parse_envelope(b"short", "xy");
        assert_eq!(name, "drop-xy");
        assert_eq!(data, b"short");
    }

    #[test]
    fn decrypt_blob_bytes_too_short() {
        let result = decrypt_blob_bytes(&[0u8; 10], &[0u8; 32], "user1");
        assert!(result.is_err());
    }

    #[test]
    fn build_parse_envelope_roundtrip() {
        let filename = "report.pdf";
        let file_data = b"binary file contents here";
        let mime = "application/pdf";

        let envelope = build_envelope(filename, file_data, mime);
        let (parsed_name, parsed_data) = parse_envelope(&envelope, "fallback");

        assert_eq!(parsed_name, filename);
        assert_eq!(parsed_data, file_data);
    }

    #[test]
    fn build_envelope_empty_data() {
        let envelope = build_envelope("empty.txt", b"", "text/plain");
        let (name, data) = parse_envelope(&envelope, "fb");
        assert_eq!(name, "empty.txt");
        assert!(data.is_empty());
    }
}
