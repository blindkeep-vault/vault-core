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

/// Decrypt an encrypted blob (raw bytes, not base64).
///
/// Heuristic selector kept for callers that haven't been threaded
/// through with the per-row `format_version` column yet (#122 Phase 2).
/// New callers should use [`decrypt_blob_bytes_versioned`] with the
/// column value from the API response — the heuristic disappears in
/// Phase 4 once every caller passes a value.
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
    decrypt_blob_bytes_versioned(blob_data, item_key, user_id, None)
}

/// Decrypt an encrypted blob, consulting an explicit `format_version`
/// instead of the legacy first-byte heuristic.
///
/// The `format_version` argument carries the per-row column added in
/// #122 Phase 2 (migrations 049-062):
///
/// - `Some(1)`: V1 path with `item:<user_id>` AAD. **No V0 fallback** —
///   #122 Phase 4 closed the cross-format `or_else` after confirming
///   prod has zero V0 rows, restoring AAD's defensive value as a
///   ciphertext-substitution backstop.
/// - `Some(0)`: V0 path only. No upward retry to V1.
/// - `None`: strict first-byte dispatch (`0x01` → V1, else → V0). Kept
///   for callers that still don't pass the column; no cross-format
///   retry, same as the column-driven arms.
pub fn decrypt_blob_bytes_versioned(
    blob_data: &[u8],
    item_key: &[u8; 32],
    user_id: &str,
    format_version: Option<i16>,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if blob_data.len() < 25 {
        return Err(CryptoError::DecryptionFailed);
    }

    let blob_aad: Vec<u8> = if user_id.is_empty() {
        Vec::new()
    } else {
        format!("item:{}", user_id).into_bytes()
    };

    let try_v1 = || -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        if blob_data[0] != 0x01 || blob_data.len() <= 25 {
            return Err(CryptoError::DecryptionFailed);
        }
        let nonce = &blob_data[1..25];
        let ciphertext = &blob_data[25..];
        decrypt_item_auto(item_key, ciphertext, nonce, &blob_aad)
    };
    let try_v0 = || decrypt_item(item_key, &blob_data[24..], &blob_data[..24]);

    match format_version {
        Some(1) => try_v1(),
        Some(0) => try_v0(),
        Some(n) => Err(CryptoError::UnsupportedFormatVersion(n)),
        None => {
            if blob_data[0] == 0x01 && blob_data.len() > 25 {
                try_v1()
            } else {
                try_v0()
            }
        }
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
    // Legacy V0 envelopes were stored as raw JSON without the 4-byte length
    // prefix; fall through to the raw bytes on unpad failure so they still
    // parse. New V1 envelopes always pad; tampered V1 prefix → JSON parse
    // fails → returns None (#129 L-1, residual).
    let envelope_bytes = unpad(&decrypted).unwrap_or(&decrypted[..]);
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

    // -----------------------------------------------------------------
    // Phase 2 part 2 (#122) — asymmetric fallback table.
    // -----------------------------------------------------------------
    //
    // Five round-trip cases from the migration plan
    // (`doc/V0_FALLBACK_REMOVAL_PLAN.md` § Phase 2 Tests). The
    // "asymmetric" property is what protects against the AAD-binding
    // erosion that started this whole effort: column = 1 retries V0 on
    // AEAD failure (handles the 1/256 backfill misclassification);
    // column = 0 does NOT retry V1 (so a tampered column flip from 0
    // to 1 simply fails to decrypt).

    use crate::crypto::{encrypt_item, encrypt_item_v1};

    fn build_v1_blob(item_key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
        // The on-the-wire V1 blob format that `decrypt_blob_bytes`
        // accepts is `0x01 || nonce(24) || 0x01 || raw_aead` — the
        // double 0x01 is intentional. The first 0x01 is the framing
        // version (used by `decrypt_blob_bytes` to slice the nonce);
        // the second 0x01 is the AEAD ciphertext-version marker that
        // `decrypt_item_auto` consumes when stripping it before AEAD
        // decryption. crypto::encrypt_item_v1 returns ciphertext that
        // already includes the inner 0x01, so concatenate as-is.
        let payload = encrypt_item_v1(item_key, plaintext, aad).unwrap();
        let mut blob = vec![0x01u8];
        blob.extend_from_slice(&payload.nonce);
        blob.extend_from_slice(&payload.ciphertext); // includes inner 0x01 prefix
        blob
    }

    fn build_v0_blob(item_key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
        let payload = encrypt_item(item_key, plaintext).unwrap();
        let mut blob = Vec::with_capacity(24 + payload.ciphertext.len());
        blob.extend_from_slice(&payload.nonce);
        blob.extend_from_slice(&payload.ciphertext);
        blob
    }

    /// column = 1, bytes V1 → success. Steady state after Phase 1.
    #[test]
    fn versioned_v1_column_v1_bytes_succeeds() {
        let item_key = [7u8; 32];
        let user = "user-123";
        let aad = format!("item:{}", user).into_bytes();
        let plaintext = b"hello phase 2";
        let blob = build_v1_blob(&item_key, plaintext, &aad);

        let decrypted = decrypt_blob_bytes_versioned(&blob, &item_key, user, Some(1)).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    /// column = 1, bytes V0 → **failure**. Phase 4 closed the
    /// cross-format `or_else`: a V0 row whose nonce happens to start
    /// with `0x01` and got backfilled as V1 by Phase 2 (the 1/256
    /// case) used to silently fall through to V0; now it fails to
    /// decrypt. Acceptable because prod has zero V0 rows — confirmed
    /// before the cutover.
    #[test]
    fn versioned_v1_column_v0_bytes_fails_no_fallback() {
        let item_key = [9u8; 32];
        let user = "user-999";
        let plaintext = b"misclassified row";

        // Synthesise the 1/256 case the old fallback used to handle.
        let mut blob = Vec::new();
        for _ in 0..16384 {
            let candidate = build_v0_blob(&item_key, plaintext);
            if candidate[0] == 0x01 {
                blob = candidate;
                break;
            }
        }
        assert!(
            !blob.is_empty(),
            "after 16384 attempts no V0 blob started with 0x01 — RNG \
             behaviour likely broken"
        );

        let result = decrypt_blob_bytes_versioned(&blob, &item_key, user, Some(1));
        assert!(
            result.is_err(),
            "V1 path must not fall back to V0 — that's the AAD-erosion \
             vector #122 Phase 4 closed"
        );
    }

    /// column = 0, bytes V0 → success. The bulk of the legacy V0 inventory.
    #[test]
    fn versioned_v0_column_v0_bytes_succeeds() {
        let item_key = [3u8; 32];
        let user = "user-abc";
        let plaintext = b"old V0 row";
        let blob = build_v0_blob(&item_key, plaintext);

        let decrypted = decrypt_blob_bytes_versioned(&blob, &item_key, user, Some(0)).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    /// column = 0, bytes V1 → failure. **No upward retry.** A tampered
    /// column flip from 0 to 1 must not silently succeed via the V1
    /// path; that would re-introduce the AAD-binding erosion we are
    /// closing. (Strictly: with column = 0 we treat the bytes as
    /// V0-framed, which means we slice nonce(24) || ciphertext from
    /// `blob[0..]` — the leading 0x01 of the V1 blob becomes part of
    /// the V0 nonce, AEAD fails.)
    #[test]
    fn versioned_v0_column_v1_bytes_fails_no_upward_retry() {
        let item_key = [11u8; 32];
        let user = "user-xyz";
        let aad = format!("item:{}", user).into_bytes();
        let blob = build_v1_blob(&item_key, b"v1 plaintext", &aad);

        let result = decrypt_blob_bytes_versioned(&blob, &item_key, user, Some(0));
        assert!(
            result.is_err(),
            "V0 path on V1 ciphertext must fail — no upward retry"
        );
    }

    /// column = 1, bytes V1 with tampered AEAD → failure. After Phase
    /// 4 there is no V0 fallback at all, so this is the trivially
    /// strict path — kept as a regression guard.
    #[test]
    fn versioned_v1_column_v1_tampered_fails() {
        let item_key = [13u8; 32];
        let user = "user-tampered";
        let aad = format!("item:{}", user).into_bytes();
        let mut blob = build_v1_blob(&item_key, b"will be tampered", &aad);

        // Flip a byte in the AEAD ciphertext (after 0x01 + 24-byte nonce).
        blob[30] ^= 0x01;

        let result = decrypt_blob_bytes_versioned(&blob, &item_key, user, Some(1));
        assert!(
            result.is_err(),
            "tampered V1 ciphertext must fail — strict V1 path, no fallback"
        );
    }

    /// `None` (legacy heuristic) is also strict after Phase 4: a V0
    /// blob whose nonce happens to start with `0x01` is dispatched to
    /// the V1 path by the first-byte heuristic, V1 fails AEAD, and the
    /// removed `or_else` no longer rescues. Same loud-fail trade-off
    /// as the column-driven 1/256 case; acceptable because prod has
    /// no V0 rows to be misdispatched in the first place.
    #[test]
    fn unversioned_v0_with_leading_0x01_now_fails() {
        let item_key = [23u8; 32];
        let user = "heuristic-strict";
        let plaintext = b"misclassified by heuristic";

        let mut blob = Vec::new();
        for _ in 0..16384 {
            let candidate = build_v0_blob(&item_key, plaintext);
            if candidate[0] == 0x01 {
                blob = candidate;
                break;
            }
        }
        assert!(!blob.is_empty(), "RNG sanity check");

        let result = decrypt_blob_bytes(&blob, &item_key, user);
        assert!(
            result.is_err(),
            "heuristic V0 fallback removed in #122 Phase 4 — V0 blob with \
             leading 0x01 must fail loudly via the V1 path"
        );
    }

    /// `decrypt_blob_bytes` (no format_version) must keep the
    /// pre-Phase-2 heuristic behaviour bit-for-bit so callers that
    /// haven't been threaded through with the column yet keep working.
    #[test]
    fn unversioned_matches_pre_phase2_heuristic() {
        let item_key = [17u8; 32];
        let user = "compat-user";
        let aad = format!("item:{}", user).into_bytes();
        let v1 = build_v1_blob(&item_key, b"v1", &aad);
        let v0 = build_v0_blob(&item_key, b"v0");

        let decrypted_v1 = decrypt_blob_bytes(&v1, &item_key, user).unwrap();
        assert_eq!(decrypted_v1.as_slice(), b"v1");

        let decrypted_v0 = decrypt_blob_bytes(&v0, &item_key, user).unwrap();
        assert_eq!(decrypted_v0.as_slice(), b"v0");
    }

    /// An unknown `format_version` value must surface as a distinct
    /// error so an operator looking at a decrypt failure can tell a
    /// forward-compat mismatch (deploy ordering, future format)
    /// apart from a real AEAD authentication failure (tampering, key
    /// mismatch, real bug). Lumping both under `DecryptionFailed`
    /// would have made #122 Phase 4 harder to debug.
    #[test]
    fn versioned_unknown_column_returns_unsupported_variant() {
        let item_key = [19u8; 32];
        let user = "user-future";
        let aad = format!("item:{}", user).into_bytes();
        let blob = build_v1_blob(&item_key, b"plaintext", &aad);

        let err = decrypt_blob_bytes_versioned(&blob, &item_key, user, Some(2)).unwrap_err();
        assert!(
            matches!(err, CryptoError::UnsupportedFormatVersion(2)),
            "Some(2) must return UnsupportedFormatVersion(2), got {err:?}"
        );

        // Negative values (defensive — sqlx maps SMALLINT to i16, so negative
        // is reachable in principle if someone hand-edits the column).
        let err = decrypt_blob_bytes_versioned(&blob, &item_key, user, Some(-1)).unwrap_err();
        assert!(
            matches!(err, CryptoError::UnsupportedFormatVersion(-1)),
            "Some(-1) must return UnsupportedFormatVersion(-1), got {err:?}"
        );
    }
}
