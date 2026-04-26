use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use zeroize::Zeroizing;

use crate::crypto::{decrypt_item, decrypt_item_auto, derive_subkey, CryptoError, MasterKey};

/// Errors from API key parsing.
#[derive(Debug, thiserror::Error)]
pub enum ApiKeyError {
    #[error("invalid API key format (expected vk_PREFIX_SECRET)")]
    InvalidFormat,
    #[error("invalid API key secret encoding: {0}")]
    InvalidEncoding(String),
    #[error("API key secret must be 32 bytes")]
    InvalidSecretLength,
}

/// Parse a `vk_PREFIX_SECRET` API key string.
/// Returns `(prefix_with_vk, 32-byte secret)`.
pub fn parse_api_key(raw_key: &str) -> Result<(String, Zeroizing<[u8; 32]>), ApiKeyError> {
    let parts: Vec<&str> = raw_key.splitn(3, '_').collect();
    if parts.len() != 3 || parts[0] != "vk" {
        return Err(ApiKeyError::InvalidFormat);
    }
    let prefix = format!("vk_{}", parts[1]);
    let secret_bytes = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(parts[2])
            .map_err(|e| ApiKeyError::InvalidEncoding(e.to_string()))?,
    );
    if secret_bytes.len() != 32 {
        return Err(ApiKeyError::InvalidSecretLength);
    }
    let arr: [u8; 32] = secret_bytes[..].try_into().unwrap();
    Ok((prefix, Zeroizing::new(arr)))
}

/// Unwrap a master key from its encrypted form (legacy heuristic).
///
/// Kept for callers that haven't been threaded through with the
/// per-row `format_version` column yet (#122 Phase 2). New callers
/// should use [`unwrap_master_key_from_encrypted_versioned`] with the
/// column value from the API response — the heuristic disappears in
/// Phase 4 once every caller passes a value.
///
/// Handles:
/// - Empty `encrypted_master_key`: legacy account, returns `password_key` as master key.
/// - V1 format: `0x01 + nonce(24) + ciphertext` with AAD `"master:{user_id}"`.
/// - V0 format: `nonce(24) + ciphertext` (no AAD).
/// - V0/V1 ambiguity: if first byte is `0x01`, tries V1 first, falls back to V0.
pub fn unwrap_master_key_from_encrypted(
    encrypted_master_key: &[u8],
    password_key: &MasterKey,
    user_id: &str,
) -> Result<MasterKey, CryptoError> {
    unwrap_master_key_from_encrypted_versioned(encrypted_master_key, password_key, user_id, None)
}

/// Unwrap a master key, consulting an explicit `format_version` from
/// `users.encrypted_master_key_format_version`.
///
/// `format_version` semantics match
/// [`crate::envelope::decrypt_blob_bytes_versioned`]:
/// - `Some(1)`: V1 with `master:<user_id>` AAD. **No V0 fallback** — see
///   the envelope counterpart; #122 Phase 4 closed the cross-format
///   `or_else` after confirming prod has zero V0 rows.
/// - `Some(0)`: V0 only; no upward retry.
/// - `None`: strict first-byte dispatch (`0x01` → V1, else → V0); no
///   cross-format retry, same as the column-driven arms.
pub fn unwrap_master_key_from_encrypted_versioned(
    encrypted_master_key: &[u8],
    password_key: &MasterKey,
    user_id: &str,
    format_version: Option<i16>,
) -> Result<MasterKey, CryptoError> {
    if encrypted_master_key.is_empty() {
        return Ok(MasterKey::from_bytes(*password_key.as_bytes()));
    }

    let kwk = derive_subkey(password_key, b"vault-enc")?;
    let aad = format!("master:{}", user_id);

    if encrypted_master_key.len() < 25 {
        return Err(CryptoError::DecryptionFailed);
    }

    let try_v1 = || -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        if encrypted_master_key[0] != 0x01 || encrypted_master_key.len() <= 25 {
            return Err(CryptoError::DecryptionFailed);
        }
        decrypt_item_auto(
            &kwk,
            &encrypted_master_key[25..],
            &encrypted_master_key[1..25],
            aad.as_bytes(),
        )
    };
    let try_v0 = || {
        decrypt_item(
            &kwk,
            &encrypted_master_key[24..],
            &encrypted_master_key[..24],
        )
    };

    let result = match format_version {
        Some(1) => try_v1(),
        Some(0) => try_v0(),
        Some(n) => Err(CryptoError::UnsupportedFormatVersion(n)),
        None => {
            if encrypted_master_key[0] == 0x01 && encrypted_master_key.len() > 25 {
                try_v1()
            } else {
                try_v0()
            }
        }
    }?;

    if result.len() != 32 {
        return Err(CryptoError::InvalidKeyLength);
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    Ok(MasterKey::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{encrypt_item, encrypt_item_v1};

    #[test]
    fn parse_api_key_valid() {
        let secret = [0xABu8; 32];
        let encoded = URL_SAFE_NO_PAD.encode(secret);
        let raw = format!("vk_test_{}", encoded);
        let (prefix, parsed_secret) = parse_api_key(&raw).unwrap();
        assert_eq!(prefix, "vk_test");
        assert_eq!(*parsed_secret, secret);
    }

    #[test]
    fn parse_api_key_invalid_format() {
        assert!(parse_api_key("not_an_api_key").is_err());
        assert!(parse_api_key("ak_prefix_secret").is_err());
        assert!(parse_api_key("vk_only").is_err());
    }

    #[test]
    fn parse_api_key_wrong_length() {
        let short = URL_SAFE_NO_PAD.encode([0u8; 16]);
        let raw = format!("vk_test_{}", short);
        assert!(matches!(
            parse_api_key(&raw),
            Err(ApiKeyError::InvalidSecretLength)
        ));
    }

    #[test]
    fn unwrap_master_key_empty_legacy() {
        let password_key = MasterKey::from_bytes([0x42u8; 32]);
        let result = unwrap_master_key_from_encrypted(&[], &password_key, "user1").unwrap();
        assert_eq!(result.as_bytes(), password_key.as_bytes());
    }

    #[test]
    fn unwrap_master_key_v0_roundtrip() {
        let master_key_bytes = [0xABu8; 32];
        let password_key = MasterKey::from_bytes([0x11u8; 32]);
        let kwk = derive_subkey(&password_key, b"vault-enc").unwrap();

        // V0: nonce(24) || ciphertext
        let enc = encrypt_item(&kwk, &master_key_bytes).unwrap();
        let mut encrypted = Vec::new();
        encrypted.extend_from_slice(&enc.nonce);
        encrypted.extend_from_slice(&enc.ciphertext);

        let recovered =
            unwrap_master_key_from_encrypted(&encrypted, &password_key, "user1").unwrap();
        assert_eq!(*recovered.as_bytes(), master_key_bytes);
    }

    #[test]
    fn unwrap_master_key_v1_roundtrip() {
        let master_key_bytes = [0xCDu8; 32];
        let password_key = MasterKey::from_bytes([0x22u8; 32]);
        let kwk = derive_subkey(&password_key, b"vault-enc").unwrap();
        let aad = b"master:user123";

        // V1: 0x01 + nonce(24) + ciphertext
        let enc = encrypt_item_v1(&kwk, &master_key_bytes, aad).unwrap();
        let mut encrypted = Vec::with_capacity(1 + 24 + enc.ciphertext.len());
        encrypted.push(0x01);
        encrypted.extend_from_slice(&enc.nonce);
        encrypted.extend_from_slice(&enc.ciphertext);

        let recovered =
            unwrap_master_key_from_encrypted(&encrypted, &password_key, "user123").unwrap();
        assert_eq!(*recovered.as_bytes(), master_key_bytes);
    }

    #[test]
    fn unwrap_master_key_too_short() {
        let password_key = MasterKey::from_bytes([0u8; 32]);
        let result = unwrap_master_key_from_encrypted(&[0u8; 10], &password_key, "user1");
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------
    // Phase 2 part 2 (#122) — asymmetric fallback for the master key
    // wrap. Mirrors `envelope::tests`'s 5-case table for the blob path.
    // -----------------------------------------------------------------

    fn build_v1_master_blob(kwk: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
        let p = encrypt_item_v1(kwk, plaintext, aad).unwrap();
        let mut blob = vec![0x01u8];
        blob.extend_from_slice(&p.nonce);
        blob.extend_from_slice(&p.ciphertext); // includes inner 0x01
        blob
    }

    fn build_v0_master_blob(kwk: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
        let p = encrypt_item(kwk, plaintext).unwrap();
        let mut blob = Vec::with_capacity(24 + p.ciphertext.len());
        blob.extend_from_slice(&p.nonce);
        blob.extend_from_slice(&p.ciphertext);
        blob
    }

    #[test]
    fn versioned_v1_column_v1_bytes_succeeds() {
        let mk = [0xCDu8; 32];
        let pwd = MasterKey::from_bytes([0x22u8; 32]);
        let kwk = derive_subkey(&pwd, b"vault-enc").unwrap();
        let blob = build_v1_master_blob(&kwk, &mk, b"master:user123");

        let recovered =
            unwrap_master_key_from_encrypted_versioned(&blob, &pwd, "user123", Some(1)).unwrap();
        assert_eq!(*recovered.as_bytes(), mk);
    }

    /// Phase 4 cutover: column = 1 with V0 bytes (the 1/256
    /// backfill-misclassification case) used to fall back via
    /// `or_else`. Now it fails. Acceptable because prod has zero V0
    /// rows — verified before the cutover.
    #[test]
    fn versioned_v1_column_v0_bytes_fails_no_fallback() {
        let mk = [0xEFu8; 32];
        let pwd = MasterKey::from_bytes([0x33u8; 32]);
        let kwk = derive_subkey(&pwd, b"vault-enc").unwrap();

        let mut blob = Vec::new();
        for _ in 0..16384 {
            let candidate = build_v0_master_blob(&kwk, &mk);
            if candidate[0] == 0x01 {
                blob = candidate;
                break;
            }
        }
        assert!(
            !blob.is_empty(),
            "couldn't synthesise a V0 blob with a leading 0x01 nonce in 16384 attempts — RNG broken?"
        );

        let result = unwrap_master_key_from_encrypted_versioned(&blob, &pwd, "user-misc", Some(1));
        assert!(
            result.is_err(),
            "V1 master-key path must not fall back to V0 — Phase 4 closed the AAD-erosion vector"
        );
    }

    #[test]
    fn versioned_v0_column_v0_bytes_succeeds() {
        let mk = [0xABu8; 32];
        let pwd = MasterKey::from_bytes([0x11u8; 32]);
        let kwk = derive_subkey(&pwd, b"vault-enc").unwrap();
        let blob = build_v0_master_blob(&kwk, &mk);

        let recovered =
            unwrap_master_key_from_encrypted_versioned(&blob, &pwd, "user1", Some(0)).unwrap();
        assert_eq!(*recovered.as_bytes(), mk);
    }

    #[test]
    fn versioned_v0_column_v1_bytes_fails_no_upward_retry() {
        let mk = [0x12u8; 32];
        let pwd = MasterKey::from_bytes([0x44u8; 32]);
        let kwk = derive_subkey(&pwd, b"vault-enc").unwrap();
        let blob = build_v1_master_blob(&kwk, &mk, b"master:user-tamp");

        let result = unwrap_master_key_from_encrypted_versioned(&blob, &pwd, "user-tamp", Some(0));
        assert!(
            result.is_err(),
            "V0 path on V1 ciphertext must fail — no upward retry"
        );
    }

    #[test]
    fn versioned_v1_column_v1_tampered_fails() {
        let mk = [0x55u8; 32];
        let pwd = MasterKey::from_bytes([0x66u8; 32]);
        let kwk = derive_subkey(&pwd, b"vault-enc").unwrap();
        let mut blob = build_v1_master_blob(&kwk, &mk, b"master:user-bad");

        // Flip a byte in the AEAD ciphertext (after 0x01 + 24-byte nonce + inner 0x01).
        blob[30] ^= 0x01;

        let result = unwrap_master_key_from_encrypted_versioned(&blob, &pwd, "user-bad", Some(1));
        assert!(
            result.is_err(),
            "tampered V1 ciphertext must fail — strict V1 path, no fallback after Phase 4"
        );
    }

    /// Mirrors the envelope-side test: an unknown `format_version`
    /// surfaces as `UnsupportedFormatVersion(n)` and not the generic
    /// `DecryptionFailed` so the failure mode is visible to operators
    /// during a forward-compat mismatch (deploy ordering, future
    /// format), separately from real AEAD authentication failures.
    #[test]
    fn versioned_unknown_column_returns_unsupported_variant() {
        let mk = [0x77u8; 32];
        let pwd = MasterKey::from_bytes([0x88u8; 32]);
        let kwk = derive_subkey(&pwd, b"vault-enc").unwrap();
        let blob = build_v1_master_blob(&kwk, &mk, b"master:user-future");

        let err = unwrap_master_key_from_encrypted_versioned(&blob, &pwd, "user-future", Some(2))
            .unwrap_err();
        assert!(
            matches!(err, CryptoError::UnsupportedFormatVersion(2)),
            "Some(2) must return UnsupportedFormatVersion(2), got {err:?}"
        );
    }
}
