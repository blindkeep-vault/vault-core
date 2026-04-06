use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

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
pub fn parse_api_key(raw_key: &str) -> Result<(String, [u8; 32]), ApiKeyError> {
    let parts: Vec<&str> = raw_key.splitn(3, '_').collect();
    if parts.len() != 3 || parts[0] != "vk" {
        return Err(ApiKeyError::InvalidFormat);
    }
    let prefix = format!("vk_{}", parts[1]);
    let secret_bytes = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|e| ApiKeyError::InvalidEncoding(e.to_string()))?;
    if secret_bytes.len() != 32 {
        return Err(ApiKeyError::InvalidSecretLength);
    }
    Ok((prefix, secret_bytes.try_into().unwrap()))
}

/// Unwrap a master key from its encrypted form.
///
/// Handles:
/// - Empty `encrypted_master_key`: legacy account, returns `password_key` as master key.
/// - V1 format: `0x01 + nonce(24) + ciphertext` with AAD `"master:{user_id}"`.
/// - V0 format: `nonce(24) + ciphertext` (no AAD).
/// - V0/V1 ambiguity: if first byte is `0x01`, tries V1 first, falls back to V0.
///
/// The caller is responsible for fetching the encrypted master key from the server.
pub fn unwrap_master_key_from_encrypted(
    encrypted_master_key: &[u8],
    password_key: &MasterKey,
    user_id: &str,
) -> Result<MasterKey, CryptoError> {
    if encrypted_master_key.is_empty() {
        return Ok(MasterKey::from_bytes(*password_key.as_bytes()));
    }

    let kwk = derive_subkey(password_key, b"vault-enc")?;
    let aad = format!("master:{}", user_id);

    if encrypted_master_key.len() < 25 {
        return Err(CryptoError::DecryptionFailed);
    }

    let result = if encrypted_master_key[0] == 0x01 && encrypted_master_key.len() > 25 {
        decrypt_item_auto(
            &kwk,
            &encrypted_master_key[25..],
            &encrypted_master_key[1..25],
            aad.as_bytes(),
        )
        .or_else(|_| {
            // Nonce happened to start with 0x01 — treat as V0
            decrypt_item(
                &kwk,
                &encrypted_master_key[24..],
                &encrypted_master_key[..24],
            )
        })
    } else {
        decrypt_item(
            &kwk,
            &encrypted_master_key[24..],
            &encrypted_master_key[..24],
        )
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
        assert_eq!(parsed_secret, secret);
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
}
