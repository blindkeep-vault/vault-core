use hkdf::Hkdf;
use hmac::Hmac;
use sha2::{Sha256, Sha512};

use crate::crypto::{decrypt_item, encrypt_item, CryptoError};

/// Normalize a mnemonic: lowercase, single-space separated.
pub fn normalize_mnemonic(m: &str) -> String {
    m.split_whitespace()
        .map(|w| w.to_lowercase())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Derive a hex-encoded lookup key from a mnemonic using HKDF-SHA256.
pub fn derive_drop_lookup_key(mnemonic: &str) -> String {
    let hkdf = Hkdf::<Sha256>::new(Some(b"vault-drop"), mnemonic.as_bytes());
    let mut out = [0u8; 32];
    hkdf.expand(b"lookup", &mut out)
        .expect("HKDF expand failed");
    hex::encode(out)
}

/// Derive a 32-byte wrapping key from a mnemonic using PBKDF2-HMAC-SHA512.
/// v1: 2048 iterations, v2+: 600,000 iterations.
pub fn derive_drop_wrapping_key(mnemonic: &str, version: i32) -> [u8; 32] {
    let iterations = if version >= 2 { 600_000 } else { 2048 };
    let mut out = [0u8; 32];
    pbkdf2::pbkdf2::<Hmac<Sha512>>(mnemonic.as_bytes(), b"vault-drop", iterations, &mut out)
        .expect("PBKDF2 failed");
    out
}

/// Wrap a 32-byte drop key: encrypt with wrapping key, return nonce(24) || ciphertext.
pub fn wrap_drop_key(wrapping_key: &[u8; 32], drop_key: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
    let enc = encrypt_item(wrapping_key, drop_key)?;
    let mut out = Vec::with_capacity(24 + enc.ciphertext.len());
    out.extend_from_slice(&enc.nonce);
    out.extend_from_slice(&enc.ciphertext);
    Ok(out)
}

/// Unwrap a drop key from nonce(24) || ciphertext format.
pub fn unwrap_drop_key(wrapping_key: &[u8; 32], wrapped: &[u8]) -> Result<[u8; 32], CryptoError> {
    if wrapped.len() < 25 {
        return Err(CryptoError::InvalidKeyLength);
    }
    let nonce = &wrapped[..24];
    let ciphertext = &wrapped[24..];
    let plain = decrypt_item(wrapping_key, ciphertext, nonce)?;
    if plain.len() != 32 {
        return Err(CryptoError::InvalidKeyLength);
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&plain);
    Ok(bytes)
}

/// Generate a BIP39 mnemonic (128-bit entropy, 12 words).
pub fn generate_bip39_mnemonic() -> String {
    use rand::RngCore;
    let mut entropy = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut entropy);
    bip39::Mnemonic::from_entropy(&entropy)
        .expect("mnemonic generation failed")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_mnemonic_trims_and_lowercases() {
        assert_eq!(
            normalize_mnemonic("  Hello   World  FOO  "),
            "hello world foo"
        );
        assert_eq!(normalize_mnemonic("single"), "single");
        assert_eq!(normalize_mnemonic(""), "");
    }

    #[test]
    fn derive_drop_lookup_key_deterministic() {
        let key1 = derive_drop_lookup_key("test mnemonic");
        let key2 = derive_drop_lookup_key("test mnemonic");
        assert_eq!(key1, key2);
        assert_eq!(key1.len(), 64); // hex-encoded 32 bytes

        // Different mnemonic → different key
        let key3 = derive_drop_lookup_key("other mnemonic");
        assert_ne!(key1, key3);
    }

    #[test]
    fn derive_drop_wrapping_key_version_difference() {
        let v1 = derive_drop_wrapping_key("test words", 1);
        let v2 = derive_drop_wrapping_key("test words", 2);
        assert_ne!(v1, v2); // Different iteration counts
    }

    #[test]
    fn wrap_unwrap_drop_key_roundtrip() {
        let wrapping_key = [0x42u8; 32];
        let drop_key = [0xABu8; 32];
        let wrapped = wrap_drop_key(&wrapping_key, &drop_key).unwrap();
        let recovered = unwrap_drop_key(&wrapping_key, &wrapped).unwrap();
        assert_eq!(recovered, drop_key);
    }

    #[test]
    fn unwrap_drop_key_too_short() {
        let wrapping_key = [0u8; 32];
        let err = unwrap_drop_key(&wrapping_key, &[0u8; 10]);
        assert!(err.is_err());
    }

    #[test]
    fn generate_bip39_mnemonic_produces_12_words() {
        let mnemonic = generate_bip39_mnemonic();
        let words: Vec<&str> = mnemonic.split_whitespace().collect();
        assert_eq!(words.len(), 12);
    }
}
