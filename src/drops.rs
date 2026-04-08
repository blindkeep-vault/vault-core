use hkdf::Hkdf;
use hmac::Hmac;
use sha2::{Sha256, Sha512};
use zeroize::Zeroizing;

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
pub fn derive_drop_wrapping_key(mnemonic: &str, version: i32) -> Zeroizing<[u8; 32]> {
    let iterations = if version >= 2 { 600_000 } else { 2048 };
    let mut out = Zeroizing::new([0u8; 32]);
    pbkdf2::pbkdf2::<Hmac<Sha512>>(mnemonic.as_bytes(), b"vault-drop", iterations, out.as_mut())
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
pub fn unwrap_drop_key(
    wrapping_key: &[u8; 32],
    wrapped: &[u8],
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    if wrapped.len() < 25 {
        return Err(CryptoError::InvalidKeyLength);
    }
    let nonce = &wrapped[..24];
    let ciphertext = &wrapped[24..];
    let plain = decrypt_item(wrapping_key, ciphertext, nonce)?;
    if plain.len() != 32 {
        return Err(CryptoError::InvalidKeyLength);
    }
    let mut bytes = Zeroizing::new([0u8; 32]);
    bytes.copy_from_slice(&plain);
    Ok(bytes)
}

/// Derive a 32-byte wrapping key from a mnemonic for wills using PBKDF2-HMAC-SHA512.
/// v1: 2048 iterations, v2+: 600,000 iterations. Salt: `vault-will`.
pub fn derive_will_wrapping_key(mnemonic: &str, version: i32) -> Zeroizing<[u8; 32]> {
    let iterations = if version >= 2 { 600_000 } else { 2048 };
    let mut out = Zeroizing::new([0u8; 32]);
    pbkdf2::pbkdf2::<Hmac<Sha512>>(mnemonic.as_bytes(), b"vault-will", iterations, out.as_mut())
        .expect("PBKDF2 failed");
    out
}

/// Derive a hex-encoded lookup key from a mnemonic for wills using HKDF-SHA256.
/// Salt: `vault-will`, info: `lookup`.
pub fn derive_will_lookup_key(mnemonic: &str) -> String {
    let hkdf = Hkdf::<Sha256>::new(Some(b"vault-will"), mnemonic.as_bytes());
    let mut out = [0u8; 32];
    hkdf.expand(b"lookup", &mut out)
        .expect("HKDF expand failed");
    hex::encode(out)
}

/// Derive recovery wrapping + auth keys from a mnemonic.
///
/// Uses PBKDF2-HMAC-SHA512 (512-bit output) for the wrapping key,
/// then HKDF-SHA256 with info `vault-recovery-auth` for the auth key.
///
/// - v1: 2048 iterations, salt `mnemonic`
/// - v2: 2048 iterations, salt `vault-recovery`
/// - v3+: 600,000 iterations, salt `vault-recovery`
pub fn derive_recovery_keys(
    mnemonic: &str,
    version: i32,
) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
    let salt: &[u8] = if version <= 1 {
        b"mnemonic"
    } else {
        b"vault-recovery"
    };
    let iterations = if version >= 3 { 600_000 } else { 2048 };

    let mut derived = Zeroizing::new([0u8; 64]);
    pbkdf2::pbkdf2::<Hmac<Sha512>>(mnemonic.as_bytes(), salt, iterations, derived.as_mut())
        .expect("PBKDF2 failed");

    let mut wrapping_key = Zeroizing::new([0u8; 32]);
    wrapping_key.copy_from_slice(&derived[..32]);

    // Derive auth key via HKDF-SHA256 (empty salt matches WebCrypto behaviour)
    let hkdf = Hkdf::<Sha256>::new(Some(&[]), &wrapping_key[..]);
    let mut auth_key = Zeroizing::new([0u8; 32]);
    hkdf.expand(b"vault-recovery-auth", auth_key.as_mut())
        .expect("HKDF expand failed");

    (wrapping_key, auth_key)
}

/// Validate a BIP39 mnemonic (word-list + checksum).
/// The mnemonic should be normalized first via [`normalize_mnemonic`].
pub fn validate_bip39_mnemonic(mnemonic: &str) -> bool {
    bip39::Mnemonic::parse_normalized(mnemonic).is_ok()
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
        assert_eq!(*recovered, drop_key);
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

    #[test]
    fn derive_will_wrapping_key_deterministic_and_versioned() {
        let v1 = derive_will_wrapping_key("test words", 1);
        let v2 = derive_will_wrapping_key("test words", 2);
        assert_ne!(v1, v2); // Different iteration counts

        let v1b = derive_will_wrapping_key("test words", 1);
        assert_eq!(v1, v1b); // Deterministic
    }

    #[test]
    fn derive_will_wrapping_key_differs_from_drop() {
        let will = derive_will_wrapping_key("test words", 2);
        let drop = derive_drop_wrapping_key("test words", 2);
        assert_ne!(will, drop); // Different salts
    }

    #[test]
    fn derive_will_lookup_key_deterministic() {
        let key1 = derive_will_lookup_key("test mnemonic");
        let key2 = derive_will_lookup_key("test mnemonic");
        assert_eq!(key1, key2);
        assert_eq!(key1.len(), 64); // hex-encoded 32 bytes

        let key3 = derive_will_lookup_key("other mnemonic");
        assert_ne!(key1, key3);
    }

    #[test]
    fn derive_will_lookup_key_differs_from_drop() {
        let will = derive_will_lookup_key("test mnemonic");
        let drop = derive_drop_lookup_key("test mnemonic");
        assert_ne!(will, drop); // Different salts
    }

    #[test]
    fn derive_recovery_keys_version_differences() {
        let (wk1, ak1) = derive_recovery_keys("test phrase", 1);
        let (wk2, ak2) = derive_recovery_keys("test phrase", 2);
        let (wk3, ak3) = derive_recovery_keys("test phrase", 3);

        // v1 uses different salt from v2/v3
        assert_ne!(wk1, wk2);
        // v2 and v3 use same salt but different iterations
        assert_ne!(wk2, wk3);
        // Auth keys derived from different wrapping keys are different
        assert_ne!(ak1, ak2);
        assert_ne!(ak2, ak3);
    }

    #[test]
    fn derive_recovery_keys_deterministic() {
        let (wk1, ak1) = derive_recovery_keys("test phrase", 3);
        let (wk2, ak2) = derive_recovery_keys("test phrase", 3);
        assert_eq!(wk1, wk2);
        assert_eq!(ak1, ak2);
    }

    #[test]
    fn validate_bip39_mnemonic_valid() {
        let mnemonic = generate_bip39_mnemonic();
        assert!(validate_bip39_mnemonic(&mnemonic));
    }

    #[test]
    fn validate_bip39_mnemonic_invalid() {
        assert!(!validate_bip39_mnemonic("not a valid mnemonic at all nope"));
        assert!(!validate_bip39_mnemonic(""));
        assert!(!validate_bip39_mnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon wrong"));
    }
}
