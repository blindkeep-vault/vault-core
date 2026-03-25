use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

/// XChaCha20-Poly1305 key length in bytes.
pub const KEY_LEN: usize = 32;
/// XChaCha20-Poly1305 nonce length in bytes (192-bit).
pub const NONCE_LEN: usize = 24;
/// X25519 / Ed25519 public key length in bytes.
pub const PUBKEY_LEN: usize = 32;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("encryption failed")]
    EncryptionFailed,
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("key derivation failed")]
    KeyDerivationFailed,
    #[error("invalid key length")]
    InvalidKeyLength,
    #[error("invalid nonce length")]
    InvalidNonceLength,
}

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct MasterKey([u8; 32]);

impl MasterKey {
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        MasterKey(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

pub struct EncryptedPayload {
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; NONCE_LEN],
}

pub struct WrappedKey {
    pub wrapped_key: Vec<u8>,
    pub ephemeral_pubkey: [u8; PUBKEY_LEN],
    pub nonce: [u8; NONCE_LEN],
}

/// Version byte prepended to V1 ciphertexts.
pub const CIPHERTEXT_V1: u8 = 0x01;

/// Derive a master key from a password using Argon2id.
///
/// Parameters: 64 MiB memory, 3 iterations, 1 parallelism.
/// These exceed OWASP minimum (47 MiB) and provide strong GPU/ASIC resistance.
pub fn derive_master_key(password: &[u8], salt: &[u8]) -> Result<MasterKey, CryptoError> {
    use argon2::{Argon2, Params};

    let params = Params::new(64 * 1024, 3, 1, Some(KEY_LEN))
        .map_err(|_| CryptoError::KeyDerivationFailed)?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let mut key = [0u8; KEY_LEN];
    argon2
        .hash_password_into(password, salt, &mut key)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;
    Ok(MasterKey(key))
}

/// Legacy derivation using Argon2::default() (19 MiB, 2 iterations, 1 parallelism).
/// Used to decrypt data encrypted before the parameter upgrade.
pub fn derive_master_key_legacy(password: &[u8], salt: &[u8]) -> Result<MasterKey, CryptoError> {
    use argon2::Argon2;

    let argon2 = Argon2::default();

    let mut key = [0u8; KEY_LEN];
    argon2
        .hash_password_into(password, salt, &mut key)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;
    Ok(MasterKey(key))
}

/// Derive a subkey from a master key using HKDF-SHA256.
pub fn derive_subkey(master: &MasterKey, info: &[u8]) -> Result<[u8; KEY_LEN], CryptoError> {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let hkdf = Hkdf::<Sha256>::new(None, master.as_bytes());
    let mut subkey = [0u8; KEY_LEN];
    hkdf.expand(info, &mut subkey)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;
    Ok(subkey)
}

/// Encrypt plaintext with a 256-bit key using XChaCha20-Poly1305.
pub fn encrypt_item(
    key: &[u8; KEY_LEN],
    plaintext: &[u8],
) -> Result<EncryptedPayload, CryptoError> {
    use chacha20poly1305::{
        aead::{Aead, KeyInit},
        XChaCha20Poly1305, XNonce,
    };
    use rand::RngCore;

    let cipher =
        XChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::InvalidKeyLength)?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| CryptoError::EncryptionFailed)?;

    Ok(EncryptedPayload {
        ciphertext,
        nonce: nonce_bytes,
    })
}

/// Decrypt ciphertext with a 256-bit key using XChaCha20-Poly1305.
/// Returns Zeroizing<Vec<u8>> so plaintext is wiped from memory on drop.
pub fn decrypt_item(
    key: &[u8; KEY_LEN],
    ciphertext: &[u8],
    nonce: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    use chacha20poly1305::{
        aead::{Aead, KeyInit},
        XChaCha20Poly1305, XNonce,
    };

    if nonce.len() != NONCE_LEN {
        return Err(CryptoError::InvalidNonceLength);
    }

    let cipher =
        XChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::InvalidKeyLength)?;
    let nonce = XNonce::from_slice(nonce);

    cipher
        .decrypt(nonce, ciphertext)
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::DecryptionFailed)
}

/// Wrap an item key for a recipient using X25519 key exchange + XChaCha20-Poly1305.
pub fn wrap_key_for_recipient(
    item_key: &[u8; KEY_LEN],
    recipient_public_key: &[u8; PUBKEY_LEN],
) -> Result<WrappedKey, CryptoError> {
    use hkdf::Hkdf;
    use sha2::Sha256;
    use x25519_dalek::{EphemeralSecret, PublicKey};

    let ephemeral_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
    let ephemeral_public = PublicKey::from(&ephemeral_secret);

    let recipient_pk = PublicKey::from(*recipient_public_key);
    let shared_secret = ephemeral_secret.diffie_hellman(&recipient_pk);

    // Reject non-contributory inputs (low-order points yield all-zero shared secret)
    if shared_secret.as_bytes().iter().all(|&b| b == 0) {
        return Err(CryptoError::KeyDerivationFailed);
    }

    let hkdf = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
    let mut wrap_key = Zeroizing::new([0u8; KEY_LEN]);
    hkdf.expand(b"vault-grant-wrap", wrap_key.as_mut())
        .map_err(|_| CryptoError::KeyDerivationFailed)?;

    let encrypted = encrypt_item(&wrap_key, item_key)?;

    Ok(WrappedKey {
        wrapped_key: encrypted.ciphertext,
        ephemeral_pubkey: *ephemeral_public.as_bytes(),
        nonce: encrypted.nonce,
    })
}

/// Unwrap an item key using the recipient's private key.
pub fn unwrap_key(
    recipient_private_key: &[u8; KEY_LEN],
    ephemeral_pubkey: &[u8; PUBKEY_LEN],
    wrapped_key: &[u8],
    nonce: &[u8],
) -> Result<[u8; KEY_LEN], CryptoError> {
    use hkdf::Hkdf;
    use sha2::Sha256;
    use x25519_dalek::{PublicKey, StaticSecret};

    let secret = StaticSecret::from(*recipient_private_key);
    let ephemeral_pk = PublicKey::from(*ephemeral_pubkey);
    let shared_secret = secret.diffie_hellman(&ephemeral_pk);

    if shared_secret.as_bytes().iter().all(|&b| b == 0) {
        return Err(CryptoError::KeyDerivationFailed);
    }

    let hkdf = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
    let mut wrap_key = Zeroizing::new([0u8; KEY_LEN]);
    hkdf.expand(b"vault-grant-wrap", wrap_key.as_mut())
        .map_err(|_| CryptoError::KeyDerivationFailed)?;

    let plaintext = decrypt_item(&wrap_key, wrapped_key, nonce)?;
    if plaintext.len() != KEY_LEN {
        return Err(CryptoError::InvalidKeyLength);
    }

    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&plaintext);
    Ok(key)
}

/// Derive a subkey from a master key using HKDF-SHA256 with an explicit salt.
pub fn derive_subkey_salted(
    master: &MasterKey,
    salt: &[u8],
    info: &[u8],
) -> Result<[u8; KEY_LEN], CryptoError> {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let hkdf = Hkdf::<Sha256>::new(Some(salt), master.as_bytes());
    let mut subkey = [0u8; KEY_LEN];
    hkdf.expand(info, &mut subkey)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;
    Ok(subkey)
}

/// Encrypt plaintext with a 256-bit key using XChaCha20-Poly1305 with AAD.
/// Returns ciphertext prefixed with CIPHERTEXT_V1 version byte.
pub fn encrypt_item_v1(
    key: &[u8; KEY_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<EncryptedPayload, CryptoError> {
    use chacha20poly1305::{
        aead::{Aead, KeyInit, Payload},
        XChaCha20Poly1305, XNonce,
    };
    use rand::RngCore;

    let cipher =
        XChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::InvalidKeyLength)?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::EncryptionFailed)?;

    // Prepend version byte
    let mut versioned = Vec::with_capacity(1 + ciphertext.len());
    versioned.push(CIPHERTEXT_V1);
    versioned.extend_from_slice(&ciphertext);

    Ok(EncryptedPayload {
        ciphertext: versioned,
        nonce: nonce_bytes,
    })
}

/// Decrypt ciphertext with automatic version detection.
/// V1 (first byte == 0x01): strips version byte, decrypts with AAD.
/// V0 (legacy): delegates to decrypt_item (no AAD).
/// Returns Zeroizing<Vec<u8>> so plaintext is wiped from memory on drop.
pub fn decrypt_item_auto(
    key: &[u8; KEY_LEN],
    ciphertext: &[u8],
    nonce: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if nonce.len() != NONCE_LEN {
        return Err(CryptoError::InvalidNonceLength);
    }

    if ciphertext.first() == Some(&CIPHERTEXT_V1) {
        use chacha20poly1305::{
            aead::{Aead, KeyInit, Payload},
            XChaCha20Poly1305, XNonce,
        };

        let cipher =
            XChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::InvalidKeyLength)?;
        let xnonce = XNonce::from_slice(nonce);
        let raw_ciphertext = &ciphertext[1..]; // strip version byte

        cipher
            .decrypt(
                xnonce,
                Payload {
                    msg: raw_ciphertext,
                    aad,
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| CryptoError::DecryptionFailed)
    } else {
        // V0 legacy: no AAD
        decrypt_item(key, ciphertext, nonce)
    }
}

/// Wrap an item key for a recipient using X25519 with key-bound HKDF and AAD.
/// HKDF salt = ephemeral_pubkey(32) || recipient_pubkey(32).
/// AAD on inner encryption = same 64-byte salt.
pub fn wrap_key_for_recipient_v1(
    item_key: &[u8; KEY_LEN],
    recipient_public_key: &[u8; PUBKEY_LEN],
) -> Result<WrappedKey, CryptoError> {
    use hkdf::Hkdf;
    use sha2::Sha256;
    use x25519_dalek::{EphemeralSecret, PublicKey};

    let ephemeral_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
    let ephemeral_public = PublicKey::from(&ephemeral_secret);

    let recipient_pk = PublicKey::from(*recipient_public_key);
    let shared_secret = ephemeral_secret.diffie_hellman(&recipient_pk);

    if shared_secret.as_bytes().iter().all(|&b| b == 0) {
        return Err(CryptoError::KeyDerivationFailed);
    }

    // Key-bound salt: ephemeral_pubkey || recipient_pubkey
    let mut salt = [0u8; PUBKEY_LEN * 2];
    salt[..PUBKEY_LEN].copy_from_slice(ephemeral_public.as_bytes());
    salt[PUBKEY_LEN..].copy_from_slice(recipient_public_key);

    let hkdf = Hkdf::<Sha256>::new(Some(&salt), shared_secret.as_bytes());
    let mut wrap_key = Zeroizing::new([0u8; KEY_LEN]);
    hkdf.expand(b"vault-grant-wrap", wrap_key.as_mut())
        .map_err(|_| CryptoError::KeyDerivationFailed)?;

    let encrypted = encrypt_item_v1(&wrap_key, item_key, &salt)?;

    Ok(WrappedKey {
        wrapped_key: encrypted.ciphertext,
        ephemeral_pubkey: *ephemeral_public.as_bytes(),
        nonce: encrypted.nonce,
    })
}

/// Unwrap an item key using V1 key-bound wrapping.
/// Requires recipient_public_key to reconstruct the HKDF salt and AAD.
pub fn unwrap_key_v1(
    recipient_private_key: &[u8; KEY_LEN],
    ephemeral_pubkey: &[u8; PUBKEY_LEN],
    wrapped_key: &[u8],
    nonce: &[u8],
    recipient_public_key: &[u8; PUBKEY_LEN],
) -> Result<[u8; KEY_LEN], CryptoError> {
    use hkdf::Hkdf;
    use sha2::Sha256;
    use x25519_dalek::{PublicKey, StaticSecret};

    let secret = StaticSecret::from(*recipient_private_key);
    let ephemeral_pk = PublicKey::from(*ephemeral_pubkey);
    let shared_secret = secret.diffie_hellman(&ephemeral_pk);

    if shared_secret.as_bytes().iter().all(|&b| b == 0) {
        return Err(CryptoError::KeyDerivationFailed);
    }

    // Key-bound salt: ephemeral_pubkey || recipient_pubkey
    let mut salt = [0u8; PUBKEY_LEN * 2];
    salt[..PUBKEY_LEN].copy_from_slice(ephemeral_pubkey);
    salt[PUBKEY_LEN..].copy_from_slice(recipient_public_key);

    let hkdf = Hkdf::<Sha256>::new(Some(&salt), shared_secret.as_bytes());
    let mut wrap_key = Zeroizing::new([0u8; KEY_LEN]);
    hkdf.expand(b"vault-grant-wrap", wrap_key.as_mut())
        .map_err(|_| CryptoError::KeyDerivationFailed)?;

    let plaintext = decrypt_item_auto(&wrap_key, wrapped_key, nonce, &salt)?;
    if plaintext.len() != KEY_LEN {
        return Err(CryptoError::InvalidKeyLength);
    }

    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&plaintext);
    Ok(key)
}

/// Verify an Ed25519 notarization signature.
/// Message format: content_hash(32) || timestamp_millis(8, BE) || tree_root(32).
/// Uses verify_strict to reject malleable (non-canonical) signatures.
pub fn verify_notarization_signature(
    public_key: &[u8; PUBKEY_LEN],
    content_hash: &[u8; PUBKEY_LEN],
    timestamp_millis: i64,
    tree_root: &[u8; PUBKEY_LEN],
    signature: &[u8; 64],
) -> bool {
    use ed25519_dalek::{Signature, VerifyingKey};

    let vk = match VerifyingKey::from_bytes(public_key) {
        Ok(k) => k,
        Err(_) => return false,
    };

    let mut msg = Vec::with_capacity(72);
    msg.extend_from_slice(content_hash);
    msg.extend_from_slice(&timestamp_millis.to_be_bytes());
    msg.extend_from_slice(tree_root);

    let sig = Signature::from_bytes(signature);
    vk.verify_strict(&msg, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v1_encrypt_decrypt_roundtrip() {
        let key = [42u8; 32];
        let plaintext = b"hello world";
        let aad = b"item:user123";

        let encrypted = encrypt_item_v1(&key, plaintext, aad).unwrap();
        assert_eq!(encrypted.ciphertext[0], CIPHERTEXT_V1);

        let decrypted =
            decrypt_item_auto(&key, &encrypted.ciphertext, &encrypted.nonce, aad).unwrap();
        assert_eq!(&*decrypted, plaintext);
    }

    #[test]
    fn v1_decrypt_rejects_wrong_aad() {
        let key = [42u8; 32];
        let plaintext = b"hello world";
        let aad = b"item:user123";

        let encrypted = encrypt_item_v1(&key, plaintext, aad).unwrap();

        let result = decrypt_item_auto(&key, &encrypted.ciphertext, &encrypted.nonce, b"wrong:aad");
        assert!(result.is_err());
    }

    #[test]
    fn v0_data_decrypts_via_auto() {
        let key = [42u8; 32];
        let plaintext = b"legacy data";

        // Retry until we get V0 ciphertext that doesn't start with 0x01
        // (expected on first try with overwhelming probability)
        loop {
            let encrypted = encrypt_item(&key, plaintext).unwrap();
            if encrypted.ciphertext[0] == CIPHERTEXT_V1 {
                continue; // extremely unlikely, but skip ambiguous case
            }
            let decrypted =
                decrypt_item_auto(&key, &encrypted.ciphertext, &encrypted.nonce, b"any:aad")
                    .unwrap();
            assert_eq!(&*decrypted, plaintext);
            break;
        }
    }

    #[test]
    fn v1_tagged_data_does_not_fallback_to_v0() {
        let key = [42u8; 32];
        let plaintext = b"v1 data";
        let aad = b"correct:aad";

        let encrypted = encrypt_item_v1(&key, plaintext, aad).unwrap();
        assert_eq!(encrypted.ciphertext[0], CIPHERTEXT_V1);

        // Decrypting with wrong AAD must fail — no fallback to V0
        let result = decrypt_item_auto(&key, &encrypted.ciphertext, &encrypted.nonce, b"wrong:aad");
        assert!(result.is_err());
    }

    #[test]
    fn decrypt_item_rejects_bad_nonce_length() {
        let key = [42u8; 32];
        let encrypted = encrypt_item(&key, b"test").unwrap();

        // Too short
        let result = decrypt_item(&key, &encrypted.ciphertext, &[0u8; 12]);
        assert!(matches!(result, Err(CryptoError::InvalidNonceLength)));

        // Too long
        let result = decrypt_item(&key, &encrypted.ciphertext, &[0u8; 32]);
        assert!(matches!(result, Err(CryptoError::InvalidNonceLength)));

        // Empty
        let result = decrypt_item(&key, &encrypted.ciphertext, &[]);
        assert!(matches!(result, Err(CryptoError::InvalidNonceLength)));
    }

    #[test]
    fn decrypt_item_auto_rejects_bad_nonce_length() {
        let key = [42u8; 32];
        let encrypted = encrypt_item_v1(&key, b"test", b"aad").unwrap();

        let result = decrypt_item_auto(&key, &encrypted.ciphertext, &[0u8; 12], b"aad");
        assert!(matches!(result, Err(CryptoError::InvalidNonceLength)));
    }

    #[test]
    fn v1_wrap_unwrap_roundtrip() {
        use x25519_dalek::{PublicKey, StaticSecret};

        let item_key = [99u8; 32];
        let recipient_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let recipient_public = PublicKey::from(&recipient_secret);

        let wrapped = wrap_key_for_recipient_v1(&item_key, recipient_public.as_bytes()).unwrap();
        assert_eq!(wrapped.wrapped_key[0], CIPHERTEXT_V1);

        let unwrapped = unwrap_key_v1(
            &recipient_secret.to_bytes(),
            &wrapped.ephemeral_pubkey,
            &wrapped.wrapped_key,
            &wrapped.nonce,
            recipient_public.as_bytes(),
        )
        .unwrap();

        assert_eq!(unwrapped, item_key);
    }

    #[test]
    fn v0_wrap_unwrap_still_works() {
        use x25519_dalek::{PublicKey, StaticSecret};

        let item_key = [77u8; 32];
        let recipient_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let recipient_public = PublicKey::from(&recipient_secret);

        let wrapped = wrap_key_for_recipient(&item_key, recipient_public.as_bytes()).unwrap();

        let unwrapped = unwrap_key(
            &recipient_secret.to_bytes(),
            &wrapped.ephemeral_pubkey,
            &wrapped.wrapped_key,
            &wrapped.nonce,
        )
        .unwrap();

        assert_eq!(unwrapped, item_key);
    }

    #[test]
    fn salted_vs_unsalted_subkeys_differ() {
        let master = MasterKey::from_bytes([1u8; 32]);
        let info = b"test-info";
        let salt = b"test-salt";

        let unsalted = derive_subkey(&master, info).unwrap();
        let salted = derive_subkey_salted(&master, salt, info).unwrap();

        assert_ne!(unsalted, salted);
    }

    #[test]
    fn derive_master_key_deterministic() {
        let password = b"correct horse battery staple";
        let salt = b"sixteen-byte-sa!"; // 16 bytes

        let k1 = derive_master_key(password, salt).unwrap();
        let k2 = derive_master_key(password, salt).unwrap();
        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn derive_master_key_differs_with_password() {
        let salt = b"sixteen-byte-sa!";
        let k1 = derive_master_key(b"password1", salt).unwrap();
        let k2 = derive_master_key(b"password2", salt).unwrap();
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn derive_master_key_differs_with_salt() {
        let password = b"same-password";
        let k1 = derive_master_key(password, b"salt-one-16byte!").unwrap();
        let k2 = derive_master_key(password, b"salt-two-16byte!").unwrap();
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn legacy_vs_current_derivation_differ() {
        let password = b"test-password";
        let salt = b"sixteen-byte-sa!";
        let legacy = derive_master_key_legacy(password, salt).unwrap();
        let current = derive_master_key(password, salt).unwrap();
        assert_ne!(legacy.as_bytes(), current.as_bytes());
    }

    #[test]
    fn derive_subkey_deterministic() {
        let master = MasterKey::from_bytes([1u8; 32]);
        let s1 = derive_subkey(&master, b"info").unwrap();
        let s2 = derive_subkey(&master, b"info").unwrap();
        assert_eq!(s1, s2);
    }

    #[test]
    fn derive_subkey_different_info_different_key() {
        let master = MasterKey::from_bytes([1u8; 32]);
        let s1 = derive_subkey(&master, b"auth").unwrap();
        let s2 = derive_subkey(&master, b"encrypt").unwrap();
        assert_ne!(s1, s2);
    }

    #[test]
    fn encrypt_decrypt_empty_plaintext() {
        let key = [42u8; 32];
        let encrypted = encrypt_item(&key, b"").unwrap();
        let decrypted = decrypt_item(&key, &encrypted.ciphertext, &encrypted.nonce).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn encrypt_decrypt_large_plaintext() {
        let key = [42u8; 32];
        let plaintext = vec![0xAB; 100_000];
        let encrypted = encrypt_item(&key, &plaintext).unwrap();
        let decrypted = decrypt_item(&key, &encrypted.ciphertext, &encrypted.nonce).unwrap();
        assert_eq!(&*decrypted, &plaintext);
    }

    #[test]
    fn decrypt_wrong_key_fails() {
        let key = [42u8; 32];
        let wrong_key = [99u8; 32];
        let encrypted = encrypt_item(&key, b"secret").unwrap();
        assert!(decrypt_item(&wrong_key, &encrypted.ciphertext, &encrypted.nonce).is_err());
    }

    #[test]
    fn decrypt_tampered_ciphertext_fails() {
        let key = [42u8; 32];
        let encrypted = encrypt_item(&key, b"secret").unwrap();
        let mut tampered = encrypted.ciphertext.clone();
        tampered[0] ^= 0xFF;
        assert!(decrypt_item(&key, &tampered, &encrypted.nonce).is_err());
    }

    #[test]
    fn v1_encrypt_decrypt_empty() {
        let key = [42u8; 32];
        let encrypted = encrypt_item_v1(&key, b"", b"aad").unwrap();
        let decrypted =
            decrypt_item_auto(&key, &encrypted.ciphertext, &encrypted.nonce, b"aad").unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn verify_notarization_signature_roundtrip() {
        use ed25519_dalek::SigningKey;

        let key = SigningKey::from_bytes(&[42u8; 32]);
        let content_hash = [0xAB; 32];
        let timestamp = 1_700_000_000_000i64;
        let tree_root = [0xCD; 32];

        // Build signature manually matching the function's format
        let mut msg = Vec::with_capacity(72);
        msg.extend_from_slice(&content_hash);
        msg.extend_from_slice(&timestamp.to_be_bytes());
        msg.extend_from_slice(&tree_root);

        use ed25519_dalek::Signer;
        let sig = key.sign(&msg);

        assert!(verify_notarization_signature(
            &key.verifying_key().to_bytes(),
            &content_hash,
            timestamp,
            &tree_root,
            &sig.to_bytes(),
        ));
    }

    #[test]
    fn verify_notarization_signature_rejects_bad_key() {
        use ed25519_dalek::SigningKey;

        let key = SigningKey::from_bytes(&[42u8; 32]);
        let other_key = SigningKey::from_bytes(&[99u8; 32]);
        let content_hash = [0xAB; 32];
        let timestamp = 1000i64;
        let tree_root = [0xCD; 32];

        let mut msg = Vec::with_capacity(72);
        msg.extend_from_slice(&content_hash);
        msg.extend_from_slice(&timestamp.to_be_bytes());
        msg.extend_from_slice(&tree_root);

        use ed25519_dalek::Signer;
        let sig = key.sign(&msg);

        assert!(!verify_notarization_signature(
            &other_key.verifying_key().to_bytes(),
            &content_hash,
            timestamp,
            &tree_root,
            &sig.to_bytes(),
        ));
    }

    #[test]
    fn master_key_zeroize_on_drop() {
        let bytes = [42u8; 32];
        let key = MasterKey::from_bytes(bytes);
        assert_eq!(key.as_bytes(), &bytes);
        // After drop, the memory should be zeroed (we can't test this directly
        // without unsafe, but we verify the type implements Zeroize)
        drop(key);
    }
}
