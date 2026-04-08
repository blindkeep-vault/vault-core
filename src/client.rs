//! High-level client-side orchestration workflows.
//!
//! These functions combine vault-core crypto primitives into the multi-step
//! business operations that every client (CLI, mobile, WASM, web) needs.
//! They are pure — no I/O, no network, no storage access.

use base64::{engine::general_purpose::STANDARD, Engine};
use rand::RngCore;
use zeroize::Zeroizing;

use crate::crypto::{self, CryptoError, MasterKey, CIPHERTEXT_V1, KEY_LEN, NONCE_LEN};
use crate::envelope::SecretBlob;
use crate::padding;

/// Errors from client orchestration functions.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("crypto: {0}")]
    Crypto(#[from] CryptoError),
    #[error("serialization: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("base64 decode failed")]
    Base64Decode,
    #[error("invalid key length")]
    InvalidKeyLength,
}

// ---------------------------------------------------------------------------
// Return types
// ---------------------------------------------------------------------------

/// Result of [`prepare_item_create`].
#[derive(Debug, Clone)]
pub struct PreparedItem {
    /// Base64-encoded encrypted blob (0x01 || nonce || ciphertext).
    pub encrypted_blob_b64: String,
    /// Wrapped item key ciphertext (V1 format: 0x01 || ciphertext).
    pub wrapped_key: Vec<u8>,
    /// Nonce used to wrap the item key.
    pub nonce: [u8; NONCE_LEN],
}

/// Result of [`prepare_grant`].
#[derive(Debug, Clone)]
pub struct PreparedGrant {
    /// Grant-format wrapped key: nonce(24) || ciphertext.
    pub grant_wrapped_key: Vec<u8>,
    /// Ephemeral X25519 public key for this grant.
    pub ephemeral_pubkey: [u8; 32],
}

/// Result of [`prepare_file_item`].
#[derive(Debug, Clone)]
pub struct PreparedFileItem {
    /// Base64-encoded encrypted metadata envelope.
    pub envelope_b64: String,
    /// Wrapped envelope key ciphertext (V1).
    pub wrapped_key: Vec<u8>,
    /// Nonce used to wrap the envelope key.
    pub nonce: [u8; NONCE_LEN],
    /// Encrypted file blob (0x01 || nonce || ciphertext), ready for S3 upload.
    pub encrypted_file: Vec<u8>,
}

/// Result of [`prepare_registration`].
#[derive(Debug)]
pub struct RegistrationPayload {
    /// Hex-encoded auth key for the server.
    pub auth_key_hex: String,
    /// X25519 public key.
    pub public_key: [u8; 32],
    /// Encrypted private key: nonce(24) || ciphertext.
    pub encrypted_private_key: Vec<u8>,
    /// Random 16-byte client salt.
    pub client_salt: Vec<u8>,
    /// The derived master key (caller may need it for subsequent operations).
    pub master_key: MasterKey,
}

/// Result of [`prepare_login`].
#[derive(Debug)]
pub struct LoginPayload {
    /// The derived master key.
    pub master_key: MasterKey,
    /// Hex-encoded auth key to send to the server.
    pub auth_key_hex: String,
}

/// Result of [`prepare_api_key_full`].
#[derive(Debug)]
pub struct PreparedApiKeyFull {
    /// Random 32-byte secret.
    pub secret: [u8; 32],
    /// Key prefix, e.g. `vk_abcd1234`.
    pub key_prefix: String,
    /// Hex-encoded auth key for the server.
    pub auth_key_hex: String,
    /// Wrapped master key: nonce(24) || ciphertext.
    pub wrapped_master_key: Vec<u8>,
}

/// Result of [`prepare_api_key_scoped`].
#[derive(Debug)]
pub struct PreparedApiKeyScoped {
    /// Random 32-byte secret.
    pub secret: [u8; 32],
    /// Key prefix, e.g. `vk_abcd1234`.
    pub key_prefix: String,
    /// Hex-encoded auth key for the server.
    pub auth_key_hex: String,
    /// Wrapped private key: nonce(24) || ciphertext.
    pub encrypted_private_key: Vec<u8>,
    /// X25519 public key for this scoped key.
    pub public_key: [u8; 32],
}

/// An item's key material, used as input to [`prepare_will_payload`].
#[derive(Debug, Clone)]
pub struct WillItemKey {
    pub item_id: String,
    pub item_key: [u8; 32],
}

/// Result of [`prepare_will_payload`].
#[derive(Debug, Clone)]
pub struct PreparedWillPayload {
    /// Map of item_id → base64(wrapped item key) for each included item.
    pub wrapped_items: serde_json::Map<String, serde_json::Value>,
    /// Will key wrapped for the heir (grant format: nonce || ciphertext).
    pub encrypted_will_key: Vec<u8>,
    /// Ephemeral public key for the heir to unwrap the will key.
    pub ephemeral_pubkey: [u8; 32],
}

// ---------------------------------------------------------------------------
// AAD helpers (centralises the string patterns)
// ---------------------------------------------------------------------------

fn item_aad(user_id: &str) -> Vec<u8> {
    if user_id.is_empty() {
        Vec::new()
    } else {
        format!("item:{}", user_id).into_bytes()
    }
}

fn wrap_aad(user_id: &str) -> Vec<u8> {
    if user_id.is_empty() {
        Vec::new()
    } else {
        format!("wrap:{}", user_id).into_bytes()
    }
}

fn group_aad(user_id: &str) -> Vec<u8> {
    format!("group:{}", user_id).into_bytes()
}

fn will_aad(user_id: &str) -> Vec<u8> {
    format!("will:{}", user_id).into_bytes()
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Encrypt plaintext with a random key using V1 format and return the
/// base64-encoded blob (0x01 || nonce || ciphertext) plus the raw key.
fn encrypt_blob_v1(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let enc = crypto::encrypt_item_v1(key, plaintext, aad)?;
    let mut blob = Vec::with_capacity(1 + NONCE_LEN + enc.ciphertext.len());
    blob.push(CIPHERTEXT_V1);
    blob.extend_from_slice(&enc.nonce);
    blob.extend_from_slice(&enc.ciphertext);
    Ok(blob)
}

fn random_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key);
    key
}

/// Unwrap an item key from V1/V0 wrapped form using the enc_subkey.
fn unwrap_item_key(
    enc_key: &[u8; KEY_LEN],
    wrapped_key: &[u8],
    nonce: &[u8],
    wrap_aad: &[u8],
) -> Result<[u8; 32], ClientError> {
    let plain = crypto::decrypt_item_auto(enc_key, wrapped_key, nonce, wrap_aad)?;
    if plain.len() != 32 {
        return Err(ClientError::InvalidKeyLength);
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&plain);
    Ok(key)
}

// ---------------------------------------------------------------------------
// Item creation / decryption
// ---------------------------------------------------------------------------

/// Prepare an encrypted item for upload.
///
/// Generates a random item key, encrypts the `SecretBlob` with AAD `item:{user_id}`,
/// and wraps the item key with the user's enc_subkey using AAD `wrap:{user_id}`.
pub fn prepare_item_create(
    master_key: &MasterKey,
    user_id: &str,
    label: &str,
    value: &str,
    item_type: Option<&str>,
) -> Result<PreparedItem, ClientError> {
    let blob = SecretBlob {
        name: label.to_string(),
        content: Some(value.to_string()),
        label: None,
        item_type: item_type.map(|s| s.to_string()),
        value: None,
        filename: None,
        mime_type: None,
        file_size: None,
        file_wrapped_key: None,
        file_nonce: None,
    };
    let blob_json = serde_json::to_vec(&blob)?;

    let item_key = random_key();
    let blob_aad = item_aad(user_id);

    let blob_data = encrypt_blob_v1(&item_key, &blob_json, &blob_aad)?;
    let blob_b64 = STANDARD.encode(&blob_data);

    let enc_key = crypto::derive_subkey(master_key, b"vault-enc")?;
    let w_aad = wrap_aad(user_id);
    let wrapped = crypto::encrypt_item_v1(&enc_key, &item_key, &w_aad)?;

    Ok(PreparedItem {
        encrypted_blob_b64: blob_b64,
        wrapped_key: wrapped.ciphertext,
        nonce: wrapped.nonce,
    })
}

/// Decrypt an owned item's blob.
///
/// Unwraps the item key using the master key's enc_subkey, then decrypts the blob.
/// The blob bytes should be raw (not base64). Returns the parsed `SecretBlob`.
pub fn decrypt_owned_item(
    master_key: &MasterKey,
    user_id: &str,
    wrapped_key: &[u8],
    nonce: &[u8],
    blob_data: &[u8],
) -> Result<SecretBlob, ClientError> {
    let enc_key = crypto::derive_subkey(master_key, b"vault-enc")?;
    let w_aad = wrap_aad(user_id);
    let item_key = unwrap_item_key(&enc_key, wrapped_key, nonce, &w_aad)?;

    let decrypted = crate::envelope::decrypt_blob_bytes(blob_data, &item_key, user_id)?;
    let blob: SecretBlob = serde_json::from_slice(&decrypted)?;
    Ok(blob)
}

/// Decrypt an owned item's inline envelope (base64-encoded, padded).
///
/// Used for file items where `encrypted_blob` contains the metadata envelope.
pub fn decrypt_owned_inline_envelope(
    master_key: &MasterKey,
    user_id: &str,
    wrapped_key: &[u8],
    nonce: &[u8],
    encrypted_blob_b64: &str,
) -> Result<SecretBlob, ClientError> {
    let enc_key = crypto::derive_subkey(master_key, b"vault-enc")?;
    let w_aad = wrap_aad(user_id);
    let item_key = unwrap_item_key(&enc_key, wrapped_key, nonce, &w_aad)?;

    crate::envelope::decrypt_inline_envelope(encrypted_blob_b64, &item_key, user_id)
        .ok_or(ClientError::Crypto(CryptoError::DecryptionFailed))
}

/// Unwrap an owned item's key using the master key.
///
/// Returns the raw 32-byte item key, useful when you need the key itself
/// (e.g. to create a grant for this item).
pub fn unwrap_owned_item_key(
    master_key: &MasterKey,
    user_id: &str,
    wrapped_key: &[u8],
    nonce: &[u8],
) -> Result<[u8; 32], ClientError> {
    let enc_key = crypto::derive_subkey(master_key, b"vault-enc")?;
    let w_aad = wrap_aad(user_id);
    unwrap_item_key(&enc_key, wrapped_key, nonce, &w_aad)
}

// ---------------------------------------------------------------------------
// Grant creation / decryption
// ---------------------------------------------------------------------------

/// Wrap an item key for a grant recipient using V1 key-bound X25519.
pub fn prepare_grant(
    item_key: &[u8; 32],
    recipient_pubkey: &[u8; 32],
) -> Result<PreparedGrant, ClientError> {
    let (grant_wrapped_key, ephemeral_pubkey) =
        crypto::wrap_key_for_grant(item_key, recipient_pubkey)?;
    Ok(PreparedGrant {
        grant_wrapped_key,
        ephemeral_pubkey,
    })
}

/// Decrypt a granted item's blob.
///
/// Uses X25519 DH to unwrap the item key, then decrypts the blob using
/// the grantor's user_id for AAD.
pub fn decrypt_granted_item(
    private_key: &[u8; 32],
    recipient_pubkey: &[u8; 32],
    ephemeral_pubkey: &[u8; 32],
    grant_wrapped_key: &[u8],
    blob_data: &[u8],
    grantor_id: &str,
) -> Result<SecretBlob, ClientError> {
    let item_key = crypto::unwrap_grant_key(
        private_key,
        ephemeral_pubkey,
        grant_wrapped_key,
        recipient_pubkey,
    )?;

    let decrypted = crate::envelope::decrypt_blob_bytes(blob_data, &item_key, grantor_id)?;

    // Try parsing as SecretBlob; if it fails, wrap raw content
    match serde_json::from_slice::<SecretBlob>(&decrypted) {
        Ok(blob) => Ok(blob),
        Err(_) => {
            let text = String::from_utf8_lossy(&decrypted).into_owned();
            Ok(SecretBlob {
                name: String::new(),
                content: Some(text),
                label: None,
                item_type: None,
                value: None,
                filename: None,
                mime_type: None,
                file_size: None,
                file_wrapped_key: None,
                file_nonce: None,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// File item creation
// ---------------------------------------------------------------------------

/// Prepare an encrypted file item for upload.
///
/// Generates separate keys for the file data and the metadata envelope.
/// Returns the encrypted file blob (for S3) and the encrypted envelope (for the API).
pub fn prepare_file_item(
    master_key: &MasterKey,
    user_id: &str,
    label: &str,
    filename: &str,
    mime_type: &str,
    file_data: &[u8],
) -> Result<PreparedFileItem, ClientError> {
    let blob_aad = item_aad(user_id);
    let w_aad = wrap_aad(user_id);
    let enc_key = crypto::derive_subkey(master_key, b"vault-enc")?;

    // Encrypt file data with its own key
    let file_key = random_key();
    let padded_file = padding::pad_plaintext(file_data);
    let encrypted_file = encrypt_blob_v1(&file_key, &padded_file, &blob_aad)?;

    // Wrap file key (stored inside the envelope)
    let file_wrapped = crypto::encrypt_item_v1(&enc_key, &file_key, &w_aad)?;

    // Build metadata envelope
    let envelope = SecretBlob {
        name: label.to_string(),
        content: None,
        label: None,
        item_type: Some("document".into()),
        value: None,
        filename: Some(filename.to_string()),
        mime_type: Some(mime_type.to_string()),
        file_size: Some(file_data.len() as u64),
        file_wrapped_key: Some(file_wrapped.ciphertext.to_vec()),
        file_nonce: Some(file_wrapped.nonce.to_vec()),
    };
    let envelope_json = serde_json::to_vec(&envelope)?;

    // Encrypt envelope with its own key
    let envelope_key = random_key();
    let padded_envelope = padding::pad_plaintext(&envelope_json);
    let envelope_data = encrypt_blob_v1(&envelope_key, &padded_envelope, &blob_aad)?;
    let envelope_b64 = STANDARD.encode(&envelope_data);

    // Wrap envelope key
    let wrapped = crypto::encrypt_item_v1(&enc_key, &envelope_key, &w_aad)?;

    Ok(PreparedFileItem {
        envelope_b64,
        wrapped_key: wrapped.ciphertext,
        nonce: wrapped.nonce,
        encrypted_file,
    })
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

/// Prepare the key material for user registration.
///
/// Generates a random client salt, derives master/auth/enc keys,
/// generates an X25519 keypair, and encrypts the private key.
pub fn prepare_registration(password: &str) -> Result<RegistrationPayload, ClientError> {
    let mut client_salt = vec![0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut client_salt);

    let master_key = crypto::derive_master_key(password.as_bytes(), &client_salt)?;
    let auth_key = crypto::derive_subkey(&master_key, b"vault-auth")?;
    let enc_key = crypto::derive_subkey(&master_key, b"vault-enc")?;

    let (privkey, pubkey) = crypto::generate_x25519_keypair();
    let enc_privkey = crypto::encrypt_item(&enc_key, &privkey)?;

    let mut encrypted_private_key = Vec::with_capacity(NONCE_LEN + enc_privkey.ciphertext.len());
    encrypted_private_key.extend_from_slice(&enc_privkey.nonce);
    encrypted_private_key.extend_from_slice(&enc_privkey.ciphertext);

    Ok(RegistrationPayload {
        auth_key_hex: hex::encode(&*auth_key),
        public_key: pubkey,
        encrypted_private_key,
        client_salt,
        master_key,
    })
}

/// Derive the master key and auth key for login.
pub fn prepare_login(password: &str, client_salt: &[u8]) -> Result<LoginPayload, ClientError> {
    let master_key = crypto::derive_master_key(password.as_bytes(), client_salt)?;
    let auth_key = crypto::derive_subkey(&master_key, b"vault-auth")?;

    Ok(LoginPayload {
        master_key,
        auth_key_hex: hex::encode(&*auth_key),
    })
}

// ---------------------------------------------------------------------------
// API keys
// ---------------------------------------------------------------------------

/// Prepare a full-access API key that wraps the user's master key.
pub fn prepare_api_key_full(master_key: &MasterKey) -> Result<PreparedApiKeyFull, ClientError> {
    let secret = random_key();
    let (wrapping_key, auth_key) = crypto::derive_api_key_keys(&secret)?;
    let wrapped_master_key = crypto::wrap_master_key(&wrapping_key, master_key)?;

    Ok(PreparedApiKeyFull {
        secret,
        key_prefix: format!("vk_{}", hex::encode(&secret[..4])),
        auth_key_hex: hex::encode(&*auth_key),
        wrapped_master_key,
    })
}

/// Prepare a scoped API key with its own X25519 keypair.
pub fn prepare_api_key_scoped() -> Result<PreparedApiKeyScoped, ClientError> {
    let secret = random_key();
    let (wrapping_key, auth_key) = crypto::derive_api_key_keys(&secret)?;

    let (privkey, pubkey) = crypto::generate_x25519_keypair();
    let wrapped_privkey = crypto::wrap_master_key(&wrapping_key, &MasterKey::from_bytes(privkey))?;

    Ok(PreparedApiKeyScoped {
        secret,
        key_prefix: format!("vk_{}", hex::encode(&secret[..4])),
        auth_key_hex: hex::encode(&*auth_key),
        encrypted_private_key: wrapped_privkey,
        public_key: pubkey,
    })
}

// ---------------------------------------------------------------------------
// Groups
// ---------------------------------------------------------------------------

/// Encrypt a group name and wrap its key.
///
/// Returns `(encrypted_blob_b64, wrapped_key, nonce)` ready for POST /groups.
pub fn encrypt_group(
    master_key: &MasterKey,
    user_id: &str,
    name: &str,
) -> Result<(String, Vec<u8>, [u8; NONCE_LEN]), ClientError> {
    let blob_json = serde_json::json!({ "name": name }).to_string();
    let g_aad = group_aad(user_id);
    let w_aad = wrap_aad(user_id);

    let group_key = random_key();
    let blob_data = encrypt_blob_v1(&group_key, blob_json.as_bytes(), &g_aad)?;
    let blob_b64 = STANDARD.encode(&blob_data);

    let enc_key = crypto::derive_subkey(master_key, b"vault-enc")?;
    let wrapped = crypto::encrypt_item_v1(&enc_key, &group_key, &w_aad)?;

    Ok((blob_b64, wrapped.ciphertext, wrapped.nonce))
}

/// Decrypt a group's name from its encrypted blob and wrapped key.
pub fn decrypt_group_name(
    master_key: &MasterKey,
    user_id: &str,
    wrapped_key: &[u8],
    nonce: &[u8],
    encrypted_blob_b64: &str,
) -> Result<String, ClientError> {
    let enc_key = crypto::derive_subkey(master_key, b"vault-enc")?;
    let w_aad = wrap_aad(user_id);
    let group_key = unwrap_item_key(&enc_key, wrapped_key, nonce, &w_aad)?;

    let blob_data = STANDARD
        .decode(encrypted_blob_b64)
        .map_err(|_| ClientError::Base64Decode)?;

    if blob_data.is_empty() {
        return Err(ClientError::Crypto(CryptoError::DecryptionFailed));
    }

    let g_aad = group_aad(user_id);
    let plaintext = if blob_data[0] == CIPHERTEXT_V1 && blob_data.len() > 25 {
        let nonce = &blob_data[1..25];
        let ciphertext = &blob_data[25..];
        crypto::decrypt_item_auto(&group_key, ciphertext, nonce, &g_aad)?
    } else if blob_data.len() > NONCE_LEN {
        crypto::decrypt_item(&group_key, &blob_data[NONCE_LEN..], &blob_data[..NONCE_LEN])?
    } else {
        return Err(ClientError::Crypto(CryptoError::DecryptionFailed));
    };

    let parsed: serde_json::Value = serde_json::from_slice(&plaintext)?;
    parsed["name"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or(ClientError::Crypto(CryptoError::DecryptionFailed))
}

// ---------------------------------------------------------------------------
// Will payload
// ---------------------------------------------------------------------------

/// Prepare a will payload: wrap each item key with a random will key,
/// then wrap the will key for the heir using X25519.
pub fn prepare_will_payload(
    user_id: &str,
    items: &[WillItemKey],
    heir_pubkey: &[u8; 32],
) -> Result<PreparedWillPayload, ClientError> {
    let will_key = random_key();
    let w_aad = will_aad(user_id);

    let mut wrapped_items = serde_json::Map::new();
    for item in items {
        let enc = crypto::encrypt_item_v1(&will_key, &item.item_key, &w_aad)?;
        // Store as base64(nonce || ciphertext) for each item
        let mut buf = Vec::with_capacity(NONCE_LEN + enc.ciphertext.len());
        buf.extend_from_slice(&enc.nonce);
        buf.extend_from_slice(&enc.ciphertext);
        wrapped_items.insert(
            item.item_id.clone(),
            serde_json::Value::String(STANDARD.encode(&buf)),
        );
    }

    // Wrap will key for heir
    let (encrypted_will_key, ephemeral_pubkey) =
        crypto::wrap_key_for_grant(&will_key, heir_pubkey)?;

    Ok(PreparedWillPayload {
        wrapped_items,
        encrypted_will_key,
        ephemeral_pubkey,
    })
}

// ---------------------------------------------------------------------------
// Password change
// ---------------------------------------------------------------------------

/// Result of [`prepare_password_change`].
#[derive(Debug)]
pub struct PasswordChangePayload {
    /// Hex-encoded new auth key.
    pub new_auth_key_hex: String,
    /// Re-encrypted private key with new enc_key.
    pub new_encrypted_private_key: Vec<u8>,
    /// New random client salt (16 bytes).
    pub new_client_salt: Vec<u8>,
    /// Re-encrypted master key with new enc_key (V1: 0x01 || nonce || ciphertext).
    pub new_encrypted_master_key: Vec<u8>,
    /// Hex-encoded current auth key (for server verification).
    pub current_auth_key_hex: String,
    /// The new master key derived from the new password.
    pub new_master_key: MasterKey,
}

/// Prepare key material for a password change.
///
/// Re-derives all keys from the new password, re-encrypts the private key
/// and master key. The caller must send the result to the server.
pub fn prepare_password_change(
    current_password: &str,
    new_password: &str,
    current_client_salt: &[u8],
    encrypted_private_key: &[u8],
    master_key: &MasterKey,
    user_id: &str,
) -> Result<PasswordChangePayload, ClientError> {
    // Derive current auth key (for server verification)
    let current_password_key =
        crypto::derive_master_key(current_password.as_bytes(), current_client_salt)?;
    let current_auth_key = crypto::derive_subkey(&current_password_key, b"vault-auth")?;
    let current_enc_key = crypto::derive_subkey(&current_password_key, b"vault-enc")?;

    // Decrypt private key to re-encrypt with new key
    let private_key = crypto::decrypt_private_key(&current_enc_key, encrypted_private_key)?;

    // Generate new salt and derive new keys
    let mut new_client_salt = vec![0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut new_client_salt);

    let new_password_key = crypto::derive_master_key(new_password.as_bytes(), &new_client_salt)?;
    let new_auth_key = crypto::derive_subkey(&new_password_key, b"vault-auth")?;
    let new_enc_key = crypto::derive_subkey(&new_password_key, b"vault-enc")?;

    // Re-encrypt private key (V0 — matches registration format)
    let enc_privkey = crypto::encrypt_item(&new_enc_key, &*private_key)?;
    let mut new_encrypted_private_key =
        Vec::with_capacity(NONCE_LEN + enc_privkey.ciphertext.len());
    new_encrypted_private_key.extend_from_slice(&enc_privkey.nonce);
    new_encrypted_private_key.extend_from_slice(&enc_privkey.ciphertext);

    // Re-encrypt master key (V1 format with AAD)
    let mk_aad = format!("master:{}", user_id);
    let enc_mk = crypto::encrypt_item_v1(&new_enc_key, master_key.as_bytes(), mk_aad.as_bytes())?;
    let mut new_encrypted_master_key = Vec::with_capacity(1 + NONCE_LEN + enc_mk.ciphertext.len());
    new_encrypted_master_key.push(CIPHERTEXT_V1);
    new_encrypted_master_key.extend_from_slice(&enc_mk.nonce);
    new_encrypted_master_key.extend_from_slice(&enc_mk.ciphertext);

    Ok(PasswordChangePayload {
        new_auth_key_hex: hex::encode(&*new_auth_key),
        new_encrypted_private_key,
        new_client_salt,
        new_encrypted_master_key,
        current_auth_key_hex: hex::encode(&*current_auth_key),
        new_master_key: new_password_key,
    })
}

// ---------------------------------------------------------------------------
// Key management helpers
// ---------------------------------------------------------------------------

/// Decrypt a user's X25519 private key using their master key.
/// Derives the enc_subkey internally.
pub fn decrypt_private_key_from_master(
    master_key: &MasterKey,
    encrypted_private_key: &[u8],
) -> Result<Zeroizing<[u8; KEY_LEN]>, ClientError> {
    let enc_key = crypto::derive_subkey(master_key, b"vault-enc")?;
    Ok(crypto::decrypt_private_key(
        &enc_key,
        encrypted_private_key,
    )?)
}

/// Result of wrapping a key for the user.
#[derive(Debug, Clone)]
pub struct WrappedKeyResult {
    /// Wrapped key ciphertext (V1 format).
    pub wrapped_key: Vec<u8>,
    /// Nonce used for wrapping.
    pub nonce: [u8; NONCE_LEN],
}

/// Wrap a raw 32-byte key under the user's encryption subkey (V1 with AAD).
pub fn wrap_key_for_user(
    master_key: &MasterKey,
    user_id: &str,
    raw_key: &[u8; 32],
) -> Result<WrappedKeyResult, ClientError> {
    let enc_key = crypto::derive_subkey(master_key, b"vault-enc")?;
    let w_aad = wrap_aad(user_id);
    let wrapped = crypto::encrypt_item_v1(&enc_key, raw_key, &w_aad)?;
    Ok(WrappedKeyResult {
        wrapped_key: wrapped.ciphertext,
        nonce: wrapped.nonce,
    })
}

/// Decrypt a raw encrypted blob (V0/V1 auto-detection).
///
/// This is the canonical way to decrypt item/grant blobs. It handles
/// V1 format (0x01 + nonce + ciphertext) and V0 format (nonce + ciphertext).
pub fn decrypt_blob(
    item_key: &[u8; 32],
    blob_data: &[u8],
    user_id: &str,
) -> Result<Zeroizing<Vec<u8>>, ClientError> {
    Ok(crate::envelope::decrypt_blob_bytes(
        blob_data, item_key, user_id,
    )?)
}

/// Unwrap an owned item key and re-wrap it for an API key's public key.
///
/// Used when granting items to scoped API keys.
pub fn grant_item_to_api_key(
    master_key: &MasterKey,
    user_id: &str,
    item_wrapped_key: &[u8],
    item_nonce: &[u8],
    api_key_pubkey: &[u8; 32],
) -> Result<crypto::WrappedKey, ClientError> {
    let item_key = unwrap_owned_item_key(master_key, user_id, item_wrapped_key, item_nonce)?;
    Ok(crypto::wrap_key_for_recipient(&item_key, api_key_pubkey)?)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_master_key() -> MasterKey {
        MasterKey::from_bytes([42u8; 32])
    }

    #[test]
    fn item_create_decrypt_roundtrip() {
        let mk = test_master_key();
        let user_id = "test-user-123";

        let prepared = prepare_item_create(&mk, user_id, "my-secret", "hunter2", None).unwrap();

        let blob_data = STANDARD.decode(&prepared.encrypted_blob_b64).unwrap();
        let blob = decrypt_owned_item(
            &mk,
            user_id,
            &prepared.wrapped_key,
            &prepared.nonce,
            &blob_data,
        )
        .unwrap();

        assert_eq!(blob.display_name(), "my-secret");
        assert_eq!(blob.secret_value(), Some("hunter2"));
    }

    #[test]
    fn grant_roundtrip() {
        let mk = test_master_key();
        let user_id = "grantor-123";

        // Create an item
        let prepared = prepare_item_create(&mk, user_id, "shared-secret", "s3cr3t", None).unwrap();
        let enc_key = crypto::derive_subkey(&mk, b"vault-enc").unwrap();
        let item_key = unwrap_item_key(
            &enc_key,
            &prepared.wrapped_key,
            &prepared.nonce,
            &wrap_aad(user_id),
        )
        .unwrap();

        // Generate recipient keypair
        let (recipient_privkey, recipient_pubkey) = crypto::generate_x25519_keypair();

        // Create grant
        let grant = prepare_grant(&item_key, &recipient_pubkey).unwrap();

        // Recipient decrypts
        let blob_data = STANDARD.decode(&prepared.encrypted_blob_b64).unwrap();
        let blob = decrypt_granted_item(
            &recipient_privkey,
            &recipient_pubkey,
            &grant.ephemeral_pubkey,
            &grant.grant_wrapped_key,
            &blob_data,
            user_id,
        )
        .unwrap();

        assert_eq!(blob.secret_value(), Some("s3cr3t"));
    }

    #[test]
    fn file_item_roundtrip() {
        let mk = test_master_key();
        let user_id = "file-user";

        let file_data = b"hello world file contents";
        let prepared =
            prepare_file_item(&mk, user_id, "my-doc", "hello.txt", "text/plain", file_data)
                .unwrap();

        // Decrypt the envelope
        let envelope = decrypt_owned_inline_envelope(
            &mk,
            user_id,
            &prepared.wrapped_key,
            &prepared.nonce,
            &prepared.envelope_b64,
        )
        .unwrap();

        assert_eq!(envelope.display_name(), "my-doc");
        assert_eq!(envelope.filename.as_deref(), Some("hello.txt"));
        assert_eq!(envelope.mime_type.as_deref(), Some("text/plain"));
        assert_eq!(envelope.file_size, Some(25));
        assert!(envelope.is_file());

        // Decrypt the file data using the file key from the envelope
        let enc_key = crypto::derive_subkey(&mk, b"vault-enc").unwrap();
        let file_key = unwrap_item_key(
            &enc_key,
            envelope.file_wrapped_key.as_deref().unwrap(),
            envelope.file_nonce.as_deref().unwrap(),
            &wrap_aad(user_id),
        )
        .unwrap();

        let decrypted =
            crate::envelope::decrypt_blob_bytes(&prepared.encrypted_file, &file_key, user_id)
                .unwrap();
        let unpadded = padding::unpad(&decrypted);
        assert_eq!(unpadded, file_data);
    }

    #[test]
    fn registration_login_roundtrip() {
        let reg = prepare_registration("super-secure-password-123").unwrap();
        assert_eq!(reg.client_salt.len(), 16);
        assert!(!reg.auth_key_hex.is_empty());
        assert_eq!(reg.public_key.len(), 32);

        let login = prepare_login("super-secure-password-123", &reg.client_salt).unwrap();
        assert_eq!(login.auth_key_hex, reg.auth_key_hex);

        // Verify the encrypted private key can be decrypted
        let enc_key = crypto::derive_subkey(&login.master_key, b"vault-enc").unwrap();
        let _privkey = crypto::decrypt_private_key(&enc_key, &reg.encrypted_private_key).unwrap();
    }

    #[test]
    fn api_key_full_roundtrip() {
        let mk = test_master_key();
        let prepared = prepare_api_key_full(&mk).unwrap();

        assert!(prepared.key_prefix.starts_with("vk_"));
        assert!(!prepared.auth_key_hex.is_empty());

        // Verify we can unwrap the master key
        let (wrapping_key, _) = crypto::derive_api_key_keys(&prepared.secret).unwrap();
        let unwrapped =
            crypto::unwrap_master_key(&wrapping_key, &prepared.wrapped_master_key).unwrap();
        assert_eq!(unwrapped.as_bytes(), mk.as_bytes());
    }

    #[test]
    fn api_key_scoped_roundtrip() {
        let prepared = prepare_api_key_scoped().unwrap();

        assert!(prepared.key_prefix.starts_with("vk_"));
        assert_eq!(prepared.public_key.len(), 32);

        // Verify we can unwrap the private key
        let (wrapping_key, _) = crypto::derive_api_key_keys(&prepared.secret).unwrap();
        let unwrapped =
            crypto::unwrap_master_key(&wrapping_key, &prepared.encrypted_private_key).unwrap();
        // Verify the keypair is consistent
        use x25519_dalek::{PublicKey, StaticSecret};
        let secret = StaticSecret::from(*unwrapped.as_bytes());
        let public = PublicKey::from(&secret);
        assert_eq!(*public.as_bytes(), prepared.public_key);
    }

    #[test]
    fn group_encrypt_decrypt_roundtrip() {
        let mk = test_master_key();
        let user_id = "group-user";

        let (blob_b64, wrapped_key, nonce) = encrypt_group(&mk, user_id, "My Group").unwrap();

        let name = decrypt_group_name(&mk, user_id, &wrapped_key, &nonce, &blob_b64).unwrap();
        assert_eq!(name, "My Group");
    }

    #[test]
    fn will_payload_roundtrip() {
        let user_id = "will-owner";
        let (heir_privkey, heir_pubkey) = crypto::generate_x25519_keypair();

        let items = vec![
            WillItemKey {
                item_id: "item-1".into(),
                item_key: [1u8; 32],
            },
            WillItemKey {
                item_id: "item-2".into(),
                item_key: [2u8; 32],
            },
        ];

        let payload = prepare_will_payload(user_id, &items, &heir_pubkey).unwrap();
        assert_eq!(payload.wrapped_items.len(), 2);
        assert!(payload.wrapped_items.contains_key("item-1"));
        assert!(payload.wrapped_items.contains_key("item-2"));

        // Heir unwraps the will key
        let will_key = crypto::unwrap_grant_key(
            &heir_privkey,
            &payload.ephemeral_pubkey,
            &payload.encrypted_will_key,
            &heir_pubkey,
        )
        .unwrap();

        // Heir decrypts each item key
        let w_aad = will_aad(user_id);
        for item in &items {
            let wrapped_b64 = payload.wrapped_items[&item.item_id].as_str().unwrap();
            let wrapped_bytes = STANDARD.decode(wrapped_b64).unwrap();
            let nonce = &wrapped_bytes[..NONCE_LEN];
            let ciphertext = &wrapped_bytes[NONCE_LEN..];
            let decrypted =
                crypto::decrypt_item_auto(&will_key, ciphertext, nonce, &w_aad).unwrap();
            assert_eq!(&*decrypted, &item.item_key);
        }
    }

    #[test]
    fn decrypt_private_key_from_master_roundtrip() {
        let reg = prepare_registration("test-password-123").unwrap();
        let privkey =
            decrypt_private_key_from_master(&reg.master_key, &reg.encrypted_private_key).unwrap();
        assert_eq!(privkey.len(), 32);
    }

    #[test]
    fn wrap_key_for_user_roundtrip() {
        let mk = test_master_key();
        let user_id = "test-user";
        let raw_key = [99u8; 32];
        let wrapped = wrap_key_for_user(&mk, user_id, &raw_key).unwrap();
        let unwrapped =
            unwrap_owned_item_key(&mk, user_id, &wrapped.wrapped_key, &wrapped.nonce).unwrap();
        assert_eq!(unwrapped, raw_key);
    }

    #[test]
    fn grant_item_to_api_key_roundtrip() {
        let mk = test_master_key();
        let user_id = "test-user";

        // Create an item
        let prepared = prepare_item_create(&mk, user_id, "test", "val", None).unwrap();

        // Generate API key pair
        let (api_privkey, api_pubkey) = crypto::generate_x25519_keypair();

        // Grant item to API key
        let grant = grant_item_to_api_key(
            &mk,
            user_id,
            &prepared.wrapped_key,
            &prepared.nonce,
            &api_pubkey,
        )
        .unwrap();

        // API key unwraps
        let item_key = crypto::unwrap_key(
            &api_privkey,
            &grant.ephemeral_pubkey,
            &grant.wrapped_key,
            &grant.nonce,
        )
        .unwrap();
        assert_eq!(item_key.len(), 32);
    }
}
