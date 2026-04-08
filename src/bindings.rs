//! Shared binding implementations for vault-wasm and vault-mobile.
//!
//! Every function here returns `Result<T, String>` (or a plain value for
//! infallible operations) so that each platform only needs to map
//! `String` -> its own error type (`JsError` / `anyhow` / etc.).
//!
//! By centralising all validation, key conversion, and vault-core calls
//! here we eliminate near-identical wrapper code on both sides.

use crate::crypto::{self, MasterKey};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Validate a byte slice is exactly 32 bytes and convert to array.
pub fn bytes_to_key32(bytes: &[u8], name: &str) -> Result<[u8; 32], String> {
    if bytes.len() != 32 {
        return Err(format!("{name} must be 32 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    Ok(arr)
}

/// Validate a byte slice is exactly 64 bytes and convert to array.
pub fn bytes_to_arr64(bytes: &[u8], name: &str) -> Result<[u8; 64], String> {
    if bytes.len() != 64 {
        return Err(format!("{name} must be 64 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 64];
    arr.copy_from_slice(bytes);
    Ok(arr)
}

/// Create a [`MasterKey`] from a byte slice.
pub fn mk_from_bytes(bytes: &[u8]) -> Result<MasterKey, String> {
    let arr = bytes_to_key32(bytes, "master key")?;
    Ok(MasterKey::from_bytes(arr))
}

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

pub fn derive_key_impl(password: &str, salt: &[u8]) -> Result<Vec<u8>, String> {
    crypto::derive_master_key(password.as_bytes(), salt)
        .map(|k| k.as_bytes().to_vec())
        .map_err(|e| e.to_string())
}

pub fn derive_key_legacy_impl(password: &str, salt: &[u8]) -> Result<Vec<u8>, String> {
    crypto::derive_master_key_legacy(password.as_bytes(), salt)
        .map(|k| k.as_bytes().to_vec())
        .map_err(|e| e.to_string())
}

pub fn derive_subkey_impl(master_key: &[u8], info: &str) -> Result<Vec<u8>, String> {
    let master = mk_from_bytes(master_key)?;
    crypto::derive_subkey(&master, info.as_bytes())
        .map(|k| k.to_vec())
        .map_err(|e| e.to_string())
}

pub fn derive_subkey_salted_impl(
    master_key: &[u8],
    salt: &[u8],
    info: &str,
) -> Result<Vec<u8>, String> {
    let master = mk_from_bytes(master_key)?;
    crypto::derive_subkey_salted(&master, salt, info.as_bytes())
        .map(|k| k.to_vec())
        .map_err(|e| e.to_string())
}

pub fn derive_api_key_keys_impl(secret: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let s = bytes_to_key32(secret, "secret")?;
    let (wk, ak) = crypto::derive_api_key_keys(&s).map_err(|e| e.to_string())?;
    Ok((wk.to_vec(), ak.to_vec()))
}

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

pub fn generate_keypair_impl() -> (Vec<u8>, Vec<u8>) {
    let (private_key, public_key) = crypto::generate_x25519_keypair();
    (private_key.to_vec(), public_key.to_vec())
}

pub fn generate_random_key_impl() -> Vec<u8> {
    use rand::RngCore;
    let mut key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key);
    key.to_vec()
}

// ---------------------------------------------------------------------------
// Symmetric encryption
// ---------------------------------------------------------------------------

/// Encrypt plaintext (V0, no AAD). Kept for backwards compatibility.
#[allow(deprecated)]
pub fn encrypt_impl(key: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let key_arr = bytes_to_key32(key, "key")?;
    let payload = crypto::encrypt_item(&key_arr, plaintext).map_err(|e| e.to_string())?;
    Ok((payload.ciphertext, payload.nonce.to_vec()))
}

pub fn decrypt_impl(key: &[u8], ciphertext: &[u8], nonce: &[u8]) -> Result<Vec<u8>, String> {
    let key_arr = bytes_to_key32(key, "key")?;
    crypto::decrypt_item(&key_arr, ciphertext, nonce)
        .map(|z| (*z).clone())
        .map_err(|e| e.to_string())
}

/// Encrypt with AAD (V1 format). Returns (ciphertext, nonce).
pub fn encrypt_v1_impl(
    key: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let key_arr = bytes_to_key32(key, "key")?;
    let payload = crypto::encrypt_item_v1(&key_arr, plaintext, aad).map_err(|e| e.to_string())?;
    Ok((payload.ciphertext, payload.nonce.to_vec()))
}

pub fn decrypt_auto_impl(
    key: &[u8],
    ciphertext: &[u8],
    nonce: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    let key_arr = bytes_to_key32(key, "key")?;
    crypto::decrypt_item_auto(&key_arr, ciphertext, nonce, aad)
        .map(|z| (*z).clone())
        .map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Asymmetric key wrapping (V0)
// ---------------------------------------------------------------------------

/// Wrap key for recipient (V0). Kept for backwards compatibility.
#[allow(clippy::type_complexity, deprecated)]
pub fn wrap_key_for_recipient_impl(
    item_key: &[u8],
    recipient_pubkey: &[u8],
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), String> {
    let ik = bytes_to_key32(item_key, "item key")?;
    let pk = bytes_to_key32(recipient_pubkey, "recipient public key")?;
    let wrapped = crypto::wrap_key_for_recipient(&ik, &pk).map_err(|e| e.to_string())?;
    Ok((
        wrapped.wrapped_key,
        wrapped.ephemeral_pubkey.to_vec(),
        wrapped.nonce.to_vec(),
    ))
}

pub fn unwrap_key_impl(
    privkey: &[u8],
    ephemeral_pub: &[u8],
    wrapped: &[u8],
    nonce: &[u8],
) -> Result<Vec<u8>, String> {
    let sk = bytes_to_key32(privkey, "private key")?;
    let ep = bytes_to_key32(ephemeral_pub, "ephemeral public key")?;
    crypto::unwrap_key(&sk, &ep, wrapped, nonce)
        .map(|k| k.to_vec())
        .map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Asymmetric key wrapping (V1)
// ---------------------------------------------------------------------------

/// Wrap key for recipient (V1). Returns (wrapped_key, ephemeral_pubkey, nonce).
#[allow(clippy::type_complexity)]
pub fn wrap_key_for_recipient_v1_impl(
    item_key: &[u8],
    recipient_pubkey: &[u8],
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), String> {
    let ik = bytes_to_key32(item_key, "item key")?;
    let pk = bytes_to_key32(recipient_pubkey, "recipient public key")?;
    let wrapped = crypto::wrap_key_for_recipient_v1(&ik, &pk).map_err(|e| e.to_string())?;
    Ok((
        wrapped.wrapped_key,
        wrapped.ephemeral_pubkey.to_vec(),
        wrapped.nonce.to_vec(),
    ))
}

pub fn unwrap_key_v1_impl(
    privkey: &[u8],
    ephemeral_pub: &[u8],
    wrapped: &[u8],
    nonce: &[u8],
    recipient_pubkey: &[u8],
) -> Result<Vec<u8>, String> {
    let sk = bytes_to_key32(privkey, "private key")?;
    let ep = bytes_to_key32(ephemeral_pub, "ephemeral public key")?;
    let rpk = bytes_to_key32(recipient_pubkey, "recipient public key")?;
    crypto::unwrap_key_v1(&sk, &ep, wrapped, nonce, &rpk)
        .map(|k| k.to_vec())
        .map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Grant key wrapping
// ---------------------------------------------------------------------------

/// Wrap key for grant. Returns (grant_wrapped_key, ephemeral_pubkey).
pub fn wrap_key_for_grant_impl(
    item_key: &[u8],
    recipient_pubkey: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let ik = bytes_to_key32(item_key, "item key")?;
    let pk = bytes_to_key32(recipient_pubkey, "recipient public key")?;
    let (wrapped, ephemeral) = crypto::wrap_key_for_grant(&ik, &pk).map_err(|e| e.to_string())?;
    Ok((wrapped, ephemeral.to_vec()))
}

pub fn unwrap_grant_key_impl(
    privkey: &[u8],
    ephemeral_pub: &[u8],
    grant_wrapped_key: &[u8],
    recipient_pubkey: &[u8],
) -> Result<Vec<u8>, String> {
    let sk = bytes_to_key32(privkey, "private key")?;
    let ep = bytes_to_key32(ephemeral_pub, "ephemeral public key")?;
    let rpk = bytes_to_key32(recipient_pubkey, "recipient public key")?;
    crypto::unwrap_grant_key(&sk, &ep, grant_wrapped_key, &rpk)
        .map(|k| k.to_vec())
        .map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Symmetric key wrapping
// ---------------------------------------------------------------------------

pub fn wrap_key_symmetric_impl(wrapping_key: &[u8], key_to_wrap: &[u8]) -> Result<Vec<u8>, String> {
    let wk = bytes_to_key32(wrapping_key, "wrapping key")?;
    let ktw = bytes_to_key32(key_to_wrap, "key to wrap")?;
    let mk = MasterKey::from_bytes(ktw);
    crypto::wrap_master_key(&wk, &mk).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Private key decryption
// ---------------------------------------------------------------------------

pub fn decrypt_private_key_impl(
    enc_key: &[u8],
    encrypted_private_key: &[u8],
) -> Result<Vec<u8>, String> {
    let ek = bytes_to_key32(enc_key, "encryption key")?;
    crypto::decrypt_private_key(&ek, encrypted_private_key)
        .map(|k| k.to_vec())
        .map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Claim secret encryption
// ---------------------------------------------------------------------------

pub fn encrypt_claim_secret_impl(claim_key: &[u8], link_secret: &[u8]) -> Result<Vec<u8>, String> {
    let ck = bytes_to_key32(claim_key, "claim key")?;
    let ls = bytes_to_key32(link_secret, "link secret")?;
    crypto::encrypt_claim_secret(&ck, &ls).map_err(|e| e.to_string())
}

pub fn decrypt_claim_secret_impl(
    claim_key: &[u8],
    claim_ciphertext: &[u8],
) -> Result<Vec<u8>, String> {
    let ck = bytes_to_key32(claim_key, "claim key")?;
    crypto::decrypt_claim_secret(&ck, claim_ciphertext)
        .map(|k| k.to_vec())
        .map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Notarization
// ---------------------------------------------------------------------------

pub fn verify_notarization_impl(
    pubkey: &[u8],
    content_hash: &[u8],
    blob_hash: Option<&[u8]>,
    timestamp_millis: i64,
    tree_root: &[u8],
    signature: &[u8],
) -> Result<bool, String> {
    let pk = bytes_to_key32(pubkey, "public key")?;
    let ch = bytes_to_key32(content_hash, "content_hash")?;
    let bh = match blob_hash {
        Some(b) => {
            if b.is_empty() {
                None
            } else {
                Some(bytes_to_key32(b, "blob_hash")?)
            }
        }
        None => None,
    };
    let tr = bytes_to_key32(tree_root, "tree_root")?;
    let sig = bytes_to_arr64(signature, "signature")?;

    Ok(crypto::verify_notarization_signature(
        &pk,
        &ch,
        bh.as_ref(),
        timestamp_millis,
        &tr,
        &sig,
    ))
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

pub fn check_policy_impl(
    policy_json: &str,
    view_count: i32,
    operation: &str,
) -> Result<bool, String> {
    let policy: crate::Policy = serde_json::from_str(policy_json).map_err(|e| e.to_string())?;
    Ok(policy.is_access_allowed(chrono::Utc::now(), view_count, None, operation, None))
}

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------

pub fn sha256_impl(data: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    Sha256::digest(data).to_vec()
}

// ---------------------------------------------------------------------------
// Padding
// ---------------------------------------------------------------------------

pub fn pad_plaintext_impl(data: &[u8]) -> Vec<u8> {
    crate::padding::pad_plaintext(data)
}

pub fn unpad_plaintext_impl(data: &[u8]) -> Vec<u8> {
    crate::padding::unpad(data).to_vec()
}

// ---------------------------------------------------------------------------
// Drops
// ---------------------------------------------------------------------------

#[cfg(feature = "drops")]
pub fn normalize_mnemonic_impl(m: &str) -> String {
    crate::drops::normalize_mnemonic(m)
}

#[cfg(feature = "drops")]
pub fn derive_drop_lookup_key_impl(mnemonic: &str) -> String {
    crate::drops::derive_drop_lookup_key(mnemonic)
}

#[cfg(feature = "drops")]
pub fn derive_drop_wrapping_key_impl(mnemonic: &str, version: i32) -> Vec<u8> {
    crate::drops::derive_drop_wrapping_key(mnemonic, version).to_vec()
}

#[cfg(feature = "drops")]
pub fn wrap_drop_key_impl(wrapping_key: &[u8], drop_key: &[u8]) -> Result<Vec<u8>, String> {
    let wk = bytes_to_key32(wrapping_key, "wrapping key")?;
    let dk = bytes_to_key32(drop_key, "drop key")?;
    crate::drops::wrap_drop_key(&wk, &dk).map_err(|e| e.to_string())
}

#[cfg(feature = "drops")]
pub fn unwrap_drop_key_impl(wrapping_key: &[u8], wrapped: &[u8]) -> Result<Vec<u8>, String> {
    let wk = bytes_to_key32(wrapping_key, "wrapping key")?;
    crate::drops::unwrap_drop_key(&wk, wrapped)
        .map(|k| k.to_vec())
        .map_err(|e| e.to_string())
}

#[cfg(feature = "drops")]
pub fn generate_bip39_mnemonic_impl() -> String {
    crate::drops::generate_bip39_mnemonic()
}

#[cfg(feature = "drops")]
pub fn validate_bip39_mnemonic_impl(mnemonic: &str) -> bool {
    crate::drops::validate_bip39_mnemonic(mnemonic)
}

#[cfg(feature = "drops")]
pub fn derive_will_wrapping_key_impl(mnemonic: &str, version: i32) -> Vec<u8> {
    crate::drops::derive_will_wrapping_key(mnemonic, version).to_vec()
}

#[cfg(feature = "drops")]
pub fn derive_will_lookup_key_impl(mnemonic: &str) -> String {
    crate::drops::derive_will_lookup_key(mnemonic)
}

/// Returns (wrapping_key, auth_key).
#[cfg(feature = "drops")]
pub fn derive_recovery_keys_impl(mnemonic: &str, version: i32) -> (Vec<u8>, Vec<u8>) {
    let (wk, ak) = crate::drops::derive_recovery_keys(mnemonic, version);
    (wk.to_vec(), ak.to_vec())
}

// ---------------------------------------------------------------------------
// Envelope
// ---------------------------------------------------------------------------

pub fn build_envelope_impl(filename: &str, data: &[u8], mime_type: &str) -> Vec<u8> {
    crate::envelope::build_envelope(filename, data, mime_type)
}

/// Returns (name, file_data).
pub fn parse_envelope_impl(data: &[u8], fallback_id: &str) -> (String, Vec<u8>) {
    let (name, file_data) = crate::envelope::parse_envelope(data, fallback_id);
    (name, file_data.to_vec())
}

/// Decrypt an encrypted blob (V0/V1 auto-detection), unpad, and return plaintext.
pub fn decrypt_blob_impl(
    item_key: &[u8],
    blob_data: &[u8],
    user_id: &str,
) -> Result<Vec<u8>, String> {
    let ik = bytes_to_key32(item_key, "item key")?;
    let decrypted =
        crate::envelope::decrypt_blob_bytes(blob_data, &ik, user_id).map_err(|e| e.to_string())?;
    let unpadded = crate::padding::unpad(&decrypted);
    Ok(unpadded.to_vec())
}

// ---------------------------------------------------------------------------
// Unlock
// ---------------------------------------------------------------------------

/// Returns (prefix, secret_bytes).
pub fn parse_api_key_impl(raw_key: &str) -> Result<(String, Vec<u8>), String> {
    let (prefix, secret) = crate::unlock::parse_api_key(raw_key).map_err(|e| e.to_string())?;
    Ok((prefix, secret.to_vec()))
}

// ---------------------------------------------------------------------------
// High-level client orchestration
// ---------------------------------------------------------------------------

#[cfg(feature = "client")]
pub mod client_ops {
    use super::*;

    /// Returns (encrypted_blob_b64, wrapped_key, nonce).
    pub fn prepare_item_create_impl(
        master_key: &[u8],
        user_id: &str,
        label: &str,
        value: &str,
    ) -> Result<(String, Vec<u8>, Vec<u8>), String> {
        let mk = mk_from_bytes(master_key)?;
        let p = crate::client::prepare_item_create(&mk, user_id, label, value, None)
            .map_err(|e| e.to_string())?;
        Ok((p.encrypted_blob_b64, p.wrapped_key, p.nonce.to_vec()))
    }

    /// Returns the decrypted SecretBlob.
    pub fn decrypt_owned_item_impl(
        master_key: &[u8],
        user_id: &str,
        wrapped_key: &[u8],
        nonce: &[u8],
        blob_data: &[u8],
    ) -> Result<crate::envelope::SecretBlob, String> {
        let mk = mk_from_bytes(master_key)?;
        crate::client::decrypt_owned_item(&mk, user_id, wrapped_key, nonce, blob_data)
            .map_err(|e| e.to_string())
    }

    pub fn unwrap_owned_item_key_impl(
        master_key: &[u8],
        user_id: &str,
        wrapped_key: &[u8],
        nonce: &[u8],
    ) -> Result<Vec<u8>, String> {
        let mk = mk_from_bytes(master_key)?;
        crate::client::unwrap_owned_item_key(&mk, user_id, wrapped_key, nonce)
            .map(|k| k.to_vec())
            .map_err(|e| e.to_string())
    }

    /// Returns (grant_wrapped_key, ephemeral_pubkey).
    pub fn prepare_grant_impl(
        item_key: &[u8],
        recipient_pubkey: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), String> {
        let ik = bytes_to_key32(item_key, "item key")?;
        let pk = bytes_to_key32(recipient_pubkey, "recipient public key")?;
        let g = crate::client::prepare_grant(&ik, &pk).map_err(|e| e.to_string())?;
        Ok((g.grant_wrapped_key, g.ephemeral_pubkey.to_vec()))
    }

    /// Returns the decrypted SecretBlob for a granted item.
    pub fn decrypt_granted_item_impl(
        private_key: &[u8],
        recipient_pubkey: &[u8],
        ephemeral_pubkey: &[u8],
        grant_wrapped_key: &[u8],
        blob_data: &[u8],
        grantor_id: &str,
    ) -> Result<crate::envelope::SecretBlob, String> {
        let sk = bytes_to_key32(private_key, "private key")?;
        let rpk = bytes_to_key32(recipient_pubkey, "recipient public key")?;
        let ep = bytes_to_key32(ephemeral_pubkey, "ephemeral public key")?;
        crate::client::decrypt_granted_item(
            &sk,
            &rpk,
            &ep,
            grant_wrapped_key,
            blob_data,
            grantor_id,
        )
        .map_err(|e| e.to_string())
    }

    /// Returns (auth_key_hex, public_key, encrypted_private_key, client_salt, master_key_bytes).
    pub fn prepare_registration_impl(
        password: &str,
    ) -> Result<(String, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>), String> {
        let reg = crate::client::prepare_registration(password).map_err(|e| e.to_string())?;
        Ok((
            reg.auth_key_hex,
            reg.public_key.to_vec(),
            reg.encrypted_private_key,
            reg.client_salt,
            reg.master_key.as_bytes().to_vec(),
        ))
    }

    /// Returns (master_key_bytes, auth_key_hex).
    pub fn prepare_login_impl(
        password: &str,
        client_salt: &[u8],
    ) -> Result<(Vec<u8>, String), String> {
        let login =
            crate::client::prepare_login(password, client_salt).map_err(|e| e.to_string())?;
        Ok((login.master_key.as_bytes().to_vec(), login.auth_key_hex))
    }

    /// Returns (encrypted_blob_b64, wrapped_key, nonce).
    pub fn encrypt_group_impl(
        master_key: &[u8],
        user_id: &str,
        name: &str,
    ) -> Result<(String, Vec<u8>, Vec<u8>), String> {
        let mk = mk_from_bytes(master_key)?;
        let (blob_b64, wrapped_key, nonce) =
            crate::client::encrypt_group(&mk, user_id, name).map_err(|e| e.to_string())?;
        Ok((blob_b64, wrapped_key, nonce.to_vec()))
    }

    pub fn decrypt_group_name_impl(
        master_key: &[u8],
        user_id: &str,
        wrapped_key: &[u8],
        nonce: &[u8],
        encrypted_blob_b64: &str,
    ) -> Result<String, String> {
        let mk = mk_from_bytes(master_key)?;
        crate::client::decrypt_group_name(&mk, user_id, wrapped_key, nonce, encrypted_blob_b64)
            .map_err(|e| e.to_string())
    }

    /// Returns (envelope_b64, wrapped_key, nonce, encrypted_file).
    #[allow(clippy::type_complexity)]
    pub fn prepare_file_item_impl(
        master_key: &[u8],
        user_id: &str,
        label: &str,
        filename: &str,
        mime_type: &str,
        file_data: &[u8],
    ) -> Result<(String, Vec<u8>, Vec<u8>, Vec<u8>), String> {
        let mk = mk_from_bytes(master_key)?;
        let p =
            crate::client::prepare_file_item(&mk, user_id, label, filename, mime_type, file_data)
                .map_err(|e| e.to_string())?;
        Ok((
            p.envelope_b64,
            p.wrapped_key,
            p.nonce.to_vec(),
            p.encrypted_file,
        ))
    }

    /// Returns (current_auth_key_hex, new_auth_key_hex, new_client_salt,
    ///          new_encrypted_master_key, new_encrypted_private_key, new_master_key_bytes).
    #[allow(clippy::type_complexity)]
    pub fn prepare_password_change_impl(
        current_password: &str,
        new_password: &str,
        current_client_salt: &[u8],
        encrypted_private_key: &[u8],
        master_key: &[u8],
        user_id: &str,
    ) -> Result<(String, String, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>), String> {
        let mk = mk_from_bytes(master_key)?;
        let p = crate::client::prepare_password_change(
            current_password,
            new_password,
            current_client_salt,
            encrypted_private_key,
            &mk,
            user_id,
        )
        .map_err(|e| e.to_string())?;
        Ok((
            p.current_auth_key_hex,
            p.new_auth_key_hex,
            p.new_client_salt,
            p.new_encrypted_master_key,
            p.new_encrypted_private_key,
            p.new_master_key.as_bytes().to_vec(),
        ))
    }

    /// Returns (secret, key_prefix, auth_key_hex, wrapped_master_key).
    pub fn prepare_api_key_full_impl(
        master_key: &[u8],
    ) -> Result<(Vec<u8>, String, String, Vec<u8>), String> {
        let mk = mk_from_bytes(master_key)?;
        let p = crate::client::prepare_api_key_full(&mk).map_err(|e| e.to_string())?;
        Ok((
            p.secret.to_vec(),
            p.key_prefix,
            p.auth_key_hex,
            p.wrapped_master_key,
        ))
    }

    /// Returns (secret, key_prefix, auth_key_hex, encrypted_private_key, public_key).
    #[allow(clippy::type_complexity)]
    pub fn prepare_api_key_scoped_impl(
    ) -> Result<(Vec<u8>, String, String, Vec<u8>, Vec<u8>), String> {
        let p = crate::client::prepare_api_key_scoped().map_err(|e| e.to_string())?;
        Ok((
            p.secret.to_vec(),
            p.key_prefix,
            p.auth_key_hex,
            p.encrypted_private_key,
            p.public_key.to_vec(),
        ))
    }

    /// Accepts items as JSON array of `[{"item_id":"...","item_key":[...]}]`.
    /// Returns (wrapped_items_json, encrypted_will_key, ephemeral_pubkey).
    pub fn prepare_will_payload_impl(
        user_id: &str,
        items_json: &str,
        heir_pubkey: &[u8],
    ) -> Result<(String, Vec<u8>, Vec<u8>), String> {
        let hp = bytes_to_key32(heir_pubkey, "heir public key")?;

        #[derive(serde::Deserialize)]
        struct ItemEntry {
            item_id: String,
            item_key: Vec<u8>,
        }
        let entries: Vec<ItemEntry> =
            serde_json::from_str(items_json).map_err(|e| e.to_string())?;
        let items: Vec<crate::client::WillItemKey> = entries
            .into_iter()
            .map(|e| {
                let mut key = [0u8; 32];
                if e.item_key.len() != 32 {
                    return Err("item_key must be 32 bytes".to_string());
                }
                key.copy_from_slice(&e.item_key);
                Ok(crate::client::WillItemKey {
                    item_id: e.item_id,
                    item_key: key,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let p =
            crate::client::prepare_will_payload(user_id, &items, &hp).map_err(|e| e.to_string())?;
        let wrapped_json = serde_json::to_string(&serde_json::Value::Object(p.wrapped_items))
            .map_err(|e| e.to_string())?;
        Ok((
            wrapped_json,
            p.encrypted_will_key,
            p.ephemeral_pubkey.to_vec(),
        ))
    }

    /// Decrypt a user's private key from their master key + encrypted private key.
    pub fn decrypt_private_key_from_master_impl(
        master_key: &[u8],
        encrypted_private_key: &[u8],
    ) -> Result<Vec<u8>, String> {
        let mk = mk_from_bytes(master_key)?;
        let pk = crate::client::decrypt_private_key_from_master(&mk, encrypted_private_key)
            .map_err(|e| e.to_string())?;
        Ok(pk.to_vec())
    }

    /// Wrap a raw 32-byte key under the user's encryption subkey.
    /// Returns (wrapped_key, nonce).
    pub fn wrap_key_for_user_impl(
        master_key: &[u8],
        user_id: &str,
        raw_key: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), String> {
        let mk = mk_from_bytes(master_key)?;
        let k = bytes_to_key32(raw_key, "raw key")?;
        let r = crate::client::wrap_key_for_user(&mk, user_id, &k).map_err(|e| e.to_string())?;
        Ok((r.wrapped_key, r.nonce.to_vec()))
    }

    /// Unwrap an owned item key and re-wrap it for an API key's public key.
    /// Returns (wrapped_key, ephemeral_pubkey, nonce).
    #[allow(clippy::type_complexity)]
    pub fn grant_item_to_api_key_impl(
        master_key: &[u8],
        user_id: &str,
        item_wrapped_key: &[u8],
        item_nonce: &[u8],
        api_key_pubkey: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), String> {
        let mk = mk_from_bytes(master_key)?;
        let pk = bytes_to_key32(api_key_pubkey, "API key public key")?;
        let wk =
            crate::client::grant_item_to_api_key(&mk, user_id, item_wrapped_key, item_nonce, &pk)
                .map_err(|e| e.to_string())?;
        Ok((
            wk.wrapped_key.to_vec(),
            wk.ephemeral_pubkey.to_vec(),
            wk.nonce.to_vec(),
        ))
    }

    /// Decrypt a file item's metadata envelope (base64 blob).
    pub fn decrypt_owned_inline_envelope_impl(
        master_key: &[u8],
        user_id: &str,
        wrapped_key: &[u8],
        nonce: &[u8],
        encrypted_blob_b64: &str,
    ) -> Result<crate::envelope::SecretBlob, String> {
        let mk = mk_from_bytes(master_key)?;
        crate::client::decrypt_owned_inline_envelope(
            &mk,
            user_id,
            wrapped_key,
            nonce,
            encrypted_blob_b64,
        )
        .map_err(|e| e.to_string())
    }

    // -----------------------------------------------------------------------
    // Link-secret grants
    // -----------------------------------------------------------------------

    /// Prepare a link-secret grant for an item.
    /// Returns (wrapped_key, nonce, link_secret, claim_key, claim_ciphertext,
    ///          claim_token_hash, file_wrapped_key_or_empty).
    #[allow(clippy::type_complexity)]
    pub fn prepare_link_grant_impl(
        item_key: &[u8],
        file_key: Option<&[u8]>,
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, String, Vec<u8>), String> {
        let ik = bytes_to_key32(item_key, "item key")?;
        let fk = match file_key {
            Some(b) if !b.is_empty() => Some(bytes_to_key32(b, "file key")?),
            _ => None,
        };
        let lg = crate::client::prepare_link_grant(&ik, fk.as_ref()).map_err(|e| e.to_string())?;
        Ok((
            lg.wrapped_key,
            lg.nonce.to_vec(),
            lg.link_secret.to_vec(),
            lg.claim_key.to_vec(),
            lg.claim_ciphertext,
            lg.claim_token_hash,
            lg.file_wrapped_key.unwrap_or_default(),
        ))
    }

    /// Decrypt an item from a link-secret grant.
    pub fn decrypt_link_grant_impl(
        claim_key: &[u8],
        claim_ciphertext: &[u8],
        wrapped_key: &[u8],
        nonce: &[u8],
        blob_data: &[u8],
        grantor_id: &str,
    ) -> Result<crate::envelope::SecretBlob, String> {
        let ck = bytes_to_key32(claim_key, "claim key")?;
        crate::client::decrypt_link_grant(
            &ck,
            claim_ciphertext,
            wrapped_key,
            nonce,
            blob_data,
            grantor_id,
        )
        .map_err(|e| e.to_string())
    }

    /// Unwrap a link-secret grant's item key without decrypting the blob.
    pub fn unwrap_link_grant_key_impl(
        claim_key: &[u8],
        claim_ciphertext: &[u8],
        wrapped_key: &[u8],
        nonce: &[u8],
    ) -> Result<Vec<u8>, String> {
        let ck = bytes_to_key32(claim_key, "claim key")?;
        crate::client::unwrap_link_grant_key(&ck, claim_ciphertext, wrapped_key, nonce)
            .map(|k| k.to_vec())
            .map_err(|e| e.to_string())
    }

    // -----------------------------------------------------------------------
    // Will payload (mnemonic fallback)
    // -----------------------------------------------------------------------

    /// Prepare a will payload using a BIP39 mnemonic for an heir without an account.
    /// items_json: `[{"item_id":"...","item_key":[...]}]`
    /// Returns (wrapped_items_json, encrypted_will_key, lookup_key, mnemonic).
    #[cfg(feature = "drops")]
    pub fn prepare_will_payload_mnemonic_impl(
        user_id: &str,
        items_json: &str,
    ) -> Result<(String, Vec<u8>, String, String), String> {
        #[derive(serde::Deserialize)]
        struct ItemEntry {
            item_id: String,
            item_key: Vec<u8>,
        }
        let entries: Vec<ItemEntry> =
            serde_json::from_str(items_json).map_err(|e| e.to_string())?;
        let items: Vec<crate::client::WillItemKey> = entries
            .into_iter()
            .map(|e| {
                let mut key = [0u8; 32];
                if e.item_key.len() != 32 {
                    return Err("item_key must be 32 bytes".to_string());
                }
                key.copy_from_slice(&e.item_key);
                Ok(crate::client::WillItemKey {
                    item_id: e.item_id,
                    item_key: key,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let p = crate::client::prepare_will_payload_mnemonic(user_id, &items)
            .map_err(|e| e.to_string())?;
        let wrapped_json = serde_json::to_string(&serde_json::Value::Object(p.wrapped_items))
            .map_err(|e| e.to_string())?;
        Ok((wrapped_json, p.encrypted_will_key, p.lookup_key, p.mnemonic))
    }
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

#[cfg(feature = "drops")]
pub mod parsing_ops {
    /// Parse drop input. Returns a JSON string describing the result.
    ///
    /// On success, returns either:
    /// - `{"type":"direct","drop_id":"...","key":[...]}`
    /// - `{"type":"mnemonic","mnemonic":"...","drop_id":null|"..."}`
    pub fn parse_drop_input_impl(key: &str, key2: Option<&str>) -> Result<String, String> {
        let result = crate::parsing::parse_drop_input(key, key2).map_err(|e| e.to_string())?;
        match result {
            crate::parsing::DropInput::Direct { drop_id, key } => Ok(serde_json::json!({
                "type": "direct",
                "drop_id": drop_id,
                "key": key.to_vec(),
            })
            .to_string()),
            crate::parsing::DropInput::Mnemonic { mnemonic, drop_id } => Ok(serde_json::json!({
                "type": "mnemonic",
                "mnemonic": mnemonic,
                "drop_id": drop_id,
            })
            .to_string()),
        }
    }

    /// Parse a grant-accept URL. Returns (grant_id, claim_key_b64) or error.
    pub fn parse_grant_url_impl(url: &str) -> Result<(String, String), String> {
        crate::parsing::parse_grant_url(url)
            .map(|gl| (gl.grant_id, gl.claim_key_b64))
            .ok_or_else(|| "could not parse grant URL".to_string())
    }
}
