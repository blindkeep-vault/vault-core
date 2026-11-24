//! RSA-OAEP recipient variant (`rsa-oaep-kms`, #297).
//!
//! Lets a recipient's private key live in a KMS or HSM that cannot do X25519
//! key agreement (AWS KMS, Scaleway Key Manager, Vault/OpenBao Transit,
//! PKCS#11 HSMs). The sender encrypts the 32-byte item key directly to the
//! recipient's RSA public key; the recipient asks its KMS to decrypt the
//! wrapped key once per item.
//!
//! Parameters (SPECIFICATION.md §7.5.1):
//! - RSAES-OAEP, hash SHA-256, MGF1 with SHA-256, empty label.
//! - Modulus between [`MIN_MODULUS_BITS`] and [`MAX_MODULUS_BITS`]; the
//!   wrapped key is exactly one modulus long (384 bytes for RSA-3072).
//! - Public key as SubjectPublicKeyInfo DER, the form KMSs export and Web
//!   Crypto's `importKey("spki", …)` takes.
//!
//! **Encryption only.** This module never performs RSA decryption: the
//! private-key step runs in the KMS through the caller-supplied callback in
//! [`unwrap_key_rsa_oaep_with`]. The `rsa` crate's decryption path is subject
//! to the Marvin timing attack (RUSTSEC-2023-0071); its encryption path uses
//! only the public key and is not. Do not add a local-decrypt helper here.
//!
//! The wrapped key carries no AAD. Binding to an item comes from the item
//! ciphertext itself: a wrapped key moved to another item yields a key that
//! fails that item's AEAD check.

use crate::crypto::{CryptoError, KEY_LEN};
use rsa::pkcs8::DecodePublicKey;
use rsa::traits::PublicKeyParts;
use rsa::{Oaep, RsaPublicKey};
use sha2::Sha256;
use zeroize::Zeroizing;

/// Smallest accepted RSA modulus, in bits.
pub const MIN_MODULUS_BITS: usize = 3072;
/// Largest accepted RSA modulus, in bits.
pub const MAX_MODULUS_BITS: usize = 4096;

/// Parse and validate a recipient public key (SPKI DER).
///
/// Rejects moduli outside [`MIN_MODULUS_BITS`]..=[`MAX_MODULUS_BITS`] and
/// moduli whose bit length is not a multiple of 8, so the wrapped-key length
/// on the unwrap side has a fixed set of valid values.
pub fn parse_recipient_public_key(spki_der: &[u8]) -> Result<RsaPublicKey, CryptoError> {
    let key = RsaPublicKey::from_public_key_der(spki_der).map_err(|_| CryptoError::InvalidKey)?;
    let bits = key.n().bits();
    if !(MIN_MODULUS_BITS..=MAX_MODULUS_BITS).contains(&bits) || bits % 8 != 0 {
        return Err(CryptoError::InvalidKey);
    }
    Ok(key)
}

/// Wrap an item key for an RSA-OAEP recipient.
///
/// Returns the OAEP ciphertext, exactly `modulus_bits / 8` bytes. The output
/// is randomized: wrapping the same key twice gives different bytes.
pub fn wrap_key_for_recipient_rsa_oaep(
    item_key: &[u8; KEY_LEN],
    recipient_spki_der: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let key = parse_recipient_public_key(recipient_spki_der)?;
    key.encrypt(
        &mut rand::rngs::OsRng,
        Oaep::new::<Sha256>(),
        item_key.as_slice(),
    )
    .map_err(|_| CryptoError::EncryptionFailed)
}

/// Unwrap an RSA-OAEP wrapped item key through a caller-supplied decrypt.
///
/// `decrypt` receives the wrapped key and must return the RSA-OAEP
/// (SHA-256 / MGF1-SHA-256 / empty label) decryption of it, typically by
/// calling the KMS: AWS KMS `Decrypt` with `RSAES_OAEP_SHA_256`, or
/// Vault/OpenBao Transit `decrypt` with `vault:v1:<base64>` ciphertext.
///
/// The callback's error is returned unchanged, so KMS failures (access
/// denied, key disabled, throttling) stay distinguishable from a malformed
/// result. A wrapped key whose length cannot match an accepted modulus is
/// rejected before the callback runs, which saves a KMS call (and an audit
/// entry) on obvious garbage. A decrypted value that is not exactly
/// [`KEY_LEN`] bytes is rejected with [`CryptoError::InvalidKeyLength`].
pub fn unwrap_key_rsa_oaep_with<F, E>(
    wrapped_key: &[u8],
    decrypt: F,
) -> Result<Zeroizing<[u8; KEY_LEN]>, E>
where
    F: FnOnce(&[u8]) -> Result<Vec<u8>, E>,
    E: From<CryptoError>,
{
    let len = wrapped_key.len();
    if !(MIN_MODULUS_BITS / 8..=MAX_MODULUS_BITS / 8).contains(&len) {
        return Err(CryptoError::DecryptionFailed.into());
    }

    let plaintext = Zeroizing::new(decrypt(wrapped_key)?);
    if plaintext.len() != KEY_LEN {
        return Err(CryptoError::InvalidKeyLength.into());
    }

    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    key.copy_from_slice(&plaintext);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::RsaPrivateKey;

    // Fixtures: see src/testdata/rsa_oaep/README.md for how they were made.
    const SPKI_2048: &[u8] = include_bytes!("testdata/rsa_oaep/rsa2048.spki.der");
    const SPKI_3072: &[u8] = include_bytes!("testdata/rsa_oaep/rsa3072.spki.der");
    const PK8_3072: &[u8] = include_bytes!("testdata/rsa_oaep/rsa3072.pk8.der");
    const PK8_3072_OTHER: &[u8] = include_bytes!("testdata/rsa_oaep/rsa3072_other.pk8.der");
    const SPKI_4096: &[u8] = include_bytes!("testdata/rsa_oaep/rsa4096.spki.der");
    const PK8_4096: &[u8] = include_bytes!("testdata/rsa_oaep/rsa4096.pk8.der");
    const ITEM_KEY: &[u8] = include_bytes!("testdata/rsa_oaep/item_key.bin");
    const WRAPPED_OPENSSL_3072: &[u8] =
        include_bytes!("testdata/rsa_oaep/wrapped_openssl_3072.bin");
    const WRAPPED_WEBCRYPTO_3072: &[u8] =
        include_bytes!("testdata/rsa_oaep/wrapped_webcrypto_3072.bin");

    /// Stand-in for the KMS: local RSA-OAEP decryption. Test-only; the
    /// library itself never decrypts (see module docs).
    fn kms(pk8: &'static [u8]) -> impl Fn(&[u8]) -> Result<Vec<u8>, CryptoError> {
        let sk = RsaPrivateKey::from_pkcs8_der(pk8).unwrap();
        move |ct| {
            sk.decrypt(Oaep::new::<Sha256>(), ct)
                .map_err(|_| CryptoError::DecryptionFailed)
        }
    }

    fn item_key() -> [u8; KEY_LEN] {
        ITEM_KEY.try_into().unwrap()
    }

    #[test]
    fn roundtrip_3072() {
        let wrapped = wrap_key_for_recipient_rsa_oaep(&item_key(), SPKI_3072).unwrap();
        assert_eq!(wrapped.len(), 384);
        let unwrapped = unwrap_key_rsa_oaep_with(&wrapped, kms(PK8_3072)).unwrap();
        assert_eq!(*unwrapped, item_key());
    }

    #[test]
    fn roundtrip_4096() {
        let wrapped = wrap_key_for_recipient_rsa_oaep(&item_key(), SPKI_4096).unwrap();
        assert_eq!(wrapped.len(), 512);
        let unwrapped = unwrap_key_rsa_oaep_with(&wrapped, kms(PK8_4096)).unwrap();
        assert_eq!(*unwrapped, item_key());
    }

    #[test]
    fn wrap_is_randomized() {
        let a = wrap_key_for_recipient_rsa_oaep(&item_key(), SPKI_3072).unwrap();
        let b = wrap_key_for_recipient_rsa_oaep(&item_key(), SPKI_3072).unwrap();
        assert_ne!(a, b);
    }

    /// Known-answer vector produced by OpenSSL (`pkeyutl -encrypt`,
    /// `rsa_oaep_md:sha256`, `rsa_mgf1_md:sha256`).
    #[test]
    fn opens_openssl_vector() {
        let k = unwrap_key_rsa_oaep_with(WRAPPED_OPENSSL_3072, kms(PK8_3072)).unwrap();
        assert_eq!(k.as_slice(), ITEM_KEY);
    }

    /// Known-answer vector produced by Web Crypto
    /// (`{name: "RSA-OAEP", hash: "SHA-256"}`, no label), the browser path.
    #[test]
    fn opens_webcrypto_vector() {
        let k = unwrap_key_rsa_oaep_with(WRAPPED_WEBCRYPTO_3072, kms(PK8_3072)).unwrap();
        assert_eq!(k.as_slice(), ITEM_KEY);
    }

    /// The parameters must match OpenSSL and Web Crypto, not only round-trip
    /// with ourselves: an OAEP decrypt with another hash must not open our
    /// output.
    #[test]
    fn wrap_uses_sha256() {
        let wrapped = wrap_key_for_recipient_rsa_oaep(&item_key(), SPKI_3072).unwrap();
        let sk = RsaPrivateKey::from_pkcs8_der(PK8_3072).unwrap();
        assert!(sk.decrypt(Oaep::new::<sha2::Sha384>(), &wrapped).is_err());
        assert!(sk.decrypt(Oaep::new::<Sha256>(), &wrapped).is_ok());
    }

    #[test]
    fn rejects_tampered_wrapped_key() {
        for i in [0usize, 191, 383] {
            let mut wrapped = WRAPPED_OPENSSL_3072.to_vec();
            wrapped[i] ^= 0x01;
            assert!(
                unwrap_key_rsa_oaep_with(&wrapped, kms(PK8_3072)).is_err(),
                "flip at byte {i} accepted"
            );
        }
    }

    #[test]
    fn rejects_wrong_recipient_key() {
        // Same modulus size, different key.
        assert!(unwrap_key_rsa_oaep_with(WRAPPED_OPENSSL_3072, kms(PK8_3072_OTHER)).is_err());
        assert!(unwrap_key_rsa_oaep_with(WRAPPED_WEBCRYPTO_3072, kms(PK8_3072_OTHER)).is_err());
        // Different modulus size.
        let wrapped = wrap_key_for_recipient_rsa_oaep(&item_key(), SPKI_4096).unwrap();
        assert!(unwrap_key_rsa_oaep_with(&wrapped, kms(PK8_3072)).is_err());
    }

    #[test]
    fn rejects_keys_below_3072_bits() {
        assert!(matches!(
            wrap_key_for_recipient_rsa_oaep(&item_key(), SPKI_2048),
            Err(CryptoError::InvalidKey)
        ));
    }

    #[test]
    fn rejects_non_spki_input() {
        assert!(matches!(
            wrap_key_for_recipient_rsa_oaep(&item_key(), &[0x30, 0x03, 0x02, 0x01, 0x01]),
            Err(CryptoError::InvalidKey)
        ));
        // A PKCS#8 private key is not a public key.
        assert!(matches!(
            wrap_key_for_recipient_rsa_oaep(&item_key(), PK8_3072),
            Err(CryptoError::InvalidKey)
        ));
    }

    #[test]
    fn rejects_bad_length_before_calling_kms() {
        for len in [0usize, 32, 256, 383, 513] {
            let called = std::cell::Cell::new(false);
            let r = unwrap_key_rsa_oaep_with(&vec![0u8; len], |_| {
                called.set(true);
                Ok::<_, CryptoError>(vec![0u8; KEY_LEN])
            });
            assert!(r.is_err(), "len {len} accepted");
            assert!(!called.get(), "KMS called for len {len}");
        }
    }

    #[test]
    fn rejects_wrong_plaintext_length() {
        for n in [0usize, 31, 33, 64] {
            let r = unwrap_key_rsa_oaep_with(WRAPPED_OPENSSL_3072, |_| {
                Ok::<_, CryptoError>(vec![7u8; n])
            });
            assert!(matches!(r, Err(CryptoError::InvalidKeyLength)), "n={n}");
        }
    }

    #[test]
    fn propagates_kms_error_unchanged() {
        #[derive(Debug, PartialEq)]
        enum KmsError {
            Disabled,
            Crypto,
        }
        impl From<CryptoError> for KmsError {
            fn from(_: CryptoError) -> Self {
                KmsError::Crypto
            }
        }
        let r = unwrap_key_rsa_oaep_with(WRAPPED_OPENSSL_3072, |_| Err(KmsError::Disabled));
        assert_eq!(r.unwrap_err(), KmsError::Disabled);
    }

    /// An unwrapped key moved to another item does not open it: the binding
    /// to the item comes from the item ciphertext's AEAD, not the wrap.
    #[test]
    fn wrapped_key_does_not_open_other_item() {
        use crate::crypto::{decrypt_item_auto, encrypt_item_v1};
        let key_a = item_key();
        let key_b = [9u8; KEY_LEN];
        let item_b = encrypt_item_v1(&key_b, b"item b", b"item:b").unwrap();

        let wrapped_a = wrap_key_for_recipient_rsa_oaep(&key_a, SPKI_3072).unwrap();
        let k = unwrap_key_rsa_oaep_with(&wrapped_a, kms(PK8_3072)).unwrap();
        assert!(decrypt_item_auto(&k, &item_b.ciphertext, &item_b.nonce, b"item:b").is_err());
    }
}
