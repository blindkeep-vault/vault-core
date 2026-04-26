use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::{Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier};

/// Server-side Argon2id parameters: 64 MiB, 3 iterations, 1 parallelism.
/// Single source of truth — `server_argon2()` and `needs_rehash()` both derive from this.
fn server_argon2_params() -> Params {
    Params::new(64 * 1024, 3, 1, None).expect("valid argon2 params")
}

/// Server-side Argon2id, used for hashing auth_key, recovery_auth_key, and API key auth.
pub fn server_argon2() -> Argon2<'static> {
    Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        server_argon2_params(),
    )
}

/// Hash an auth key (or API key secret) with server-side Argon2id.
pub fn hash_auth_key(auth_key: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = server_argon2().hash_password(auth_key.as_bytes(), &salt)?;
    Ok(hash.to_string())
}

/// Verify an auth key against a stored hash.
pub fn verify_auth_key(auth_key: &str, hash: &str) -> Result<bool, argon2::password_hash::Error> {
    let parsed = PasswordHash::new(hash)?;
    match server_argon2().verify_password(auth_key.as_bytes(), &parsed) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(e) => Err(e),
    }
}

/// Check whether a stored hash uses at least the current recommended Argon2 parameters.
/// Returns true when the hash is *weaker* than the recommendation, or when it can't be
/// parsed at all; stronger hashes (e.g., from a future tuning bump that hasn't been
/// re-applied to a row yet) are left alone so they aren't silently downgraded.
pub fn needs_rehash(hash: &str) -> bool {
    let parsed = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return true,
    };
    let params = match Params::try_from(&parsed) {
        Ok(p) => p,
        Err(_) => return true,
    };
    let reference = server_argon2_params();
    params.m_cost() < reference.m_cost()
        || params.t_cost() < reference.t_cost()
        || params.p_cost() < reference.p_cost()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify_roundtrip() {
        let key = "deadbeefcafebabe1234567890abcdef";
        let hash = hash_auth_key(key).unwrap();
        assert!(verify_auth_key(key, &hash).unwrap());
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let hash = hash_auth_key("correct-key-value-here-32chars!!").unwrap();
        assert!(!verify_auth_key("wrong-key-value-here-32chars!!", &hash).unwrap());
    }

    #[test]
    fn current_params_dont_need_rehash() {
        let hash = hash_auth_key("test-key-for-rehash-check-32ch!").unwrap();
        assert!(!needs_rehash(&hash));
    }

    fn hash_with_params(key: &str, params: Params) -> String {
        let salt = SaltString::generate(&mut OsRng);
        let argon = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        argon
            .hash_password(key.as_bytes(), &salt)
            .unwrap()
            .to_string()
    }

    #[test]
    fn weaker_params_need_rehash() {
        // Lower m_cost than the 64 MiB / 3 iter / 1 par recommendation.
        let weak = Params::new(32 * 1024, 3, 1, None).unwrap();
        let hash = hash_with_params("test-key-for-rehash-check-32ch!", weak);
        assert!(needs_rehash(&hash));
    }

    #[test]
    fn stronger_params_do_not_need_rehash() {
        // 128 MiB / 4 iter is strictly stronger; must not trigger a downgrade rehash.
        let strong = Params::new(128 * 1024, 4, 1, None).unwrap();
        let hash = hash_with_params("test-key-for-rehash-check-32ch!", strong);
        assert!(!needs_rehash(&hash));
    }

    #[test]
    fn one_axis_stronger_one_at_recommendation_does_not_need_rehash() {
        // m_cost stronger, t_cost and p_cost at the recommendation — pins that the OR
        // is over `<`, not `!=`, on each axis independently.
        let mixed = Params::new(128 * 1024, 3, 1, None).unwrap();
        let hash = hash_with_params("test-key-for-rehash-check-32ch!", mixed);
        assert!(!needs_rehash(&hash));
    }

    #[test]
    fn malformed_hash_needs_rehash() {
        assert!(needs_rehash("not-a-phc-string"));
    }
}
