use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::{Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier};

/// Server-side Argon2id: 64 MiB, 3 iterations, 1 parallelism.
/// Used for hashing auth_key, recovery_auth_key, and API key auth on the server.
pub fn server_argon2() -> Argon2<'static> {
    let params = Params::new(64 * 1024, 3, 1, None).expect("valid argon2 params");
    Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
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

/// Check whether a stored hash uses the current recommended Argon2 parameters.
/// Returns false if the hash uses older/weaker parameters and should be rehashed.
pub fn needs_rehash(hash: &str) -> bool {
    let parsed = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return true,
    };
    // Check if params match our current recommendation: m=65536, t=3, p=1
    let params = match Params::try_from(&parsed) {
        Ok(p) => p,
        Err(_) => return true,
    };
    params.m_cost() != 64 * 1024 || params.t_cost() != 3 || params.p_cost() != 1
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
}
