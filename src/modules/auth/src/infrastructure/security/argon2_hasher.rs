use argon2::{
    Argon2, PasswordHash, PasswordHasher as _, PasswordVerifier,
    password_hash::SaltString,
};
use async_trait::async_trait;
use rand::{RngCore, rngs::OsRng};

use crate::application::ports::password_hasher::PasswordHasher;
use crate::domain::errors::auth_error::AuthError;

/// Argon2id with the crate defaults (19 MiB, 2 passes, 1 lane: the OWASP
/// minimum). Hashes are PHC strings, so parameters can be raised later and old
/// hashes keep verifying.
///
/// Argon2 is deliberately slow, so the work runs on the blocking pool instead
/// of stalling the async executor.
#[derive(Clone, Default)]
pub struct Argon2PasswordHasher {
    argon2: Argon2<'static>,
}

impl Argon2PasswordHasher {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl PasswordHasher for Argon2PasswordHasher {
    async fn hash(&self, password: &str) -> Result<String, AuthError> {
        let argon2 = self.argon2.clone();
        let password = password.to_owned();
        tokio::task::spawn_blocking(move || {
            let mut salt = [0u8; 16];
            OsRng.fill_bytes(&mut salt);
            let salt = SaltString::encode_b64(&salt)
                .map_err(|e| AuthError::Internal(e.to_string()))?;
            argon2
                .hash_password(password.as_bytes(), &salt)
                .map(|hash| hash.to_string())
                .map_err(|e| AuthError::Internal(e.to_string()))
        })
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?
    }

    async fn verify(&self, password: &str, hash: &str) -> bool {
        let argon2 = self.argon2.clone();
        let password = password.to_owned();
        let hash = hash.to_owned();
        tokio::task::spawn_blocking(move || {
            PasswordHash::new(&hash).is_ok_and(|parsed| {
                argon2.verify_password(password.as_bytes(), &parsed).is_ok()
            })
        })
        .await
        .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn hashes_and_verifies() {
        let hasher = Argon2PasswordHasher::new();
        let hash = hasher.hash("correct horse").await.unwrap();

        assert!(hash.starts_with("$argon2id$"));
        assert!(!hash.contains("correct horse"));
        assert!(hasher.verify("correct horse", &hash).await);
        assert!(!hasher.verify("wrong", &hash).await);
    }

    #[tokio::test]
    async fn salts_every_hash() {
        let hasher = Argon2PasswordHasher::new();
        let a = hasher.hash("same").await.unwrap();
        let b = hasher.hash("same").await.unwrap();
        assert_ne!(a, b);
    }

    #[tokio::test]
    async fn an_unparsable_hash_never_verifies() {
        let hasher = Argon2PasswordHasher::new();
        assert!(!hasher.verify("anything", "not-a-phc-string").await);
        assert!(!hasher.verify("anything", "").await);
    }
}
