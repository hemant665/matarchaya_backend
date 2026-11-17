use crate::domain::errors::auth_error::AuthError;
use async_trait::async_trait;

#[async_trait]
pub trait PasswordHasher: Send + Sync {
    /// Returns a self-describing hash string safe to store as-is.
    async fn hash(&self, password: &str) -> Result<String, AuthError>;

    /// `false` for a wrong password *and* for a hash that cannot be parsed.
    async fn verify(&self, password: &str, hash: &str) -> bool;
}
