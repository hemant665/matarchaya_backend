use crate::domain::models::refresh_token::{NewRefreshToken, RefreshToken};
use async_trait::async_trait;
use base::result_paging::RepositoryResult;
use uuid::Uuid;

#[async_trait]
pub trait RefreshTokenRepository: Send + Sync {
    async fn create(
        &self,
        new_token: &NewRefreshToken,
    ) -> RepositoryResult<RefreshToken>;

    async fn find_by_hash(
        &self,
        token_hash: &str,
    ) -> RepositoryResult<Option<RefreshToken>>;

    /// Atomically revokes the still-active token `old_id` and stores `next`.
    ///
    /// Returns `None` (and stores nothing) if `old_id` was already revoked,
    /// i.e. another request got there first. That is what makes concurrent
    /// use of one token detectable.
    async fn rotate(
        &self,
        old_id: Uuid,
        next: &NewRefreshToken,
    ) -> RepositoryResult<Option<RefreshToken>>;

    /// Revokes every token of one login (one device's session).
    async fn revoke_family(&self, family_id: Uuid) -> RepositoryResult<()>;
}
