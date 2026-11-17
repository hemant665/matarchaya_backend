use crate::domain::models::user::{NewUser, User};
use async_trait::async_trait;
use base::result_paging::RepositoryResult;
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[async_trait]
pub trait UserRepository: Send + Sync {
    /// Active (not soft-deleted) users only.
    async fn find_by_id(&self, id: Uuid) -> RepositoryResult<Option<User>>;
    /// `email` must already be normalized (trimmed, lowercase).
    async fn find_by_email(
        &self,
        email: &str,
    ) -> RepositoryResult<Option<User>>;
    /// A duplicate email surfaces as a unique-violation `RepositoryError`.
    async fn create(&self, new_user: &NewUser) -> RepositoryResult<User>;
    async fn touch_last_login(
        &self,
        id: Uuid,
        at: DateTime<Utc>,
    ) -> RepositoryResult<()>;
}
