use crate::domain::models::role::Role;
use async_trait::async_trait;
use base::result_paging::RepositoryResult;

#[async_trait]
pub trait RoleRepository: Send + Sync {
    async fn find_by_name(&self, name: &str) -> RepositoryResult<Option<Role>>;
    async fn role_has_permission(
        &self,
        role_name: &str,
        permission_name: &str,
    ) -> RepositoryResult<bool>;
}
