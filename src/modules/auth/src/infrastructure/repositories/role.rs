use async_trait::async_trait;
use base::result_paging::RepositoryResult;
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use crate::domain::models::role::Role;
use crate::domain::repositories::role::RoleRepository;

#[derive(FromRow)]
struct RoleRow {
    id: Uuid,
    name: String,
    description: String,
}

impl From<RoleRow> for Role {
    fn from(row: RoleRow) -> Self {
        Self {
            id: row.id,
            name: row.name,
            description: row.description,
        }
    }
}

pub struct PgRoleRepository {
    pool: PgPool,
}

impl PgRoleRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl RoleRepository for PgRoleRepository {
    async fn find_by_name(&self, name: &str) -> RepositoryResult<Option<Role>> {
        let row = sqlx::query_as::<_, RoleRow>(
            "SELECT id, name, description FROM roles WHERE name = $1",
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(Role::from))
    }

    async fn role_has_permission(
        &self,
        role_name: &str,
        permission_name: &str,
    ) -> RepositoryResult<bool> {
        let allowed = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS ( \
                 SELECT 1 FROM role_permissions rp \
                 JOIN roles r       ON r.id = rp.role_id \
                 JOIN permissions p ON p.id = rp.permission_id \
                 WHERE r.name = $1 AND p.name = $2 \
             )",
        )
        .bind(role_name)
        .bind(permission_name)
        .fetch_one(&self.pool)
        .await?;
        Ok(allowed)
    }
}
