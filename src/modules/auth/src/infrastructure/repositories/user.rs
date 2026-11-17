use async_trait::async_trait;
use base::result_paging::RepositoryResult;
use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use crate::domain::models::user::{NewUser, User};
use crate::domain::repositories::user::UserRepository;

/// Columns of `User`, with the role name joined in.
const USER_COLUMNS: &str = "u.id, u.email, u.name, u.password_hash, \
    u.role_id, r.name AS role_name, u.is_active, u.last_login, \
    u.created_at, u.updated_at";

/// Database shape of a user. Kept here so the domain model stays free of sqlx.
#[derive(FromRow)]
struct UserRow {
    id: Uuid,
    email: String,
    name: String,
    password_hash: String,
    role_id: Uuid,
    role_name: String,
    is_active: bool,
    last_login: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<UserRow> for User {
    fn from(row: UserRow) -> Self {
        Self {
            id: row.id,
            email: row.email,
            name: row.name,
            password_hash: row.password_hash,
            role_id: row.role_id,
            role_name: row.role_name,
            is_active: row.is_active,
            last_login: row.last_login,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

pub struct PgUserRepository {
    pool: PgPool,
}

impl PgUserRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UserRepository for PgUserRepository {
    async fn find_by_id(&self, id: Uuid) -> RepositoryResult<Option<User>> {
        let sql = format!(
            "SELECT {USER_COLUMNS} FROM users u \
             JOIN roles r ON r.id = u.role_id \
             WHERE u.id = $1 AND u.deleted_at IS NULL"
        );
        let row = sqlx::query_as::<_, UserRow>(&sql)
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(User::from))
    }

    async fn find_by_email(
        &self,
        email: &str,
    ) -> RepositoryResult<Option<User>> {
        let sql = format!(
            "SELECT {USER_COLUMNS} FROM users u \
             JOIN roles r ON r.id = u.role_id \
             WHERE u.email = $1 AND u.deleted_at IS NULL"
        );
        let row = sqlx::query_as::<_, UserRow>(&sql)
            .bind(email)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(User::from))
    }

    async fn create(&self, new_user: &NewUser) -> RepositoryResult<User> {
        let sql = format!(
            "WITH u AS ( \
                 INSERT INTO users (email, name, password_hash, role_id) \
                 VALUES ($1, $2, $3, $4) RETURNING * \
             ) \
             SELECT {USER_COLUMNS} FROM u \
             JOIN roles r ON r.id = u.role_id"
        );
        let row = sqlx::query_as::<_, UserRow>(&sql)
            .bind(&new_user.email)
            .bind(&new_user.name)
            .bind(&new_user.password_hash)
            .bind(new_user.role_id)
            .fetch_one(&self.pool)
            .await?;
        Ok(row.into())
    }

    async fn touch_last_login(
        &self,
        id: Uuid,
        at: DateTime<Utc>,
    ) -> RepositoryResult<()> {
        sqlx::query("UPDATE users SET last_login = $2 WHERE id = $1")
            .bind(id)
            .bind(at)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
