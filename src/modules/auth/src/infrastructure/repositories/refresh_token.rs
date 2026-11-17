use async_trait::async_trait;
use base::result_paging::RepositoryResult;
use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use crate::domain::models::refresh_token::{NewRefreshToken, RefreshToken};
use crate::domain::repositories::refresh_token::RefreshTokenRepository;

const COLUMNS: &str =
    "id, user_id, token_hash, family_id, issued_at, expires_at, is_revoked";

#[derive(FromRow)]
struct RefreshTokenRow {
    id: Uuid,
    user_id: Uuid,
    token_hash: String,
    family_id: Uuid,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    is_revoked: bool,
}

impl From<RefreshTokenRow> for RefreshToken {
    fn from(row: RefreshTokenRow) -> Self {
        Self {
            id: row.id,
            user_id: row.user_id,
            token_hash: row.token_hash,
            family_id: row.family_id,
            issued_at: row.issued_at,
            expires_at: row.expires_at,
            is_revoked: row.is_revoked,
        }
    }
}

pub struct PgRefreshTokenRepository {
    pool: PgPool,
}

impl PgRefreshTokenRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

fn insert_sql() -> String {
    format!(
        "INSERT INTO refresh_tokens \
             (user_id, token_hash, family_id, issued_at, expires_at) \
         VALUES ($1, $2, $3, $4, $5) RETURNING {COLUMNS}"
    )
}

#[async_trait]
impl RefreshTokenRepository for PgRefreshTokenRepository {
    async fn create(
        &self,
        new_token: &NewRefreshToken,
    ) -> RepositoryResult<RefreshToken> {
        let row = sqlx::query_as::<_, RefreshTokenRow>(&insert_sql())
            .bind(new_token.user_id)
            .bind(&new_token.token_hash)
            .bind(new_token.family_id)
            .bind(new_token.issued_at)
            .bind(new_token.expires_at)
            .fetch_one(&self.pool)
            .await?;
        Ok(row.into())
    }

    async fn find_by_hash(
        &self,
        token_hash: &str,
    ) -> RepositoryResult<Option<RefreshToken>> {
        let row = sqlx::query_as::<_, RefreshTokenRow>(&format!(
            "SELECT {COLUMNS} FROM refresh_tokens WHERE token_hash = $1"
        ))
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(RefreshToken::from))
    }

    async fn rotate(
        &self,
        old_id: Uuid,
        next: &NewRefreshToken,
    ) -> RepositoryResult<Option<RefreshToken>> {
        let mut tx = self.pool.begin().await?;

        // `AND is_revoked = FALSE` is the guard: if two requests race on the
        // same token, Postgres lets exactly one UPDATE match the row.
        let revoked = sqlx::query(
            "UPDATE refresh_tokens SET is_revoked = TRUE \
             WHERE id = $1 AND is_revoked = FALSE",
        )
        .bind(old_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();

        if revoked == 0 {
            tx.rollback().await?;
            return Ok(None);
        }

        let row = sqlx::query_as::<_, RefreshTokenRow>(&insert_sql())
            .bind(next.user_id)
            .bind(&next.token_hash)
            .bind(next.family_id)
            .bind(next.issued_at)
            .bind(next.expires_at)
            .fetch_one(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(Some(row.into()))
    }

    async fn revoke_family(&self, family_id: Uuid) -> RepositoryResult<()> {
        sqlx::query(
            "UPDATE refresh_tokens SET is_revoked = TRUE \
             WHERE family_id = $1 AND is_revoked = FALSE",
        )
        .bind(family_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
