use std::{error::Error, sync::Arc};

use auth::{
    application::services::auth::{AuthService, AuthServiceImpl},
    config::AuthConfig,
    infrastructure::{
        repositories::{
            PgRefreshTokenRepository, PgRoleRepository, PgUserRepository,
        },
        security::{Argon2PasswordHasher, JwtAccessTokenProvider},
    },
};
use chrono::Duration;
use sqlx::PgPool;

use crate::config::AppConfig;

/// Migrations from the repo-level `migrations/` folder, embedded at compile
/// time (see `build.rs`).
static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

type BoxError = Box<dyn Error + Send + Sync>;

/// Holds every service the HTTP layer needs. Each module contributes its own
/// services here; this is the only place where concrete implementations are
/// chosen.
pub struct Container {
    pub sqlx_pool: PgPool,
    pub auth_config: AuthConfig,
    pub auth_service: Arc<dyn AuthService>,
}

impl Container {
    /// Connects to the database, applies pending migrations, then builds the
    /// services. A failed migration aborts startup rather than serving
    /// requests against an unknown schema.
    pub async fn new(config: &AppConfig) -> Result<Self, BoxError> {
        let pool = base::sqlx_init::create_pool(&config.database)
            .await
            .map_err(|e| format!("could not connect to the database: {e}"))?;

        log::info!("Checking and applying pending database migrations");
        MIGRATOR.run(&pool).await?;
        log::info!("Database migrations are up to date");

        Self::from_pool(pool, config.auth.clone()).await
    }

    /// Wires the services onto an already-migrated pool. Also the entry point
    /// for tests, which get a pool from `#[sqlx::test]`.
    pub async fn from_pool(
        pool: PgPool,
        auth_config: AuthConfig,
    ) -> Result<Self, BoxError> {
        let auth_service: Arc<dyn AuthService> = Arc::new(
            AuthServiceImpl::new(
                Arc::new(PgUserRepository::new(pool.clone())),
                Arc::new(PgRoleRepository::new(pool.clone())),
                Arc::new(PgRefreshTokenRepository::new(pool.clone())),
                Arc::new(Argon2PasswordHasher::new()),
                Arc::new(JwtAccessTokenProvider::new(
                    &auth_config.jwt_secret,
                    auth_config.access_token_ttl_minutes,
                )),
                Duration::days(auth_config.refresh_token_ttl_days),
            )
            .await?,
        );

        if let Some(admin) = &auth_config.bootstrap_admin {
            let created = auth_service
                .ensure_admin(&admin.email, &admin.name, &admin.password)
                .await?;
            if created {
                log::info!("Created bootstrap admin account {}", admin.email);
            }
        }

        Ok(Self {
            sqlx_pool: pool,
            auth_config,
            auth_service,
        })
    }
}
