use crate::config::DatabaseConfig;
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::time::Duration;

/// Connects the shared Postgres pool.
pub async fn create_pool(
    config: &DatabaseConfig,
) -> Result<PgPool, sqlx::Error> {
    PgPoolOptions::new()
        .max_connections(config.max_connections)
        .acquire_timeout(Duration::from_secs(10))
        .connect(&config.url)
        .await
}
