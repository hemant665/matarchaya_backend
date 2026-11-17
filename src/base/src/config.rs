//! Environment-driven configuration helpers.
//!
//! Each crate owns the config it needs (e.g. `auth::config::AuthConfig`) and
//! builds it with these helpers; the `app` crate composes them. Everything
//! returns a [`ConfigError`] instead of panicking, so a bad `.env` produces one
//! readable startup message.

use std::{env, fmt, str::FromStr};

#[derive(Debug)]
pub struct ConfigError(pub String);

impl ConfigError {
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "configuration error: {}", self.0)
    }
}

impl std::error::Error for ConfigError {}

/// A variable that must be set and non-blank.
pub fn env_required(key: &str) -> Result<String, ConfigError> {
    env_optional(key).ok_or_else(|| {
        ConfigError::new(format!("environment variable {key} is not set"))
    })
}

/// A variable that may be absent; blank values count as absent.
pub fn env_optional(key: &str) -> Option<String> {
    env::var(key)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

pub fn env_or(key: &str, default: &str) -> String {
    env_optional(key).unwrap_or_else(|| default.to_string())
}

/// Parses a variable, falling back to `default` when it is absent.
pub fn env_parse<T>(key: &str, default: T) -> Result<T, ConfigError>
where
    T: FromStr,
    T::Err: fmt::Display,
{
    match env_optional(key) {
        None => Ok(default),
        Some(raw) => raw.parse::<T>().map_err(|e| {
            ConfigError::new(format!("{key}={raw:?} is invalid: {e}"))
        }),
    }
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub address: String,
    pub port: u16,
}

impl ServerConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        Ok(Self {
            address: env_or("ADDRESS", "127.0.0.1"),
            port: env_parse("PORT", 8080)?,
        })
    }
}

#[derive(Clone)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
}

impl DatabaseConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        Ok(Self {
            url: env_required("DATABASE_URL")?,
            max_connections: env_parse("DATABASE_MAX_CONNECTIONS", 10)?,
        })
    }
}

// The URL usually embeds the DB password, so never print it.
impl fmt::Debug for DatabaseConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatabaseConfig")
            .field("url", &"<redacted>")
            .field("max_connections", &self.max_connections)
            .finish()
    }
}
