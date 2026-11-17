use auth::config::AuthConfig;
use base::config::{ConfigError, DatabaseConfig, ServerConfig, env_or};

/// Everything the process needs from the environment, composed from each
/// module's own config. Add a module's config here when you add the module.
#[derive(Debug)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub cors_allowed_origins: Vec<String>,
    pub auth: AuthConfig,
}

impl AppConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        let origins = env_or(
            "CORS_ALLOWED_ORIGINS",
            "http://localhost:5173,http://localhost:3000",
        );
        Ok(Self {
            server: ServerConfig::from_env()?,
            database: DatabaseConfig::from_env()?,
            cors_allowed_origins: parse_origins(&origins),
            auth: AuthConfig::from_env()?,
        })
    }
}

fn parse_origins(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|o| o.trim().trim_end_matches('/').to_string())
        .filter(|o| !o.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_comma_separated_origins() {
        assert_eq!(
            parse_origins(" http://a.test , https://b.test/ ,,"),
            vec!["http://a.test", "https://b.test"]
        );
    }
}
