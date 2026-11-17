use base::config::{
    ConfigError, env_optional, env_or, env_parse, env_required,
};
use std::fmt;

/// Weakest JWT secret we accept. HS256 wants at least a 256-bit key.
const MIN_JWT_SECRET_LEN: usize = 32;

/// First admin account, created on startup when it does not exist yet.
/// Without it there is no way to sign in to a fresh database.
#[derive(Clone)]
pub struct BootstrapAdmin {
    pub email: String,
    pub name: String,
    pub password: String,
}

#[derive(Clone)]
pub struct AuthConfig {
    pub jwt_secret: String,
    pub access_token_ttl_minutes: i64,
    pub refresh_token_ttl_days: i64,
    pub refresh_cookie_name: String,
    /// `true` (default): `Secure; SameSite=None`, which works cross-site over
    /// HTTPS. `false` is for plain-http local dev: `SameSite=Lax`.
    pub refresh_cookie_secure: bool,
    /// Browsers only send the cookie to this path, so keep it in step with
    /// where the `/auth` routes are mounted (it is `/auth` by default).
    pub refresh_cookie_path: String,
    pub bootstrap_admin: Option<BootstrapAdmin>,
}

// Both structs hold secrets; keep them out of logs even under `{:?}`.
impl fmt::Debug for BootstrapAdmin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BootstrapAdmin")
            .field("email", &self.email)
            .field("password", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for AuthConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthConfig")
            .field("jwt_secret", &"<redacted>")
            .field("access_token_ttl_minutes", &self.access_token_ttl_minutes)
            .field("refresh_token_ttl_days", &self.refresh_token_ttl_days)
            .field("refresh_cookie_name", &self.refresh_cookie_name)
            .field("refresh_cookie_secure", &self.refresh_cookie_secure)
            .field("refresh_cookie_path", &self.refresh_cookie_path)
            .field("bootstrap_admin", &self.bootstrap_admin)
            .finish()
    }
}

impl AuthConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        let bootstrap_admin = match (
            env_optional("BOOTSTRAP_ADMIN_EMAIL"),
            env_optional("BOOTSTRAP_ADMIN_PASSWORD"),
        ) {
            (Some(email), Some(password)) => Some(BootstrapAdmin {
                email,
                password,
                name: env_or("BOOTSTRAP_ADMIN_NAME", "Admin"),
            }),
            (None, None) => None,
            _ => {
                return Err(ConfigError::new(
                    "BOOTSTRAP_ADMIN_EMAIL and BOOTSTRAP_ADMIN_PASSWORD \
                     must be set together",
                ));
            }
        };

        Self {
            jwt_secret: env_required("JWT_SECRET")?,
            access_token_ttl_minutes: env_parse("JWT_TOKEN_EXP_MINUTES", 15)?,
            refresh_token_ttl_days: env_parse("REFRESH_TOKEN_EXP_DAYS", 30)?,
            refresh_cookie_name: env_or(
                "REFRESH_TOKEN_COOKIE_NAME",
                "refresh_token",
            ),
            refresh_cookie_secure: env_parse("REFRESH_COOKIE_SECURE", true)?,
            refresh_cookie_path: env_or("REFRESH_COOKIE_PATH", "/auth"),
            bootstrap_admin,
        }
        .validate()
    }

    pub fn validate(self) -> Result<Self, ConfigError> {
        if self.jwt_secret.len() < MIN_JWT_SECRET_LEN {
            return Err(ConfigError::new(format!(
                "JWT_SECRET must be at least {MIN_JWT_SECRET_LEN} characters"
            )));
        }
        if self.access_token_ttl_minutes <= 0 {
            return Err(ConfigError::new(
                "JWT_TOKEN_EXP_MINUTES must be greater than 0",
            ));
        }
        if self.refresh_token_ttl_days <= 0 {
            return Err(ConfigError::new(
                "REFRESH_TOKEN_EXP_DAYS must be greater than 0",
            ));
        }
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid() -> AuthConfig {
        AuthConfig {
            jwt_secret: "x".repeat(MIN_JWT_SECRET_LEN),
            access_token_ttl_minutes: 15,
            refresh_token_ttl_days: 30,
            refresh_cookie_name: "refresh_token".into(),
            refresh_cookie_secure: true,
            refresh_cookie_path: "/auth".into(),
            bootstrap_admin: None,
        }
    }

    #[test]
    fn accepts_a_valid_config() {
        assert!(valid().validate().is_ok());
    }

    #[test]
    fn rejects_a_short_jwt_secret() {
        let mut config = valid();
        config.jwt_secret = "short".into();
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_non_positive_lifetimes() {
        let mut config = valid();
        config.access_token_ttl_minutes = 0;
        assert!(config.validate().is_err());

        let mut config = valid();
        config.refresh_token_ttl_days = -1;
        assert!(config.validate().is_err());
    }
}
