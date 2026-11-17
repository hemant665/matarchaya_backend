use std::{fmt, sync::Arc};

use async_trait::async_trait;
use base::jwt_claims::JwtClaims;
use chrono::{Duration, Utc};
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::application::ports::{
    password_hasher::PasswordHasher, token_provider::AccessTokenProvider,
};
use crate::domain::errors::auth_error::AuthError;
use crate::domain::models::refresh_token::NewRefreshToken;
use crate::domain::models::role::ROLE_ADMIN;
use crate::domain::models::user::{NewUser, User};
use crate::domain::repositories::{
    refresh_token::RefreshTokenRepository, role::RoleRepository,
    user::UserRepository,
};

const MIN_PASSWORD_LEN: usize = 8;
/// Upper bound so an oversized password can't be used to burn CPU in Argon2.
const MAX_PASSWORD_LEN: usize = 256;
const MAX_EMAIL_LEN: usize = 255;
const MAX_NAME_LEN: usize = 150;

/// The user as exposed to clients.
#[derive(Debug, Clone)]
pub struct SessionUser {
    pub id: Uuid,
    pub email: String,
    pub name: String,
    pub role: String,
}

impl From<&User> for SessionUser {
    fn from(user: &User) -> Self {
        Self {
            id: user.id,
            email: user.email.clone(),
            name: user.name.clone(),
            role: user.role_name.clone(),
        }
    }
}

/// Result of a successful login or refresh.
pub struct Session {
    pub access_token: String,
    /// The raw opaque token. Only its hash is stored server-side.
    pub refresh_token: String,
    pub user: SessionUser,
}

// Tokens must not leak into logs through `{:?}`.
impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("access_token", &"<redacted>")
            .field("refresh_token", &"<redacted>")
            .field("user", &self.user)
            .finish()
    }
}

#[async_trait]
pub trait AuthService: Send + Sync + 'static {
    /// Verifies credentials and starts a new session (a new token family).
    async fn login(
        &self,
        email: &str,
        password: &str,
    ) -> Result<Session, AuthError>;

    /// Exchanges a refresh token for a new access token and a *new* refresh
    /// token. The presented token stops working; replaying it revokes the
    /// whole session.
    async fn refresh(&self, refresh_token: &str) -> Result<Session, AuthError>;

    /// Ends the session `refresh_token` belongs to. Idempotent: an unknown
    /// token, or one owned by someone else, is a no-op.
    async fn logout(
        &self,
        user_id: Uuid,
        refresh_token: &str,
    ) -> Result<(), AuthError>;

    async fn current_user(
        &self,
        user_id: Uuid,
    ) -> Result<SessionUser, AuthError>;

    /// Verifies an access token and that its role holds `permission`.
    async fn authorize(
        &self,
        access_token: &str,
        permission: &str,
    ) -> Result<JwtClaims, AuthError>;

    /// Creates the admin account if no user has this email yet. Returns
    /// whether it was created. Never touches an existing account.
    async fn ensure_admin(
        &self,
        email: &str,
        name: &str,
        password: &str,
    ) -> Result<bool, AuthError>;
}

pub struct AuthServiceImpl {
    users: Arc<dyn UserRepository>,
    roles: Arc<dyn RoleRepository>,
    refresh_tokens: Arc<dyn RefreshTokenRepository>,
    hasher: Arc<dyn PasswordHasher>,
    access_tokens: Arc<dyn AccessTokenProvider>,
    refresh_ttl: Duration,
    /// Hash of a throwaway password. Verified against when the email is
    /// unknown so the response time doesn't reveal which emails are registered.
    timing_hash: String,
}

impl AuthServiceImpl {
    pub async fn new(
        users: Arc<dyn UserRepository>,
        roles: Arc<dyn RoleRepository>,
        refresh_tokens: Arc<dyn RefreshTokenRepository>,
        hasher: Arc<dyn PasswordHasher>,
        access_tokens: Arc<dyn AccessTokenProvider>,
        refresh_ttl: Duration,
    ) -> Result<Self, AuthError> {
        let timing_hash = hasher.hash(&generate_token()).await?;
        Ok(Self {
            users,
            roles,
            refresh_tokens,
            hasher,
            access_tokens,
            refresh_ttl,
            timing_hash,
        })
    }

    /// Issues an access token and stores a fresh refresh token in `family_id`.
    async fn start_session(
        &self,
        user: &User,
        family_id: Uuid,
    ) -> Result<Session, AuthError> {
        let access_token =
            self.access_tokens.issue(user.id, &user.role_name)?;
        let refresh_token = generate_token();
        let now = Utc::now();
        self.refresh_tokens
            .create(&NewRefreshToken {
                user_id: user.id,
                token_hash: hash_token(&refresh_token),
                family_id,
                issued_at: now,
                expires_at: now + self.refresh_ttl,
            })
            .await?;
        Ok(Session {
            access_token,
            refresh_token,
            user: user.into(),
        })
    }
}

#[async_trait]
impl AuthService for AuthServiceImpl {
    async fn login(
        &self,
        email: &str,
        password: &str,
    ) -> Result<Session, AuthError> {
        let email = normalize_email(email);
        if email.is_empty() || password.is_empty() {
            return Err(AuthError::Validation(
                "Email and password are required".into(),
            ));
        }
        if password.len() > MAX_PASSWORD_LEN {
            return Err(AuthError::InvalidCredentials);
        }

        let Some(user) = self.users.find_by_email(&email).await? else {
            self.hasher.verify(password, &self.timing_hash).await;
            return Err(AuthError::InvalidCredentials);
        };

        if !self.hasher.verify(password, &user.password_hash).await {
            return Err(AuthError::InvalidCredentials);
        }
        // Checked after the password so a disabled account is only revealed
        // to someone who actually knows its password.
        if !user.is_active {
            return Err(AuthError::AccountDisabled);
        }

        let session = self.start_session(&user, Uuid::new_v4()).await?;

        if let Err(err) = self.users.touch_last_login(user.id, Utc::now()).await
        {
            // Bookkeeping only; never fail a valid login over it.
            log::warn!("could not record last login for {}: {err}", user.id);
        }
        Ok(session)
    }

    async fn refresh(&self, refresh_token: &str) -> Result<Session, AuthError> {
        let stored = self
            .refresh_tokens
            .find_by_hash(&hash_token(refresh_token))
            .await?
            .ok_or(AuthError::InvalidRefreshToken)?;

        if stored.is_revoked {
            // An already-used token is being presented again: either a bug or
            // theft. Kill the whole session so the thief's copy dies too.
            log::warn!(
                "revoked refresh token reused; revoking family {}",
                stored.family_id
            );
            self.refresh_tokens.revoke_family(stored.family_id).await?;
            return Err(AuthError::InvalidRefreshToken);
        }
        if stored.is_expired(Utc::now()) {
            return Err(AuthError::InvalidRefreshToken);
        }

        let Some(user) = self.users.find_by_id(stored.user_id).await? else {
            self.refresh_tokens.revoke_family(stored.family_id).await?;
            return Err(AuthError::InvalidRefreshToken);
        };
        if !user.is_active {
            self.refresh_tokens.revoke_family(stored.family_id).await?;
            return Err(AuthError::AccountDisabled);
        }

        let access_token =
            self.access_tokens.issue(user.id, &user.role_name)?;
        let next_token = generate_token();
        let now = Utc::now();
        let next = NewRefreshToken {
            user_id: user.id,
            token_hash: hash_token(&next_token),
            // Same family: reuse detection must be able to revoke the chain.
            family_id: stored.family_id,
            issued_at: now,
            expires_at: now + self.refresh_ttl,
        };

        match self.refresh_tokens.rotate(stored.id, &next).await? {
            Some(_) => Ok(Session {
                access_token,
                refresh_token: next_token,
                user: (&user).into(),
            }),
            None => {
                // Lost a race: the token was spent between our read and write.
                self.refresh_tokens.revoke_family(stored.family_id).await?;
                Err(AuthError::InvalidRefreshToken)
            }
        }
    }

    async fn logout(
        &self,
        user_id: Uuid,
        refresh_token: &str,
    ) -> Result<(), AuthError> {
        let stored = self
            .refresh_tokens
            .find_by_hash(&hash_token(refresh_token))
            .await?;
        if let Some(token) = stored
            && token.user_id == user_id
        {
            self.refresh_tokens.revoke_family(token.family_id).await?;
        }
        Ok(())
    }

    async fn current_user(
        &self,
        user_id: Uuid,
    ) -> Result<SessionUser, AuthError> {
        let user = self
            .users
            .find_by_id(user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;
        if !user.is_active {
            return Err(AuthError::AccountDisabled);
        }
        Ok((&user).into())
    }

    async fn authorize(
        &self,
        access_token: &str,
        permission: &str,
    ) -> Result<JwtClaims, AuthError> {
        let claims = self.access_tokens.verify(access_token)?;
        if !self
            .roles
            .role_has_permission(&claims.role, permission)
            .await?
        {
            return Err(AuthError::Forbidden);
        }
        Ok(claims)
    }

    async fn ensure_admin(
        &self,
        email: &str,
        name: &str,
        password: &str,
    ) -> Result<bool, AuthError> {
        let email = normalize_email(email);
        let name = name.trim();
        if !is_plausible_email(&email) {
            return Err(AuthError::Validation(
                "Admin email is not a valid email address".into(),
            ));
        }
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(AuthError::Validation(
                "Admin name must be 1-150 characters".into(),
            ));
        }
        if password.len() < MIN_PASSWORD_LEN
            || password.len() > MAX_PASSWORD_LEN
        {
            return Err(AuthError::Validation(format!(
                "Admin password must be {MIN_PASSWORD_LEN}-{MAX_PASSWORD_LEN} \
                 characters"
            )));
        }

        if self.users.find_by_email(&email).await?.is_some() {
            return Ok(false);
        }
        let role =
            self.roles.find_by_name(ROLE_ADMIN).await?.ok_or_else(|| {
                AuthError::Internal(format!(
                    "role {ROLE_ADMIN:?} is missing; were migrations applied?"
                ))
            })?;

        let new_user = NewUser {
            email,
            name: name.to_string(),
            password_hash: self.hasher.hash(password).await?,
            role_id: role.id,
        };
        match self.users.create(&new_user).await {
            Ok(_) => Ok(true),
            // Another instance created it between our check and the insert.
            Err(err) if err.is_unique_violation() => Ok(false),
            Err(err) => Err(err.into()),
        }
    }
}

fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

fn is_plausible_email(email: &str) -> bool {
    email.len() <= MAX_EMAIL_LEN
        && !email.contains(char::is_whitespace)
        && email.split_once('@').is_some_and(|(local, domain)| {
            !local.is_empty() && domain.contains('.')
        })
}

/// 256 random bits, hex encoded. Used for refresh tokens.
fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// SHA-256 is enough here (not Argon2): the input is 256 random bits, so there
/// is nothing to brute-force, and lookups must be fast and deterministic.
fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}
