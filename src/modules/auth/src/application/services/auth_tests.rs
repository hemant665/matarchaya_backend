//! Use-case tests against in-memory fakes: no database, no HTTP.

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use async_trait::async_trait;
use base::{jwt_claims::JwtClaims, result_paging::RepositoryResult};
use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;

use super::auth::{AuthService, AuthServiceImpl};
use crate::application::ports::{
    password_hasher::PasswordHasher, token_provider::AccessTokenProvider,
};
use crate::domain::errors::auth_error::AuthError;
use crate::domain::models::{
    refresh_token::{NewRefreshToken, RefreshToken},
    role::Role,
    user::{NewUser, User},
};
use crate::domain::repositories::{
    refresh_token::RefreshTokenRepository, role::RoleRepository,
    user::UserRepository,
};

// --- fakes ------------------------------------------------------------------

#[derive(Default)]
struct FakeUsers(Mutex<Vec<User>>);

#[async_trait]
impl UserRepository for FakeUsers {
    async fn find_by_id(&self, id: Uuid) -> RepositoryResult<Option<User>> {
        Ok(self.0.lock().unwrap().iter().find(|u| u.id == id).cloned())
    }
    async fn find_by_email(
        &self,
        email: &str,
    ) -> RepositoryResult<Option<User>> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .iter()
            .find(|u| u.email == email)
            .cloned())
    }
    async fn create(&self, new_user: &NewUser) -> RepositoryResult<User> {
        let now = Utc::now();
        let user = User {
            id: Uuid::new_v4(),
            email: new_user.email.clone(),
            name: new_user.name.clone(),
            password_hash: new_user.password_hash.clone(),
            role_id: new_user.role_id,
            role_name: "admin".into(),
            is_active: true,
            last_login: None,
            created_at: now,
            updated_at: now,
        };
        self.0.lock().unwrap().push(user.clone());
        Ok(user)
    }
    async fn touch_last_login(
        &self,
        id: Uuid,
        at: DateTime<Utc>,
    ) -> RepositoryResult<()> {
        if let Some(u) = self.0.lock().unwrap().iter_mut().find(|u| u.id == id)
        {
            u.last_login = Some(at);
        }
        Ok(())
    }
}

struct FakeRoles;

#[async_trait]
impl RoleRepository for FakeRoles {
    async fn find_by_name(&self, name: &str) -> RepositoryResult<Option<Role>> {
        Ok(Some(Role {
            id: Uuid::new_v4(),
            name: name.into(),
            description: String::new(),
        }))
    }
    async fn role_has_permission(
        &self,
        role_name: &str,
        permission_name: &str,
    ) -> RepositoryResult<bool> {
        Ok(match role_name {
            "admin" => true,
            "user" => permission_name == "user",
            _ => false,
        })
    }
}

#[derive(Default)]
struct FakeRefreshTokens(Mutex<Vec<RefreshToken>>);

impl FakeRefreshTokens {
    fn all(&self) -> Vec<RefreshToken> {
        self.0.lock().unwrap().clone()
    }
}

fn to_token(new: &NewRefreshToken) -> RefreshToken {
    RefreshToken {
        id: Uuid::new_v4(),
        user_id: new.user_id,
        token_hash: new.token_hash.clone(),
        family_id: new.family_id,
        issued_at: new.issued_at,
        expires_at: new.expires_at,
        is_revoked: false,
    }
}

#[async_trait]
impl RefreshTokenRepository for FakeRefreshTokens {
    async fn create(
        &self,
        new: &NewRefreshToken,
    ) -> RepositoryResult<RefreshToken> {
        let token = to_token(new);
        self.0.lock().unwrap().push(token.clone());
        Ok(token)
    }
    async fn find_by_hash(
        &self,
        token_hash: &str,
    ) -> RepositoryResult<Option<RefreshToken>> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .iter()
            .find(|t| t.token_hash == token_hash)
            .cloned())
    }
    async fn rotate(
        &self,
        old_id: Uuid,
        next: &NewRefreshToken,
    ) -> RepositoryResult<Option<RefreshToken>> {
        let mut tokens = self.0.lock().unwrap();
        let old = tokens.iter_mut().find(|t| t.id == old_id).unwrap();
        if old.is_revoked {
            return Ok(None);
        }
        old.is_revoked = true;
        let token = to_token(next);
        tokens.push(token.clone());
        Ok(Some(token))
    }
    async fn revoke_family(&self, family_id: Uuid) -> RepositoryResult<()> {
        for t in self
            .0
            .lock()
            .unwrap()
            .iter_mut()
            .filter(|t| t.family_id == family_id)
        {
            t.is_revoked = true;
        }
        Ok(())
    }
}

/// "Hashes" by prefixing, and counts `verify` calls.
#[derive(Default)]
struct FakeHasher {
    verifies: AtomicUsize,
}

#[async_trait]
impl PasswordHasher for FakeHasher {
    async fn hash(&self, password: &str) -> Result<String, AuthError> {
        Ok(format!("hashed:{password}"))
    }
    async fn verify(&self, password: &str, hash: &str) -> bool {
        self.verifies.fetch_add(1, Ordering::SeqCst);
        hash == format!("hashed:{password}")
    }
}

struct FakeTokens;

impl AccessTokenProvider for FakeTokens {
    fn issue(&self, user_id: Uuid, role: &str) -> Result<String, AuthError> {
        Ok(format!("{user_id}|{role}"))
    }
    fn verify(&self, token: &str) -> Result<JwtClaims, AuthError> {
        let (sub, role) =
            token.split_once('|').ok_or(AuthError::InvalidToken)?;
        Ok(JwtClaims {
            sub: sub.parse().map_err(|_| AuthError::InvalidToken)?,
            role: role.into(),
            exp: 0,
            iat: 0,
        })
    }
}

// --- harness ----------------------------------------------------------------

struct Harness {
    service: AuthServiceImpl,
    users: Arc<FakeUsers>,
    tokens: Arc<FakeRefreshTokens>,
    hasher: Arc<FakeHasher>,
}

impl Harness {
    async fn new() -> Self {
        let users = Arc::new(FakeUsers::default());
        let tokens = Arc::new(FakeRefreshTokens::default());
        let hasher = Arc::new(FakeHasher::default());
        let service = AuthServiceImpl::new(
            users.clone(),
            Arc::new(FakeRoles),
            tokens.clone(),
            hasher.clone(),
            Arc::new(FakeTokens),
            Duration::days(30),
        )
        .await
        .unwrap();
        Self { service, users, tokens, hasher }
    }

    /// Creates the admin `a@b.co` / `password123`.
    async fn with_admin() -> Self {
        let h = Self::new().await;
        assert!(
            h.service
                .ensure_admin("a@b.co", "Ada", "password123")
                .await
                .unwrap()
        );
        h
    }

    fn set_active(&self, active: bool) {
        self.users.0.lock().unwrap()[0].is_active = active;
    }
}

// --- login ------------------------------------------------------------------

#[tokio::test]
async fn login_returns_tokens_and_user() {
    let h = Harness::with_admin().await;
    let session = h.service.login("a@b.co", "password123").await.unwrap();

    assert_eq!(session.user.email, "a@b.co");
    assert_eq!(session.user.role, "admin");
    assert!(session.access_token.contains("|admin"));
    assert_eq!(session.refresh_token.len(), 64);
    assert_eq!(h.tokens.all().len(), 1);
    assert!(h.users.0.lock().unwrap()[0].last_login.is_some());
}

#[tokio::test]
async fn login_normalizes_email() {
    let h = Harness::with_admin().await;
    assert!(h.service.login("  A@B.Co ", "password123").await.is_ok());
}

#[tokio::test]
async fn stores_only_the_hash_of_the_refresh_token() {
    let h = Harness::with_admin().await;
    let session = h.service.login("a@b.co", "password123").await.unwrap();
    assert_ne!(h.tokens.all()[0].token_hash, session.refresh_token);
}

#[tokio::test]
async fn wrong_password_is_rejected() {
    let h = Harness::with_admin().await;
    let err = h.service.login("a@b.co", "nope").await.unwrap_err();
    assert!(matches!(err, AuthError::InvalidCredentials));
    assert!(h.tokens.all().is_empty());
}

#[tokio::test]
async fn unknown_email_looks_like_a_wrong_password() {
    let h = Harness::with_admin().await;
    let before = h.hasher.verifies.load(Ordering::SeqCst);

    let err = h
        .service
        .login("who@b.co", "password123")
        .await
        .unwrap_err();

    assert!(matches!(err, AuthError::InvalidCredentials));
    // A hash was still verified, so timing doesn't reveal the email is unknown.
    assert_eq!(h.hasher.verifies.load(Ordering::SeqCst), before + 1);
}

#[tokio::test]
async fn blank_fields_are_a_validation_error() {
    let h = Harness::with_admin().await;
    assert!(matches!(
        h.service.login("  ", "x").await.unwrap_err(),
        AuthError::Validation(_)
    ));
    assert!(matches!(
        h.service.login("a@b.co", "").await.unwrap_err(),
        AuthError::Validation(_)
    ));
}

#[tokio::test]
async fn oversized_password_is_rejected_without_hashing() {
    let h = Harness::with_admin().await;
    let before = h.hasher.verifies.load(Ordering::SeqCst);
    let err = h
        .service
        .login("a@b.co", &"x".repeat(10_000))
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::InvalidCredentials));
    assert_eq!(h.hasher.verifies.load(Ordering::SeqCst), before);
}

#[tokio::test]
async fn disabled_account_cannot_log_in_but_is_hidden_from_guessers() {
    let h = Harness::with_admin().await;
    h.set_active(false);

    assert!(matches!(
        h.service.login("a@b.co", "password123").await.unwrap_err(),
        AuthError::AccountDisabled
    ));
    // Without the right password the account's state is not revealed.
    assert!(matches!(
        h.service.login("a@b.co", "wrong").await.unwrap_err(),
        AuthError::InvalidCredentials
    ));
}

// --- refresh ----------------------------------------------------------------

#[tokio::test]
async fn refresh_rotates_the_token_within_the_same_family() {
    let h = Harness::with_admin().await;
    let first = h.service.login("a@b.co", "password123").await.unwrap();

    let second = h.service.refresh(&first.refresh_token).await.unwrap();

    assert_ne!(first.refresh_token, second.refresh_token);
    let stored = h.tokens.all();
    assert_eq!(stored.len(), 2);
    assert_eq!(stored[0].family_id, stored[1].family_id);
    assert!(stored[0].is_revoked);
    assert!(!stored[1].is_revoked);
    // The new token keeps working.
    assert!(h.service.refresh(&second.refresh_token).await.is_ok());
}

#[tokio::test]
async fn replaying_a_used_refresh_token_revokes_the_whole_session() {
    let h = Harness::with_admin().await;
    let first = h.service.login("a@b.co", "password123").await.unwrap();
    let second = h.service.refresh(&first.refresh_token).await.unwrap();

    let err = h.service.refresh(&first.refresh_token).await.unwrap_err();
    assert!(matches!(err, AuthError::InvalidRefreshToken));

    // The legitimate holder's newer token is dead too.
    assert!(matches!(
        h.service.refresh(&second.refresh_token).await.unwrap_err(),
        AuthError::InvalidRefreshToken
    ));
    assert!(h.tokens.all().iter().all(|t| t.is_revoked));
}

#[tokio::test]
async fn unknown_refresh_token_is_rejected() {
    let h = Harness::with_admin().await;
    assert!(matches!(
        h.service.refresh("not-a-real-token").await.unwrap_err(),
        AuthError::InvalidRefreshToken
    ));
}

#[tokio::test]
async fn expired_refresh_token_is_rejected() {
    let h = Harness::with_admin().await;
    let session = h.service.login("a@b.co", "password123").await.unwrap();
    h.tokens.0.lock().unwrap()[0].expires_at =
        Utc::now() - Duration::seconds(1);

    assert!(matches!(
        h.service.refresh(&session.refresh_token).await.unwrap_err(),
        AuthError::InvalidRefreshToken
    ));
}

#[tokio::test]
async fn refresh_for_a_disabled_user_revokes_the_session() {
    let h = Harness::with_admin().await;
    let session = h.service.login("a@b.co", "password123").await.unwrap();
    h.set_active(false);

    assert!(matches!(
        h.service.refresh(&session.refresh_token).await.unwrap_err(),
        AuthError::AccountDisabled
    ));
    assert!(h.tokens.all().iter().all(|t| t.is_revoked));
}

// --- logout -----------------------------------------------------------------

#[tokio::test]
async fn logout_revokes_only_that_session() {
    let h = Harness::with_admin().await;
    let laptop = h.service.login("a@b.co", "password123").await.unwrap();
    let phone = h.service.login("a@b.co", "password123").await.unwrap();

    h.service
        .logout(laptop.user.id, &laptop.refresh_token)
        .await
        .unwrap();

    assert!(h.service.refresh(&laptop.refresh_token).await.is_err());
    assert!(h.service.refresh(&phone.refresh_token).await.is_ok());
}

#[tokio::test]
async fn logout_is_a_no_op_for_unknown_or_foreign_tokens() {
    let h = Harness::with_admin().await;
    let session = h.service.login("a@b.co", "password123").await.unwrap();

    h.service.logout(session.user.id, "unknown").await.unwrap();
    h.service
        .logout(Uuid::new_v4(), &session.refresh_token)
        .await
        .unwrap();

    // Someone else's id must not be able to end this session.
    assert!(h.service.refresh(&session.refresh_token).await.is_ok());
}

// --- authorize / current_user -----------------------------------------------

#[tokio::test]
async fn authorize_checks_the_role_permission() {
    let h = Harness::new().await;
    let id = Uuid::new_v4();

    assert!(
        h.service
            .authorize(&format!("{id}|admin"), "admin")
            .await
            .is_ok()
    );
    assert!(
        h.service
            .authorize(&format!("{id}|user"), "user")
            .await
            .is_ok()
    );
    assert!(matches!(
        h.service
            .authorize(&format!("{id}|user"), "admin")
            .await
            .unwrap_err(),
        AuthError::Forbidden
    ));
    assert!(matches!(
        h.service.authorize("garbage", "user").await.unwrap_err(),
        AuthError::InvalidToken
    ));
}

#[tokio::test]
async fn current_user_requires_an_active_account() {
    let h = Harness::with_admin().await;
    let id = h.users.0.lock().unwrap()[0].id;

    assert_eq!(h.service.current_user(id).await.unwrap().email, "a@b.co");
    assert!(matches!(
        h.service.current_user(Uuid::new_v4()).await.unwrap_err(),
        AuthError::UserNotFound
    ));
    h.set_active(false);
    assert!(matches!(
        h.service.current_user(id).await.unwrap_err(),
        AuthError::AccountDisabled
    ));
}

// --- ensure_admin -----------------------------------------------------------

#[tokio::test]
async fn ensure_admin_is_idempotent_and_never_overwrites() {
    let h = Harness::with_admin().await;

    let created = h
        .service
        .ensure_admin("A@B.co", "Someone Else", "different-password")
        .await
        .unwrap();

    assert!(!created);
    let users = h.users.0.lock().unwrap();
    assert_eq!(users.len(), 1);
    assert_eq!(users[0].name, "Ada");
    assert_eq!(users[0].password_hash, "hashed:password123");
}

#[tokio::test]
async fn ensure_admin_validates_its_input() {
    let h = Harness::new().await;
    for (email, name, password) in [
        ("not-an-email", "Ada", "password123"),
        ("a@b.co", "  ", "password123"),
        ("a@b.co", "Ada", "short"),
    ] {
        assert!(matches!(
            h.service
                .ensure_admin(email, name, password)
                .await
                .unwrap_err(),
            AuthError::Validation(_)
        ));
    }
    assert!(h.users.0.lock().unwrap().is_empty());
}
