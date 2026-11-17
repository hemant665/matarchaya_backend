//! SQL and migration behaviour against a real Postgres.
//!
//! These are `#[ignore]`d so a plain `cargo test` needs no database. Run with:
//!
//! ```text
//! DATABASE_URL=postgres://user:pass@localhost/postgres \
//!     cargo test -p auth -- --include-ignored
//! ```
//!
//! `#[sqlx::test]` creates a throwaway database per test and drops it after,
//! so it never touches existing data.

use auth::{
    domain::{
        models::{refresh_token::NewRefreshToken, user::NewUser},
        repositories::{
            refresh_token::RefreshTokenRepository, role::RoleRepository,
            user::UserRepository,
        },
    },
    infrastructure::repositories::{
        PgRefreshTokenRepository, PgRoleRepository, PgUserRepository,
    },
};
use chrono::{Duration, Utc};
use sqlx::PgPool;
use uuid::Uuid;

async fn new_user(pool: &PgPool, email: &str) -> NewUser {
    let role = PgRoleRepository::new(pool.clone())
        .find_by_name("user")
        .await
        .unwrap()
        .expect("migrations seed the `user` role");
    NewUser {
        email: email.into(),
        name: "Test".into(),
        password_hash: "$argon2id$stub".into(),
        role_id: role.id,
    }
}

fn token(user_id: Uuid, family_id: Uuid, hash: &str) -> NewRefreshToken {
    let now = Utc::now();
    NewRefreshToken {
        user_id,
        token_hash: hash.into(),
        family_id,
        issued_at: now,
        expires_at: now + Duration::days(30),
    }
}

#[sqlx::test(migrations = "../../../migrations")]
#[ignore = "needs a Postgres server (DATABASE_URL)"]
async fn migrations_seed_roles_and_permissions(pool: PgPool) {
    let roles = PgRoleRepository::new(pool);

    assert!(roles.role_has_permission("admin", "admin").await.unwrap());
    assert!(roles.role_has_permission("admin", "user").await.unwrap());
    assert!(roles.role_has_permission("user", "user").await.unwrap());
    assert!(!roles.role_has_permission("user", "admin").await.unwrap());
    assert!(!roles.role_has_permission("ghost", "user").await.unwrap());
    assert!(!roles.role_has_permission("admin", "ghost").await.unwrap());
    assert!(roles.find_by_name("admin").await.unwrap().is_some());
    assert!(roles.find_by_name("ghost").await.unwrap().is_none());
}

#[sqlx::test(migrations = "../../../migrations")]
#[ignore = "needs a Postgres server (DATABASE_URL)"]
async fn users_round_trip_with_their_role(pool: PgPool) {
    let users = PgUserRepository::new(pool.clone());
    let created = users
        .create(&new_user(&pool, "ada@example.com").await)
        .await
        .unwrap();

    assert_eq!(created.role_name, "user");
    assert!(created.is_active);
    assert!(created.last_login.is_none());

    let by_email = users
        .find_by_email("ada@example.com")
        .await
        .unwrap()
        .unwrap();
    let by_id = users.find_by_id(created.id).await.unwrap().unwrap();
    assert_eq!(by_email.id, created.id);
    assert_eq!(by_id.email, "ada@example.com");
    assert!(
        users
            .find_by_email("nobody@example.com")
            .await
            .unwrap()
            .is_none()
    );

    let at = Utc::now();
    users.touch_last_login(created.id, at).await.unwrap();
    let after = users.find_by_id(created.id).await.unwrap().unwrap();
    assert!(after.last_login.is_some());
}

#[sqlx::test(migrations = "../../../migrations")]
#[ignore = "needs a Postgres server (DATABASE_URL)"]
async fn duplicate_and_uppercase_emails_are_rejected_by_the_database(
    pool: PgPool,
) {
    let users = PgUserRepository::new(pool.clone());
    users
        .create(&new_user(&pool, "ada@example.com").await)
        .await
        .unwrap();

    let dup = users
        .create(&new_user(&pool, "ada@example.com").await)
        .await
        .unwrap_err();
    assert!(dup.is_unique_violation());

    // The app lowercases; the CHECK constraint is the backstop.
    let upper = users
        .create(&new_user(&pool, "Grace@Example.com").await)
        .await
        .unwrap_err();
    assert_eq!(upper.code, 400);
}

#[sqlx::test(migrations = "../../../migrations")]
#[ignore = "needs a Postgres server (DATABASE_URL)"]
async fn soft_deleted_users_are_invisible_and_free_their_email(pool: PgPool) {
    let users = PgUserRepository::new(pool.clone());
    let first = users
        .create(&new_user(&pool, "ada@example.com").await)
        .await
        .unwrap();

    sqlx::query("UPDATE users SET deleted_at = NOW() WHERE id = $1")
        .bind(first.id)
        .execute(&pool)
        .await
        .unwrap();

    assert!(users.find_by_id(first.id).await.unwrap().is_none());
    assert!(
        users
            .find_by_email("ada@example.com")
            .await
            .unwrap()
            .is_none()
    );

    // The email can be registered again.
    let second = users
        .create(&new_user(&pool, "ada@example.com").await)
        .await
        .unwrap();
    assert_ne!(second.id, first.id);
}

#[sqlx::test(migrations = "../../../migrations")]
#[ignore = "needs a Postgres server (DATABASE_URL)"]
async fn refresh_token_rotation_and_family_revocation(pool: PgPool) {
    let users = PgUserRepository::new(pool.clone());
    let tokens = PgRefreshTokenRepository::new(pool.clone());
    let user = users
        .create(&new_user(&pool, "ada@example.com").await)
        .await
        .unwrap();
    let family = Uuid::new_v4();

    let first = tokens
        .create(&token(user.id, family, "hash-1"))
        .await
        .unwrap();
    assert!(!first.is_revoked);
    assert_eq!(
        tokens.find_by_hash("hash-1").await.unwrap().unwrap().id,
        first.id
    );
    assert!(tokens.find_by_hash("missing").await.unwrap().is_none());

    // Rotating revokes the old token and stores the next one...
    let second = tokens
        .rotate(first.id, &token(user.id, family, "hash-2"))
        .await
        .unwrap()
        .expect("first rotation succeeds");
    assert_eq!(second.family_id, family);
    assert!(
        tokens
            .find_by_hash("hash-1")
            .await
            .unwrap()
            .unwrap()
            .is_revoked
    );

    // ...and spending the same token again stores nothing.
    let again = tokens
        .rotate(first.id, &token(user.id, family, "hash-3"))
        .await
        .unwrap();
    assert!(again.is_none());
    assert!(tokens.find_by_hash("hash-3").await.unwrap().is_none());

    tokens.revoke_family(family).await.unwrap();
    assert!(
        tokens
            .find_by_hash("hash-2")
            .await
            .unwrap()
            .unwrap()
            .is_revoked
    );
}

#[sqlx::test(migrations = "../../../migrations")]
#[ignore = "needs a Postgres server (DATABASE_URL)"]
async fn concurrent_rotations_of_one_token_let_exactly_one_win(pool: PgPool) {
    let users = PgUserRepository::new(pool.clone());
    let tokens =
        std::sync::Arc::new(PgRefreshTokenRepository::new(pool.clone()));
    let user = users
        .create(&new_user(&pool, "ada@example.com").await)
        .await
        .unwrap();
    let family = Uuid::new_v4();
    let first = tokens
        .create(&token(user.id, family, "start"))
        .await
        .unwrap();

    let attempts: Vec<_> = (0..8)
        .map(|i| {
            let tokens = tokens.clone();
            let next = token(user.id, family, &format!("next-{i}"));
            tokio::spawn(async move { tokens.rotate(first.id, &next).await })
        })
        .collect();

    let mut winners = 0;
    for attempt in attempts {
        if attempt.await.unwrap().unwrap().is_some() {
            winners += 1;
        }
    }
    assert_eq!(winners, 1);
}

#[sqlx::test(migrations = "../../../migrations")]
#[ignore = "needs a Postgres server (DATABASE_URL)"]
async fn deleting_a_user_removes_their_refresh_tokens(pool: PgPool) {
    let users = PgUserRepository::new(pool.clone());
    let tokens = PgRefreshTokenRepository::new(pool.clone());
    let user = users
        .create(&new_user(&pool, "ada@example.com").await)
        .await
        .unwrap();
    tokens
        .create(&token(user.id, Uuid::new_v4(), "hash"))
        .await
        .unwrap();

    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user.id)
        .execute(&pool)
        .await
        .unwrap();

    assert!(tokens.find_by_hash("hash").await.unwrap().is_none());
}
