//! End-to-end auth lifecycle over HTTP with the real Postgres-backed services.
//!
//! `#[ignore]`d so a plain `cargo test` needs no database. Run with:
//!
//! ```text
//! DATABASE_URL=postgres://user:pass@localhost/postgres \
//!     cargo test -p app --test auth_flow -- --include-ignored
//! ```

use std::sync::Arc;

use actix_web::{
    cookie::Cookie,
    http::{StatusCode, header},
    test,
};
use app::{container::Container, create_app::create_app};
use auth::config::{AuthConfig, BootstrapAdmin};
use serde_json::{Value, json};
use sqlx::PgPool;

const EMAIL: &str = "admin@example.com";
const PASSWORD: &str = "correct-horse-battery";

fn config(password: &str) -> AuthConfig {
    AuthConfig {
        jwt_secret: "integration-test-secret-integration-test".into(),
        access_token_ttl_minutes: 15,
        refresh_token_ttl_days: 30,
        refresh_cookie_name: "refresh_token".into(),
        refresh_cookie_secure: true,
        refresh_cookie_path: "/auth".into(),
        bootstrap_admin: Some(BootstrapAdmin {
            email: EMAIL.into(),
            name: "Admin".into(),
            password: password.into(),
        }),
    }
}

macro_rules! app {
    ($pool:expr) => {{
        let container = Arc::new(
            Container::from_pool($pool.clone(), config(PASSWORD))
                .await
                .unwrap(),
        );
        test::init_service(create_app(container, Arc::from(Vec::new()))).await
    }};
}

/// Logs in; returns (access token, refresh cookie).
macro_rules! login {
    ($app:expr) => {{
        let req = test::TestRequest::post()
            .uri("/auth/login")
            .set_json(json!({ "email": EMAIL, "password": PASSWORD }))
            .to_request();
        let resp = test::call_service(&$app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let cookie = resp
            .response()
            .cookies()
            .find(|c| c.name() == "refresh_token")
            .unwrap()
            .into_owned();
        let body: Value = test::read_body_json(resp).await;
        (body["accessToken"].as_str().unwrap().to_string(), cookie)
    }};
}

macro_rules! refresh {
    ($app:expr, $cookie:expr) => {{
        let req = test::TestRequest::post()
            .uri("/auth/refresh")
            .cookie($cookie.clone())
            .to_request();
        test::call_service(&$app, req).await
    }};
}

#[sqlx::test(migrations = "../../migrations")]
#[ignore = "needs a Postgres server (DATABASE_URL)"]
async fn login_me_refresh_replay_and_logout(pool: PgPool) {
    let app = app!(pool);

    // The bootstrap admin can sign in; wrong credentials cannot.
    let bad = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/auth/login")
            .set_json(json!({ "email": EMAIL, "password": "wrong" }))
            .to_request(),
    )
    .await;
    assert_eq!(bad.status(), StatusCode::BAD_REQUEST);

    let (access, cookie) = login!(app);

    // The access token opens /auth/me.
    let me = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/auth/me")
            .insert_header((header::AUTHORIZATION, format!("Bearer {access}")))
            .to_request(),
    )
    .await;
    assert_eq!(me.status(), StatusCode::OK);
    let me: Value = test::read_body_json(me).await;
    assert_eq!(me["email"], EMAIL);
    assert_eq!(me["role"], "admin");

    // Refresh rotates the cookie.
    let resp = refresh!(app, cookie);
    assert_eq!(resp.status(), StatusCode::OK);
    let rotated: Cookie<'static> = resp
        .response()
        .cookies()
        .find(|c| c.name() == "refresh_token")
        .unwrap()
        .into_owned();
    assert_ne!(rotated.value(), cookie.value());
    let body: Value = test::read_body_json(resp).await;
    assert!(body["accessToken"].is_string());

    // Replaying the first cookie fails and burns the whole session...
    assert_eq!(refresh!(app, cookie).status(), StatusCode::UNAUTHORIZED);
    assert_eq!(refresh!(app, rotated).status(), StatusCode::UNAUTHORIZED);

    // ...but a fresh login is unaffected, and logout ends just that session.
    let (access, cookie) = login!(app);
    let out = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/auth/logout")
            .insert_header((header::AUTHORIZATION, format!("Bearer {access}")))
            .cookie(cookie.clone())
            .to_request(),
    )
    .await;
    assert_eq!(out.status(), StatusCode::OK);
    assert_eq!(refresh!(app, cookie).status(), StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrations = "../../migrations")]
#[ignore = "needs a Postgres server (DATABASE_URL)"]
async fn the_access_token_is_a_real_jwt_with_the_expected_claims(pool: PgPool) {
    let app = app!(pool);
    let (access, _) = login!(app);

    let parts: Vec<&str> = access.split('.').collect();
    assert_eq!(parts.len(), 3);
    let payload = String::from_utf8(base64_url_decode(parts[1])).unwrap();
    let claims: Value = serde_json::from_str(&payload).unwrap();
    assert_eq!(claims["role"], "admin");
    assert!(claims["exp"].as_i64().unwrap() > claims["iat"].as_i64().unwrap());
}

#[sqlx::test(migrations = "../../migrations")]
#[ignore = "needs a Postgres server (DATABASE_URL)"]
async fn restarting_with_bootstrap_config_never_overwrites_the_admin(
    pool: PgPool,
) {
    // First boot creates the admin; a second boot with a *different* password
    // in the environment must leave the existing account alone.
    Container::from_pool(pool.clone(), config(PASSWORD))
        .await
        .unwrap();
    let second = Arc::new(
        Container::from_pool(pool.clone(), config("some-other-password"))
            .await
            .unwrap(),
    );
    let app =
        test::init_service(create_app(second, Arc::from(Vec::new()))).await;

    let (_access, _cookie) = login!(app); // still the original password

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
}

/// Tiny base64url decoder so the test needs no extra dependency.
fn base64_url_decode(input: &str) -> Vec<u8> {
    let alphabet =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let (mut out, mut buf, mut bits) = (Vec::new(), 0u32, 0);
    for c in input.bytes() {
        buf =
            (buf << 6) | alphabet.iter().position(|&a| a == c).unwrap() as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    out
}
