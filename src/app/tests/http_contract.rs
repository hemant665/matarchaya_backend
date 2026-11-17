//! HTTP contract tests: status codes, JSON shapes, cookies, CORS. They run
//! against a stub `AuthService` and a pool that never connects, so they need
//! no database.

use std::sync::Arc;

use actix_web::{
    http::{StatusCode, header},
    test,
};
use app::{container::Container, create_app::create_app};
use async_trait::async_trait;
use auth::{
    application::services::auth::{AuthService, Session, SessionUser},
    config::AuthConfig,
    domain::errors::auth_error::AuthError,
};
use base::jwt_claims::JwtClaims;
use serde_json::{Value, json};
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

const FRONTEND: &str = "http://localhost:5173";

struct StubAuth;

fn user() -> SessionUser {
    SessionUser {
        id: Uuid::nil(),
        email: "admin@example.com".into(),
        name: "Admin".into(),
        role: "admin".into(),
    }
}

#[async_trait]
impl AuthService for StubAuth {
    async fn login(
        &self,
        _: &str,
        password: &str,
    ) -> Result<Session, AuthError> {
        if password == "good" {
            Ok(Session {
                access_token: "access-1".into(),
                refresh_token: "refresh-1".into(),
                user: user(),
            })
        } else {
            Err(AuthError::InvalidCredentials)
        }
    }
    async fn refresh(&self, token: &str) -> Result<Session, AuthError> {
        if token == "refresh-1" {
            Ok(Session {
                access_token: "access-2".into(),
                refresh_token: "refresh-2".into(),
                user: user(),
            })
        } else {
            Err(AuthError::InvalidRefreshToken)
        }
    }
    async fn logout(&self, _: Uuid, _: &str) -> Result<(), AuthError> {
        Ok(())
    }
    async fn current_user(&self, _: Uuid) -> Result<SessionUser, AuthError> {
        Ok(user())
    }
    async fn authorize(
        &self,
        token: &str,
        _: &str,
    ) -> Result<JwtClaims, AuthError> {
        match token {
            "valid" => Ok(JwtClaims {
                sub: Uuid::nil(),
                role: "admin".into(),
                exp: 0,
                iat: 0,
            }),
            "expired" => Err(AuthError::TokenExpired),
            _ => Err(AuthError::InvalidToken),
        }
    }
    async fn ensure_admin(
        &self,
        _: &str,
        _: &str,
        _: &str,
    ) -> Result<bool, AuthError> {
        Ok(false)
    }
}

fn auth_config() -> AuthConfig {
    AuthConfig {
        jwt_secret: "x".repeat(32),
        access_token_ttl_minutes: 15,
        refresh_token_ttl_days: 30,
        refresh_cookie_name: "refresh_token".into(),
        refresh_cookie_secure: true,
        refresh_cookie_path: "/auth".into(),
        bootstrap_admin: None,
    }
}

macro_rules! app {
    () => {{
        let container = Arc::new(Container {
            // Never connects: nothing here touches the database.
            sqlx_pool: PgPoolOptions::new()
                .connect_lazy("postgres://stub:stub@127.0.0.1:1/stub")
                .unwrap(),
            auth_config: auth_config(),
            auth_service: Arc::new(StubAuth),
        });
        test::init_service(create_app(
            container,
            Arc::from(vec![FRONTEND.to_string()]),
        ))
        .await
    }};
}

async fn json_body(
    resp: actix_web::dev::ServiceResponse<impl actix_web::body::MessageBody>,
) -> Value {
    test::read_body_json(resp).await
}

#[actix_web::test]
async fn health_is_ok() {
    let app = app!();
    let resp = test::call_service(
        &app,
        test::TestRequest::get().uri("/health").to_request(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn login_returns_the_shape_the_frontend_reads() {
    let app = app!();
    let req = test::TestRequest::post()
        .uri("/auth/login")
        .set_json(json!({ "email": "admin@example.com", "password": "good" }))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );

    let cookie = resp
        .response()
        .cookies()
        .find(|c| c.name() == "refresh_token")
        .expect("refresh cookie is set")
        .into_owned();
    assert_eq!(cookie.value(), "refresh-1");
    assert_eq!(cookie.http_only(), Some(true));
    assert_eq!(cookie.secure(), Some(true));
    assert_eq!(cookie.path(), Some("/auth"));

    let body = json_body(resp).await;
    assert_eq!(body["accessToken"], "access-1");
    assert_eq!(body["user"]["email"], "admin@example.com");
    assert_eq!(body["user"]["name"], "Admin");
    assert_eq!(body["user"]["role"], "admin");
    // The refresh token must never appear where page scripts can read it.
    assert!(!body.to_string().contains("refresh-1"));
}

#[actix_web::test]
async fn bad_credentials_are_a_400_with_a_message() {
    let app = app!();
    let req = test::TestRequest::post()
        .uri("/auth/login")
        .set_json(json!({ "email": "admin@example.com", "password": "bad" }))
        .to_request();
    let resp = test::call_service(&app, req).await;

    // Not 401: see `api::errors` for why.
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = json_body(resp).await;
    assert_eq!(body["message"], "Invalid email or password");
    assert_eq!(body["statusCode"], 400);
}

#[actix_web::test]
async fn malformed_login_body_gets_a_json_error() {
    let app = app!();
    let req = test::TestRequest::post()
        .uri("/auth/login")
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .set_payload("{not json")
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = json_body(resp).await;
    assert_eq!(body["message"], "Invalid request body");
}

#[actix_web::test]
async fn missing_field_gets_a_json_error() {
    let app = app!();
    let req = test::TestRequest::post()
        .uri("/auth/login")
        .set_json(json!({ "email": "admin@example.com" }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(resp).await["statusCode"], 400);
}

#[actix_web::test]
async fn oversized_login_body_is_refused() {
    let app = app!();
    let req = test::TestRequest::post()
        .uri("/auth/login")
        .set_json(json!({ "email": "a@b.co", "password": "x".repeat(10_000) }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[actix_web::test]
async fn refresh_rotates_the_cookie() {
    let app = app!();
    let req = test::TestRequest::post()
        .uri("/auth/refresh")
        .cookie(actix_web::cookie::Cookie::new("refresh_token", "refresh-1"))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), StatusCode::OK);
    let cookie = resp
        .response()
        .cookies()
        .find(|c| c.name() == "refresh_token")
        .unwrap()
        .into_owned();
    assert_eq!(cookie.value(), "refresh-2");
    assert_eq!(json_body(resp).await["accessToken"], "access-2");
}

#[actix_web::test]
async fn refresh_without_a_cookie_is_401() {
    let app = app!();
    let resp = test::call_service(
        &app,
        test::TestRequest::post().uri("/auth/refresh").to_request(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json_body(resp).await["message"], "Missing refresh token");
}

#[actix_web::test]
async fn refresh_with_a_bad_cookie_is_401() {
    let app = app!();
    let req = test::TestRequest::post()
        .uri("/auth/refresh")
        .cookie(actix_web::cookie::Cookie::new("refresh_token", "nope"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[actix_web::test]
async fn protected_routes_demand_a_valid_bearer_token() {
    let app = app!();

    for (uri, method_post) in [("/auth/me", false), ("/auth/logout", true)] {
        let build = |token: Option<&str>| {
            let mut req = if method_post {
                test::TestRequest::post()
            } else {
                test::TestRequest::get()
            }
            .uri(uri);
            if let Some(token) = token {
                req = req
                    .insert_header((header::AUTHORIZATION, token.to_string()));
            }
            req.to_request()
        };

        for header_value in [
            None,
            Some("Bearer garbage"),
            Some("Bearer expired"),
            Some("Basic valid"),
            Some("valid"),
            Some("Bearer "),
        ] {
            let resp = test::call_service(&app, build(header_value)).await;
            assert_eq!(
                resp.status(),
                StatusCode::UNAUTHORIZED,
                "{uri} with {header_value:?}"
            );
            let body = json_body(resp).await;
            assert_eq!(body["statusCode"], 401);
            assert!(body["message"].is_string());
        }
    }
}

#[actix_web::test]
async fn auth_rejections_still_carry_cors_headers() {
    // A 401 without CORS headers is invisible to the browser (it reports a
    // network error), which would break the frontend's refresh-on-401 flow.
    let app = app!();
    let req = test::TestRequest::get()
        .uri("/auth/me")
        .insert_header((header::ORIGIN, FRONTEND))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        resp.headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .unwrap(),
        FRONTEND
    );
    assert_eq!(
        resp.headers()
            .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
            .unwrap(),
        "true"
    );
}

#[actix_web::test]
async fn me_returns_the_current_user() {
    let app = app!();
    let req = test::TestRequest::get()
        .uri("/auth/me")
        .insert_header((header::AUTHORIZATION, "Bearer valid"))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["email"], "admin@example.com");
    assert_eq!(body["role"], "admin");
}

#[actix_web::test]
async fn logout_clears_the_refresh_cookie() {
    let app = app!();
    let req = test::TestRequest::post()
        .uri("/auth/logout")
        .insert_header((header::AUTHORIZATION, "Bearer valid"))
        .cookie(actix_web::cookie::Cookie::new("refresh_token", "refresh-1"))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), StatusCode::OK);
    let cookie = resp
        .response()
        .cookies()
        .find(|c| c.name() == "refresh_token")
        .unwrap()
        .into_owned();
    assert_eq!(cookie.value(), "");
    assert_eq!(
        cookie.max_age(),
        Some(actix_web::cookie::time::Duration::ZERO)
    );
    assert_eq!(cookie.path(), Some("/auth"));
}

#[actix_web::test]
async fn cors_allows_the_frontend_with_credentials_and_nobody_else() {
    let app = app!();
    let preflight = |origin: &'static str| {
        test::TestRequest::default()
            .method(actix_web::http::Method::OPTIONS)
            .uri("/auth/refresh")
            .insert_header((header::ORIGIN, origin))
            .insert_header((header::ACCESS_CONTROL_REQUEST_METHOD, "POST"))
            .to_request()
    };

    let ok = test::call_service(&app, preflight(FRONTEND)).await;
    assert_eq!(ok.status(), StatusCode::OK);
    assert_eq!(
        ok.headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .unwrap(),
        FRONTEND
    );
    assert_eq!(
        ok.headers()
            .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
            .unwrap(),
        "true"
    );

    let denied =
        test::call_service(&app, preflight("https://evil.example")).await;
    assert_ne!(denied.status(), StatusCode::OK);
}
