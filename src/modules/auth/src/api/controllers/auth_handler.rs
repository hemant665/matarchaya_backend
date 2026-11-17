use actix_web::{HttpRequest, HttpResponse, http::header, web};
use base::{
    error::{ApiError, ApiResponse},
    jwt_claims::JwtClaims,
};

use crate::api::dto::auth::{LoginRequest, MessageResponse, UserDto};
use crate::api::mappers::auth::{to_session_response, to_user_dto};
use crate::api::utils::cookie::{refresh_cookie, removal_cookie};
use crate::application::services::auth::{AuthService, Session};
use crate::config::AuthConfig;

/// `POST /auth/login`
pub async fn login_handler(
    auth: web::Data<dyn AuthService>,
    config: web::Data<AuthConfig>,
    body: web::Json<LoginRequest>,
) -> Result<HttpResponse, ApiError> {
    let session = auth.login(&body.email, &body.password).await?;
    Ok(session_response(&config, &session))
}

/// `POST /auth/refresh`: the refresh token comes from the HttpOnly cookie.
pub async fn refresh_handler(
    auth: web::Data<dyn AuthService>,
    config: web::Data<AuthConfig>,
    req: HttpRequest,
) -> Result<HttpResponse, ApiError> {
    let cookie = req
        .cookie(&config.refresh_cookie_name)
        .ok_or_else(|| ApiError::unauthorized("Missing refresh token"))?;
    let session = auth.refresh(cookie.value()).await?;
    Ok(session_response(&config, &session))
}

/// `POST /auth/logout` (requires a valid access token)
pub async fn logout_handler(
    auth: web::Data<dyn AuthService>,
    config: web::Data<AuthConfig>,
    req: HttpRequest,
    claims: JwtClaims,
) -> Result<HttpResponse, ApiError> {
    if let Some(cookie) = req.cookie(&config.refresh_cookie_name) {
        auth.logout(claims.sub, cookie.value()).await?;
    }
    Ok(HttpResponse::Ok()
        .cookie(removal_cookie(&config))
        .json(MessageResponse { message: "Logged out" }))
}

/// `GET /auth/me`
pub async fn me_handler(
    auth: web::Data<dyn AuthService>,
    claims: JwtClaims,
) -> Result<ApiResponse<UserDto>, ApiError> {
    let user = auth.current_user(claims.sub).await?;
    Ok(ApiResponse(to_user_dto(&user)))
}

/// Body with the access token, refresh token in the cookie, and `no-store` so
/// no proxy or browser cache keeps a copy of either.
fn session_response(config: &AuthConfig, session: &Session) -> HttpResponse {
    HttpResponse::Ok()
        .cookie(refresh_cookie(config, &session.refresh_token))
        .insert_header((header::CACHE_CONTROL, "no-store"))
        .json(to_session_response(session))
}
