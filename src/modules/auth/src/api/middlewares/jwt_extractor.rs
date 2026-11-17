use actix_web::{
    Error, HttpMessage,
    body::{BoxBody, EitherBody, MessageBody},
    dev::{ServiceRequest, ServiceResponse},
    http::header::AUTHORIZATION,
    middleware::Next,
    web,
};
use base::error::ApiError;

use crate::application::services::auth::AuthService;
use crate::domain::errors::auth_error::AuthError;

/// Guards a route: the request must carry a valid `Authorization: Bearer`
/// access token whose role holds `permission`. On success the decoded
/// `JwtClaims` are stored in the request, ready for handlers to extract.
///
/// ```ignore
/// web::resource("/me").wrap(from_fn(|req, next| async move {
///     check_permission_middleware(req, next, "user").await
/// }))
/// ```
///
/// A rejection is returned as a normal `Ok(response)`, not `Err(..)`. An `Err`
/// would skip the outer middleware's response handling, so the CORS layer
/// would not add its headers and the browser would see a network error
/// instead of the 401/403.
pub async fn check_permission_middleware<B: MessageBody + 'static>(
    req: ServiceRequest,
    next: Next<B>,
    permission: &str,
) -> Result<ServiceResponse<EitherBody<B, BoxBody>>, Error> {
    match authorize(&req, permission).await {
        Ok(claims) => {
            req.extensions_mut().insert(claims);
            next.call(req)
                .await
                .map(ServiceResponse::map_into_left_body)
        }
        Err(err) => Ok(req.error_response(err).map_into_right_body()),
    }
}

async fn authorize(
    req: &ServiceRequest,
    permission: &str,
) -> Result<base::jwt_claims::JwtClaims, ApiError> {
    let auth =
        req.app_data::<web::Data<dyn AuthService>>()
            .ok_or_else(|| {
                log::error!("AuthService is not registered in app data");
                ApiError::internal()
            })?;

    let token = bearer_token(req)?;
    Ok(auth.authorize(token, permission).await?)
}

fn bearer_token(req: &ServiceRequest) -> Result<&str, ApiError> {
    let header = req
        .headers()
        .get(AUTHORIZATION)
        .ok_or(AuthError::MissingToken)?
        .to_str()
        .map_err(|_| AuthError::InvalidToken)?;

    let (scheme, token) =
        header.split_once(' ').ok_or(AuthError::InvalidToken)?;
    if !scheme.eq_ignore_ascii_case("bearer") || token.trim().is_empty() {
        return Err(AuthError::InvalidToken.into());
    }
    Ok(token.trim())
}
