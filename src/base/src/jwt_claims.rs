use actix_web::{FromRequest, HttpMessage};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ApiError;

/// Claims carried by the access token.
///
/// Lives in the shared kernel so any module's handlers can take a `JwtClaims`
/// argument without depending on the `auth` crate. The auth middleware
/// verifies the token and places the claims in the request extensions; this
/// extractor only reads them back.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    /// User id.
    pub sub: Uuid,
    pub role: String,
    /// Expiry, seconds since the Unix epoch.
    pub exp: i64,
    /// Issued at, seconds since the Unix epoch.
    pub iat: i64,
}

impl FromRequest for JwtClaims {
    type Error = ApiError;
    type Future = futures_util::future::Ready<Result<Self, Self::Error>>;

    fn from_request(
        req: &actix_web::HttpRequest,
        _: &mut actix_web::dev::Payload,
    ) -> Self::Future {
        futures_util::future::ready(
            req.extensions().get::<JwtClaims>().cloned().ok_or_else(|| {
                ApiError::unauthorized("Missing or invalid JWT")
            }),
        )
    }
}
