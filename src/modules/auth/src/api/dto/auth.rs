use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// `POST /auth/login`. No `Debug` derive: it would print the password.
#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

/// Matches the frontend's `AuthUser`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserDto {
    pub id: Uuid,
    pub name: String,
    pub email: String,
    pub role: String,
}

/// Body of login and refresh. The refresh token is *not* here: it travels only
/// in the HttpOnly cookie, out of reach of page scripts.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionResponse {
    pub access_token: String,
    pub user: UserDto,
}

#[derive(Debug, Serialize)]
pub struct MessageResponse {
    pub message: &'static str,
}
