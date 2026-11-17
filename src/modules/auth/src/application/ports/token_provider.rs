use crate::domain::errors::auth_error::AuthError;
use base::jwt_claims::JwtClaims;
use uuid::Uuid;

/// Issues and checks the short-lived access token (a signed JWT).
pub trait AccessTokenProvider: Send + Sync {
    fn issue(&self, user_id: Uuid, role: &str) -> Result<String, AuthError>;

    /// `TokenExpired` for an expired token, `InvalidToken` for anything else
    /// that does not verify.
    fn verify(&self, token: &str) -> Result<JwtClaims, AuthError>;
}
