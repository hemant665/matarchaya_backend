use base::error::RepositoryError;
use std::fmt;

/// Everything that can go wrong in the auth use cases. The HTTP status for
/// each variant is decided in `api::errors`, not here.
#[derive(Debug)]
pub enum AuthError {
    /// The request itself is malformed (missing field, weak password, ...).
    Validation(String),
    /// Unknown email or wrong password. Deliberately one variant for both.
    InvalidCredentials,
    AccountDisabled,
    /// No bearer token was presented.
    MissingToken,
    InvalidToken,
    TokenExpired,
    /// Unknown, expired, revoked or replayed refresh token.
    InvalidRefreshToken,
    /// Authenticated, but the role lacks the required permission.
    Forbidden,
    UserNotFound,
    /// Infrastructure failure; the detail is for logs only.
    Internal(String),
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Validation(message) => write!(f, "{message}"),
            Self::InvalidCredentials => {
                write!(f, "Invalid email or password")
            }
            Self::AccountDisabled => write!(f, "This account is disabled"),
            Self::MissingToken => write!(f, "Authentication required"),
            Self::InvalidToken => write!(f, "Invalid access token"),
            Self::TokenExpired => write!(f, "Access token expired"),
            Self::InvalidRefreshToken => {
                write!(f, "Invalid or expired refresh token")
            }
            Self::Forbidden => {
                write!(f, "You do not have permission to do this")
            }
            Self::UserNotFound => write!(f, "User not found"),
            Self::Internal(detail) => write!(f, "internal error: {detail}"),
        }
    }
}

impl std::error::Error for AuthError {}

impl From<RepositoryError> for AuthError {
    fn from(value: RepositoryError) -> Self {
        Self::Internal(value.message)
    }
}
