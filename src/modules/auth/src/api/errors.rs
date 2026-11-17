use base::error::ApiError;

use crate::domain::errors::auth_error::AuthError;

/// The one place that decides which HTTP status each domain error gets.
impl From<AuthError> for ApiError {
    fn from(err: AuthError) -> Self {
        let message = err.to_string();
        match err {
            AuthError::Validation(_) => ApiError::bad_request(message),
            // 400 rather than 401 on purpose: the frontend's axios interceptor
            // treats any 401 as "access token expired", tries a refresh and
            // then shows the *refresh* error instead of this one.
            AuthError::InvalidCredentials => ApiError::bad_request(message),
            AuthError::AccountDisabled | AuthError::Forbidden => {
                ApiError::forbidden(message)
            }
            AuthError::MissingToken
            | AuthError::InvalidToken
            | AuthError::TokenExpired
            | AuthError::InvalidRefreshToken => ApiError::unauthorized(message),
            AuthError::UserNotFound => ApiError::not_found(message),
            AuthError::Internal(detail) => {
                log::error!("auth failure: {detail}");
                ApiError::internal()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(err: AuthError) -> u16 {
        ApiError::from(err).code
    }

    #[test]
    fn maps_each_error_to_the_expected_status() {
        assert_eq!(status(AuthError::Validation("x".into())), 400);
        assert_eq!(status(AuthError::InvalidCredentials), 400);
        assert_eq!(status(AuthError::AccountDisabled), 403);
        assert_eq!(status(AuthError::Forbidden), 403);
        assert_eq!(status(AuthError::MissingToken), 401);
        assert_eq!(status(AuthError::InvalidToken), 401);
        assert_eq!(status(AuthError::TokenExpired), 401);
        assert_eq!(status(AuthError::InvalidRefreshToken), 401);
        assert_eq!(status(AuthError::UserNotFound), 404);
    }

    #[test]
    fn internal_errors_do_not_leak_their_detail() {
        let api =
            ApiError::from(AuthError::Internal("db password=hunter2".into()));
        assert_eq!(api.code, 500);
        assert!(!api.message.contains("hunter2"));
    }
}
