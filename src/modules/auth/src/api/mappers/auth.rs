use crate::api::dto::auth::{SessionResponse, UserDto};
use crate::application::services::auth::{Session, SessionUser};

pub fn to_user_dto(user: &SessionUser) -> UserDto {
    UserDto {
        id: user.id,
        name: user.name.clone(),
        email: user.email.clone(),
        role: user.role.clone(),
    }
}

pub fn to_session_response(session: &Session) -> SessionResponse {
    SessionResponse {
        access_token: session.access_token.clone(),
        user: to_user_dto(&session.user),
    }
}
