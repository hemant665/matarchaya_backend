use actix_web::{HttpResponse, Responder, http::StatusCode};
use serde::Serialize;

/// Error returned from HTTP handlers.
///
/// Serialized as `{ "message": "...", "statusCode": 400 }`, the shape the
/// frontend's `extractMessage` already reads.
#[derive(Debug, Serialize)]
pub struct ApiError {
    pub message: String,
    pub code: u16,
}

impl ApiError {
    pub fn new(message: impl Into<String>, code: u16) -> Self {
        Self { message: message.into(), code }
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(message, 400)
    }

    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(message, 401)
    }

    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(message, 403)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(message, 404)
    }

    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(message, 409)
    }

    /// Opaque on purpose: the cause is logged where it happens, never sent to
    /// the client.
    pub fn internal() -> Self {
        Self::new("Something went wrong", 500)
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Error: {}, Code: {}", self.message, self.code)
    }
}

impl actix_web::ResponseError for ApiError {
    fn status_code(&self) -> StatusCode {
        StatusCode::from_u16(self.code)
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
    }

    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code()).json(serde_json::json!({
            "message": self.message,
            "statusCode": self.status_code().as_u16(),
        }))
    }
}

/// Error handler for `web::JsonConfig`, so malformed or oversized JSON bodies
/// get the same JSON error shape as every other failure instead of plain text.
pub fn json_error_handler(
    err: actix_web::error::JsonPayloadError,
    _req: &actix_web::HttpRequest,
) -> actix_web::Error {
    use actix_web::error::JsonPayloadError::{Overflow, OverflowKnownLength};
    log::debug!("rejected JSON body: {err}");
    match err {
        Overflow { .. } | OverflowKnownLength { .. } => {
            ApiError::new("Request body too large", 413).into()
        }
        _ => ApiError::bad_request("Invalid request body").into(),
    }
}

/// Successful 200 response; the payload is the whole JSON body.
#[derive(Debug, Serialize)]
pub struct ApiResponse<T: Serialize>(pub T);

impl<T: Serialize> Responder for ApiResponse<T> {
    type Body = actix_web::body::BoxBody;

    fn respond_to(
        self,
        _req: &actix_web::HttpRequest,
    ) -> HttpResponse<Self::Body> {
        HttpResponse::Ok().json(self.0)
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(value: sqlx::Error) -> Self {
        RepositoryError::from(value).into()
    }
}

impl From<uuid::Error> for ApiError {
    fn from(value: uuid::Error) -> Self {
        Self::bad_request(value.to_string())
    }
}

/// Error produced by the persistence layer.
#[derive(Debug)]
pub struct RepositoryError {
    pub message: String,
    /// HTTP status this error maps to: 500 unless the database reported a
    /// constraint violation (unique/FK -> 409, check -> 400).
    pub code: u16,
}

impl RepositoryError {
    pub fn new(message: impl Into<String>) -> Self {
        Self { message: message.into(), code: 500 }
    }

    /// True when the write conflicts with an existing row.
    pub fn is_unique_violation(&self) -> bool {
        self.code == 409
    }
}

impl std::fmt::Display for RepositoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for RepositoryError {}

impl From<sqlx::Error> for RepositoryError {
    fn from(value: sqlx::Error) -> Self {
        let code = match value.as_database_error() {
            Some(db) if db.is_unique_violation() => 409,
            Some(db) if db.is_foreign_key_violation() => 409,
            Some(db) if db.is_check_violation() => 400,
            _ => 500,
        };
        Self { message: value.to_string(), code }
    }
}

impl From<RepositoryError> for ApiError {
    fn from(value: RepositoryError) -> Self {
        // The raw database string is never forwarded to the client.
        match value.code {
            409 => Self::conflict("Resource already exists"),
            400 => Self::bad_request("Invalid request data"),
            _ => {
                log::error!("repository error: {}", value.message);
                Self::internal()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repository_error_maps_code_and_hides_database_text() {
        let mut e = RepositoryError::new("duplicate key ...");
        e.code = 409;
        assert!(e.is_unique_violation());
        let api: ApiError = e.into();
        assert_eq!(api.code, 409);
        assert_eq!(api.message, "Resource already exists");

        let api: ApiError = RepositoryError::new("boom").into();
        assert_eq!(api.code, 500);
        assert_eq!(api.message, "Something went wrong");
    }
}
