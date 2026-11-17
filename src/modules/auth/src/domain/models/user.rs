use chrono::{DateTime, Utc};
use std::fmt;
use uuid::Uuid;

#[derive(Clone)]
pub struct User {
    pub id: Uuid,
    /// Always lowercase.
    pub email: String,
    pub name: String,
    pub password_hash: String,
    pub role_id: Uuid,
    pub role_name: String,
    pub is_active: bool,
    pub last_login: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// The hash must never end up in logs through a stray `{:?}`.
impl fmt::Debug for User {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("User")
            .field("id", &self.id)
            .field("email", &self.email)
            .field("name", &self.name)
            .field("password_hash", &"<redacted>")
            .field("role_name", &self.role_name)
            .field("is_active", &self.is_active)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub struct NewUser {
    pub email: String,
    pub name: String,
    pub password_hash: String,
    pub role_id: Uuid,
}
