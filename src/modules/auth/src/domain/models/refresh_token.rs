use chrono::{DateTime, Utc};
use uuid::Uuid;

/// A stored refresh token. Only the hash of the opaque token is kept.
#[derive(Debug, Clone)]
pub struct RefreshToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    /// All tokens descending from one login share a family.
    pub family_id: Uuid,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub is_revoked: bool,
}

impl RefreshToken {
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        self.expires_at <= now
    }
}

#[derive(Debug, Clone)]
pub struct NewRefreshToken {
    pub user_id: Uuid,
    pub token_hash: String,
    pub family_id: Uuid,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}
