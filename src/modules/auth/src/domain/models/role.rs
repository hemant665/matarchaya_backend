use uuid::Uuid;

/// Role names the code itself relies on. Further roles are plain data.
pub const ROLE_ADMIN: &str = "admin";

#[derive(Debug, Clone)]
pub struct Role {
    pub id: Uuid,
    pub name: String,
    pub description: String,
}
