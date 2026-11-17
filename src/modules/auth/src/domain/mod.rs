//! Innermost layer: entities, domain errors and the repository traits the
//! rest of the module depends on. It must not import `actix_web` or `sqlx`.

pub mod errors;
pub mod models;
pub mod repositories;
