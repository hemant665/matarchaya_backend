//! Adapters for the traits declared in `domain` and `application`: SQLx
//! repositories and the Argon2 / JWT security implementations. Nothing here
//! knows about HTTP.

pub mod repositories;
pub mod security;
