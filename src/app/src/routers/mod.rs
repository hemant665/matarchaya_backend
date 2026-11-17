//! One file per module, each exposing a `*_routes` function that `create_app`
//! mounts. Route guards (which permission a path needs) are decided here, not
//! inside the module crates.

pub mod auth;
pub mod health;
