//! Authentication module.
//!
//! Onion layout; dependencies only point inward:
//!
//! ```text
//!   api ──────────┐
//!                 ├──▶ application ──▶ domain
//!   infrastructure┘         (ports)       (models, errors, repository traits)
//! ```
//!
//! * `domain`: entities, domain errors and repository traits. No framework.
//! * `application`: use cases (`AuthService`) and the ports they need
//!   (password hashing, access tokens). Depends on `domain` only.
//! * `infrastructure`: adapters for those traits (SQLx repositories, Argon2,
//!   JWT). Knows `domain` and `application`, nothing about HTTP.
//! * `api`: the HTTP layer (handlers, DTOs, middleware). Calls `application`.
//!
//! The `app` crate is the only place that wires the layers together.

pub mod api;
pub mod application;
pub mod config;
pub mod domain;
pub mod infrastructure;
