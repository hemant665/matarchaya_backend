//! Shared kernel used by every crate in the workspace.
//!
//! Anything here must stay free of business rules: it holds only the plumbing
//! (configuration helpers, error types, DB pool, logging, request claims) that
//! modules have in common.

pub mod config;
pub mod error;
pub mod jwt_claims;
pub mod log_config;
pub mod result_paging;
pub mod sqlx_init;
