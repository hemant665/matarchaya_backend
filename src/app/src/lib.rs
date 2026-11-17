//! Composition root: the only crate that knows every module. It builds the
//! configuration, wires each module's layers together (`container`), and
//! mounts their routes (`routers`). Modules never depend on one another.

pub mod config;
pub mod container;
pub mod create_app;
mod routers;
