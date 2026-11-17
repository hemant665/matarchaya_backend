//! Use cases. Depends on `domain` only: anything that needs the outside world
//! (database, password hashing, token signing) is reached through a trait, and
//! the adapters live in `infrastructure`.

pub mod ports;
pub mod services;
