//! Service implementations for the generated API trait.
//!
//! The Worker's configuration, the one place its bindings are read, is in
//! [`config`]. The two handlers, one per generated trait, are in [`handler`]:
//! the token endpoints and the discovery endpoints. The layers are in
//! [`layer`]: exchange auth, which the crate root layers over the token
//! endpoints, so no handler authenticates; the discovery endpoints' public
//! caching; and OAuth's rules for every response, over everything.
//!
//! The health endpoints are the SDK's `HealthHandler`, merged beside them in
//! the crate root: they're a deployment check, not part of the API, so the
//! spec doesn't declare them. Readiness asks [`health`]'s check of the
//! config, which reads the secrets.

pub mod authz;
pub mod config;
pub mod handler;
pub mod health;
pub mod layer;
