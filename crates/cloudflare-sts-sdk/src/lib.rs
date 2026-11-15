//! The Rust SDK for the cloudflare-sts HTTP API: its types, a client, and the
//! traits a server of it implements, generated from the OpenAPI document.
//!
//! Everything is under [`v1`]:
//!
//! ```
//! use cloudflare_sts_sdk::v1::*;
//! ```
//!
//! # What is in it
//!
//! - **Types**: [`v1::TokenExchangeRequest`] and [`v1::TokenExchangeResponse`],
//!   [`v1::TokenRevocationRequest`], the authorization server metadata, and
//!   [`v1::Error`], the body of every error, with [`v1::Error::new`].
//! - **Server** (`server` feature): a trait per tag, `TokenServiceApi` and
//!   `DiscoveryServiceApi`, a response enum per operation, and a router per
//!   trait, `token_service_api_router` and `discovery_service_api_router`,
//!   which check requests against the spec before they reach a handler.
//! - **Client** (`client` feature): `HttpClient`, a method per operation.
//! - **Health**: the endpoints a server answers beside the API,
//!   [`v1::HEALTH_LIVE_PATH`] and [`v1::HEALTH_READY_PATH`]; `HealthHandler`,
//!   which answers them (`server` feature), and `HealthClient`, which asks
//!   (`client` feature).
//!
//! # Generated code
//!
//! `openapi/sts/v1/stsv1.tsp` is the source, in
//! [TypeSpec](https://typespec.io), and compiles to the OpenAPI document
//! `stsv1.yaml` beside it. `build.rs` runs
//! [openapi-to-rust](https://github.com/gpu-cli/openapi-to-rust) over the
//! document into `OUT_DIR`, so none of the Rust is checked in or edited by
//! hand. What is hand-written is in `service/`, mounted into `v1` beside it:
//! the models' companions in `service/model.rs`, the health endpoints in
//! `service/handler.rs`.

mod service;

/// Everything for `sts.v1`: the types, and the server and client the
/// crate's features enable.
pub mod v1 {
    // The generated module root opens with `unused_imports`, which `include!`
    // can't take: build.rs strips it, and it's restated here. The clippy lints
    // are the generator's style, not ours to fix.
    #![allow(
        unused_imports,
        clippy::collapsible_if,
        clippy::double_must_use,
        clippy::match_single_binding,
        clippy::redundant_field_names,
        clippy::result_large_err
    )]

    include!(concat!(env!("OUT_DIR"), "/stsv1/mod.rs"));

    pub use crate::service::handler::*;
}
