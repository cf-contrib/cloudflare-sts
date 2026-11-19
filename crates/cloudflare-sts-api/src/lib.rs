//! The Worker half of cloudflare-sts: a broker that exchanges OIDC tokens
//! for short-lived Cloudflare credentials, or its own tokens for other
//! services.
//!
//! Each request reads the Worker's configuration from its bindings, and the
//! policy from Workers KV unless the isolate holds one from the last minute, then
//! serves the SDK's routers over it: the token endpoints, with the auth layer
//! authenticating every exchange before its handler; the discovery endpoints,
//! cached publicly; and the health endpoints beside them, ready only while
//! the secrets can be read, with OAuth's rules for responses over all of it. A
//! configuration that can't be read, an unset account, a Cloudflare token
//! that isn't a Secrets Store binding or an invalid policy, fails every
//! request instead, with a `server_error`.
//!
//! The hourly cron deletes the expired tokens the broker minted.

mod oidc;
mod service;

use std::sync::Arc;

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response as HttpResponse},
};
use cloudflare_sts_sdk::v1::{self, ErrorCode};
use tower_service::Service;
use tracing::{error, info};
use tracing_web::MakeWebConsoleWriter;
use worker::*;

use crate::service::{
    config::Config,
    handler::{DiscoveryServiceHandler, TokenServiceHandler},
    health::ConfigCheck,
    layer::{AuthenticateLayer, OAuthResponseLayer, cache_publicly},
    rotate::rotate,
};

/// Logs as JSON lines, one per event with its fields at the top level, which
/// Workers Logs indexes. The time is left to Workers Logs.
#[event(start)]
fn start() {
    tracing_subscriber::fmt()
        .json()
        .flatten_event(true)
        .with_current_span(false)
        .with_span_list(false)
        .with_target(false)
        .without_time()
        .with_writer(MakeWebConsoleWriter::new())
        .init();
}

#[event(fetch)]
async fn fetch(req: HttpRequest, env: Env, _ctx: Context) -> Result<HttpResponse> {
    let mut router = match Config::load(&env).await {
        // Each router checks its requests against the spec, form bodies
        // included, before they reach a handler; the auth layer
        // authenticates every exchange first.
        Ok(config) => {
            let config = Arc::new(config);
            v1::token_service_api_router(TokenServiceHandler::new(config.clone()))
                .layer(AuthenticateLayer::new(config.clone()))
                // Merged after the auth layer, so outside it: they're public.
                .merge(
                    v1::discovery_service_api_router(DiscoveryServiceHandler::new(config.clone()))
                        .layer(axum::middleware::map_response(cache_publicly)),
                )
                // Not in the spec: they're for whoever deploys the Worker, not
                // its clients. Ready only while the config checks out.
                .merge(
                    v1::HealthHandler::new()
                        .readiness(ConfigCheck::new(config))
                        .into_router(),
                )
                // Over everything, the health endpoints too.
                .layer(OAuthResponseLayer)
        }
        // Misconfigured, the Worker serves nothing: every request, the health
        // endpoints' too, is refused, with why logged.
        Err(err) => {
            let msg = err.to_string();
            axum::Router::new().fallback(move || async move {
                error!(event = "misconfigured", message = %msg);
                let body = v1::Error::new(ErrorCode::ServerError, "the broker is misconfigured");
                (StatusCode::INTERNAL_SERVER_ERROR, Json(body)).into_response()
            })
        }
    };
    Ok(router.call(req).await?)
}

/// The hourly cron: where the policy asks for it, rolling the broker's own
/// Cloudflare token, and then the cleanup of expired `cloudflare-sts:` tokens.
/// They're independent, so one that fails doesn't cost the other its turn.
///
/// The rotation goes first because it's the half whose failure can't be made
/// good later. The cleanup lists every token and deletes each expired one, so
/// a large backlog can spend the invocation's subrequest budget; missing a
/// cleanup costs an hour of expired tokens lying about, where missing a
/// rotation can leave the broker's own token to expire with nothing able to
/// replace it.
#[event(scheduled)]
async fn scheduled(_event: ScheduledEvent, env: Env, _ctx: ScheduleContext) {
    let config = match Config::load(&env).await {
        Ok(config) => Arc::new(config),
        Err(err) => {
            error!(event = "cron.failed", message = %err);
            return;
        }
    };

    if let Err(why) = rotate(&env, &config).await {
        error!(event = "rotation.failed", message = %why);
    }

    match TokenServiceHandler::new(config.clone()).cleanup().await {
        Ok(deleted) => info!(event = "cleanup.done", deleted),
        Err(err) => error!(
            event = "cleanup.failed",
            error = err.error.as_str(),
            message = %err.error_description,
        ),
    }
}
