//! The broker's readiness check, for `/health/ready`.
//!
//! [`Config::load`] checks the bindings and the policy, read from KV, and a
//! Worker that fails it serves nothing.
//! [`ConfigCheck`] checks the rest of the configuration, what only reading it
//! can: the secrets an exchange reads, the Cloudflare token. A secret that's
//! bound but can't be read, say one Secrets Store won't hand over, then shows
//! up as `503` on the probe, with why in the log, not only as a `500` on the
//! first exchange.
//!
//! It doesn't call Cloudflare's API to verify the token: the endpoint is
//! public, and anyone probing it would spend the token's rate limit.

use std::sync::Arc;

use cloudflare_sts_sdk::v1::{HealthCheck, HealthCheckError};
use tracing::error;
use worker::send::SendFuture;

use super::config::Config;

/// Checks the configuration as an exchange would read it.
pub struct ConfigCheck {
    config: Arc<Config>,
}

impl ConfigCheck {
    /// A check over the Worker's configuration, shared with the handlers.
    pub fn new(config: Arc<Config>) -> Self {
        Self { config }
    }

    /// Reads the Cloudflare token.
    async fn read_secrets(&self) -> Result<(), String> {
        self.config
            .cloudflare()
            .client()
            .await
            .map_err(|err| err.to_string())?;
        Ok(())
    }
}

impl HealthCheck for ConfigCheck {
    // Secrets Store futures aren't `Send`: they hold JavaScript values. A
    // Worker is single-threaded, so the check runs in a `SendFuture`, as the
    // handlers do.
    fn check(&self) -> impl Future<Output = Result<(), HealthCheckError>> + Send {
        SendFuture::new(async move {
            self.read_secrets().await.map_err(|why| {
                error!(event = "unready", message = %why);
                why.into()
            })
        })
    }
}
