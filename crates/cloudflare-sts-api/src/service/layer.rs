//! What runs around the API's routes, as tower layers: exchange auth, OAuth's
//! rules for every response, and the discovery endpoints' caching.
//!
//! [`AuthenticateLayer`] is layered over the token endpoints in the crate root.
//! Every token exchange needs an OIDC token from a provider the policy names,
//! as its `subject_token`. The layer verifies it with [`oidc`] before
//! the request reaches the handler, and refuses the exchange if it isn't
//! valid, or none of its provider's claim sets matches: `invalid_request`, or
//! `temporarily_unavailable` when the issuer's keys can't be had. An exchange
//! with another `grant_type` is refused as `unsupported_grant_type`.
//! Revocation passes straight through: holding the token is its proof.
//!
//! The handler takes the caller's verified token from
//! [`oidc::verified`], by the token as sent: never by decoding it
//! itself, so a token the layer didn't verify gets nothing.
//!
//! [`OAuthResponseLayer`] is layered over everything: it gives the generated
//! validation's refusals the OAuth error body every error has, and every
//! response `Cache-Control: no-store` unless it has one. [`cache_publicly`]
//! gives the discovery endpoints' answers theirs.

use std::{
    convert::Infallible,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use axum::{
    Json,
    body::{Body, to_bytes},
    extract::Request,
    http::{HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Response},
};
use cloudflare_sts_sdk::v1::{self, ErrorCode};
use serde_json::Value;
use tower_layer::Layer;
use tower_service::Service;
use tracing::warn;
use worker::send::SendFuture;

use super::{
    config::{Config, PolicyConfig},
    handler::TOKEN_EXCHANGE,
};
use crate::oidc;

/// Where the token exchange is.
const TOKEN_PATH: &str = "/oauth/token";

/// The most of a request body read: the generated router's limit.
const MAX_BODY_BYTES: usize = 16 * 1024;

/// Authenticates every token exchange before the routes it's layered over,
/// against the providers in the Worker's policy. Revocation passes through.
#[derive(Clone)]
pub struct AuthenticateLayer {
    config: Arc<Config>,
}

impl AuthenticateLayer {
    /// A layer that takes the providers from `config`.
    pub fn new(config: Arc<Config>) -> Self {
        Self { config }
    }
}

impl<S> Layer<S> for AuthenticateLayer {
    type Service = Authenticate<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Authenticate {
            inner,
            config: self.config.clone(),
        }
    }
}

/// [`AuthenticateLayer`]'s service: authenticates an exchange, then hands the
/// request to the service it wraps.
#[derive(Clone)]
pub struct Authenticate<S> {
    inner: S,
    config: Arc<Config>,
}

impl<S> Service<Request> for Authenticate<S>
where
    S: Service<Request, Response = Response, Error = Infallible> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request) -> Self::Future {
        // The service polled ready is the one to call: a clone takes its
        // place for the next request.
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let config = self.config.clone();

        Box::pin(async move {
            if req.method() != Method::POST || req.uri().path() != TOKEN_PATH {
                return inner.call(req).await;
            }

            // The token is in the form body, which the handler reads again.
            let (parts, body) = req.into_parts();
            let Ok(body) = to_bytes(body, MAX_BODY_BYTES).await else {
                let err = v1::Error::new(ErrorCode::InvalidRequest, "the body is over 16 KiB");
                return Ok((StatusCode::BAD_REQUEST, Json(err)).into_response());
            };
            let grant_type = form_field(&body, "grant_type");
            let token = form_field(&body, "subject_token");
            let req = Request::from_parts(parts, Body::from(body));

            // Another grant is RFC 6749's unsupported_grant_type, which the
            // generated validation can't tell from any other invalid body.
            if let Some(grant_type) = grant_type
                && grant_type != TOKEN_EXCHANGE
            {
                let shown: String = grant_type.chars().take(200).collect();
                let message = format!("grant_type {shown} isn't supported: only token exchange");
                warn!(event = "token.deny", error = "unsupported_grant_type", %message);
                let err = v1::Error::new(ErrorCode::UnsupportedGrantType, message);
                return Ok((StatusCode::BAD_REQUEST, Json(err)).into_response());
            }

            // Without one, there's nothing to verify: the generated validation
            // refuses the request, and the handler would find no identity.
            let Some(token) = token else {
                return inner.call(req).await;
            };

            // Verifying fetches the issuer's keys, and fetch futures aren't
            // `Send`, which the router wants; a Worker is single-threaded, so
            // it runs in a `SendFuture`.
            let policy = config.policy();
            let accepted = SendFuture::new(async {
                let (provider, jwt) = policy.providers.verify(&token).await?;
                let verdict = policy.admit(&provider.name, &jwt.claims);
                if verdict.allowed {
                    Ok(())
                } else {
                    Err(oidc::Error::InsufficientScope {
                        issuer: jwt.claims.iss().unwrap_or_default().to_string(),
                        subject: jwt.claims.sub().map(String::from),
                        policies: verdict.policies,
                    })
                }
            });
            match accepted.await {
                Ok(_) => inner.call(req).await,
                Err(err) => Ok(deny(policy, err)),
            }
        })
    }
}

/// The field of a form body named `name`, if it has one that isn't empty.
fn form_field(body: &[u8], name: &str) -> Option<String> {
    let fields: Vec<(String, String)> = serde_urlencoded::from_bytes(body).ok()?;
    fields
        .into_iter()
        .find(|(field, value)| field == name && !value.is_empty())
        .map(|(_, value)| value)
}

/// Denies an exchange whose token [`oidc`] didn't accept, with why
/// logged, and returned unless it's an issuer's fault. A subject token that
/// isn't valid, or that the policy doesn't take, is `invalid_request` (RFC
/// 8693 §2.2.2).
fn deny(policy: &PolicyConfig, err: oidc::Error) -> Response {
    let (status, body) = match err {
        oidc::Error::InvalidToken(message) => {
            warn!(event = "token.deny", error = "invalid_request", %message);
            let body = v1::Error::new(ErrorCode::InvalidRequest, message);
            (StatusCode::BAD_REQUEST, body)
        }
        oidc::Error::InsufficientScope {
            issuer,
            subject,
            policies,
        } => {
            // Named as the policy names it.
            let provider = policy
                .providers
                .find(&issuer)
                .map_or(issuer.as_str(), |provider| provider.name.as_str());
            let message = format!("the policy doesn't admit the token to provider {provider}");
            warn!(
                event = "token.deny",
                provider,
                sub = subject,
                policies = ?policies,
                error = "invalid_request",
                %message,
            );
            let body = v1::Error::new(ErrorCode::InvalidRequest, message);
            (StatusCode::BAD_REQUEST, body)
        }
        oidc::Error::TemporarilyUnavailable(message) => {
            warn!(event = "token.deny", error = "temporarily_unavailable", %message);
            let body = v1::Error::new(
                ErrorCode::TemporarilyUnavailable,
                "the subject token's issuer couldn't be reached",
            );
            (StatusCode::SERVICE_UNAVAILABLE, body)
        }
    };
    (status, Json(body)).into_response()
}

/// Makes every response one OAuth's rules allow (RFC 6749 §5): the generated
/// validation's refusals the OAuth error every error is, and every response
/// without a `Cache-Control` `no-store`.
///
/// The generated validation answers `application/problem+json` with `400`,
/// `413`, `415` or `422`; OAuth has `400` with `invalid_request` (§5.2).
/// Token responses must not be cached (§5.1), and neither must anything else
/// but what [`cache_publicly`] has already marked.
#[derive(Clone, Copy, Debug, Default)]
pub struct OAuthResponseLayer;

impl<S> Layer<S> for OAuthResponseLayer {
    type Service = OAuthResponse<S>;

    fn layer(&self, inner: S) -> Self::Service {
        OAuthResponse { inner }
    }
}

/// [`OAuthResponseLayer`]'s service: hands the request to the service it
/// wraps, then makes its response one OAuth's rules allow.
#[derive(Clone)]
pub struct OAuthResponse<S> {
    inner: S,
}

impl<S> Service<Request> for OAuthResponse<S>
where
    S: Service<Request, Response = Response, Error = Infallible> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request) -> Self::Future {
        // The service polled ready is the one to call: a clone takes its
        // place for the next request.
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);

        Box::pin(async move {
            let path = req.uri().path().to_owned();
            let response = inner.call(req).await?;

            let problem = response
                .headers()
                .get(header::CONTENT_TYPE)
                .is_some_and(|value| value == "application/problem+json");
            let mut response = if problem {
                let body = to_bytes(response.into_body(), MAX_BODY_BYTES)
                    .await
                    .unwrap_or_default();
                let err = v1::Error::new(ErrorCode::InvalidRequest, problem_description(&body));
                // Logged like any denial, with what was wrong, which never
                // includes the values sent.
                let event = if path == TOKEN_PATH {
                    "token.deny"
                } else {
                    "token.revoke"
                };
                warn!(event, error = err.error.as_str(), message = %err.error_description);
                (StatusCode::BAD_REQUEST, Json(err)).into_response()
            } else {
                response
            };

            response
                .headers_mut()
                .entry(header::CACHE_CONTROL)
                .or_insert(HeaderValue::from_static("no-store"));
            Ok(response)
        })
    }
}

/// Lets the discovery endpoints' answers be cached for five minutes: they're
/// public, and the same for every caller. Errors aren't, so
/// [`OAuthResponseLayer`] makes them `no-store`.
pub async fn cache_publicly(mut response: Response) -> Response {
    if response.status() == StatusCode::OK {
        response.headers_mut().insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("public, max-age=300"),
        );
    }
    response
}

/// What the generated validation found wrong, from its problem details: each
/// violation's place and what's wrong there, or the problem itself.
fn problem_description(body: &[u8]) -> String {
    let problem: Value = serde_json::from_slice(body).unwrap_or_default();
    let violations: Vec<String> = problem["errors"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|violation| {
            let location = violation["location"].as_str().unwrap_or_default();
            let message = violation["message"].as_str().unwrap_or_default();
            format!("{location} {message}")
        })
        .collect();
    if !violations.is_empty() {
        return violations.join("; ");
    }
    match problem["code"].as_str() {
        Some("unsupported_media_type") => {
            "the body must be form-encoded (application/x-www-form-urlencoded)".into()
        }
        _ => problem["title"]
            .as_str()
            .unwrap_or("the request doesn't fit the API")
            .to_lowercase(),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn finds_a_field_in_the_form() {
        let form = |body: &str| form_field(body.as_bytes(), "subject_token");
        assert_eq!(
            form("grant_type=x&subject_token=a.b.c").as_deref(),
            Some("a.b.c")
        );
        assert_eq!(form("subject_token=a%2Bb").as_deref(), Some("a+b"));
        assert_eq!(form("subject_token="), None);
        assert_eq!(form("grant_type=x"), None);
        assert_eq!(form("{\"subject_token\":\"a\"}"), None);
    }

    #[test]
    fn says_what_the_validation_found_wrong() {
        let problem = json!({
            "type": "x", "title": "Request validation failed", "status": 422, "code": "request_validation_failed",
            "errors": [
                { "code": "min_length", "location": "/body/token", "message": "does not meet the length constraint" },
                { "code": "required", "location": "/body/grant_type", "message": "is required" },
            ],
        });
        assert_eq!(
            problem_description(problem.to_string().as_bytes()),
            "/body/token does not meet the length constraint; /body/grant_type is required"
        );
        let media = json!({ "type": "x", "title": "Unsupported media type", "status": 415, "code": "unsupported_media_type" });
        assert_eq!(
            problem_description(media.to_string().as_bytes()),
            "the body must be form-encoded (application/x-www-form-urlencoded)"
        );
    }
}
