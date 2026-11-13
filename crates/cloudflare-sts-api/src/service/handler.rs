//! The broker's API: the SDK's two generated traits, each in a handler over
//! the policy and secrets in the Worker's [`Config`]. [`TokenServiceHandler`]
//! is `TokenServiceApi`: the token exchange and revocation, and the cron's
//! cleanup of the tokens the broker minted. [`DiscoveryServiceHandler`] is
//! `DiscoveryServiceApi`: the metadata and keys services verify the broker's
//! own tokens with, which are public.
//!
//! # Send
//!
//! The generated traits want `Send` futures, so axum can serve them on any
//! thread. Fetch, Secrets Store and WebCrypto futures aren't `Send`: they hold
//! JavaScript values. A Worker is single-threaded, so each method runs its body
//! in a `SendFuture`, which asserts it.
//!
//! # Errors
//!
//! Each method returns its operation's response enum, one variant per status
//! the spec declares, so a status the spec doesn't list can't be returned.
//! Errors are OAuth errors (RFC 6749 §5.2). A caller's mistake (400) says what
//! it was. A fault of the broker's (500, 503) doesn't say why: that goes to the
//! log. A refused exchange or revocation is audited with the whole description
//! either way.
//!
//! # Exchanges
//!
//! No method authenticates: by the time an exchange reaches one, the auth
//! [`layer`](super::layer) has, and the handler takes the caller's identity
//! from it.

use std::sync::Arc;

use chrono::DateTime;
use cloudflare::v4::{
    ApiOpError, HttpClient, IamCreatePayload, IamTokenStatus, R2TempAccessCredsRequest,
    R2TempAccessCredsRequestPermission,
};
use cloudflare_sts_sdk::v1::{
    self, AuthorizationServerMetadata, BucketCredentials, DiscoveryServiceApi, Error, ErrorCode,
    IdentityProvider, IssuedTokenType, Jwks, OpenIdProviderMetadata, TokenExchangeRequest,
    TokenExchangeRequestSubjectTokenType as SubjectTokenType, TokenExchangeResponse,
    TokenExchangeResponseTokenType as TokenType, TokenRevocationRequest, TokenServiceApi,
};
use serde_json::json;
use tracing::{error, info, warn};
use worker::{Date, send::SendFuture};

use super::config::{BucketPermission, CLOUDFLARE_AUDIENCE, Config, ProfileConfig, ProviderConfig};
use crate::oidc::{self, AccessTokenClaims, Jwt, SigningKey};

/// The token exchange grant, RFC 8693's.
pub(super) const TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

/// Every minted token's name starts with this. Revocation and the cleanup
/// never touch anything else.
const TOKEN_PREFIX: &str = "cloudflare-sts:";

/// The longest token name Cloudflare takes.
const NAME_MAX: usize = 120;

/// Tokens listed per page by the cleanup.
const PAGE_SIZE: usize = 50;

/// The signing key, read now, or `None` if none is bound: what the broker
/// signs its own tokens with, and publishes the public half of.
pub(super) async fn signing_key(config: &Config) -> Result<Option<SigningKey>, Error> {
    let misconfigured = |why: String| Error::new(ErrorCode::ServerError, why);
    match config.signing_key().await {
        Ok(Some(pem)) => SigningKey::import(&pem)
            .await
            .map(Some)
            .map_err(|err| misconfigured(format!("the signing key: {err}"))),
        Ok(None) => Ok(None),
        Err(err) => Err(misconfigured(err.to_string())),
    }
}

/// The token endpoints, over the Worker's configuration.
#[derive(Clone)]
pub struct TokenServiceHandler {
    config: Arc<Config>,
}

impl TokenServiceHandler {
    /// A handler over the Worker's configuration, shared with the auth layer.
    pub fn new(config: Arc<Config>) -> Self {
        Self { config }
    }

    /// Cloudflare's API, as the Cloudflare token, read now.
    async fn cloudflare(&self) -> Result<HttpClient, Error> {
        let client = self.config.cloudflare().client().await;
        client.map_err(|err| Error::new(ErrorCode::ServerError, err.to_string()))
    }

    /// Deletes expired `cloudflare-sts:` tokens, for the hourly cron. Returns how many.
    pub async fn cleanup(&self) -> Result<usize, Error> {
        let cloudflare = self.cloudflare().await?;
        let account_id = self.config.cloudflare().account_id();
        let now = Date::now().as_millis() / 1000;

        // Collect first: deleting while paginating would shift later pages and
        // skip tokens.
        let mut expired = Vec::new();
        for page in 1.. {
            let tokens = cloudflare
                .accounts_tokens_list_builder(account_id)
                .page(page as f64)
                .per_page(PAGE_SIZE as f64)
                .include_expired(true)
                .send()
                .await
                .map_err(|err| upstream("tokens.list", err))?
                .result
                .unwrap_or_default();
            let count = tokens.len();
            for token in tokens {
                let (Some(id), Some(name), Some(expires_on)) =
                    (token.id, token.name, token.expires_on)
                else {
                    continue;
                };
                let lapsed = token.status == Some(IamTokenStatus::Expired)
                    || expires_on.timestamp() <= now as i64;
                if name.starts_with(TOKEN_PREFIX) && lapsed {
                    expired.push((id, name, expires_on));
                }
            }
            if count < PAGE_SIZE {
                break;
            }
        }

        let mut deleted = 0;
        for (id, name, expires_on) in expired {
            match cloudflare.accounts_tokens_delete(account_id, &id).await {
                Ok(_) => {
                    deleted += 1;
                    info!(
                        event = "token.cleanup",
                        token_id = %id,
                        name = %name,
                        expires_at = expires_on.timestamp(),
                    );
                }
                Err(err) if err.api().is_some_and(|api| api.status == 404) => {}
                Err(err) => return Err(upstream("tokens.delete", err)),
            }
        }
        Ok(deleted)
    }

    /// The broker's own token, for a profile with another service's `audience`.
    async fn service_token(
        &self,
        identity: &Jwt,
        provider: &ProviderConfig,
        profile: &ProfileConfig,
        ttl: u64,
        issued_token_type: IssuedTokenType,
    ) -> Result<TokenExchangeResponse, Error> {
        let Some(key) = signing_key(&self.config).await? else {
            return Err(Error::new(
                ErrorCode::ServerError,
                format!(
                    "a token for {} needs a signing key, and none is bound",
                    profile.audience
                ),
            ));
        };
        let now = Date::now().as_millis() / 1000;
        let issuer = &self.config.policy().issuer;
        let (claims, expires_at) = payload(issuer, identity, provider, profile, ttl, now)?;
        let signed = key
            .sign_access_token(claims)
            .await
            .map_err(|err| Error::new(ErrorCode::ServerError, format!("signing a token: {err}")))?;
        info!(
            event = "token.issue",
            provider = %provider.name,
            profile = %profile.name,
            sub = identity.claims.sub(),
            claims = %serde_json::Value::Object(provider.matched_claims(Some(profile), &identity.claims)),
            audience = %profile.audience,
            jti = %signed.jti,
            expires_at,
        );
        Ok(TokenExchangeResponse {
            access_token: Some(signed.jwt),
            account_id: None,
            bucket: None,
            expires_at: expires_at as i64,
            expires_in: expires_at.saturating_sub(now) as i64,
            issued_token_type,
            profile: profile.name.clone(),
            token_id: None,
            token_type: TokenType::Bearer,
        })
    }

    /// A Cloudflare API token, R2 credentials, or both, as the profile has
    /// them.
    async fn cloudflare_credentials(
        &self,
        identity: &Jwt,
        provider: &ProviderConfig,
        profile: &ProfileConfig,
        ttl: u64,
    ) -> Result<TokenExchangeResponse, Error> {
        let account_id = self.config.cloudflare().account_id();
        let claims =
            serde_json::Value::Object(provider.matched_claims(Some(profile), &identity.claims));

        // Filled in before anything is minted, so an unusable claim leaves
        // nothing behind.
        let bucket = profile
            .bucket
            .as_ref()
            .map(|bucket| {
                let prefixes = bucket
                    .prefixes
                    .iter()
                    .map(|prefix| prefix.fill(&identity.claims))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|why| {
                        Error::new(
                            ErrorCode::InvalidRequest,
                            format!("bucket {}: {why}", bucket.name),
                        )
                    })?;
                Ok::<_, Error>((bucket, prefixes))
            })
            .transpose()?;

        let cloudflare = self.cloudflare().await?;
        let now = Date::now().as_millis() / 1000;
        // In whole seconds, which is what the tokens API takes.
        let expires_on = DateTime::from_timestamp((now + ttl / 1000) as i64, 0).unwrap_or_default();

        // The token: its permission groups looked up by name, then minted. Not
        // retried: a create that failed midway leaves an orphan the cleanup
        // removes.
        let mut token = None;
        if let Some(config) = &profile.token {
            let groups = cloudflare
                .accounts_tokens_permission_groups_list(account_id, None::<&str>, None::<&str>)
                .await
                .map_err(|err| upstream("permissionGroups.list", err))?
                .result
                .unwrap_or_default();
            let policies = config
                .iam_policies(&groups)
                .map_err(|why| Error::new(ErrorCode::ServerError, why))?;
            let payload = IamCreatePayload {
                condition: None,
                expires_on: Some(expires_on),
                name: token_name(provider, identity),
                not_before: None,
                policies,
            };
            let created = cloudflare
                .accounts_tokens_create(account_id, payload)
                .await
                .map_err(|err| upstream("tokens.create", err))?
                .result;
            let Some((Some(id), Some(value), expires)) =
                created.map(|created| (created.id, created.value, created.expires_on))
            else {
                return Err(missing("tokens.create"));
            };
            let expires = expires.unwrap_or(expires_on);
            info!(
                event = "token.mint",
                provider = %provider.name,
                profile = %profile.name,
                sub = identity.claims.sub(),
                claims = %claims,
                token_id = %id,
                expires_at = expires.timestamp(),
            );
            token = Some((id, value, expires));
        }

        // The bucket's credentials, with the Cloudflare token, whose ID is
        // its R2 access key ID, as their parent. Half a profile isn't handed
        // out: if they fail, the token is deleted.
        let issued = if let Some((bucket, prefixes)) = bucket {
            let r2 = async {
                let parent_access_key_id = cloudflare
                    .accounts_tokens_verify(account_id)
                    .await
                    .map_err(|err| upstream("tokens.verify", err))?
                    .result
                    .ok_or_else(|| missing("tokens.verify"))?
                    .id;
                let request = R2TempAccessCredsRequest {
                    bucket: bucket.name.clone(),
                    objects: None,
                    parent_access_key_id,
                    permission: match bucket.permission {
                        BucketPermission::ObjectReadWrite => {
                            R2TempAccessCredsRequestPermission::ObjectReadWrite
                        }
                        BucketPermission::ObjectReadOnly => {
                            R2TempAccessCredsRequestPermission::ObjectReadOnly
                        }
                    },
                    prefixes: (!prefixes.is_empty()).then(|| prefixes.clone()),
                    ttl_seconds: (ttl / 1000) as f64,
                };
                let credentials = cloudflare
                    .r2_temporary_credentials_create(account_id, request)
                    .await
                    .map_err(|err| upstream("temporaryCredentials.create", err))?
                    .result;
                let (Some(access_key_id), Some(secret_access_key), Some(session_token)) = (
                    credentials.access_key_id,
                    credentials.secret_access_key,
                    credentials.session_token,
                ) else {
                    return Err(missing("temporaryCredentials.create"));
                };
                info!(
                    event = "r2.issued",
                    provider = %provider.name,
                    profile = %profile.name,
                    sub = identity.claims.sub(),
                    claims = %claims,
                    bucket = %bucket.name,
                    prefixes = ?prefixes,
                    permission = bucket.permission.as_str(),
                    expires_at = expires_on.timestamp(),
                );
                Ok(BucketCredentials {
                    access_key_id,
                    endpoint: format!("https://{account_id}.r2.cloudflarestorage.com"),
                    expires_on,
                    name: bucket.name.clone(),
                    prefixes,
                    secret_access_key,
                    session_token,
                })
            };
            match r2.await {
                Ok(credentials) => Some(credentials),
                Err(err) => {
                    // Best effort: the cleanup is the fallback.
                    if let Some((token_id, _, _)) = &token {
                        match cloudflare
                            .accounts_tokens_delete(account_id, token_id)
                            .await
                        {
                            Ok(_) => info!(event = "token.revoke", token_id, reason = "discarded"),
                            Err(err) => error!(
                                event = "token.revoke",
                                token_id,
                                reason = "discard_failed",
                                detail = %err,
                            ),
                        }
                    }
                    return Err(err);
                }
            }
        } else {
            None
        };

        let expires_at = token
            .as_ref()
            .map_or(expires_on, |(_, _, at)| *at)
            .timestamp();
        let (access_token, token_id, issued_token_type, token_type) = match token {
            Some((id, value, _)) => (
                Some(value),
                Some(id),
                IssuedTokenType::UrnIetfParamsOauthTokenTypeAccessToken,
                TokenType::Bearer,
            ),
            None => (
                None,
                None,
                IssuedTokenType::UrnCloudflareStsParamsOauthTokenTypeR2Credentials,
                TokenType::NA,
            ),
        };
        Ok(TokenExchangeResponse {
            access_token,
            account_id: Some(account_id.into()),
            bucket: issued,
            expires_at,
            expires_in: (expires_at - now as i64).max(0),
            issued_token_type,
            profile: profile.name.clone(),
            token_id,
            token_type,
        })
    }
}

#[async_trait::async_trait]
impl TokenServiceApi for TokenServiceHandler {
    /// `POST /oauth/token`: an RFC 8693 token exchange. The caller's token,
    /// which the auth layer verified, for what the profile it matches hands
    /// out.
    async fn exchange_token(&self, request: TokenExchangeRequest) -> v1::ExchangeTokenResponse {
        SendFuture::new(async move {
            let policy = self.config.policy();
            let mut caller: Option<(Jwt, &ProviderConfig)> = None;
            let mut named: Option<&ProfileConfig> = None;
            let exchanged = async {
                // What the generated validation can't check: the audience,
                // and whether what's asked for can be issued for it.
                // Cloudflare's gets Cloudflare credentials; any other, a
                // JWT.
                let invalid = |code, description: String| Err(Error::new(code, description));
                let audience = request.audience.as_deref().unwrap_or(CLOUDFLARE_AUDIENCE);
                if audience.is_empty() {
                    return invalid(
                        ErrorCode::InvalidRequest,
                        "audience must not be empty".into(),
                    );
                }
                let shown: String = audience.chars().take(200).collect();
                let issuable = match (
                    audience == CLOUDFLARE_AUDIENCE,
                    &request.requested_token_type,
                ) {
                    (_, None) => true,
                    (true, Some(t)) => matches!(
                        t,
                        IssuedTokenType::UrnIetfParamsOauthTokenTypeAccessToken
                            | IssuedTokenType::UrnCloudflareStsParamsOauthTokenTypeR2Credentials
                    ),
                    (false, Some(t)) => matches!(
                        t,
                        IssuedTokenType::UrnIetfParamsOauthTokenTypeJwt
                            | IssuedTokenType::UrnIetfParamsOauthTokenTypeAccessToken
                    ),
                };
                // What the broker won't issue for the audience is RFC 8693's
                // invalid_target.
                if let (false, Some(requested)) = (issuable, &request.requested_token_type) {
                    return invalid(
                        ErrorCode::InvalidTarget,
                        format!("{requested} can't be issued for {shown}"),
                    );
                }
                if audience != CLOUDFLARE_AUDIENCE
                    && !policy.profiles.iter().any(|p| p.audience == audience)
                {
                    return invalid(
                        ErrorCode::InvalidTarget,
                        format!("no profile is for audience {shown}"),
                    );
                }
                // `id_token` and `jwt` alike: an OIDC token is a JWT.
                let (SubjectTokenType::UrnIetfParamsOauthTokenTypeIdToken
                | SubjectTokenType::UrnIetfParamsOauthTokenTypeJwt) = request.subject_token_type;

                // Who the layer verified the caller is. A subject token that
                // isn't valid, or that the policy doesn't take, is
                // invalid_request (RFC 8693 §2.2.2).
                let invalid_request = |why: &str| Error::new(ErrorCode::InvalidRequest, why);
                let identity = oidc::verified(&request.subject_token)
                    .ok_or_else(|| invalid_request("the subject token wasn't verified"))?;
                let provider = policy
                    .provider_for(&identity.claims)
                    .map_err(|why| invalid_request(&why))?;
                let (identity, provider) = &*caller.insert((identity, provider));

                let profile = policy
                    .profile_for(
                        &provider.name,
                        &identity.claims,
                        request.profile.as_deref(),
                        audience,
                    )
                    .map_err(|why| invalid_request(&why))?;
                named = Some(profile);
                let ttl = profile
                    .ttl_for(request.ttl.as_deref())
                    .map_err(|why| invalid_request(&why))?;
                if profile.audience == CLOUDFLARE_AUDIENCE {
                    self.cloudflare_credentials(identity, provider, profile, ttl)
                        .await
                } else {
                    // An access token is a JWT: named as asked for.
                    let issued_token_type = match request.requested_token_type {
                        Some(IssuedTokenType::UrnIetfParamsOauthTokenTypeJwt) => {
                            IssuedTokenType::UrnIetfParamsOauthTokenTypeJwt
                        }
                        _ => IssuedTokenType::UrnIetfParamsOauthTokenTypeAccessToken,
                    };
                    self.service_token(identity, provider, profile, ttl, issued_token_type)
                        .await
                }
            };

            match exchanged.await {
                Ok(response) => v1::ExchangeTokenResponse::Ok(response),
                Err(err) => {
                    let profile = named
                        .map(|p| p.name.as_str())
                        .or(request.profile.as_deref());
                    warn!(
                        event = "token.deny",
                        provider = caller.as_ref().map(|(_, provider)| provider.name.as_str()),
                        profile,
                        sub = caller.as_ref().and_then(|(identity, _)| identity.claims.sub()),
                        claims = caller.as_ref().map(|(identity, provider)| {
                            display(serde_json::Value::Object(provider.matched_claims(named, &identity.claims)))
                        }),
                        error = err.error.as_str(),
                        message = %err.error_description,
                    );
                    // A caller's mistake says what it was. A fault of the
                    // broker's doesn't: the log line does.
                    match err.error {
                        ErrorCode::InvalidRequest
                        | ErrorCode::InvalidTarget
                        | ErrorCode::UnsupportedGrantType => {
                            v1::ExchangeTokenResponse::BadRequest(err)
                        }
                        ErrorCode::TemporarilyUnavailable => {
                            v1::ExchangeTokenResponse::ServiceUnavailable(Error::new(
                                err.error,
                                "a service the broker relies on failed; its logs say which",
                            ))
                        }
                        ErrorCode::ServerError => {
                            v1::ExchangeTokenResponse::InternalServerError(Error::new(
                                err.error,
                                "the broker failed; its logs say why",
                            ))
                        }
                    }
                }
            }
        })
        .await
    }

    /// `POST /oauth/revoke`: an RFC 7009 revocation of a token the broker
    /// minted. Holding the token is the proof. Answers `Ok` whether the token
    /// was revoked, already gone, or not the broker's: to the broker, a token
    /// it didn't mint is an invalid one, which RFC 7009 §2.2 answers with
    /// `200` too. It's never deleted.
    async fn revoke_token(&self, request: TokenRevocationRequest) -> v1::RevokeTokenResponse {
        SendFuture::new(async move {
            // Holding the token is the proof: Cloudflare says which it is,
            // and it's deleted if the broker minted it. Cloudflare doesn't
            // recognize one invalid, expired, deleted or another account's.
            let revoked = async {
                let account_id = self.config.cloudflare().account_id();
                let presenter = self.config.cloudflare().client_as(&request.token);
                let status = |err: &ApiOpError<_>| err.api().map(|api| api.status);
                let id = match presenter.accounts_tokens_verify(account_id).await {
                    Ok(verified) => match verified.result {
                        Some(result) => result.id,
                        None => return Ok(RevokeStatus::Gone),
                    },
                    Err(err) if matches!(status(&err), Some(400 | 401 | 403 | 404)) => {
                        return Ok(RevokeStatus::Gone);
                    }
                    Err(err) => return Err(upstream("tokens.verify", err)),
                };

                let cloudflare = self.cloudflare().await?;
                let name = match cloudflare.accounts_tokens_get(account_id, &id).await {
                    Ok(details) => details.result.and_then(|token| token.name),
                    Err(err) if err.api().is_some_and(|api| api.status == 404) => {
                        return Ok(RevokeStatus::Gone);
                    }
                    Err(err) => return Err(upstream("tokens.get", err)),
                };
                if !name.is_some_and(|name| name.starts_with(TOKEN_PREFIX)) {
                    return Ok(RevokeStatus::NotMinted(id));
                }

                match cloudflare.accounts_tokens_delete(account_id, &id).await {
                    Ok(_) => Ok(RevokeStatus::Deleted(id)),
                    Err(err) if err.api().is_some_and(|api| api.status == 404) => {
                        Ok(RevokeStatus::Deleted(id))
                    }
                    Err(err) => Err(upstream("tokens.delete", err)),
                }
            };
            match revoked.await {
                Ok(RevokeStatus::Deleted(token_id)) => {
                    info!(event = "token.revoke", token_id);
                    v1::RevokeTokenResponse::Ok
                }
                Ok(RevokeStatus::Gone) => {
                    info!(event = "token.revoke", reason = "already_gone");
                    v1::RevokeTokenResponse::Ok
                }
                Ok(RevokeStatus::NotMinted(token_id)) => {
                    warn!(event = "token.revoke", token_id, reason = "not_minted");
                    v1::RevokeTokenResponse::Ok
                }
                Err(err) => {
                    warn!(
                        event = "token.revoke",
                        error = err.error.as_str(),
                        message = %err.error_description,
                    );
                    // As for an exchange: the broker's faults say why only in
                    // the log line.
                    match err.error {
                        ErrorCode::InvalidRequest
                        | ErrorCode::InvalidTarget
                        | ErrorCode::UnsupportedGrantType => {
                            v1::RevokeTokenResponse::BadRequest(err)
                        }
                        ErrorCode::TemporarilyUnavailable => {
                            v1::RevokeTokenResponse::ServiceUnavailable(Error::new(
                                err.error,
                                "a service the broker relies on failed; its logs say which",
                            ))
                        }
                        ErrorCode::ServerError => v1::RevokeTokenResponse::InternalServerError(
                            Error::new(err.error, "the broker failed; its logs say why"),
                        ),
                    }
                }
            }
        })
        .await
    }
}

/// The discovery endpoints, over the Worker's configuration.
#[derive(Clone)]
pub struct DiscoveryServiceHandler {
    config: Arc<Config>,
}

impl DiscoveryServiceHandler {
    /// A handler over the Worker's configuration.
    pub fn new(config: Arc<Config>) -> Self {
        Self { config }
    }
}

#[async_trait::async_trait]
impl DiscoveryServiceApi for DiscoveryServiceHandler {
    /// `GET /.well-known/oauth-authorization-server`: the broker's
    /// Authorization Server Metadata (RFC 8414), so services can find its keys
    /// and endpoints. It issues tokens by exchange only, so there's no
    /// authorization endpoint. With providers people sign in with, it also
    /// says which, so a client needs only the broker's URL.
    async fn metadata(&self) -> v1::MetadataResponse {
        let policy = self.config.policy();
        let issuer = &policy.issuer;
        let url = |path: &str| format!("{issuer}{path}").parse();
        let (Ok(jwks_uri), Ok(token_endpoint), Ok(revocation_endpoint)) = (
            url("/.well-known/jwks"),
            url("/oauth/token"),
            url("/oauth/revoke"),
        ) else {
            error!(%issuer, "the issuer makes no URLs");
            return v1::MetadataResponse::InternalServerError(Error::new(
                ErrorCode::ServerError,
                "the broker is misconfigured; its logs say why",
            ));
        };
        v1::MetadataResponse::Ok(AuthorizationServerMetadata {
            issuer: issuer.clone(),
            jwks_uri,
            token_endpoint,
            revocation_endpoint,
            response_types_supported: vec![],
            grant_types_supported: vec![TOKEN_EXCHANGE.into()],
            token_endpoint_auth_methods_supported: Some(vec!["none".into()]),
            revocation_endpoint_auth_methods_supported: Some(vec!["none".into()]),
            identity_providers: Some(
                policy
                    .identity_providers()
                    .map(|provider| IdentityProvider {
                        name: provider.name.clone(),
                        issuer: provider.issuer.clone(),
                        client_id: provider.client_id.clone().unwrap_or_default(),
                    })
                    .collect::<Vec<_>>(),
            )
            .filter(|providers| !providers.is_empty()),
        })
    }

    /// `GET /.well-known/openid-configuration`: the broker's OpenID Provider
    /// Metadata (OpenID Connect Discovery 1.0), for services that find an
    /// issuer's keys only that way, such as AWS IAM. There's no authorization
    /// endpoint, as for GitHub's and Kubernetes' issuers; the rest is what
    /// Discovery requires.
    async fn openid_configuration(&self) -> v1::OpenidConfigurationResponse {
        let issuer = &self.config.policy().issuer;
        let Ok(jwks_uri) = format!("{issuer}/.well-known/jwks").parse() else {
            error!(%issuer, "the issuer makes no URLs");
            return v1::OpenidConfigurationResponse::InternalServerError(Error::new(
                ErrorCode::ServerError,
                "the broker is misconfigured; its logs say why",
            ));
        };
        v1::OpenidConfigurationResponse::Ok(OpenIdProviderMetadata {
            issuer: issuer.clone(),
            jwks_uri,
            response_types_supported: vec!["id_token".into()],
            subject_types_supported: vec!["public".into()],
            id_token_signing_alg_values_supported: vec!["RS256".into()],
        })
    }

    /// `GET /.well-known/jwks`: the broker's public key, or none when no
    /// signing key is bound.
    async fn jwks(&self) -> v1::JwksResponse {
        SendFuture::new(async move {
            let keys = async {
                let Some(key) = signing_key(&self.config).await? else {
                    return Ok(Jwks { keys: vec![] });
                };
                let jwk = serde_json::from_value(key.public_jwk()).map_err(|err| {
                    Error::new(ErrorCode::ServerError, format!("the public key: {err}"))
                })?;
                Ok::<_, Error>(Jwks { keys: vec![jwk] })
            };
            match keys.await {
                Ok(jwks) => v1::JwksResponse::Ok(jwks),
                Err(err) => {
                    error!(error = err.error.as_str(), message = %err.error_description);
                    v1::JwksResponse::InternalServerError(Error::new(
                        err.error,
                        "the broker failed; its logs say why",
                    ))
                }
            }
        })
        .await
    }
}

/// What revoking a token did.
enum RevokeStatus {
    /// The broker minted it, and it's deleted: its ID.
    Deleted(String),
    /// Cloudflare doesn't know it: invalid, expired, deleted, or another
    /// account's.
    Gone,
    /// The broker didn't mint it, so it's left alone: its ID.
    NotMinted(String),
}

/// `cloudflare-sts:<provider>:<sub>`, whatever the issuer, cut to fit: what a token
/// minted for `identity` is named.
fn token_name(provider: &ProviderConfig, identity: &Jwt) -> String {
    let sub = identity.claims.sub().unwrap_or("unknown");
    let name = format!("{TOKEN_PREFIX}{}:{sub}", provider.name);
    name.chars().take(NAME_MAX).collect()
}

/// A Cloudflare API failure: `temporarily_unavailable`, a `503`, which says
/// why only in the log.
fn upstream<E: std::fmt::Debug>(what: &str, err: ApiOpError<E>) -> Error {
    let why = match &err {
        ApiOpError::Api(api) => format!("returned {}", api.status),
        ApiOpError::Transport(err) => err.to_string(),
    };
    Error::new(
        ErrorCode::TemporarilyUnavailable,
        format!("Cloudflare: {what}: {why}"),
    )
}

/// A Cloudflare API answer without what it should have had, reported as
/// [`upstream`] reports a failure.
fn missing(what: &str) -> Error {
    Error::new(
        ErrorCode::TemporarilyUnavailable,
        format!("Cloudflare: {what} returned nothing"),
    )
}

/// The claims of an access token for another service (RFC 9068), issued at
/// `now` (seconds since the epoch), and when it expires. It never outlives the
/// token the caller presented. Its `client_id` is the provider's name: the
/// caller doesn't authenticate as a client, and it's the provider that says
/// who it is.
///
/// It has the claims the policy matched on, under the issuer's names, so the
/// service can match on the same ones. Nothing else: an issuer's other claims,
/// such as an email, stay behind. Signing adds its `jti`.
fn payload(
    issuer: &str,
    identity: &Jwt,
    provider: &ProviderConfig,
    profile: &ProfileConfig,
    ttl: u64,
    now: u64,
) -> Result<(AccessTokenClaims, u64), Error> {
    let claims = &identity.claims;
    let not_after = claims.exp().unwrap_or(u64::MAX);
    let expires_at = (now + ttl / 1000).min(not_after);
    // The caller's token was accepted with clock tolerance; a token that can't
    // live at all isn't issued.
    if expires_at <= now {
        return Err(Error::new(
            ErrorCode::InvalidRequest,
            "the subject token has expired",
        ));
    }

    let mut other = provider.matched_claims(Some(profile), claims);
    for (name, value) in [
        ("provider", json!(provider.name)),
        ("profile", json!(profile.name)),
        ("nbf", json!(now)),
    ] {
        other.insert(name.into(), value);
    }
    let sub = match identity.claims.sub() {
        Some(sub) => sub.to_string(),
        None => format!("{}:unknown", provider.name),
    };
    let payload = AccessTokenClaims {
        iss: issuer.to_string(),
        sub,
        aud: profile.audience.clone(),
        client_id: provider.name.clone(),
        iat: now,
        exp: expires_at,
        other,
    };
    Ok((payload, expires_at))
}

#[cfg(test)]
mod tests {
    use serde_json::{Map, Value};

    use super::*;
    use crate::service::config::tests::{CACHE, NOW, claims, parse, policy};

    fn identity(claims: Map<String, Value>) -> Jwt {
        Jwt {
            header: oidc::Header::default(),
            claims: claims.into(),
        }
    }

    #[test]
    fn names_tokens_after_the_provider_and_the_subject() {
        let policy = parse(&policy());
        let provider = &policy.providers[0];
        assert_eq!(
            token_name(provider, &identity(claims())),
            "cloudflare-sts:github:repo:example-org/app:ref:refs/heads/main"
        );
        assert_eq!(
            token_name(provider, &identity(Map::new())),
            "cloudflare-sts:github:unknown"
        );

        let mut long = claims();
        long.insert("sub".into(), "x".repeat(200).into());
        let name = token_name(provider, &identity(long));
        assert_eq!(name.chars().count(), 120);
        assert!(name.starts_with("cloudflare-sts:github:xxx"));
    }

    #[test]
    fn copies_only_the_claims_the_policy_matches_on() {
        let policy = parse(&policy());
        let (provider, profile) = (&policy.providers[0], &policy.profiles[1]);
        let mut matched = claims();
        matched.insert("email".into(), "someone@example.com".into());
        let (issued, expires_at) = payload(
            "https://cloudflare-sts-api.example.com",
            &identity(matched),
            provider,
            profile,
            15 * 60_000,
            NOW,
        )
        .unwrap();
        assert_eq!(expires_at, NOW + 300, "never past the caller's own token");
        assert_eq!(
            Value::Object(oidc::Claims::from(issued).into_inner()),
            json!({
                "ref": "refs/heads/main",
                "repository_owner_id": "100000001",
                "provider": "github",
                "profile": "nix-push",
                "iss": "https://cloudflare-sts-api.example.com",
                "aud": CACHE,
                "sub": "repo:example-org/app:ref:refs/heads/main",
                "client_id": "github",
                "iat": NOW,
                "nbf": NOW,
                "exp": NOW + 300,
            })
        );

        let mut expired = claims();
        expired.insert("exp".into(), json!(NOW));
        let err = payload(
            "https://x.example.com",
            &identity(expired),
            provider,
            profile,
            60_000,
            NOW,
        )
        .unwrap_err();
        assert_eq!(err.error_description, "the subject token has expired");
    }
}
