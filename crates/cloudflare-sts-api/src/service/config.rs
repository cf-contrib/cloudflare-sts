//! The Worker's configuration, read from its bindings.
//!
//! [`Config::load`] is the only place that reads `Env`: the crate root
//! builds one per request and hands it to the handler and the auth layer,
//! which take what they need from it.
//!
//! The policy is read from Workers KV and held by the isolate for
//! [`POLICY_TTL`], so a change takes effect within about that long, plus KV's
//! own edge caching. It fails closed: once the held policy has expired, a KV
//! that can't be read, or a policy that's missing or invalid, fails every
//! request; an expired policy is never served.
//!
//! An unset account, an unreadable or invalid policy, or a Cloudflare token
//! that isn't a Secrets Store binding fails it, and the Worker serves nothing
//! until it's fixed. The secrets' values are read only when they're used, so a
//! rotated one takes effect on the next request.
//!
//! The policy's format is here too: [`PolicyConfig`], its providers and
//! profiles and bucket prefixes, and what parsing checks, the guardrails among
//! it. It's in two parts, two KV keys: the configuration, in TOML,
//! says what the broker trusts and what a profile hands out; the Cedar policy
//! ([`authz`](super::authz)) says who gets it. Checking a token against a
//! provider is in the auth [`layer`](super::layer); what a caller gets, in the
//! [`handler`](super::handler).

use std::{cell::RefCell, collections::BTreeMap, sync::Arc};

use cloudflare::v4::{
    HttpClient, IamEffect, IamPermissionGroup,
    IamPermissionsGroupResponseCollectionResultItem as PermissionGroup,
    IamPolicyWithPermissionGroupsAndResources as IamPolicy, IamResources,
    IamResourcesTypeObjectNested, IamResourcesTypeObjectNestedAdditionalProperty,
    IamResourcesTypeObjectString,
};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};
use tracing::warn;
use worker::{Env, Error, SecretStore, js_sys, wasm_bindgen::JsValue};

use super::authz::{Authz, Verdict};
use crate::oidc::{Provider, Providers, check_url};

/// The binding of the account the Cloudflare token belongs to, and tokens are
/// minted in.
const ACCOUNT_KEY: &str = "CLOUDFLARE_STS_API_ACCOUNT_ID";

/// The Workers KV binding the policy is read from.
const POLICY_BINDING: &str = "CLOUDFLARE_STS_API_POLICY_KV";

/// The keys in that namespace: the configuration, TOML (or JSON), and the
/// Cedar policy.
const CONFIG_KEY: &str = "config";
const POLICY_KEY: &str = "policy";

/// Where the policy was before it moved to KV: a plain-text variable. Still
/// set, it's refused with where it went, not ignored.
const OLD_POLICY_VAR: &str = "CLOUDFLARE_STS_API_POLICY";

/// How long an isolate keeps the policy it parsed before reading it again.
const POLICY_TTL: f64 = 60_000.0;

/// The binding of the Cloudflare token: account-owned, with "Account API Tokens
/// Write", plus R2 permissions covering what profiles' buckets delegate.
const CLOUDFLARE_TOKEN_KEY: &str = "CLOUDFLARE_STS_API_CLOUDFLARE_TOKEN";

/// The binding of the RSA private key (PKCS#8 PEM, at least 2048 bits) the
/// broker signs its own tokens with. Optional: without it, the broker issues
/// none and publishes no keys.
const SIGNING_KEY_KEY: &str = "CLOUDFLARE_STS_API_SIGNING_KEY";

/// Where Cloudflare's API is.
const CLOUDFLARE_URL: &str = "https://api.cloudflare.com/client/v4";

/// The audience for Cloudflare API tokens and R2 credentials, and every
/// profile's default.
pub const CLOUDFLARE_AUDIENCE: &str = "https://api.cloudflare.com";

/// The scopes of Cloudflare's permission groups, which a token policy's
/// resources fall under.
const CLOUDFLARE_ACCOUNT_SCOPE: &str = "com.cloudflare.api.account";
const CLOUDFLARE_ZONE_SCOPE: &str = "com.cloudflare.api.account.zone";
const CLOUDFLARE_R2_SCOPE: &str = "com.cloudflare.edge.r2.bucket";

const SECOND: u64 = 1000;
const MINUTE: u64 = 60 * SECOND;
const HOUR: u64 = 60 * MINUTE;

/// The shortest TTL anything is issued for.
const MIN_TTL: u64 = MINUTE;
const MAX_TTL: u64 = 24 * HOUR;
const DEFAULT_TTL: u64 = 15 * MINUTE;
const DEFAULT_MAX_TTL: u64 = HOUR;

/// What the Worker is configured with, from its bindings.
pub struct Config {
    /// The policy in KV, checked against the account.
    policy: Arc<PolicyConfig>,
    /// The account tokens are minted in, and its API.
    cloudflare: CloudflareConfig,
    /// `CLOUDFLARE_STS_API_SIGNING_KEY`'s binding. None issues no tokens of
    /// the broker's own.
    signing_key: Option<Secret>,
}

impl Config {
    /// Reads the Worker's bindings, and the policy from KV unless this
    /// isolate has one that hasn't expired.
    ///
    /// # Errors
    ///
    /// When the account isn't set, a secret isn't a Secrets Store binding, or
    /// the policy can't be read from KV or is invalid.
    pub async fn load(env: &Env) -> worker::Result<Self> {
        let cloudflare = CloudflareConfig::from_env(env)?;
        let policy = load_policy(env, cloudflare.account_id()).await?;
        Ok(Self {
            policy,
            cloudflare,
            signing_key: Secret::from_env(env, SIGNING_KEY_KEY)?,
        })
    }

    /// The policy.
    pub fn policy(&self) -> &PolicyConfig {
        &self.policy
    }

    /// The account tokens are minted in, and its API.
    pub fn cloudflare(&self) -> &CloudflareConfig {
        &self.cloudflare
    }

    /// Reads the signing key, a PKCS#8 PEM, or `None` if none is bound.
    pub async fn signing_key(&self) -> worker::Result<Option<String>> {
        match &self.signing_key {
            Some(secret) => secret.read().await.map(Some),
            None => Ok(None),
        }
    }
}

thread_local! {
    /// The last policy this isolate parsed, and when it expires (ms since the
    /// epoch). Only a valid policy is kept.
    static POLICY: RefCell<Option<(f64, Arc<PolicyConfig>)>> = const { RefCell::new(None) };
}

/// The policy: the isolate's, if it hasn't expired, else read from KV and
/// parsed. A failed read or parse leaves nothing held and fails the request.
async fn load_policy(env: &Env, account_id: &str) -> worker::Result<Arc<PolicyConfig>> {
    let now = js_sys::Date::now();
    let held = POLICY.with(|held| {
        held.borrow()
            .as_ref()
            .filter(|(expires, _)| *expires > now)
            .map(|(_, policy)| policy.clone())
    });
    if let Some(policy) = held {
        return Ok(policy);
    }
    POLICY.with(|held| held.borrow_mut().take());

    let moved = js_sys::Reflect::get(env.as_ref(), &JsValue::from_str(OLD_POLICY_VAR))
        .is_ok_and(|binding| !binding.is_undefined());
    if moved {
        return Err(Error::RustError(format!(
            "{OLD_POLICY_VAR} is no longer read: the policy is keys `{CONFIG_KEY}` (TOML) and `{POLICY_KEY}` (Cedar) in the Workers KV binding {POLICY_BINDING}"
        )));
    }
    let kv = env.kv(POLICY_BINDING).map_err(|why| {
        Error::RustError(format!(
            "{POLICY_BINDING} must be a Workers KV binding: {why}"
        ))
    })?;
    let read = |key: &'static str| {
        let kv = &kv;
        async move {
            kv.get(key)
                .text()
                .await
                .map_err(|why| {
                    Error::RustError(format!("{POLICY_BINDING}: `{key}` can't be read: {why}"))
                })?
                .ok_or_else(|| Error::RustError(format!("{POLICY_BINDING}: `{key}` isn't set")))
        }
    };
    let (config, cedar) = (read(CONFIG_KEY).await?, read(POLICY_KEY).await?);
    let policy = PolicyConfig::parse(&config, &cedar, account_id)
        .map(Arc::new)
        .map_err(|why| Error::RustError(format!("{POLICY_BINDING}: {why}")))?;
    POLICY.with(|held| *held.borrow_mut() = Some((now + POLICY_TTL, policy.clone())));
    Ok(policy)
}

/// The Cloudflare account tokens are minted in, and how to reach its API.
pub struct CloudflareConfig {
    /// `CLOUDFLARE_STS_API_ACCOUNT_ID`.
    account_id: String,
    /// `CLOUDFLARE_STS_API_CLOUDFLARE_TOKEN`'s binding, not yet its value.
    token: Secret,
    /// Where its API is.
    url: String,
}

impl CloudflareConfig {
    /// Reads the account and the Cloudflare token's binding.
    fn from_env(env: &Env) -> worker::Result<Self> {
        let var = |key| env.var(key).map(|value| value.to_string()).ok();
        let Some(account_id) = var(ACCOUNT_KEY).filter(|id| !id.is_empty()) else {
            return Err(Error::RustError(format!("{ACCOUNT_KEY} must be set")));
        };
        let token = Secret::from_env(env, CLOUDFLARE_TOKEN_KEY)?.ok_or_else(|| {
            Error::RustError(format!(
                "{CLOUDFLARE_TOKEN_KEY} must be a Secrets Store binding"
            ))
        })?;

        // Only a `stand-ins` build, for the integration tests, takes Cloudflare's
        // API from anywhere but Cloudflare.
        #[cfg(feature = "stand-ins")]
        let url =
            var("CLOUDFLARE_STS_API_CLOUDFLARE_URL").unwrap_or_else(|| CLOUDFLARE_URL.to_string());
        #[cfg(not(feature = "stand-ins"))]
        let url = CLOUDFLARE_URL.to_string();

        Ok(Self {
            account_id,
            token,
            url,
        })
    }

    /// The account tokens are minted in.
    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    /// The API, as the Cloudflare token, read now.
    pub async fn client(&self) -> worker::Result<HttpClient> {
        let token = self.token.read().await?;
        Ok(self.client_as(&token))
    }

    /// One call to the API as the Cloudflare token, for what the generated
    /// client can't say. Returns the status and the JSON body, which isn't
    /// parsed on a non-JSON error page.
    pub(super) async fn call(
        &self,
        method: worker::Method,
        path: &str,
        body: Option<&Value>,
    ) -> worker::Result<(u16, Value)> {
        let token = self.token.read().await?;
        let headers = worker::Headers::new();
        headers.set("authorization", &format!("Bearer {token}"))?;
        headers.set("accept", "application/json")?;
        let mut init = worker::RequestInit::new();
        init.with_method(method);
        if let Some(body) = body {
            headers.set("content-type", "application/json")?;
            init.with_body(Some(JsValue::from_str(&body.to_string())));
        }
        init.with_headers(headers);
        let request = worker::Request::new_with_init(&format!("{}{path}", self.url), &init)?;
        let mut response = worker::Fetch::Request(request).send().await?;
        let status = response.status_code();
        let text = response.text().await.unwrap_or_default();
        Ok((status, serde_json::from_str(&text).unwrap_or(Value::Null)))
    }

    /// The API, as `token`: one a caller presents, say.
    pub fn client_as(&self, token: &str) -> HttpClient {
        HttpClient::new()
            .with_base_url(&self.url)
            .with_api_key(token)
    }
}

/// A secret in Secrets Store, read when it's used.
///
/// Bound as anything else, a plain Worker secret say, it's refused rather than
/// taken as a weaker setup: a Secrets Store secret never passes through
/// Terraform.
struct Secret {
    key: &'static str,
    store: SecretStore,
}

impl Secret {
    /// The secret bound as `key`, or `None` if nothing is.
    fn from_env(env: &Env, key: &'static str) -> worker::Result<Option<Self>> {
        if let Ok(store) = env.secret_store(key) {
            return Ok(Some(Self { key, store }));
        }
        let bound = js_sys::Reflect::get(env.as_ref(), &JsValue::from_str(key))
            .is_ok_and(|binding| !binding.is_undefined());
        if bound {
            return Err(Error::RustError(format!(
                "{key} must be a Secrets Store binding"
            )));
        }
        Ok(None)
    }

    async fn read(&self) -> worker::Result<String> {
        let key = self.key;
        match self.store.get().await {
            Ok(Some(value)) if !value.is_empty() => Ok(value),
            Ok(_) => Err(Error::RustError(format!("{key} is empty"))),
            Err(err) => Err(Error::RustError(format!("{key} can't be read: {err}"))),
        }
    }
}

/// The policy: the OIDC issuers the broker trusts, its providers, and what
/// their callers may get, its profiles.
///
/// It knows no issuer by name: who may do what is in the Cedar policy.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    /// The configuration's format version: 4.
    version: u64,
    /// The broker's own URL: the issuer of the tokens it signs for other
    /// services.
    pub issuer: String,
    pub providers: Providers<ProviderConfig>,
    /// What profiles that don't say get.
    #[serde(default)]
    defaults: DefaultsConfig,
    pub profiles: Vec<ProfileConfig>,
    /// Who gets what. Not in the TOML.
    #[serde(skip)]
    authz: Authz,
}

impl PolicyConfig {
    /// The policy: the configuration, in TOML (or JSON, which is what
    /// Terraform writes), and the Cedar policy, checked against the account
    /// tokens are minted in.
    ///
    /// # Errors
    ///
    /// The first problem found: the guardrails are checked here, so an unsafe
    /// policy never serves a request.
    pub fn parse(config: &str, cedar: &str, account_id: &str) -> Result<Self, String> {
        let bad =
            |err: &dyn std::fmt::Display| format!("config must be TOML, or a JSON object: {err}");
        let mut policy: Self = if config.trim_start().starts_with('{') {
            serde_json::from_str(config).map_err(|err| bad(&err))?
        } else {
            toml::from_str(config).map_err(|err| bad(&err))?
        };
        policy.check(account_id)?;
        let authz = Authz::parse(cedar)?;
        authz.check(
            policy.providers.iter().map(|p| p.name.as_str()),
            policy.profiles.iter().map(|p| (p.name.as_str(), p.enabled)),
        )?;
        policy.authz = authz;
        Ok(policy)
    }

    /// Whether `provider` lets the token with `claims` in at all: its tenant,
    /// pinned. Checked as the token is verified.
    pub fn admit(&self, provider: &str, claims: &Map<String, Value>) -> Verdict {
        self.authz.admit(provider, claims, CLOUDFLARE_AUDIENCE)
    }

    /// What deserializing can't check, filling in each profile's provider and
    /// TTLs on the way.
    fn check(&mut self, account_id: &str) -> Result<(), String> {
        if self.version != 4 {
            return Err("version must be 4".to_string());
        }
        check_origin(&self.issuer).map_err(|why| format!("issuer {why}"))?;

        for (index, provider) in self.providers.iter_mut().enumerate() {
            provider.resolve(&format!("providers[{index}]"))?;
        }
        self.providers.check("providers")?;
        for (index, provider) in self.providers.iter().enumerate() {
            let at = format!("providers[{index}]");
            provider.check(&at)?;
            if self.providers[..index]
                .iter()
                .any(|other| other.name == provider.name)
            {
                return Err(format!("{at}: {} is named twice", provider.name));
            }
        }

        let defaults = self.defaults.resolved();
        check_ttls("defaults", defaults.ttl, defaults.max_ttl)?;

        if self.profiles.is_empty() {
            return Err("profiles must name at least one profile".to_string());
        }
        for index in 0..self.profiles.len() {
            let at = format!("profiles[{index}]");
            let (earlier, rest) = self.profiles.split_at_mut(index);
            let profile = &mut rest[0];
            if earlier.iter().any(|other| other.name == profile.name) {
                return Err(format!("{at}: {} is named twice", profile.name));
            }
            profile.resolve(&at, &self.providers, &defaults)?;
            profile.check(&at, &self.issuer, account_id)?;
        }
        Ok(())
    }

    /// The providers people sign in with: those with a `client_id`.
    pub fn identity_providers(&self) -> impl Iterator<Item = &ProviderConfig> {
        self.providers
            .iter()
            .filter(|provider| provider.client_id.is_some())
    }

    /// The provider a token's claims say it comes from, by its `iss`.
    ///
    /// # Errors
    ///
    /// When no provider is for that issuer.
    pub fn provider_for(&self, claims: &Map<String, Value>) -> Result<&ProviderConfig, String> {
        let iss = claims
            .get("iss")
            .and_then(Value::as_str)
            .unwrap_or_default();
        self.providers.find(iss).ok_or_else(|| {
            let shown: String = iss.chars().take(200).collect();
            format!("no provider is for issuer {shown}")
        })
    }

    /// The profile a caller gets: the ones `requested` names (the request's
    /// `scope`), each of which its token must be allowed, or the only one
    /// it's allowed when none is named. Several are combined into one, as
    /// [`ProfileConfig::combined`] says. Whether its provider lets it in was
    /// checked when it was verified.
    ///
    /// # Errors
    ///
    /// Why it gets none: [`Refusal::Scope`] when a scope can't be had,
    /// [`Refusal::Request`] when none was named and the token doesn't
    /// settle on one.
    pub fn profiles_for(
        &self,
        provider: &str,
        claims: &Map<String, Value>,
        requested: &[&str],
        audience: &str,
    ) -> Result<(ProfileConfig, Vec<String>), Refusal> {
        // The `@id`s of the policies that allowed it, if any did. A `forbid`
        // that fired is logged: the caller is only told nothing matched.
        let matches = |p: &ProfileConfig| -> Option<Vec<String>> {
            if !p.enabled {
                return None;
            }
            let verdict = self.authz.profile(&p.name, claims, &p.audience);
            if verdict.allowed {
                return Some(verdict.policies);
            }
            if !verdict.policies.is_empty() {
                warn!(event = "policy.forbid", profile = %p.name, policies = ?verdict.policies);
            }
            None
        };
        let profiles = self
            .profiles
            .iter()
            .filter(|p| p.provider == provider && p.audience == audience);

        if !requested.is_empty() {
            // Each scope once, in the order given.
            let mut names: Vec<&str> = Vec::new();
            for name in requested {
                if !names.contains(name) {
                    names.push(name);
                }
            }
            let mut granted: Vec<(&ProfileConfig, Vec<String>)> = Vec::new();
            for name in names {
                if let Some(profile) = profiles.clone().find(|p| p.name == name)
                    && let Some(policies) = matches(profile)
                {
                    granted.push((profile, policies));
                    continue;
                }
                return Err(Refusal::Scope(
                    match self.profiles.iter().find(|p| p.name == name) {
                        None => format!("unknown scope {name}"),
                        Some(named) if named.provider != provider => {
                            format!("scope {name} isn't for provider {provider}")
                        }
                        Some(named) if named.audience != audience => {
                            format!("scope {name} isn't for {audience}")
                        }
                        Some(named) if !named.enabled => format!("scope {name} is disabled"),
                        Some(_) => format!("scope {name} doesn't match the token"),
                    },
                ));
            }
            let allowed_by = granted
                .iter()
                .flat_map(|(_, policies)| policies.iter().cloned())
                .fold(Vec::<String>::new(), |mut all, id| {
                    if !all.contains(&id) {
                        all.push(id);
                    }
                    all
                });
            let combined =
                ProfileConfig::combined(&granted.iter().map(|(p, _)| *p).collect::<Vec<_>>())
                    .map_err(Refusal::Scope)?;
            return Ok((combined, allowed_by));
        }

        let candidates: Vec<(&ProfileConfig, Vec<String>)> = profiles
            .filter_map(|p| matches(p).map(|policies| (p, policies)))
            .collect();
        match candidates.as_slice() {
            [] => Err(Refusal::Request("no profile matches the token".into())),
            [(profile, policies)] => Ok(((*profile).clone(), policies.clone())),
            several => {
                let names: Vec<&str> = several.iter().map(|(p, _)| p.name.as_str()).collect();
                Err(Refusal::Request(format!(
                    "profiles {} all match the token: name one in scope",
                    names.join(", ")
                )))
            }
        }
    }
}

/// The policy's `defaults`: what profiles that don't say get, in
/// milliseconds. Written as durations, `90s`, `15m`, `1h30m`; zero is unset.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct DefaultsConfig {
    #[serde(default, deserialize_with = "duration")]
    ttl: u64,
    #[serde(default, deserialize_with = "duration")]
    max_ttl: u64,
}

impl DefaultsConfig {
    /// These, with what's unset the broker's own.
    fn resolved(&self) -> Self {
        let max_ttl = nonzero_or(self.max_ttl, DEFAULT_MAX_TTL);
        let ttl = nonzero_or(self.ttl, DEFAULT_TTL.min(max_ttl));
        Self { ttl, max_ttl }
    }
}

/// An OIDC issuer the broker trusts, and which of its tokens.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderConfig {
    /// What profiles name it by, and minted tokens are named after.
    pub name: String,
    /// Matched exactly against a token's `iss`.
    pub issuer: String,
    /// A value the token's `aud` must have: its `client_id` if left out.
    #[serde(default)]
    pub audience: String,
    /// Where its keys are. `None` means its metadata says.
    #[serde(default)]
    pub jwks_uri: Option<String>,
    /// The `typ` its tokens must have (RFC 8725 §3.11), such as `at+jwt` for
    /// another broker's access tokens, so another kind of token its issuer
    /// signs can't pass for one. `None` takes any.
    #[serde(default)]
    pub typ: Option<String>,
    /// The OAuth client people sign in to it as, for an ID token whose `aud`
    /// is this client: the metadata tells clients such as cf-vault. `None` for
    /// a provider only machines get tokens from, such as GitHub Actions.
    #[serde(default)]
    pub client_id: Option<String>,
}

/// What the auth layer verifies a token from it against.
impl Provider for ProviderConfig {
    fn issuer(&self) -> &str {
        &self.issuer
    }

    fn audience(&self) -> &str {
        &self.audience
    }

    fn jwks_uri(&self) -> Option<&str> {
        self.jwks_uri.as_deref()
    }

    fn typ(&self) -> Option<&str> {
        self.typ.as_deref()
    }
}

impl ProviderConfig {
    /// Fills in the audience from the client ID when it's left out, before
    /// the providers are checked.
    fn resolve(&mut self, at: &str) -> Result<(), String> {
        let Some(client_id) = &self.client_id else {
            return Ok(());
        };
        if client_id.is_empty() {
            return Err(format!("{at}.client_id must not be empty"));
        }
        // An ID token's aud is the client it was issued to: another audience
        // would refuse every token people sign in for.
        if self.audience.is_empty() {
            self.audience = client_id.clone();
        } else if self.audience != *client_id {
            return Err(format!(
                "{at}.audience must be its client_id, {client_id}, or left out"
            ));
        }
        Ok(())
    }

    fn check(&self, at: &str) -> Result<(), String> {
        // Its issuer, jwks_uri and audience are the providers' check.
        check_provider_name(&self.name).map_err(|why| format!("{at}.name {why}"))?;
        if self.typ.as_deref().is_some_and(str::is_empty) {
            return Err(format!("{at}.typ must not be empty"));
        }
        // Guardrail 1, that the provider is pinned, is the policy's: it must
        // admit each provider.
        Ok(())
    }
}

/// Why a caller gets no profile.
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    /// A scope it asked for can't be had, or the scopes can't be combined:
    /// RFC 6749's `invalid_scope`.
    Scope(String),
    /// It named none, and the token doesn't settle on one.
    Request(String),
}

/// What a caller may get, and who may get it.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileConfig {
    pub name: String,
    /// The provider whose tokens it's for. May be left out when the policy
    /// has only one, which it's then filled in with.
    #[serde(default)]
    pub provider: String,
    /// Off switch for incidents: a disabled profile never matches, even when
    /// a request names it.
    #[serde(default = "ProfileConfig::enabled_by_default")]
    pub enabled: bool,
    /// What it issues for: Cloudflare credentials, or the broker's own token
    /// for another service.
    #[serde(default = "ProfileConfig::cloudflare_audience")]
    pub audience: String,
    /// The claims of the caller's token to log and to copy into a token the
    /// broker signs for another service: what that service may match on, as
    /// the Cedar policy matched on them. Nothing else is copied.
    #[serde(default)]
    pub forward_claims: Vec<String>,
    /// For everything it hands out, the token and the bucket's credentials,
    /// in milliseconds. Taken from the defaults when unset.
    #[serde(default, deserialize_with = "duration")]
    pub ttl: u64,
    /// The longest TTL a request can ask for, in milliseconds.
    #[serde(default, deserialize_with = "duration")]
    pub max_ttl: u64,
    pub token: Option<TokenConfig>,
    /// The bucket its caller gets R2 credentials for. One per profile, so the
    /// action always exports them under the same names.
    pub bucket: Option<BucketConfig>,
    /// The Access application its caller gets a service token for. One per
    /// profile, so the action always exports it under the same names.
    pub access: Option<AccessConfig>,
}

impl ProfileConfig {
    fn enabled_by_default() -> bool {
        true
    }

    fn cloudflare_audience() -> String {
        CLOUDFLARE_AUDIENCE.to_string()
    }

    /// Fills in what the policy leaves to be: its provider, when there's
    /// only one, and its TTLs from `defaults`.
    fn resolve(
        &mut self,
        at: &str,
        providers: &Providers<ProviderConfig>,
        defaults: &DefaultsConfig,
    ) -> Result<(), String> {
        if self.provider.is_empty() {
            // With one provider, it's the only one a profile can be for.
            let [only] = &providers[..] else {
                return Err(format!("{at}.provider is required with several providers"));
            };
            self.provider = only.name.clone();
        }
        if !providers.iter().any(|p| p.name == self.provider) {
            return Err(format!(
                "{at}.provider: no provider is named {}",
                self.provider
            ));
        }
        self.max_ttl = nonzero_or(self.max_ttl, defaults.max_ttl);
        self.ttl = nonzero_or(self.ttl, defaults.ttl);
        Ok(())
    }

    /// The claims in `claims` that `forward_claims` names: what's worth writing
    /// down about a caller, and copying into the broker's own tokens. Never
    /// secret.
    pub fn forwarded_claims(&self, claims: &Map<String, Value>) -> Map<String, Value> {
        /// A string, number or boolean, or a list of them.
        fn copyable(value: &Value) -> bool {
            match value {
                Value::String(text) => !text.is_empty(),
                Value::Number(_) | Value::Bool(_) => true,
                Value::Array(values) => values.iter().all(|v| !v.is_array() && copyable(v)),
                _ => false,
            }
        }

        self.forward_claims
            .iter()
            .filter_map(|name| {
                let value = claims.get(name).filter(|v| copyable(v))?;
                Some((name.clone(), value.clone()))
            })
            .collect()
    }

    /// The TTL to issue with, in milliseconds: the requested one, clamped to
    /// `max_ttl` rather than refused, or the profile's.
    ///
    /// # Errors
    ///
    /// When the requested one isn't a duration of at least a minute.
    pub fn ttl_for(&self, requested: Option<&str>) -> Result<u64, String> {
        let Some(requested) = requested else {
            return Ok(self.ttl);
        };
        match parse_duration(requested) {
            Some(ttl) if ttl >= MIN_TTL => Ok(ttl.min(self.max_ttl)),
            _ => Err(format!("ttl {requested} isn't a duration of at least 1m")),
        }
    }

    /// One profile that grants what all of `profiles` do, for a request that
    /// names several scopes. They are for Cloudflare, and their token
    /// policies add up to one token. A bucket's credentials are for one
    /// bucket, so at most one profile may have one. The TTLs are the
    /// shortest, so nothing outlives what any of them allows. The name is
    /// the scopes, space-delimited, which is what the response says was
    /// granted.
    ///
    /// # Errors
    ///
    /// Why they can't be combined.
    fn combined(profiles: &[&ProfileConfig]) -> Result<ProfileConfig, String> {
        let [first, rest @ ..] = profiles else {
            return Err("no scope".into());
        };
        if rest.is_empty() {
            return Ok((*first).clone());
        }
        let names = profiles.iter().map(|p| p.name.as_str());
        if first.audience != CLOUDFLARE_AUDIENCE {
            // The broker's own token carries one profile's claims.
            return Err(format!(
                "scopes {} are for {}, which takes one scope",
                names.collect::<Vec<_>>().join(", "),
                first.audience
            ));
        }
        let with_bucket: Vec<&str> = profiles
            .iter()
            .filter(|p| p.bucket.is_some())
            .map(|p| p.name.as_str())
            .collect();
        if with_bucket.len() > 1 {
            return Err(format!(
                "scopes {} each have a bucket, and R2 credentials are for one: ask for one of them",
                with_bucket.join(", ")
            ));
        }
        let with_access: Vec<&str> = profiles
            .iter()
            .filter(|p| p.access.is_some())
            .map(|p| p.name.as_str())
            .collect();
        if with_access.len() > 1 {
            return Err(format!(
                "scopes {} each have an access, and a service token is for one application: ask for one of them",
                with_access.join(", ")
            ));
        }
        let mut forward_claims: Vec<String> = Vec::new();
        for claim in profiles.iter().flat_map(|p| &p.forward_claims) {
            if !forward_claims.contains(claim) {
                forward_claims.push(claim.clone());
            }
        }
        let policies: Vec<TokenPolicyConfig> = profiles
            .iter()
            .filter_map(|p| p.token.as_ref())
            .flat_map(|t| t.policies.iter().cloned())
            .collect();
        Ok(ProfileConfig {
            name: names.collect::<Vec<_>>().join(" "),
            provider: first.provider.clone(),
            enabled: true,
            audience: first.audience.clone(),
            forward_claims,
            ttl: profiles.iter().map(|p| p.ttl).min().unwrap_or(first.ttl),
            max_ttl: profiles
                .iter()
                .map(|p| p.max_ttl)
                .min()
                .unwrap_or(first.max_ttl),
            token: (!policies.is_empty()).then_some(TokenConfig { policies }),
            bucket: profiles.iter().find_map(|p| p.bucket.clone()),
            access: profiles.iter().find_map(|p| p.access.clone()),
        })
    }

    fn check(&self, at: &str, issuer: &str, account_id: &str) -> Result<(), String> {
        check_profile_name(&self.name).map_err(|why| format!("{at}.name {why}"))?;
        check_forward_claims(&self.forward_claims)
            .map_err(|why| format!("{at}.forward_claims {why}"))?;

        // Guardrail 5: audiences are kept apart. The broker signs its own
        // token for another service; Cloudflare credentials are another
        // profile's job.
        let credentials = self.token.is_some() || self.bucket.is_some() || self.access.is_some();
        if self.audience == CLOUDFLARE_AUDIENCE {
            if !credentials {
                return Err(format!(
                    "{at} must have a token, a bucket, an access, or a mix"
                ));
            }
        } else {
            check_origin(&self.audience).map_err(|why| format!("{at}.audience {why}"))?;
            if self.audience == issuer {
                return Err(format!(
                    "{at}.audience must be another service, not the broker"
                ));
            }
            if credentials {
                return Err(format!(
                    "{at}: a profile for {} can't have a token, a bucket or an access",
                    self.audience
                ));
            }
        }

        if let Some(token) = &self.token {
            token.check(&format!("{at}.token"), account_id)?;
        }
        if let Some(bucket) = &self.bucket {
            bucket.check(&format!("{at}.bucket"))?;
        }
        if let Some(access) = &self.access {
            access.check(&format!("{at}.access"), issuer)?;
        }

        // Guardrail 4: TTLs are capped, well within the 7 days R2 credentials
        // can live.
        check_ttls(at, self.ttl, self.max_ttl)
    }
}

/// A Cloudflare API token: its policies, in Cloudflare's own format, with
/// permission groups by name.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenConfig {
    pub policies: Vec<TokenPolicyConfig>,
}

impl TokenConfig {
    /// The policies, in the API's shape, with each permission's group from
    /// `groups`, the account's.
    ///
    /// # Errors
    ///
    /// A permission no group is named, never silently dropped.
    pub fn iam_policies(&self, groups: &[PermissionGroup]) -> Result<Vec<IamPolicy>, String> {
        self.policies
            .iter()
            .map(|policy| policy.iam_policy(groups))
            .collect()
    }

    fn check(&self, at: &str, account_id: &str) -> Result<(), String> {
        if self.policies.is_empty() {
            return Err(format!("{at}.policies must contain at least one policy"));
        }
        for (index, policy) in self.policies.iter().enumerate() {
            policy.check(&format!("{at}.policies[{index}]"), account_id)?;
        }
        Ok(())
    }
}

/// One of a token's policies.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenPolicyConfig {
    #[serde(default)]
    pub effect: Effect,
    /// Permission-group names, resolved to IDs when a token is minted.
    pub permissions: Vec<String>,
    /// Cloudflare's own token `resources`, e.g.
    /// `com.cloudflare.api.account.zone.<zone_id>: "*"`.
    pub resources: BTreeMap<String, ResourceValue>,
}

impl TokenPolicyConfig {
    /// The policy in the API's shape, with each permission's group from
    /// `groups`, the account's.
    fn iam_policy(&self, groups: &[PermissionGroup]) -> Result<IamPolicy, String> {
        let scope = self.permission_scope();
        let permission_groups = self
            .permissions
            .iter()
            .map(|name| {
                Ok(IamPermissionGroup {
                    id: Self::group_id(groups, name, scope)?,
                    meta: None,
                    name: None,
                })
            })
            .collect::<Result<_, String>>()?;
        Ok(IamPolicy {
            effect: match self.effect {
                Effect::Allow => IamEffect::Allow,
                Effect::Deny => IamEffect::Deny,
            },
            id: None,
            permission_groups,
            resources: self.iam_resources(),
        })
    }

    /// The ID of the group named `name`, or, of several so named, the one at
    /// `scope`.
    fn group_id(groups: &[PermissionGroup], name: &str, scope: &str) -> Result<String, String> {
        let named: Vec<&PermissionGroup> = groups
            .iter()
            .filter(|group| group.name.as_deref() == Some(name))
            .collect();
        let scoped: Vec<&PermissionGroup> = named
            .iter()
            .copied()
            .filter(|group| group.scopes.iter().flatten().any(|s| s == scope))
            .collect();
        let group = match (named.as_slice(), scoped.as_slice()) {
            ([], _) => return Err(format!("no permission group is named {name}")),
            ([group], _) | (_, [group]) => *group,
            _ => {
                return Err(format!(
                    "several permission groups are named {name}, at no one scope of the resources"
                ));
            }
        };
        group
            .id
            .clone()
            .ok_or_else(|| format!("permission group {name} has no ID"))
    }

    /// The resources in the API's shape: all flat values, or all nested
    /// maps, as the policy's checks made sure.
    fn iam_resources(&self) -> IamResources {
        let flat: Option<_> = self
            .resources
            .iter()
            .map(|(key, value)| match value {
                ResourceValue::Flat(value) => Some((key.clone(), value.clone())),
                ResourceValue::Nested(_) => None,
            })
            .collect();
        if let Some(additional_properties) = flat {
            return IamResources::IamResourcesTypeObjectString(IamResourcesTypeObjectString {
                additional_properties,
            });
        }
        let additional_properties = self
            .resources
            .iter()
            .filter_map(|(key, value)| match value {
                ResourceValue::Nested(nested) => Some((
                    key.clone(),
                    IamResourcesTypeObjectNestedAdditionalProperty {
                        additional_properties: nested.clone(),
                    },
                )),
                ResourceValue::Flat(_) => None,
            })
            .collect();
        IamResources::IamResourcesTypeObjectNested(IamResourcesTypeObjectNested {
            additional_properties,
        })
    }

    /// The scope a permission group needs for the resources, used to pick
    /// between same-named groups.
    fn permission_scope(&self) -> &'static str {
        let zone = format!("{CLOUDFLARE_ZONE_SCOPE}.");
        let keys = || self.resources.keys();
        if keys().any(|k| k.starts_with(CLOUDFLARE_R2_SCOPE)) {
            return CLOUDFLARE_R2_SCOPE;
        }
        if keys().any(|k| k.starts_with(&zone)) {
            return CLOUDFLARE_ZONE_SCOPE;
        }
        // Nested form: `account.<id>: { "account.zone.*": "*" }` grants every zone
        // in the account.
        let nested = self.resources.values().any(|value| match value {
            ResourceValue::Nested(nested) => nested.keys().any(|k| k.starts_with(&zone)),
            ResourceValue::Flat(_) => false,
        });
        if nested {
            CLOUDFLARE_ZONE_SCOPE
        } else {
            CLOUDFLARE_ACCOUNT_SCOPE
        }
    }

    fn check(&self, at: &str, account_id: &str) -> Result<(), String> {
        /// A Cloudflare ID: 32 lowercase hex digits.
        fn is_id(value: &str) -> bool {
            value.len() == 32 && value.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f'))
        }

        if self.permissions.is_empty() || self.permissions.iter().any(String::is_empty) {
            return Err(format!(
                "{at}.permissions must name at least one permission group"
            ));
        }
        // Guardrail 3: no token-management permissions, or a caller could
        // mint itself tokens the policy never allowed.
        if self.effect == Effect::Allow
            && let Some(name) = self
                .permissions
                .iter()
                .find(|name| name.to_lowercase().contains("api tokens"))
        {
            return Err(format!(
                "{at}.permissions: {name} isn't grantable: it manages tokens"
            ));
        }

        if self.resources.is_empty() {
            return Err(format!("{at}.resources must name at least one resource"));
        }
        let nested = |value: &ResourceValue| matches!(value, ResourceValue::Nested(_));
        if self.resources.values().any(nested) && !self.resources.values().all(nested) {
            return Err(format!(
                "{at}.resources must be all \"*\" values or all nested maps, as Cloudflare takes them"
            ));
        }
        for key in self.resources.keys() {
            if !key.starts_with("com.cloudflare.") {
                return Err(format!("{at}.resources: {key} isn't a Cloudflare resource"));
            }
            // Tokens are minted in one account; another account's ID is a
            // copy-paste mistake.
            let account = key.strip_prefix("com.cloudflare.api.account.");
            if account.is_some_and(|id| is_id(id) && id != account_id) {
                return Err(format!("{at}.resources: {key} isn't the broker's account"));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Effect {
    #[default]
    Allow,
    Deny,
}

/// A resource in Cloudflare's own token format: flat, such as `"*"`, or a
/// nested map.
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum ResourceValue {
    Flat(String),
    Nested(BTreeMap<String, String>),
}

/// The Cloudflare Access application a profile's caller gets a service token
/// for. The token is tagged with the application's host, which is what an
/// Access policy of `service_token_tag` matches, so it admits this
/// application and no other.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessConfig {
    /// The application's origin, such as `https://nix.example.com`.
    pub audience: String,
}

impl AccessConfig {
    /// The tag every service token for this application carries: a
    /// `service_token_tag` rule with this key and `host()` admits it.
    pub const TAG: &'static str = "cloudflare-sts-audience";

    /// The application's host, which a token's tag holds.
    pub fn host(&self) -> &str {
        self.audience
            .split_once("://")
            .map_or(self.audience.as_str(), |(_, host)| host)
    }

    fn check(&self, at: &str, issuer: &str) -> Result<(), String> {
        check_origin(&self.audience).map_err(|why| format!("{at}.audience {why}"))?;
        if self.audience == issuer {
            return Err(format!(
                "{at}.audience must be another service, not the broker"
            ));
        }
        Ok(())
    }
}

/// A bucket a profile's caller gets R2 credentials for.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BucketConfig {
    pub name: String,
    pub permission: BucketPermission,
    /// What the credentials are limited to. None means the whole bucket.
    #[serde(default)]
    pub prefixes: Vec<PrefixTemplate>,
}

impl BucketConfig {
    fn check(&self, at: &str) -> Result<(), String> {
        // R2's bucket name rules: 3-63 lowercase letters, digits and
        // hyphens, starting and ending with a letter or digit.
        let name = &self.name;
        let allowed = name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
        if !(allowed
            && (3..=63).contains(&name.len())
            && !name.starts_with('-')
            && !name.ends_with('-'))
        {
            return Err(format!("{at}.name must be a valid R2 bucket name"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum BucketPermission {
    ObjectReadWrite,
    ObjectReadOnly,
}

impl BucketPermission {
    /// As the policy writes it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ObjectReadWrite => "object-read-write",
            Self::ObjectReadOnly => "object-read-only",
        }
    }
}

/// A bucket prefix template, its path segments filled in from the caller's
/// claims: `github.com/{repository}/`.
///
/// The prefix is all that keeps one caller out of another's keys, so a
/// placeholder fills whole path segments, the template ends with `/`, and
/// what fills it is checked as strictly as the template was.
#[derive(Clone, Debug, Deserialize)]
#[serde(try_from = "String")]
pub struct PrefixTemplate(Vec<Segment>);

#[derive(Clone, Debug, PartialEq)]
enum Segment {
    Text(String),
    Claim(String),
}

impl TryFrom<String> for PrefixTemplate {
    type Error = String;

    fn try_from(template: String) -> Result<Self, String> {
        let invalid = |why: &str| format!("prefix {template} {why}");
        if template.contains("${") {
            // Terraform's templatefile would fill those in.
            return Err(invalid("must use {claim} placeholders, not ${claim}"));
        }
        // Without it, github.com/org/site would also cover github.com/org/site-old/.
        let Some(path) = template.strip_suffix('/') else {
            return Err(invalid("must end with /"));
        };
        path.split('/')
            .map(|segment| {
                let placeholder = segment.strip_prefix('{').and_then(|s| s.strip_suffix('}'));
                if let Some(claim) = placeholder.filter(|claim| !claim.contains(['{', '}'])) {
                    let named = (1..=64).contains(&claim.len())
                        && claim.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
                    if !named {
                        return Err(invalid("has a placeholder that doesn't name a claim"));
                    }
                    return Ok(Segment::Claim(claim.to_string()));
                }
                // Otherwise two callers could get the same prefix: {owner}{id}
                // is "a1"+"23" and "a"+"123" alike.
                if segment.contains(['{', '}']) {
                    return Err(invalid("must have placeholders as whole path segments, e.g. github.com/{repository}/"));
                }
                if !Self::is_segment(segment) {
                    return Err(invalid("must have path segments of letters, digits, ., _ and -, other than . and .."));
                }
                Ok(Segment::Text(segment.to_string()))
            })
            .collect::<Result<_, _>>()
            .map(Self)
    }
}

impl PrefixTemplate {
    /// A path segment a prefix may have: letters, digits, `.`, `_` and `-`, other
    /// than `.` and `..`.
    fn is_segment(segment: &str) -> bool {
        !segment.is_empty()
            && segment != "."
            && !segment.contains("..")
            && segment
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    }

    /// The prefix for a caller with `claims`.
    ///
    /// A value can span path segments, `owner/repo`, only when it fills the
    /// template's one placeholder. With several, each fills exactly one, so two
    /// callers can never fill a template to the same prefix.
    ///
    /// # Errors
    ///
    /// The claim that's missing or can't be used in a key.
    pub fn fill(&self, claims: &Map<String, Value>) -> Result<String, String> {
        let placeholders = self
            .0
            .iter()
            .filter(|s| matches!(s, Segment::Claim(_)))
            .count();
        let mut prefix = String::new();
        for segment in &self.0 {
            match segment {
                Segment::Text(text) => prefix.push_str(text),
                Segment::Claim(claim) => {
                    let value = match claims.get(claim) {
                        Some(Value::String(text)) => text.clone(),
                        Some(Value::Number(number)) => number.to_string(),
                        _ => String::new(),
                    };
                    let usable = !value.is_empty()
                        && value.split('/').all(Self::is_segment)
                        && (placeholders == 1 || !value.contains('/'));
                    if !usable {
                        return Err(format!(
                            "the {claim} claim is missing or can't be used in a prefix"
                        ));
                    }
                    prefix.push_str(&value);
                }
            }
            prefix.push('/');
        }
        Ok(prefix)
    }
}

/// Whether `name` can name a provider. It goes into the names of minted
/// tokens, which `:` separates, and into `client_id`.
fn check_provider_name(name: &str) -> Result<(), &'static str> {
    if !is_name(name, &['_', '.', '-'], 64) {
        return Err("must be 1-64 of [A-Za-z0-9_.-], starting with a letter or digit");
    }
    Ok(())
}

/// Whether `name` can name a profile. It's never part of a token name, a path
/// or a key, so it can say whose it is: `<owner>/<repo>:<workflow>.<job>`.
fn check_profile_name(name: &str) -> Result<(), &'static str> {
    if !is_name(name, &['_', '.', ':', '/', '-'], 255) {
        return Err("must be 1-255 of [A-Za-z0-9_.:/-], starting with a letter or digit");
    }
    Ok(())
}

/// Whether `name` is at most `max` ASCII letters, digits and `extra`, starting
/// with a letter or digit.
fn is_name(name: &str, extra: &[char], max: usize) -> bool {
    let first = name
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphanumeric());
    let rest = name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || extra.contains(&c));
    first && rest && name.len() <= max
}

/// Whether `url` is a bare origin, as an issuer or audience is: an
/// [`check_url`] URL without a path.
fn check_origin(url: &str) -> Result<(), &'static str> {
    check_url(url)?;
    let host = url.split_once("://").map_or("", |(_, host)| host);
    if host.contains(['/', '?', '#', '@']) || host.ends_with(':') {
        return Err("must be a bare origin such as https://cloudflare-sts-api.example.com");
    }
    Ok(())
}

/// `value`, unless it's zero, which is unset.
fn nonzero_or(value: u64, default: u64) -> u64 {
    if value == 0 { default } else { value }
}

/// Checks a TTL and the longest one a request can ask for, at `at`.
fn check_ttls(at: &str, ttl: u64, max_ttl: u64) -> Result<(), String> {
    if max_ttl > MAX_TTL {
        return Err(format!("{at}.max_ttl must be at most 24h"));
    }
    if ttl < MIN_TTL {
        return Err(format!("{at}.ttl must be at least 1m"));
    }
    if ttl > max_ttl {
        return Err(format!("{at}.ttl must not exceed max_ttl"));
    }
    Ok(())
}

fn duration<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
    let value = String::deserialize(deserializer)?;
    parse_duration(&value).ok_or_else(|| {
        serde::de::Error::custom(format!("{value} must be a duration such as 15m or 1h30m"))
    })
}

/// `90s`, `15m`, `1h30m` in milliseconds, or `None` for anything else, zero
/// included.
fn parse_duration(value: &str) -> Option<u64> {
    let mut units = [('h', HOUR), ('m', MINUTE), ('s', SECOND)].into_iter();
    let mut rest = value;
    let mut total: u64 = 0;
    while !rest.is_empty() {
        let digits = rest
            .find(|c: char| !c.is_ascii_digit())
            .filter(|&at| at > 0)?;
        let count: u64 = rest[..digits].parse().ok()?;
        let unit = rest[digits..].chars().next()?;
        // Each unit once, largest first.
        let (_, ms) = units.find(|(name, _)| *name == unit)?;
        total = total.checked_add(count.checked_mul(ms)?)?;
        rest = &rest[digits + 1..];
    }
    (total > 0).then_some(total)
}

/// Names the broker's tokens already have, which a copied claim must not take
/// the place of.
const RESERVED_CLAIMS: [&str; 10] = [
    "iss",
    "sub",
    "aud",
    "exp",
    "iat",
    "nbf",
    "jti",
    "client_id",
    "provider",
    "profile",
];

/// That `names` are claim names to copy: non-empty, not repeated, and not ones
/// the broker's tokens set themselves.
fn check_forward_claims(names: &[String]) -> Result<(), String> {
    for (index, name) in names.iter().enumerate() {
        if name.is_empty() {
            return Err("must not have an empty name".to_string());
        }
        if RESERVED_CLAIMS.contains(&name.as_str()) {
            return Err(format!("can't copy {name}: the broker's tokens set it"));
        }
        if names[..index].contains(name) {
            return Err(format!("names {name} twice"));
        }
    }
    Ok(())
}

#[cfg(test)]
pub(super) mod tests {
    use serde_json::json;

    use super::*;

    pub(crate) const NOW: u64 = 1_800_000_000;
    pub(crate) const ACCOUNT_ID: &str = "0123456789abcdef0123456789abcdef";
    pub(crate) const ISSUER: &str = "https://token.actions.githubusercontent.com";
    pub(crate) const BROKER: &str = "https://cloudflare-sts-api.example.com";
    pub(crate) const CACHE: &str = "https://cloudflare-nix-api.example.com";

    /// A policy: one provider, pinned to the test org, a profile for
    /// Cloudflare, and one for the cache.
    pub(crate) fn policy() -> Value {
        json!({
            "version": 4,
            "issuer": BROKER,
            "providers": [{ "name": "github", "issuer": ISSUER, "audience": BROKER }],
            "profiles": [
                {
                    "name": "deploy",
                    "forward_claims": ["repository", "ref"],
                    "token": { "policies": [{ "permissions": ["Workers Scripts Write"], "resources": { (format!("com.cloudflare.api.account.{ACCOUNT_ID}")): "*" } }] },
                },
                { "name": "nix-push", "audience": CACHE, "forward_claims": ["repository_owner_id", "ref"] },
            ],
        })
    }

    /// Cedar for `policy`: each provider admits its test org, `deploy` and its
    /// copies take the org's main branch, and every other profile any main.
    pub(crate) fn cedar(policy: &Value) -> String {
        let mut text = String::new();
        let list = |key: &str| policy[key].as_array().cloned().unwrap_or_default();
        for provider in list("providers") {
            let Some(name) = provider["name"].as_str() else {
                continue;
            };
            text += &format!(
                "@id(\"admit-{name}\") permit (principal, action == Admit::Action::\"{name}\", resource) \
                 when {{ context.repository_owner_id == \"100000001\" }};\n"
            );
        }
        for profile in list("profiles") {
            let Some(name) = profile["name"].as_str() else {
                continue;
            };
            let rule = if name.starts_with("deploy") {
                "context.repository like \"example-org/*\" && context.ref == \"refs/heads/main\""
            } else {
                "context.ref == \"refs/heads/main\""
            };
            text += &format!(
                "@id(\"allow-{name}\") permit (principal, action == Profile::Action::\"{name}\", resource) when {{ {rule} }};\n"
            );
        }
        text
    }

    pub(crate) fn parse(policy: &Value) -> PolicyConfig {
        PolicyConfig::parse(&policy.to_string(), &cedar(policy), ACCOUNT_ID)
            .expect("the policy should parse")
    }

    fn parse_err(policy: &Value) -> String {
        PolicyConfig::parse(&policy.to_string(), &cedar(policy), ACCOUNT_ID).unwrap_err()
    }

    /// The test policy, with `pointer` set to `value`.
    fn with(pointer: &str, value: Value) -> Value {
        let mut policy = policy();
        let (parent, key) = pointer.rsplit_once('/').unwrap();
        match policy.pointer_mut(parent).unwrap() {
            Value::Object(map) => map.insert(key.to_string(), value),
            Value::Array(list) => {
                list.push(value);
                None
            }
            _ => unreachable!(),
        };
        policy
    }

    /// The test policy with one more profile.
    fn with_profile(profile: Value) -> Value {
        with("/profiles/-", profile)
    }

    fn token() -> Value {
        policy()["profiles"][0]["token"].clone()
    }

    pub(crate) fn claims() -> Map<String, Value> {
        json!({
            "iss": ISSUER,
            "aud": BROKER,
            "sub": "repo:example-org/app:ref:refs/heads/main",
            "exp": NOW + 300,
            "iat": NOW - 10,
            "repository": "example-org/app",
            "repository_id": "200000002",
            "repository_owner_id": "100000001",
            "ref": "refs/heads/main",
            "groups": ["cache-readers", "cache-uploaders"],
            "email_verified": true,
        })
        .as_object()
        .unwrap()
        .clone()
    }

    #[test]
    fn fills_in_the_provider_and_the_ttls() {
        let policy = parse(&with("/defaults", json!({ "max_ttl": "2h" })));
        let deploy = &policy.profiles[0];
        assert_eq!(deploy.provider, "github");
        assert_eq!(deploy.audience, CLOUDFLARE_AUDIENCE);
        assert!(deploy.enabled);
        assert_eq!((deploy.ttl, deploy.max_ttl), (15 * MINUTE, 2 * HOUR));

        let policy = parse(&with_profile(
            json!({ "name": "short" , "ttl": "90s", "max_ttl": "5m", "token": token() }),
        ));
        let short = &policy.profiles[2];
        assert_eq!((short.ttl, short.max_ttl), (90 * SECOND, 5 * MINUTE));
    }

    #[test]
    fn names_the_providers_people_sign_in_with_by_their_client_id() {
        assert_eq!(parse(&policy()).identity_providers().count(), 0);

        let mut both = policy();
        both["providers"].as_array_mut().unwrap().extend([
            json!({ "name": "access", "issuer": "https://example.cloudflareaccess.com/cdn-cgi/access/sso/oidc/abc", "client_id": "abc"  }),
            json!({ "name": "okta", "issuer": "https://example.okta.com", "audience": "0oa1", "client_id": "0oa1"  }),
        ]);
        both["profiles"][0]["provider"] = json!("github");
        both["profiles"][1]["provider"] = json!("github");
        let policy = parse(&both);
        let people: Vec<(&str, &str)> = policy
            .identity_providers()
            .map(|p| (p.name.as_str(), p.audience.as_str()))
            .collect();
        // The audience is the client ID, whether it's said or not.
        assert_eq!(people, [("access", "abc"), ("okta", "0oa1")]);
    }

    #[test]
    fn parses_durations() {
        for (value, ms) in [
            ("90s", 90 * SECOND),
            ("15m", 15 * MINUTE),
            ("1h30m", 90 * MINUTE),
        ] {
            assert_eq!(parse_duration(value), Some(ms), "{value}");
        }
        for value in ["", "0s", "600", "m", "1m1h", "1h1h", "1d", " 1m", "-1m"] {
            assert_eq!(parse_duration(value), None, "{value}");
        }
    }

    #[test]
    fn rejects_bad_policies() {
        let gitlab =
            json!({ "name": "gitlab", "issuer": "https://gitlab.com", "audience": BROKER });
        let cases = [
            (
                json!("not a policy"),
                "config must be TOML, or a JSON object",
            ),
            (with("/version", json!(2)), "version must be 4"),
            (with("/extra", json!(1)), "unknown field `extra`"),
            (
                with("/issuer", json!("https://broker.example.com/x")),
                "issuer must be a bare origin",
            ),
            (
                with("/providers", json!([])),
                "providers must name at least one provider",
            ),
            (
                with("/providers/-", gitlab.clone()),
                "profiles[0].provider is required with several providers",
            ),
            (
                with("/profiles/0/provider", json!("gitlab")),
                "profiles[0].provider: no provider is named gitlab",
            ),
            (with("/login", json!("github")), "unknown field `login`"),
            (
                with("/profiles", json!([])),
                "profiles must name at least one profile",
            ),
            (
                with("/profiles/1/name", json!("deploy")),
                "profiles[1]: deploy is named twice",
            ),
            (
                with("/profiles/0/name", json!("-x")),
                "profiles[0].name must be 1-255 of [A-Za-z0-9_.:/-]",
            ),
            (
                with("/profiles/0/name", json!("x".repeat(256))),
                "profiles[0].name must be 1-255",
            ),
            (
                with("/profiles/0/ttl", json!("forever")),
                "forever must be a duration",
            ),
            (
                with("/profiles/0/token/policies/0/effect", json!("maybe")),
                "unknown variant `maybe`",
            ),
        ];
        for (policy, expected) in cases {
            let err = parse_err(&policy);
            assert!(err.contains(expected), "{expected}: {err}");
        }
    }

    #[test]
    fn takes_profile_names_that_say_whose_they_are() {
        for name in ["example-org/app:ci.deploy", &"x".repeat(255)] {
            let policy = parse(&with("/profiles/0/name", json!(name)));
            assert_eq!(policy.profiles[0].name, name);
        }
    }

    #[test]
    fn rejects_bad_providers() {
        let cases = [
            (
                with("/providers/0/name", json!("com.github:actions")),
                "providers[0].name must be 1-64 of [A-Za-z0-9_.-]",
            ),
            (
                with("/providers/0/name", json!("example-org/actions")),
                "providers[0].name must be 1-64 of [A-Za-z0-9_.-]",
            ),
            (
                with("/providers/0/audience", json!("")),
                "providers[0].audience must not be empty",
            ),
            (
                with("/providers/0/issuer", json!("http://issuer.example.com")),
                "providers[0].issuer must be an https:// URL",
            ),
            (
                with("/providers/0/jwks_uri", json!("http://keys.example.com")),
                "providers[0].jwks_uri must be an https:// URL",
            ),
            (
                with(
                    "/providers/-",
                    json!({ "name": "github", "issuer": "https://gitlab.com", "audience": BROKER  }),
                ),
                "github is named twice",
            ),
            (
                with(
                    "/providers/-",
                    json!({ "name": "again", "issuer": ISSUER, "audience": BROKER  }),
                ),
                "is configured twice",
            ),
        ];
        for (policy, expected) in cases {
            let err = parse_err(&policy);
            assert!(err.contains(expected), "{expected}: {err}");
        }

        for (field, value, expected) in [
            (
                "client_id",
                json!(""),
                "providers[0].client_id must not be empty",
            ),
            (
                "client_id",
                json!("abc"),
                "providers[0].audience must be its client_id, abc, or left out",
            ),
        ] {
            let err = parse_err(&with(&format!("/providers/0/{field}"), value));
            assert_eq!(err, expected);
        }
    }

    #[test]
    fn allows_http_only_on_loopback() {
        for issuer in [
            "http://127.0.0.1:8791/issuers/actions",
            "http://localhost",
            "http://[::1]:9000/oidc",
        ] {
            parse(&with("/providers/0/issuer", json!(issuer)));
        }
        for issuer in [
            "http://127.0.0.1.example.com",
            "http://localhost.example.com",
        ] {
            let err = parse_err(&with("/providers/0/issuer", json!(issuer)));
            assert!(err.contains("https://"), "{issuer}: {err}");
        }
    }

    #[test]
    fn keeps_token_policies_to_the_guardrails() {
        let resources = |resources: Value| {
            with(
                "/profiles/0/token",
                json!({ "policies": [{ "permissions": ["DNS Write"], "resources": resources }] }),
            )
        };
        let cases = [
            (
                with("/profiles/0/token/policies", json!([])),
                "policies must contain at least one policy",
            ),
            (
                with("/profiles/0/token/policies/0/permissions", json!([])),
                "must name at least one permission group",
            ),
            (
                with(
                    "/profiles/0/token/policies/0/permissions",
                    json!(["Account API Tokens Write"]),
                ),
                "Account API Tokens Write isn't grantable",
            ),
            (resources(json!({})), "must name at least one resource"),
            (
                resources(json!({ "zone.x": "*" })),
                "zone.x isn't a Cloudflare resource",
            ),
            (
                resources(
                    json!({ "com.cloudflare.api.account.ffffffffffffffffffffffffffffffff": "*" }),
                ),
                "isn't the broker's account",
            ),
            (
                resources(
                    json!({ "com.cloudflare.api.account.a": { "x": "*" }, "com.cloudflare.api.account.zone.z": "*" }),
                ),
                "must be all \"*\" values or all nested maps",
            ),
        ];
        for (policy, expected) in cases {
            let err = parse_err(&policy);
            assert!(err.contains(expected), "{expected}: {err}");
        }

        // Denying token management is fine; so is a zone of any account.
        let deny = json!({ "effect": "deny", "permissions": ["API Tokens Write"], "resources": { (format!("com.cloudflare.api.account.{ACCOUNT_ID}")): "*" } });
        parse(&with("/profiles/0/token/policies/-", deny));
        parse(&resources(
            json!({ "com.cloudflare.api.account.zone.fedcba9876543210fedcba9876543210": "*" }),
        ));
        parse(&resources(
            json!({ (format!("com.cloudflare.api.account.{ACCOUNT_ID}")): { "com.cloudflare.api.account.zone.*": "*" } }),
        ));
    }

    #[test]
    fn caps_ttls() {
        let cases = [
            (
                with("/defaults", json!({ "max_ttl": "25h" })),
                "defaults.max_ttl must be at most 24h",
            ),
            (
                with("/profiles/0/ttl", json!("30s")),
                "profiles[0].ttl must be at least 1m",
            ),
            (
                with("/profiles/0/ttl", json!("2h")),
                "profiles[0].ttl must not exceed max_ttl",
            ),
            (
                with("/profiles/0/max_ttl", json!("25h")),
                "profiles[0].max_ttl must be at most 24h",
            ),
        ];
        for (policy, expected) in cases {
            let err = parse_err(&policy);
            assert!(err.contains(expected), "{expected}: {err}");
        }
    }

    #[test]
    fn keeps_audiences_apart() {
        let cases = [
            (
                json!({ "name": "nothing"  }),
                "profiles[2] must have a token, a bucket, an access, or a mix",
            ),
            (
                json!({ "name": "both", "audience": CACHE , "token": token() }),
                "a profile for https://cloudflare-nix-api.example.com can't have a token, a bucket or an access",
            ),
            (
                json!({ "name": "self", "audience": BROKER  }),
                "must be another service, not the broker",
            ),
            (
                json!({ "name": "path", "audience": format!("{CACHE}/x")  }),
                "must be a bare origin",
            ),
        ];
        for (profile, expected) in cases {
            let err = parse_err(&with_profile(profile));
            assert!(err.contains(expected), "{expected}: {err}");
        }
    }

    #[test]
    fn checks_the_bucket() {
        let bucket = |bucket: Value| json!({ "name": "state" , "bucket": bucket });
        let cases = [
            (
                bucket(json!({ "name": "Org_State", "permission": "object-read-write" })),
                "must be a valid R2 bucket name",
            ),
            (
                bucket(json!({ "name": "org-state", "permission": "admin" })),
                "unknown variant `admin`",
            ),
            (
                json!({ "name": "state" , "buckets": [{ "name": "org-state", "permission": "object-read-only" }] }),
                "unknown field `buckets`",
            ),
        ];
        for (profile, expected) in cases {
            let err = parse_err(&with_profile(profile));
            assert!(err.contains(expected), "{expected}: {err}");
        }
    }

    fn prefix(template: &str) -> Result<PrefixTemplate, String> {
        PrefixTemplate::try_from(template.to_string())
    }

    #[test]
    fn rejects_bad_prefixes() {
        let cases = [
            (
                "github.com/${repository}/",
                "{claim} placeholders, not ${claim}",
            ),
            ("github.com/{repository}", "must end with /"),
            ("/github.com/", "path segments of"),
            ("a//b/", "path segments of"),
            ("a/../b/", "path segments of"),
            ("a/./b/", "path segments of"),
            ("a/*/", "path segments of"),
            ("{owner}{id}/", "placeholders as whole path segments"),
            ("x{owner}/", "placeholders as whole path segments"),
            ("{}/", "doesn't name a claim"),
            ("{repo-sitory}/", "doesn't name a claim"),
        ];
        for (template, expected) in cases {
            let err = prefix(template).unwrap_err();
            assert!(err.contains(expected), "{template}: {err}");
        }
    }

    #[test]
    fn fills_prefixes_from_the_claims() {
        let fill = |template: &str| prefix(template).unwrap().fill(&claims());
        assert_eq!(
            fill("github.com/{repository}/").unwrap(),
            "github.com/example-org/app/"
        );
        assert_eq!(
            fill("{repository_owner_id}/{repository_id}/").unwrap(),
            "100000001/200000002/"
        );
        assert_eq!(fill("shared/").unwrap(), "shared/");

        let mut claims = claims();
        claims.insert("project_id".into(), json!(500000001));
        let numbered = prefix("{project_id}/").unwrap().fill(&claims);
        assert_eq!(numbered.unwrap(), "500000001/");
    }

    #[test]
    fn refuses_claims_a_prefix_cant_use() {
        let refused = |template: &str, value: Value| {
            let mut claims = claims();
            claims.insert("repository".into(), value);
            prefix(template).unwrap().fill(&claims).unwrap_err()
        };
        for value in [
            json!("../other-org/app"),
            json!("org/./app"),
            json!("org//app"),
            json!("a b"),
            json!(""),
            json!(true),
            json!(["a"]),
        ] {
            assert_eq!(
                refused("{repository}/", value.clone()),
                "the repository claim is missing or can't be used in a prefix",
                "{value}"
            );
        }
        // Spanning segments only as the one placeholder: otherwise
        // {owner}/{repository} could be filled the same by two callers.
        assert!(prefix("{repository}/").unwrap().fill(&claims()).is_ok());
        refused(
            "{repository_owner_id}/{repository}/",
            json!("example-org/app"),
        );
        assert!(prefix("{missing}/").unwrap().fill(&claims()).is_err());
    }

    #[test]
    fn picks_the_provider_by_the_tokens_issuer() {
        let policy = parse(&policy());
        assert_eq!(policy.provider_for(&claims()).unwrap().name, "github");

        let mut other = claims();
        other.insert("iss".into(), "https://other.example.com".into());
        assert_eq!(
            policy.provider_for(&other).unwrap_err(),
            "no provider is for issuer https://other.example.com"
        );
    }

    /// The profile a caller with `claims` gets, or why not.
    fn selected(
        policy: &Value,
        claims: Map<String, Value>,
        requested: Option<&str>,
        audience: &str,
    ) -> Result<String, String> {
        let scopes: Vec<&str> = requested.into_iter().collect();
        scoped(policy, claims, &scopes, audience)
    }

    /// The same for several scopes: the combined profile's name, or why not.
    fn scoped(
        policy: &Value,
        claims: Map<String, Value>,
        scopes: &[&str],
        audience: &str,
    ) -> Result<String, String> {
        parse(policy)
            .profiles_for("github", &claims, scopes, audience)
            .map(|(profile, _)| profile.name)
            .map_err(|refusal| match refusal {
                Refusal::Scope(why) | Refusal::Request(why) => why,
            })
    }

    fn ok(name: &str) -> Result<String, String> {
        Ok(name.to_string())
    }

    fn err(message: &str) -> Result<String, String> {
        Err(message.to_string())
    }

    #[test]
    fn selects_the_one_matching_profile_or_says_why_not() {
        let policy = policy();
        let main = claims();
        assert_eq!(
            selected(&policy, main.clone(), None, CLOUDFLARE_AUDIENCE),
            ok("deploy")
        );
        assert_eq!(selected(&policy, main.clone(), None, CACHE), ok("nix-push"));

        let mut dev = claims();
        dev.insert("ref".into(), "refs/heads/dev".into());
        let cases = [
            (
                dev.clone(),
                None,
                CLOUDFLARE_AUDIENCE,
                "no profile matches the token",
            ),
            (
                dev,
                Some("deploy"),
                CLOUDFLARE_AUDIENCE,
                "scope deploy doesn't match the token",
            ),
            (
                main.clone(),
                Some("nope"),
                CLOUDFLARE_AUDIENCE,
                "unknown scope nope",
            ),
            (
                main,
                Some("deploy"),
                CACHE,
                "scope deploy isn't for https://cloudflare-nix-api.example.com",
            ),
        ];
        for (claims, requested, audience, expected) in cases {
            assert_eq!(
                selected(&policy, claims, requested, audience),
                err(expected)
            );
        }
    }

    /// The test policy with two more Cloudflare profiles: `dns`, a token, and
    /// `state`, a bucket.
    fn with_more() -> Value {
        let mut policy = policy();
        let profiles = policy["profiles"].as_array_mut().unwrap();
        profiles.push(json!({
            "name": "dns",
            "ttl": "10m",
            "max_ttl": "30m",
            "token": { "policies": [{ "permissions": ["DNS Write"], "resources": { (format!("com.cloudflare.api.account.{ACCOUNT_ID}")): "*" } }] },
        }));
        profiles.push(json!({
            "name": "state",
            "bucket": { "name": "org-state", "permission": "object-read-write" },
        }));
        policy
    }

    #[test]
    fn combines_several_scopes_into_one_grant() {
        let policy = with_more();
        assert_eq!(
            scoped(&policy, claims(), &["deploy", "state"], CLOUDFLARE_AUDIENCE),
            ok("deploy state")
        );
        // Each once, in the order given, whatever the spacing
        assert_eq!(
            scoped(
                &policy,
                claims(),
                &["dns", "deploy", "dns"],
                CLOUDFLARE_AUDIENCE
            ),
            ok("dns deploy")
        );

        let (profile, allowed_by) = parse(&policy)
            .profiles_for(
                "github",
                &claims(),
                &["deploy", "dns", "state"],
                CLOUDFLARE_AUDIENCE,
            )
            .unwrap();
        // The token policies add up; the bucket is the one there is
        assert_eq!(profile.token.as_ref().unwrap().policies.len(), 2);
        assert_eq!(profile.bucket.as_ref().unwrap().name, "org-state");
        // The shortest TTLs win, so nothing outlives what any scope allows
        let policy = parse(&policy);
        let shortest = policy.profiles.iter().map(|p| p.ttl).min().unwrap();
        let tightest = policy.profiles.iter().map(|p| p.max_ttl).min().unwrap();
        assert_eq!((profile.ttl, profile.max_ttl), (shortest, tightest));
        assert_eq!(
            allowed_by,
            ["allow-deploy", "allow-dns", "allow-state"],
            "every policy that allowed a scope"
        );
    }

    #[test]
    fn one_scope_that_cant_be_had_refuses_them_all() {
        let policy = with_more();
        let mut dev = claims();
        dev.insert("ref".into(), "refs/heads/dev".into());
        // `dns` and `state` take any main; `deploy` needs main in the org: all are refused
        // for a branch that isn't main, and one unknown name refuses the rest.
        assert_eq!(
            scoped(&policy, dev, &["dns", "deploy"], CLOUDFLARE_AUDIENCE),
            err("scope dns doesn't match the token")
        );
        assert_eq!(
            scoped(&policy, claims(), &["dns", "nope"], CLOUDFLARE_AUDIENCE),
            err("unknown scope nope")
        );
    }

    #[test]
    fn scopes_that_cant_be_combined_are_refused() {
        let mut policy = with_more();
        policy["profiles"].as_array_mut().unwrap().push(json!({
            "name": "state-two",
            "bucket": { "name": "org-other", "permission": "object-read-only" },
        }));
        assert_eq!(
            scoped(
                &policy,
                claims(),
                &["state", "state-two"],
                CLOUDFLARE_AUDIENCE
            ),
            err(
                "scopes state, state-two each have a bucket, and R2 credentials are for one: ask for one of them"
            )
        );

        // The broker's own token is for one profile, so two for a service are refused
        let mut policy = policy;
        policy["profiles"]
            .as_array_mut()
            .unwrap()
            .push(json!({ "name": "nix-pull", "audience": CACHE, "forward_claims": ["ref"] }));
        assert_eq!(
            scoped(&policy, claims(), &["nix-push", "nix-pull"], CACHE),
            err(&format!(
                "scopes nix-push, nix-pull are for {CACHE}, which takes one scope"
            ))
        );
        assert_eq!(
            scoped(&policy, claims(), &["nix-push"], CACHE),
            ok("nix-push")
        );
    }

    #[test]
    fn an_access_is_a_credential_of_a_profile_for_cloudflare() {
        let nix = json!({ "name": "nix", "access": { "audience": CACHE } });
        let mut policy = with_profile(nix.clone());
        let parsed = parse(&policy);
        let access = parsed
            .profiles
            .iter()
            .find(|p| p.name == "nix")
            .and_then(|p| p.access.as_ref())
            .expect("the profile has its access");
        // The token is tagged with the host: what an Access policy matches.
        assert_eq!(access.host(), "cloudflare-nix-api.example.com");

        // It combines with a token, and the grant has both
        let (profile, _) = parsed
            .profiles_for("github", &claims(), &["deploy", "nix"], CLOUDFLARE_AUDIENCE)
            .unwrap();
        assert!(profile.token.is_some() && profile.access.is_some());

        // Two applications can't be had in one grant, like two buckets
        policy["profiles"].as_array_mut().unwrap().push(
            json!({ "name": "nix-two", "access": { "audience": "https://other.example.com" } }),
        );
        assert_eq!(
            scoped(&policy, claims(), &["nix", "nix-two"], CLOUDFLARE_AUDIENCE),
            err(
                "scopes nix, nix-two each have an access, and a service token is for one application: ask for one of them"
            )
        );
    }

    #[test]
    fn rejects_a_bad_access() {
        // Not an origin, or the broker itself
        for (audience, why) in [
            ("https://nix.example.com/path", "must be a bare origin"),
            (BROKER, "must be another service, not the broker"),
        ] {
            let err = parse_err(&with_profile(
                json!({ "name": "nix", "access": { "audience": audience } }),
            ));
            assert!(
                err.contains("profiles[2].access.audience") && err.contains(why),
                "{audience}: {err}"
            );
        }
        // An access is Cloudflare's: a profile for a service has no credentials
        let err = parse_err(&with_profile(
            json!({ "name": "nix", "audience": CACHE, "access": { "audience": CACHE } }),
        ));
        assert!(
            err.contains("can't have a token, a bucket or an access"),
            "{err}"
        );
    }

    #[test]
    fn naming_no_scope_is_a_request_problem_and_a_bad_scope_a_scope_problem() {
        let policy = parse(&with_more());
        assert!(matches!(
            policy.profiles_for("github", &claims(), &[], CLOUDFLARE_AUDIENCE),
            Err(Refusal::Request(_))
        ));
        assert!(matches!(
            policy.profiles_for("github", &claims(), &["nope"], CLOUDFLARE_AUDIENCE),
            Err(Refusal::Scope(_))
        ));
    }

    #[test]
    fn refuses_when_several_profiles_match_and_none_is_named() {
        let mut policy = policy();
        let mut again = policy["profiles"][0].clone();
        again["name"] = json!("deploy-again");
        policy["profiles"].as_array_mut().unwrap().push(again);
        assert_eq!(
            selected(&policy, claims(), None, CLOUDFLARE_AUDIENCE),
            err("profiles deploy, deploy-again all match the token: name one in scope")
        );
        assert_eq!(
            selected(&policy, claims(), Some("deploy-again"), CLOUDFLARE_AUDIENCE),
            ok("deploy-again")
        );
    }

    #[test]
    fn never_matches_a_disabled_profile_even_by_name() {
        let mut policy = policy();
        policy["profiles"][0]["enabled"] = json!(false);
        assert_eq!(
            selected(&policy, claims(), Some("deploy"), CLOUDFLARE_AUDIENCE),
            err("scope deploy is disabled")
        );
        assert_eq!(
            selected(&policy, claims(), None, CLOUDFLARE_AUDIENCE),
            err("no profile matches the token")
        );
    }

    #[test]
    fn never_gives_one_providers_token_anothers_profile() {
        let mut policy = policy();
        policy["providers"].as_array_mut().unwrap().push(json!({ "name": "gitlab", "issuer": "https://gitlab.com", "audience": "https://cloudflare-sts-api.example.com"  }));
        policy["profiles"][0]["provider"] = json!("gitlab");
        policy["profiles"][1]["provider"] = json!("github");
        assert_eq!(
            selected(&policy, claims(), Some("deploy"), CLOUDFLARE_AUDIENCE),
            err("scope deploy isn't for provider github")
        );
    }

    #[test]
    fn clamps_the_ttl_to_max_ttl_and_rejects_nonsense() {
        let policy = parse(&policy());
        let profile = &policy.profiles[0];
        assert_eq!(profile.ttl_for(None).ok(), Some(15 * 60_000));
        assert_eq!(profile.ttl_for(Some("5m")).ok(), Some(5 * 60_000));
        assert_eq!(profile.ttl_for(Some("12h")).ok(), Some(60 * 60_000));
        for ttl in ["30s", "forever", "600"] {
            assert!(profile.ttl_for(Some(ttl)).is_err(), "{ttl}");
        }
    }

    fn token_policy(resources: Value) -> TokenPolicyConfig {
        serde_json::from_value(json!({ "permissions": ["x"], "resources": resources })).unwrap()
    }

    #[test]
    fn picks_the_scope_from_the_resources() {
        let zone = "com.cloudflare.api.account.zone.fedcba9876543210fedcba9876543210";
        let account = "com.cloudflare.api.account.0123456789abcdef0123456789abcdef";
        let scope = |resources: Value| token_policy(resources).permission_scope();
        assert_eq!(scope(json!({ zone: "*" })), CLOUDFLARE_ZONE_SCOPE);
        assert_eq!(scope(json!({ account: "*" })), CLOUDFLARE_ACCOUNT_SCOPE);
        assert_eq!(
            scope(json!({ account: { "com.cloudflare.api.account.zone.*": "*" } })),
            CLOUDFLARE_ZONE_SCOPE
        );
        assert_eq!(
            scope(json!({ "com.cloudflare.edge.r2.bucket.x_default_y": "*" })),
            CLOUDFLARE_R2_SCOPE
        );
    }

    #[test]
    fn passes_resources_through_in_either_form() {
        let json = |resources: Value| {
            serde_json::to_value(token_policy(resources).iam_resources()).unwrap()
        };
        let flat = json!({ "com.cloudflare.api.account.zone.z": "*" });
        let nested =
            json!({ "com.cloudflare.api.account.a": { "com.cloudflare.api.account.zone.*": "*" } });
        assert_eq!(json(flat.clone()), flat);
        assert_eq!(json(nested.clone()), nested);
    }

    #[test]
    fn knows_a_caller_by_the_claims_its_profile_forwards() {
        let parsed = parse(&policy());
        let mut claims = claims();
        claims.insert("email".into(), "someone@example.com".into());
        assert_eq!(
            Value::Object(parsed.profiles[0].forwarded_claims(&claims)),
            json!({ "ref": "refs/heads/main", "repository": "example-org/app" }),
            "only what it names: the email stays behind"
        );
        assert_eq!(
            Value::Object(parsed.profiles[1].forwarded_claims(&claims)),
            json!({ "ref": "refs/heads/main", "repository_owner_id": "100000001" })
        );
        let mut none = policy();
        none["profiles"][1]["forward_claims"] = json!([]);
        assert_eq!(
            parse(&none).profiles[1].forwarded_claims(&claims),
            Map::new(),
            "a profile that names none forwards none"
        );
        claims.remove("ref");
        assert_eq!(
            Value::Object(parsed.profiles[0].forwarded_claims(&claims)),
            json!({ "repository": "example-org/app" }),
            "a claim the token doesn't have is left out"
        );
    }

    #[test]
    fn rejects_bad_forward_claims() {
        let cases = [
            (json!([""]), "must not have an empty name"),
            (json!(["ref", "ref"]), "names ref twice"),
            (json!(["iss"]), "can't copy iss: the broker's tokens set it"),
            (json!(["profile"]), "can't copy profile"),
        ];
        for (names, expected) in cases {
            let err = parse_err(&with("/profiles/0/forward_claims", names.clone()));
            assert!(err.contains(expected), "{names}: {err}");
        }
    }

    #[test]
    fn reads_toml_or_json() {
        let toml = r#"
            version = 4
            issuer = "https://cloudflare-sts-api.example.com"

            [[providers]]
            name = "github"
            issuer = "https://token.actions.githubusercontent.com"
            audience = "https://cloudflare-sts-api.example.com"

            [[profiles]]
            name = "deploy"
            forward_claims = ["repository"]
            [[profiles.token.policies]]
            permissions = ["Workers Scripts Write"]
            resources = { "com.cloudflare.api.account.0123456789abcdef0123456789abcdef" = "*" }
        "#;
        let cedar = r#"
            @id("a") permit (principal, action == Admit::Action::"github", resource);
            @id("b") permit (principal, action == Profile::Action::"deploy", resource);
        "#;
        let policy = PolicyConfig::parse(toml, cedar, ACCOUNT_ID).unwrap();
        assert_eq!(policy.profiles[0].forward_claims, ["repository"]);
        assert_eq!(policy.profiles[0].ttl, 15 * MINUTE);

        let err = PolicyConfig::parse("version = ", cedar, ACCOUNT_ID).unwrap_err();
        assert!(
            err.contains("config must be TOML, or a JSON object"),
            "{err}"
        );
        let err = PolicyConfig::parse(
            &toml.replace("version = 4", "version = 3"),
            cedar,
            ACCOUNT_ID,
        )
        .unwrap_err();
        assert_eq!(err, "version must be 4");
        let err =
            PolicyConfig::parse(&format!("{toml}\nclaims = []"), cedar, ACCOUNT_ID).unwrap_err();
        assert!(
            err.contains("unknown field `claims`"),
            "a version 3 claims field is refused: {err}"
        );
    }

    /// The first fenced block of `lang` in the README.
    fn readme_block(lang: &str) -> &'static str {
        let readme = include_str!("../../README.md");
        let start = readme
            .find(&format!("```{lang}\n"))
            .unwrap_or_else(|| panic!("a {lang} block in the README"))
            + lang.len()
            + 4;
        &readme[start..start + readme[start..].find("```").unwrap()]
    }

    #[test]
    fn loads_the_readmes_example() {
        let policy = PolicyConfig::parse(readme_block("toml"), readme_block("cedar"), ACCOUNT_ID)
            .expect("the README's example policy should load");
        assert_eq!(policy.providers.len(), 3);
        assert_eq!(policy.profiles.len(), 5);

        // And it does what it says: the apply job, from main, in prod.
        let mut claims = claims();
        claims.insert("repository_id".into(), "200000002".into());
        claims.insert("environment".into(), "prod".into());
        let (profile, policies) = policy
            .profiles_for(
                "com.github.actions",
                &claims,
                &["example-org/infra:ci.apply"],
                CLOUDFLARE_AUDIENCE,
            )
            .unwrap();
        assert_eq!(profile.name, "example-org/infra:ci.apply");
        assert_eq!(policies, ["apply-from-main"]);
        assert!(policy.admit("com.github.actions", &claims).allowed);

        claims.insert("event_name".into(), "pull_request_target".into());
        let forbidden = policy.admit("com.github.actions", &claims);
        assert!(!forbidden.allowed, "a forbid beats the permit");
        assert_eq!(forbidden.policies, ["no-pull-request-target"]);
    }

    #[test]
    fn refuses_a_policy_that_doesnt_fit_the_configuration() {
        let config = policy();
        let ok = cedar(&config);
        let parse =
            |cedar: &str| PolicyConfig::parse(&config.to_string(), cedar, ACCOUNT_ID).unwrap_err();

        let without = ok
            .replace("admit-github", "other")
            .replace("Admit::Action::\"github\"", "Admit::Action::\"gitlab\"");
        assert!(
            parse(&without).contains("names no provider"),
            "{}",
            parse(&without)
        );
        let only_profiles: String = ok
            .lines()
            .filter(|l| !l.contains("Admit"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            parse(&only_profiles).contains("provider github has no policy admitting it"),
            "a provider that nothing pins is refused: {}",
            parse(&only_profiles)
        );
        let no_deploy: String = ok
            .lines()
            .filter(|l| !l.contains("allow-deploy"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(parse(&no_deploy).contains("profile deploy has no policy allowing anyone"));
    }

    #[test]
    fn picks_permission_groups_by_name_then_scope() {
        let groups: Vec<PermissionGroup> = serde_json::from_value(json!([
            { "id": "pg-dns-write", "name": "DNS Write", "scopes": [CLOUDFLARE_ZONE_SCOPE] },
            { "id": "pg-lb-write-account", "name": "Load Balancers Write", "scopes": [CLOUDFLARE_ACCOUNT_SCOPE] },
            { "id": "pg-lb-write-zone", "name": "Load Balancers Write", "scopes": [CLOUDFLARE_ZONE_SCOPE] },
        ]))
        .unwrap();
        let pick = |name, scope| TokenPolicyConfig::group_id(&groups, name, scope);
        assert_eq!(
            pick("DNS Write", CLOUDFLARE_ACCOUNT_SCOPE).as_deref(),
            Ok("pg-dns-write")
        );
        assert_eq!(
            pick("Load Balancers Write", CLOUDFLARE_ZONE_SCOPE).as_deref(),
            Ok("pg-lb-write-zone")
        );
        assert_eq!(
            pick("Load Balancers Write", CLOUDFLARE_ACCOUNT_SCOPE).as_deref(),
            Ok("pg-lb-write-account")
        );
        assert_eq!(
            pick("Load Balancers Write", CLOUDFLARE_R2_SCOPE),
            Err("several permission groups are named Load Balancers Write, at no one scope of the resources".into())
        );
        assert_eq!(
            pick("Nope", CLOUDFLARE_ACCOUNT_SCOPE),
            Err("no permission group is named Nope".into())
        );
    }

    #[test]
    fn a_provider_may_name_the_typ_its_tokens_must_have() {
        let typed = parse(&with("/providers/0/typ", json!("at+jwt")));
        assert_eq!(Provider::typ(&typed.providers[0]), Some("at+jwt"));
        assert_eq!(Provider::typ(&parse(&policy()).providers[0]), None);
        let err = parse_err(&with("/providers/0/typ", json!("")));
        assert!(err.contains("providers[0].typ must not be empty"), "{err}");
    }
}
