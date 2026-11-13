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
//! profiles, their claim sets and bucket prefixes, and what parsing checks,
//! the guardrails among it. Checking a token against a provider is in the auth
//! [`layer`](super::layer); what a caller gets, in the
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
use worker::{Env, Error, SecretStore, js_sys, wasm_bindgen::JsValue};

use crate::oidc::{ClaimRules, Provider, Providers, check_url};

/// The binding of the account the Cloudflare token belongs to, and tokens are
/// minted in.
const ACCOUNT_KEY: &str = "CLOUDFLARE_STS_API_ACCOUNT_ID";

/// The Workers KV binding the policy is read from.
const POLICY_BINDING: &str = "CLOUDFLARE_STS_API_POLICY_KV";

/// The key in that namespace holding the policy, as JSON.
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
            "{OLD_POLICY_VAR} is no longer read: the policy is key `{POLICY_KEY}` in the Workers KV binding {POLICY_BINDING}"
        )));
    }
    let kv = env.kv(POLICY_BINDING).map_err(|why| {
        Error::RustError(format!(
            "{POLICY_BINDING} must be a Workers KV binding: {why}"
        ))
    })?;
    let json = kv
        .get(POLICY_KEY)
        .text()
        .await
        .map_err(|why| {
            Error::RustError(format!(
                "{POLICY_BINDING}: `{POLICY_KEY}` can't be read: {why}"
            ))
        })?
        .ok_or_else(|| Error::RustError(format!("{POLICY_BINDING}: `{POLICY_KEY}` isn't set")))?;
    let policy = PolicyConfig::parse(&json, account_id)
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
/// It knows no issuer by name: who may do what is in the claim sets, as in
/// cloudflare-nix.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    /// The policy format's version: 3.
    version: u64,
    /// The broker's own URL: the issuer of the tokens it signs for other
    /// services.
    pub issuer: String,
    pub providers: Providers<ProviderConfig>,
    /// What profiles that don't say get.
    #[serde(default)]
    defaults: DefaultsConfig,
    pub profiles: Vec<ProfileConfig>,
}

impl PolicyConfig {
    /// The policy in `json`, checked against the account tokens are minted in.
    ///
    /// # Errors
    ///
    /// The first problem found: the guardrails are checked here, so an unsafe
    /// policy never serves a request.
    pub fn parse(json: &str, account_id: &str) -> Result<Self, String> {
        let mut policy: Self = serde_json::from_str(json).map_err(|err| {
            format!("must be a JSON policy of {{ version, issuer, providers, defaults?, profiles }}: {err}")
        })?;
        policy.check(account_id)?;
        Ok(policy)
    }

    /// What deserializing can't check, filling in each profile's provider and
    /// TTLs on the way.
    fn check(&mut self, account_id: &str) -> Result<(), String> {
        if self.version != 3 {
            return Err("version must be 3".to_string());
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

    /// The profile a token from `provider` with `claims` gets for
    /// `audience`: the one `requested`, or else the only one that matches.
    /// The token must match one of the profile's claim sets; its provider's
    /// are checked when it's verified.
    ///
    /// # Errors
    ///
    /// Why it gets none.
    pub fn profile_for(
        &self,
        provider: &str,
        claims: &Map<String, Value>,
        requested: Option<&str>,
        audience: &str,
    ) -> Result<&ProfileConfig, String> {
        let matches = |p: &ProfileConfig| p.enabled && p.claims.matches(claims);
        let mut profiles = self
            .profiles
            .iter()
            .filter(|p| p.provider == provider && p.audience == audience);

        if let Some(requested) = requested {
            if let Some(profile) = profiles.find(|p| p.name == requested)
                && matches(profile)
            {
                return Ok(profile);
            }
            return Err(match self.profiles.iter().find(|p| p.name == requested) {
                None => format!("unknown profile {requested}"),
                Some(named) if named.provider != provider => {
                    format!("profile {requested} isn't for provider {provider}")
                }
                Some(named) if named.audience != audience => {
                    format!("profile {requested} isn't for {audience}")
                }
                Some(named) if !named.enabled => format!("profile {requested} is disabled"),
                Some(_) => format!("profile {requested} doesn't match the token"),
            });
        }

        let candidates: Vec<&ProfileConfig> = profiles.filter(|p| matches(p)).collect();
        match candidates.as_slice() {
            [] => Err("no profile matches the token".into()),
            [profile] => Ok(profile),
            several => {
                let names: Vec<&str> = several.iter().map(|p| p.name.as_str()).collect();
                Err(format!(
                    "profiles {} all match the token: name one",
                    names.join(", ")
                ))
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
    /// Every token from it must match one of these, whichever profile it gets.
    pub claims: ClaimRules,
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

    /// The claims its claim sets and `profile`'s match on, with their values
    /// in `claims`: what's worth writing down about a caller, and copying into
    /// the broker's own tokens. Never secret.
    pub fn matched_claims(
        &self,
        profile: Option<&ProfileConfig>,
        claims: &Map<String, Value>,
    ) -> Map<String, Value> {
        /// A string, number or boolean, or a list of them, as claim sets
        /// match on.
        fn copyable(value: &Value) -> bool {
            match value {
                Value::String(text) => !text.is_empty(),
                Value::Number(_) | Value::Bool(_) => true,
                Value::Array(values) => values.iter().all(|v| !v.is_array() && copyable(v)),
                _ => false,
            }
        }

        let profile = profile.map(|p| p.claims.names());
        self.claims
            .names()
            .chain(profile.into_iter().flatten())
            .filter_map(|name| {
                let value = claims.get(name).filter(|v| copyable(v))?;
                Some((name.to_string(), value.clone()))
            })
            .collect()
    }

    fn check(&self, at: &str) -> Result<(), String> {
        // Its issuer, jwks_uri and audience are the providers' check.
        check_provider_name(&self.name).map_err(|why| format!("{at}.name {why}"))?;
        if self.typ.as_deref().is_some_and(str::is_empty) {
            return Err(format!("{at}.typ must not be empty"));
        }
        // Guardrail 1: the provider is pinned. An issuer that gives anyone's
        // projects a token, as GitHub Actions does, would otherwise let them
        // all in.
        self.claims.check(&format!("{at}.claims"))?;
        Ok(())
    }
}

/// What a caller may get, and who may get it.
#[derive(Debug, Deserialize)]
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
    /// A token must match one of these, as well as one of its provider's.
    pub claims: ClaimRules,
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

    fn check(&self, at: &str, issuer: &str, account_id: &str) -> Result<(), String> {
        check_profile_name(&self.name).map_err(|why| format!("{at}.name {why}"))?;
        self.claims.check(&format!("{at}.claims"))?;

        // Guardrail 5: audiences are kept apart. The broker signs its own
        // token for another service; Cloudflare credentials are another
        // profile's job.
        let credentials = self.token.is_some() || self.bucket.is_some();
        if self.audience == CLOUDFLARE_AUDIENCE {
            if !credentials {
                return Err(format!("{at} must have a token, a bucket or both"));
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
                    "{at}: a profile for {} can't have a token or a bucket",
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

        // Guardrail 4: TTLs are capped, well within the 7 days R2 credentials
        // can live.
        check_ttls(at, self.ttl, self.max_ttl)
    }
}

/// A Cloudflare API token: its policies, in Cloudflare's own format, with
/// permission groups by name.
#[derive(Debug, Deserialize)]
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
#[derive(Debug, Deserialize)]
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

/// A bucket a profile's caller gets R2 credentials for.
#[derive(Debug, Deserialize)]
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
#[derive(Debug, Deserialize)]
#[serde(try_from = "String")]
pub struct PrefixTemplate(Vec<Segment>);

#[derive(Debug, PartialEq)]
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
            "version": 3,
            "issuer": BROKER,
            "providers": [{ "name": "github", "issuer": ISSUER, "audience": BROKER, "claims": [{ "repository_owner_id": "100000001" }] }],
            "profiles": [
                {
                    "name": "deploy",
                    "claims": [{ "repository": "example-org/*", "ref": "refs/heads/main" }],
                    "token": { "policies": [{ "permissions": ["Workers Scripts Write"], "resources": { (format!("com.cloudflare.api.account.{ACCOUNT_ID}")): "*" } }] },
                },
                { "name": "nix-push", "audience": CACHE, "claims": [{ "ref": "refs/heads/main" }] },
            ],
        })
    }

    pub(crate) fn parse(policy: &Value) -> PolicyConfig {
        PolicyConfig::parse(&policy.to_string(), ACCOUNT_ID).expect("the policy should parse")
    }

    fn parse_err(policy: &Value) -> String {
        PolicyConfig::parse(&policy.to_string(), ACCOUNT_ID).unwrap_err()
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
            json!({ "name": "short", "claims": [{ "ref": "x" }], "ttl": "90s", "max_ttl": "5m", "token": token() }),
        ));
        let short = &policy.profiles[2];
        assert_eq!((short.ttl, short.max_ttl), (90 * SECOND, 5 * MINUTE));
    }

    #[test]
    fn names_the_providers_people_sign_in_with_by_their_client_id() {
        assert_eq!(parse(&policy()).identity_providers().count(), 0);

        let mut both = policy();
        both["providers"].as_array_mut().unwrap().extend([
            json!({ "name": "access", "issuer": "https://example.cloudflareaccess.com/cdn-cgi/access/sso/oidc/abc", "client_id": "abc", "claims": [{ "x": "y" }] }),
            json!({ "name": "okta", "issuer": "https://example.okta.com", "audience": "0oa1", "client_id": "0oa1", "claims": [{ "x": "y" }] }),
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
        let gitlab = json!({ "name": "gitlab", "issuer": "https://gitlab.com", "audience": BROKER, "claims": [{ "namespace_id": "4000001" }] });
        let cases = [
            (json!("not a policy"), "must be a JSON policy"),
            (with("/version", json!(2)), "version must be 3"),
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
                with("/profiles/0/claims", json!([])),
                "profiles[0].claims must contain at least one claim set",
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
                with("/providers/0/claims", json!([])),
                "providers[0].claims must contain at least one claim set",
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
                    json!({ "name": "github", "issuer": "https://gitlab.com", "audience": BROKER, "claims": [{ "x": "y" }] }),
                ),
                "github is named twice",
            ),
            (
                with(
                    "/providers/-",
                    json!({ "name": "again", "issuer": ISSUER, "audience": BROKER, "claims": [{ "x": "y" }] }),
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
                json!({ "name": "nothing", "claims": [{ "ref": "x" }] }),
                "profiles[2] must have a token, a bucket or both",
            ),
            (
                json!({ "name": "both", "audience": CACHE, "claims": [{ "ref": "x" }], "token": token() }),
                "a profile for https://cloudflare-nix-api.example.com can't have a token or a bucket",
            ),
            (
                json!({ "name": "self", "audience": BROKER, "claims": [{ "ref": "x" }] }),
                "must be another service, not the broker",
            ),
            (
                json!({ "name": "path", "audience": format!("{CACHE}/x"), "claims": [{ "ref": "x" }] }),
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
        let bucket = |bucket: Value| json!({ "name": "state", "claims": [{ "ref": "x" }], "bucket": bucket });
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
                json!({ "name": "state", "claims": [{ "ref": "x" }], "buckets": [{ "name": "org-state", "permission": "object-read-only" }] }),
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
    fn rejects_bad_claim_sets() {
        let cases = [
            (json!([{}]), "a claim set must match at least one claim"),
            (
                json!([{ "repository_id": "2000*" }]),
                "claim repository_id: ID claims must match exactly",
            ),
            (json!([{ "ref": "" }]), "non-empty string"),
            (json!([{ "ref": null }]), "non-empty string"),
            (json!([{ "ref": -1 }]), "non-empty string"),
            (
                json!([{ "ref": "*" }]),
                "claim ref: * may only end a pattern",
            ),
            (json!([{ "ref": "*main" }]), "may only end a pattern"),
            (json!([{ "ref": "refs/*/main" }]), "may only end a pattern"),
            (json!([{ "ref": "refs/**" }]), "may only end a pattern"),
        ];
        for (claims, expected) in cases {
            for pointer in ["/providers/0/claims", "/profiles/0/claims"] {
                let err = parse_err(&with(pointer, claims.clone()));
                assert!(err.contains(expected), "{pointer} {claims}: {err}");
            }
        }
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
        parse(policy)
            .profile_for("github", &claims, requested, audience)
            .map(|profile| profile.name.clone())
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
                "profile deploy doesn't match the token",
            ),
            (
                main.clone(),
                Some("nope"),
                CLOUDFLARE_AUDIENCE,
                "unknown profile nope",
            ),
            (
                main,
                Some("deploy"),
                CACHE,
                "profile deploy isn't for https://cloudflare-nix-api.example.com",
            ),
        ];
        for (claims, requested, audience, expected) in cases {
            assert_eq!(
                selected(&policy, claims, requested, audience),
                err(expected)
            );
        }
    }

    #[test]
    fn refuses_when_several_profiles_match_and_none_is_named() {
        let mut policy = policy();
        let mut again = policy["profiles"][0].clone();
        again["name"] = json!("deploy-again");
        policy["profiles"].as_array_mut().unwrap().push(again);
        assert_eq!(
            selected(&policy, claims(), None, CLOUDFLARE_AUDIENCE),
            err("profiles deploy, deploy-again all match the token: name one")
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
            err("profile deploy is disabled")
        );
        assert_eq!(
            selected(&policy, claims(), None, CLOUDFLARE_AUDIENCE),
            err("no profile matches the token")
        );
    }

    #[test]
    fn never_gives_one_providers_token_anothers_profile() {
        let mut policy = policy();
        policy["providers"].as_array_mut().unwrap().push(json!({ "name": "gitlab", "issuer": "https://gitlab.com", "audience": "https://cloudflare-sts-api.example.com", "claims": [{ "ref": "refs/heads/main" }] }));
        policy["profiles"][0]["provider"] = json!("gitlab");
        policy["profiles"][1]["provider"] = json!("github");
        assert_eq!(
            selected(&policy, claims(), Some("deploy"), CLOUDFLARE_AUDIENCE),
            err("profile deploy isn't for provider github")
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
    fn knows_a_caller_by_the_claims_the_policy_matches_on() {
        let policy = parse(&policy());
        let mut claims = claims();
        claims.insert("email".into(), "someone@example.com".into());
        let provider = &policy.providers[0];
        assert_eq!(
            Value::Object(provider.matched_claims(Some(&policy.profiles[0]), &claims)),
            json!({
                "ref": "refs/heads/main",
                "repository": "example-org/app",
                "repository_owner_id": "100000001",
            })
        );
        assert_eq!(
            Value::Object(provider.matched_claims(None, &claims)),
            json!({ "repository_owner_id": "100000001" })
        );
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
