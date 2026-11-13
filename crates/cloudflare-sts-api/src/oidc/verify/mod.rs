//! Verifying tokens, the resource server's side: the [`Provider`]s whose
//! tokens are accepted, and [`Providers::verify`], which validates a token as
//! RFC 7519 §7.2 and RFC 8725 say, against the one its `iss` names. Then
//! [`ClaimRules`] let it in, or not.
//!
//! What verifying does with a provider is [`ProviderExt`]'s: implemented for
//! every [`Provider`], so an implementor can neither override it nor see it.
//! Its keys come from [`keys`], found through its [`metadata`] unless it
//! names a `jwks_uri`. Verified tokens are cached per isolate until they
//! expire, so [`verified`] can give one back.

mod keys;
mod metadata;

use std::{
    cell::RefCell,
    collections::HashMap,
    ops::{Deref, DerefMut},
};

use serde::Deserialize;
use sha2::{Digest, Sha256};
use worker::Date;

use self::keys::RsaKey;
pub use self::keys::check_url;
use crate::oidc::{
    Claims, Error, Header, Jwt,
    error::invalid,
    jwt::{LEEWAY_SECS, Unverified},
};

thread_local! {
    static VERIFIED: RefCell<VerifiedCache> = RefCell::new(VerifiedCache::new());
}

/// An OpenID Provider whose tokens are accepted: the issuer, and what its
/// tokens must be to be verified. Implement it on your configuration's type.
///
/// It only says what's configured: verifying is [`Providers::verify`]'s.
pub trait Provider {
    /// Its issuer identifier, matched exactly against a token's `iss`.
    fn issuer(&self) -> &str;

    /// The audience a token's `aud` must contain: whoever verifies it. A
    /// trailing `/` is ignored, here and in the token.
    fn audience(&self) -> &str;

    /// Where its JWK Set is. `None`, the default, reads it from the
    /// `jwks_uri` in its metadata.
    fn jwks_uri(&self) -> Option<&str> {
        None
    }

    /// The `typ` its tokens must have (RFC 8725 §3.11), such as
    /// [`AT_JWT`](crate::oidc::AT_JWT), so another kind of token it issues can't
    /// pass for one. `None`, the default, takes any.
    fn typ(&self) -> Option<&str> {
        None
    }
}

/// The providers whose tokens are accepted. Written as a JSON array of
/// whatever `P` deserializes from.
///
/// Deserializing doesn't check it: [`check`](Self::check) does, saying where.
/// Nothing unchecked is ever fetched from, though: keys only come over HTTPS,
/// or plain HTTP on loopback.
#[derive(Debug, Deserialize)]
#[serde(transparent)]
pub struct Providers<P>(Vec<P>);

impl<P: Provider> Providers<P> {
    /// Verifies `token`, a JWT, against the provider its `iss` names: its
    /// header, its signature, then its registered claims. Returns that
    /// provider and the token, which [`verified`] gives back
    /// until it expires.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidToken`] when it isn't valid, and
    /// [`Error::TemporarilyUnavailable`] when its issuer's keys can't be had.
    pub async fn verify(&self, token: &str) -> Result<(&P, Jwt), Error> {
        let now_ms = Date::now().as_millis();
        if let Some(jwt) = cached(token, now_ms) {
            // Its signature holds; its header and claims are checked again,
            // as cheap as that is, against the provider it's from now.
            let provider = self.for_claims(&jwt.claims)?;
            provider.check_header(&jwt.header)?;
            provider.validate(&jwt.claims, now_ms)?;
            return Ok((provider, jwt));
        }

        let Unverified {
            jwt,
            signing_input,
            signature,
        } = Unverified::decode(token)?;
        let provider = self.for_claims(&jwt.claims)?;
        provider.check_header(&jwt.header)?;
        let key = provider.key(jwt.header.kid.as_deref(), now_ms).await?;
        if !key.verify(signing_input.as_bytes(), &signature).await? {
            return Err(invalid("bad signature"));
        }
        provider.validate(&jwt.claims, now_ms)?;

        if let Some(exp) = jwt.claims.exp() {
            let expires_at = (exp + LEEWAY_SECS) * 1000;
            store(token, jwt.clone(), expires_at, now_ms);
        }
        Ok((provider, jwt))
    }

    /// The provider for `issuer`.
    pub fn find(&self, issuer: &str) -> Option<&P> {
        self.0.iter().find(|provider| provider.issuer() == issuer)
    }

    /// What deserializing can't check: that there's a provider, each one's
    /// issuer and `jwks_uri` are HTTPS (or loopback), its audience isn't
    /// empty, and no issuer is configured twice. `at` is where the providers
    /// are, for the message.
    ///
    /// # Errors
    ///
    /// The first problem found.
    pub fn check(&self, at: &str) -> Result<(), String> {
        if self.0.is_empty() {
            return Err(format!("{at} must name at least one provider"));
        }
        for (index, provider) in self.0.iter().enumerate() {
            let at = format!("{at}[{index}]");
            check_url(provider.issuer()).map_err(|why| format!("{at}.issuer {why}"))?;
            if let Some(jwks_uri) = provider.jwks_uri() {
                check_url(jwks_uri).map_err(|why| format!("{at}.jwks_uri {why}"))?;
            }
            if provider.audience().trim_end_matches('/').is_empty() {
                return Err(format!("{at}.audience must not be empty"));
            }
            if self.0[..index]
                .iter()
                .any(|other| other.issuer() == provider.issuer())
            {
                return Err(format!("{at}: {} is configured twice", provider.issuer()));
            }
        }
        Ok(())
    }

    /// The provider a token's claims say it comes from, by its `iss`, read
    /// unverified only to pick the keys to verify it with.
    fn for_claims(&self, claims: &Claims) -> Result<&P, Error> {
        let iss = claims.iss().unwrap_or_default();
        self.find(iss).ok_or_else(|| {
            let shown: String = iss.chars().take(200).collect();
            Error::InvalidToken(format!("no provider is for issuer {shown}"))
        })
    }
}

impl<P> Deref for Providers<P> {
    type Target = [P];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// For a policy to fill in what its providers leave out before
/// [`check`](Providers::check), such as an audience that defaults to another
/// field.
impl<P> DerefMut for Providers<P> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<P> From<Vec<P>> for Providers<P> {
    fn from(providers: Vec<P>) -> Self {
        Self(providers)
    }
}

/// What verifying does with a provider. Implemented for every [`Provider`]
/// below, and private, so it can't be overridden to skip a check.
trait ProviderExt: Provider {
    /// What the provider needs of a token's JOSE Header beyond what decoding
    /// it checked: its `typ`, if the provider names one.
    fn check_header(&self, header: &Header) -> Result<(), Error> {
        match self.typ() {
            Some(typ) if !header.typ_is(typ) => Err(invalid(&format!("typ must be {typ}"))),
            _ => Ok(()),
        }
    }

    /// Validates a token's registered claims for this provider, at `now_ms`.
    fn validate(&self, claims: &Claims, now_ms: u64) -> Result<(), Error> {
        claims.validate(self.issuer(), self.audience(), now_ms / 1000)
    }

    /// The provider's key that `kid` names, or its only one when there's no
    /// `kid`.
    async fn key(&self, kid: Option<&str>, now_ms: u64) -> Result<RsaKey, Error> {
        keys::find(self.issuer(), self.jwks_uri(), kid, now_ms).await
    }
}

impl<P: Provider + ?Sized> ProviderExt for P {}

/// `token`, verified, if it's cached and hasn't expired by `now_ms`.
fn cached(token: &str, now_ms: u64) -> Option<Jwt> {
    let key = VerifiedCache::key(token);
    VERIFIED.with_borrow(|cache| cache.get(&key, now_ms))
}

/// Caches `jwt`, verified from `token`, until `expires_at`.
fn store(token: &str, jwt: Jwt, expires_at: u64, now_ms: u64) {
    let key = VerifiedCache::key(token);
    VERIFIED.with_borrow_mut(|cache| cache.insert(key, jwt, expires_at, now_ms));
}

/// `token`, if [`Providers::verify`](crate::oidc::Providers::verify) accepted it in
/// this isolate and it hasn't expired since.
pub fn verified(token: &str) -> Option<Jwt> {
    cached(token, Date::now().as_millis())
}

/// Per-isolate cache of verified tokens, keyed by the SHA-256 of the token
/// so raw tokens are never stored.
struct VerifiedCache {
    entries: HashMap<[u8; 32], (u64, Jwt)>,
}

impl VerifiedCache {
    /// Upper bound on entries, so a flood of distinct tokens can't grow the
    /// isolate's memory without limit.
    const MAX_ENTRIES: usize = 1024;

    fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    fn key(token: &str) -> [u8; 32] {
        Sha256::digest(token.as_bytes()).into()
    }

    fn get(&self, key: &[u8; 32], now_ms: u64) -> Option<Jwt> {
        self.entries
            .get(key)
            .filter(|(expires_at, _)| now_ms < *expires_at)
            .map(|(_, jwt)| jwt.clone())
    }

    fn insert(&mut self, key: [u8; 32], jwt: Jwt, expires_at: u64, now_ms: u64) {
        if self.entries.len() >= Self::MAX_ENTRIES {
            self.entries
                .retain(|_, (expires_at, _)| now_ms < *expires_at);
        }
        if self.entries.len() >= Self::MAX_ENTRIES {
            self.entries.clear();
        }
        self.entries.insert(key, (expires_at, jwt));
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Map, Value, json};

    use super::*;
    use crate::oidc::ALGORITHM;

    const ISSUER: &str = "https://token.actions.githubusercontent.com";
    const AUDIENCE: &str = "https://cloudflare-sts-api.example.com";

    #[derive(Debug, Deserialize)]
    struct TestProvider {
        issuer: String,
        #[serde(default = "audience")]
        audience: String,
        jwks_uri: Option<String>,
        typ: Option<String>,
    }

    fn audience() -> String {
        AUDIENCE.to_string()
    }

    impl Provider for TestProvider {
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

    fn providers(value: Value) -> Providers<TestProvider> {
        serde_json::from_value(value).unwrap()
    }

    fn claims(iss: &str) -> Claims {
        let claims: Map<String, Value> = json!({ "iss": iss }).as_object().unwrap().clone();
        claims.into()
    }

    #[test]
    fn picks_the_provider_by_the_tokens_issuer() {
        let providers = providers(json!([{ "issuer": ISSUER }]));
        assert_eq!(
            providers.for_claims(&claims(ISSUER)).unwrap().issuer,
            ISSUER
        );
        assert_eq!(
            providers
                .for_claims(&claims("https://other.example.com"))
                .err(),
            Some(Error::InvalidToken(
                "no provider is for issuer https://other.example.com".into()
            ))
        );
        assert_eq!(providers.len(), 1, "it derefs to the providers");
    }

    #[test]
    fn checks_the_typ_a_provider_names() {
        let header = Header {
            alg: ALGORITHM.into(),
            kid: None,
            typ: Some("JWT".into()),
        };
        let typ = |typ: Value| providers(json!([{ "issuer": ISSUER, "typ": typ }]));
        assert_eq!(typ(Value::Null)[0].check_header(&header), Ok(()));
        assert_eq!(typ(json!("jwt"))[0].check_header(&header), Ok(()));
        assert_eq!(
            typ(json!("at+jwt"))[0].check_header(&header),
            Err(invalid("typ must be at+jwt"))
        );
    }

    #[test]
    fn check_says_whats_wrong_and_where() {
        let check = |value: Value| providers(value).check("providers");
        assert_eq!(check(json!([{ "issuer": ISSUER }])), Ok(()));
        assert_eq!(
            check(
                json!([{ "issuer": "http://localhost:8788", "jwks_uri": "http://127.0.0.1/jwks" }])
            ),
            Ok(())
        );
        for (value, expected) in [
            (json!([]), "providers must name at least one provider"),
            (
                json!([{ "issuer": "http://issuer.example.com" }]),
                "providers[0].issuer must be an https:// URL",
            ),
            (
                json!([{ "issuer": ISSUER, "jwks_uri": "http://issuer.example.com/jwks" }]),
                "providers[0].jwks_uri must be an https:// URL",
            ),
            (
                json!([{ "issuer": ISSUER, "audience": "/" }]),
                "providers[0].audience must not be empty",
            ),
            (
                json!([{ "issuer": ISSUER }, { "issuer": ISSUER }]),
                "providers[1]: https://token.actions.githubusercontent.com is configured twice",
            ),
        ] {
            assert_eq!(check(value.clone()), Err(expected.to_string()), "{value}");
        }
    }

    fn jwt() -> Jwt {
        Jwt {
            header: Header::default(),
            claims: Claims::default(),
        }
    }

    #[test]
    fn verified_tokens_expire() {
        let mut cache = VerifiedCache::new();
        let key = VerifiedCache::key("token");
        cache.insert(key, jwt(), 100, 0);
        assert_eq!(cache.get(&key, 99), Some(jwt()));
        assert_eq!(cache.get(&key, 100), None);
    }

    #[test]
    fn verified_tokens_are_bounded() {
        let mut cache = VerifiedCache::new();
        for i in 0..=VerifiedCache::MAX_ENTRIES {
            cache.insert(VerifiedCache::key(&i.to_string()), jwt(), 100, 0);
        }
        assert!(cache.entries.len() <= VerifiedCache::MAX_ENTRIES);
    }
}
