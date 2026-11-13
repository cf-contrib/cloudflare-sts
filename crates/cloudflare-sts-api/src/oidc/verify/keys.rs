//! An issuer's keys: its JWK Set (RFC 7517), the RSA public keys (RFC 7518
//! §6.3) in it that verify RS256 signatures, fetching it, and caching it per
//! isolate.

use std::{cell::RefCell, collections::HashMap};

use serde::{Deserialize, de::DeserializeOwned};
use worker::{AbortSignal, Fetch, Method, Request};

use super::metadata;
use crate::oidc::{ALGORITHM, Error, crypto, error::invalid};

/// How long a fetched JWK Set is trusted before it's fetched again.
const JWKS_TTL_MS: u64 = 10 * 60 * 1000;

/// An unknown `kid` refetches an issuer's JWK Set at most this often, so
/// tokens with made-up key IDs can't make the Worker hammer the issuer.
const JWKS_MIN_REFETCH_MS: u64 = 30 * 1000;

thread_local! {
    /// Each issuer's keys, by issuer.
    static KEYS: RefCell<HashMap<String, KeySet>> = RefCell::new(HashMap::new());
}

/// `issuer`'s key that `kid` names, or its only one when there's no `kid`:
/// cached, or fetched from `jwks_uri`, or the `jwks_uri` in its metadata.
pub(super) async fn find(
    issuer: &str,
    jwks_uri: Option<&str>,
    kid: Option<&str>,
    now_ms: u64,
) -> Result<RsaKey, Error> {
    let unknown = || invalid("unknown signing key");
    match KEYS.with_borrow(|sets| KeySet::lookup(sets.get(issuer), kid, now_ms)) {
        Lookup::Hit(key) => return Ok(key),
        Lookup::Unknown => return Err(unknown()),
        Lookup::Fetch => {}
    }

    let jwks_uri = match jwks_uri {
        Some(jwks_uri) => jwks_uri.to_string(),
        None => metadata::jwks_uri(issuer).await?,
    };
    let jwks: JwkSet = fetch_json(&jwks_uri).await?;
    let set = KeySet {
        keys: jwks.rs256_keys(),
        fetched_at: now_ms,
    };
    let key = set.find(kid).cloned();
    KEYS.with_borrow_mut(|sets| sets.insert(issuer.to_string(), set));
    key.ok_or_else(unknown)
}

/// How long an issuer has to answer.
const FETCH_TIMEOUT_MS: u32 = 10 * 1000;

/// Whether `url` is somewhere keys may be fetched from: HTTPS, or plain HTTP
/// on a loopback address, for a local issuer in development. For checking
/// other URLs in a configuration the same way;
/// [`Providers::check`](crate::oidc::Providers::check) checks providers'.
///
/// # Errors
///
/// Why it isn't.
pub fn check_url(url: &str) -> Result<(), &'static str> {
    let loopback = ["http://127.0.0.1", "http://localhost", "http://[::1]"]
        .iter()
        .any(|prefix| {
            url.strip_prefix(prefix)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with([':', '/']))
        });
    let https = url
        .strip_prefix("https://")
        .is_some_and(|rest| !rest.is_empty() && !rest.starts_with('/'));
    if url.contains(char::is_whitespace) || !(https || loopback) {
        return Err("must be an https:// URL");
    }
    Ok(())
}

/// The JSON at `url`. A URL [`check_url`] refuses is never fetched, whoever
/// configured it.
pub(super) async fn fetch_json<T: DeserializeOwned>(url: &str) -> Result<T, Error> {
    let unavailable =
        |err: worker::Error| Error::TemporarilyUnavailable(format!("fetching {url}: {err}"));
    check_url(url).map_err(|why| Error::TemporarilyUnavailable(format!("{url} {why}")))?;

    // `Request::new` hands the URL to the runtime; `Url::parse` would pull the
    // `url` crate and its IDNA tables into the bundle.
    let req = Request::new(url, Method::Get).map_err(unavailable)?;
    let signal = AbortSignal::from(web_sys::AbortSignal::timeout_with_u32(FETCH_TIMEOUT_MS));
    let mut resp = Fetch::Request(req)
        .send_with_signal(&signal)
        .await
        .map_err(unavailable)?;
    if resp.status_code() != 200 {
        return Err(Error::TemporarilyUnavailable(format!(
            "fetching {url} returned {}",
            resp.status_code()
        )));
    }
    resp.json().await.map_err(unavailable)
}

/// A JWK Set (RFC 7517 §5).
#[derive(Deserialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}

/// A JWK (RFC 7517 §4), with the members an RSA public key (RFC 7518 §6.3.1)
/// is read by.
#[derive(Deserialize)]
struct Jwk {
    kty: String,
    #[serde(rename = "use")]
    use_: Option<String>,
    key_ops: Option<Vec<String>>,
    alg: Option<String>,
    kid: Option<String>,
    n: Option<String>,
    e: Option<String>,
}

impl Jwk {
    /// Whether it may verify RS256 signatures: an RSA key that, if it says
    /// what it's for, says signatures (RFC 7517 §4.2, §4.3) with RS256
    /// (§4.4; RFC 8725 §3.1).
    fn verifies_rs256(&self) -> bool {
        self.kty == "RSA"
            && self.use_.as_deref().is_none_or(|use_| use_ == "sig")
            && (self.key_ops.as_ref()).is_none_or(|ops| ops.iter().any(|op| op == "verify"))
            && self.alg.as_deref().is_none_or(|alg| alg == ALGORITHM)
    }
}

/// An issuer's RSA public key.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct RsaKey {
    kid: Option<String>,
    n: String,
    e: String,
}

impl RsaKey {
    /// Its `kid`, if it has one.
    pub(crate) fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }

    /// Whether `signature` is its RS256 signature of `signing_input`, checked
    /// with WebCrypto.
    pub(crate) async fn verify(
        &self,
        signing_input: &[u8],
        signature: &[u8],
    ) -> Result<bool, Error> {
        crypto::verify_rs256(&self.n, &self.e, signing_input, signature)
            .await
            .map_err(|err| Error::TemporarilyUnavailable(err.to_string()))
    }
}

impl JwkSet {
    /// The keys in it that verify RS256 signatures. Any others are skipped, as
    /// RFC 7517 §5 says keys that aren't understood are.
    fn rs256_keys(self) -> Vec<RsaKey> {
        self.keys
            .into_iter()
            .filter(Jwk::verifies_rs256)
            .filter_map(|key| {
                Some(RsaKey {
                    kid: key.kid,
                    n: key.n?,
                    e: key.e?,
                })
            })
            .collect()
    }
}

/// An issuer's keys, cached per isolate.
struct KeySet {
    keys: Vec<RsaKey>,
    fetched_at: u64,
}

#[derive(Debug, PartialEq)]
enum Lookup {
    Hit(RsaKey),
    Fetch,
    /// Unknown `kid`, and the JWK Set was fetched too recently to try again.
    Unknown,
}

impl KeySet {
    /// The key with this `kid`; without one, the only key there is.
    fn find(&self, kid: Option<&str>) -> Option<&RsaKey> {
        match kid {
            Some(kid) => self.keys.iter().find(|key| key.kid() == Some(kid)),
            None => match self.keys.as_slice() {
                [only] => Some(only),
                _ => None,
            },
        }
    }

    fn lookup(set: Option<&KeySet>, kid: Option<&str>, now_ms: u64) -> Lookup {
        let Some(set) = set else {
            return Lookup::Fetch;
        };
        let age = now_ms.saturating_sub(set.fetched_at);
        match set.find(kid) {
            Some(key) if age < JWKS_TTL_MS => Lookup::Hit(key.clone()),
            Some(_) => Lookup::Fetch,
            None if age < JWKS_MIN_REFETCH_MS => Lookup::Unknown,
            None => Lookup::Fetch,
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn keeps_only_keys_that_verify_rs256() {
        let jwks: JwkSet = serde_json::from_value(json!({ "keys": [
            { "kty": "RSA", "kid": "plain", "n": "AQAB", "e": "AQAB" },
            { "kty": "RSA", "kid": "sig", "use": "sig", "alg": "RS256", "key_ops": ["verify"], "n": "AQAB", "e": "AQAB" },
            { "kty": "RSA", "kid": "enc", "use": "enc", "n": "AQAB", "e": "AQAB" },
            { "kty": "RSA", "kid": "rs512", "alg": "RS512", "n": "AQAB", "e": "AQAB" },
            { "kty": "RSA", "kid": "encrypt", "key_ops": ["encrypt"], "n": "AQAB", "e": "AQAB" },
            { "kty": "RSA", "kid": "no-modulus", "e": "AQAB" },
            { "kty": "EC", "kid": "ec", "x": "AA", "y": "AA" },
        ]}))
        .unwrap();
        let keys = jwks.rs256_keys();
        let kids: Vec<_> = keys.iter().filter_map(RsaKey::kid).collect();
        assert_eq!(kids, ["plain", "sig"]);
    }

    #[test]
    fn allows_http_only_on_loopback() {
        for url in [
            "https://issuer.example.com",
            "http://127.0.0.1:8788",
            "http://localhost",
            "http://[::1]:9000/oidc",
        ] {
            assert_eq!(check_url(url), Ok(()), "{url}");
        }
        for url in [
            "http://issuer.example.com",
            "https://",
            "http://127.0.0.1.example.com",
            "http://localhost.example.com",
            "https://issuer.example.com/a b",
        ] {
            assert!(check_url(url).is_err(), "{url}");
        }
    }

    #[test]
    fn refetches_sparingly() {
        let jwks: JwkSet = serde_json::from_value(json!({ "keys": [
            { "kty": "RSA", "kid": "key-1", "n": "AQAB", "e": "AQAB" },
        ]}))
        .unwrap();
        let set = KeySet {
            keys: jwks.rs256_keys(),
            fetched_at: 0,
        };

        assert_eq!(KeySet::lookup(None, Some("key-1"), 0), Lookup::Fetch);
        assert!(matches!(
            KeySet::lookup(Some(&set), Some("key-1"), 1),
            Lookup::Hit(_)
        ));
        // Without a kid, the only key.
        assert!(matches!(
            KeySet::lookup(Some(&set), None, 1),
            Lookup::Hit(_)
        ));
        assert_eq!(
            KeySet::lookup(Some(&set), Some("key-1"), JWKS_TTL_MS),
            Lookup::Fetch
        );
        assert_eq!(
            KeySet::lookup(Some(&set), Some("key-2"), 1),
            Lookup::Unknown
        );
        assert_eq!(
            KeySet::lookup(Some(&set), Some("key-2"), JWKS_MIN_REFETCH_MS),
            Lookup::Fetch
        );
    }
}
