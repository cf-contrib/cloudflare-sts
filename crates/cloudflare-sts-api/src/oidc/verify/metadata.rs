//! An issuer's metadata: where its keys are, from its OpenID Provider Metadata
//! (OpenID Connect Discovery 1.0) or its Authorization Server Metadata (RFC
//! 8414).

use serde::Deserialize;

use super::keys::{check_url, fetch_json};
use crate::oidc::Error;

/// The `jwks_uri` in `issuer`'s metadata: its OpenID Provider Metadata, or,
/// when it publishes none, its Authorization Server Metadata.
pub(crate) async fn jwks_uri(issuer: &str) -> Result<String, Error> {
    let mut failures = Vec::new();
    for url in metadata_urls(issuer) {
        match fetch_json::<Metadata>(&url).await {
            Ok(metadata) => return metadata.jwks_uri(issuer, &url),
            Err(err) => failures.push(err.to_string()),
        }
    }
    Err(Error::TemporarilyUnavailable(failures.join("; ")))
}

/// Where `issuer` publishes its metadata, in the order tried:
///
/// - OpenID Connect Discovery 1.0 §4 appends
///   `/.well-known/openid-configuration` to the issuer;
/// - RFC 8414 §3.1 puts `/.well-known/oauth-authorization-server` between
///   its host and its path.
///
/// A trailing `/` on the issuer is dropped first, as both say.
fn metadata_urls(issuer: &str) -> [String; 2] {
    let issuer = issuer.trim_end_matches('/');
    let host_end = issuer
        .find("://")
        .and_then(|scheme| issuer[scheme + 3..].find('/').map(|path| scheme + 3 + path))
        .unwrap_or(issuer.len());
    let (origin, path) = issuer.split_at(host_end);
    [
        format!("{issuer}/.well-known/openid-configuration"),
        format!("{origin}/.well-known/oauth-authorization-server{path}"),
    ]
}

/// What's read of an issuer's metadata: OpenID Provider Metadata (OpenID
/// Connect Discovery 1.0 §3) or Authorization Server Metadata (RFC 8414 §2),
/// whose `issuer` and `jwks_uri` mean the same.
#[derive(Deserialize)]
struct Metadata {
    issuer: String,
    jwks_uri: Option<String>,
}

impl Metadata {
    /// Its `jwks_uri`, if it's `issuer`'s, fetched from `url`. The metadata
    /// must name its own issuer (OpenID Connect Discovery 1.0 §4.3, RFC 8414
    /// §3.3), so one issuer can't hand out another's keys.
    fn jwks_uri(self, issuer: &str, url: &str) -> Result<String, Error> {
        let unavailable = |why: String| Err(Error::TemporarilyUnavailable(format!("{url}: {why}")));
        if self.issuer != issuer {
            return unavailable(format!("is for issuer {}, not {issuer}", self.issuer));
        }
        let Some(jwks_uri) = self.jwks_uri else {
            return unavailable("names no jwks_uri".to_string());
        };
        if let Err(why) = check_url(&jwks_uri) {
            return unavailable(format!("jwks_uri {why}"));
        }
        Ok(jwks_uri)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn finds_metadata_where_both_specs_put_it() {
        assert_eq!(
            metadata_urls("https://broker.example.com"),
            [
                "https://broker.example.com/.well-known/openid-configuration",
                "https://broker.example.com/.well-known/oauth-authorization-server",
            ]
        );
        assert_eq!(
            metadata_urls("https://gitlab.example.com/tenant/"),
            [
                "https://gitlab.example.com/tenant/.well-known/openid-configuration",
                "https://gitlab.example.com/.well-known/oauth-authorization-server/tenant",
            ]
        );
        assert_eq!(
            metadata_urls("http://127.0.0.1:8788"),
            [
                "http://127.0.0.1:8788/.well-known/openid-configuration",
                "http://127.0.0.1:8788/.well-known/oauth-authorization-server",
            ]
        );
    }

    #[test]
    fn metadata_must_be_the_issuers_own() {
        const ISSUER: &str = "https://broker.example.com";
        const URL: &str = "https://broker.example.com/.well-known/oauth-authorization-server";
        let metadata =
            |value: serde_json::Value| -> Metadata { serde_json::from_value(value).unwrap() };

        assert_eq!(
            metadata(json!({ "issuer": ISSUER, "jwks_uri": "https://broker.example.com/jwks" }))
                .jwks_uri(ISSUER, URL),
            Ok("https://broker.example.com/jwks".to_string())
        );
        for (value, why) in [
            (
                json!({ "issuer": "https://other.example.com", "jwks_uri": "https://other.example.com/jwks" }),
                "is for issuer https://other.example.com, not https://broker.example.com",
            ),
            (json!({ "issuer": ISSUER }), "names no jwks_uri"),
            (
                json!({ "issuer": ISSUER, "jwks_uri": "http://broker.example.com/jwks" }),
                "jwks_uri must be an https:// URL",
            ),
        ] {
            assert_eq!(
                metadata(value).jwks_uri(ISSUER, URL),
                Err(Error::TemporarilyUnavailable(format!("{URL}: {why}")))
            );
        }
    }
}
