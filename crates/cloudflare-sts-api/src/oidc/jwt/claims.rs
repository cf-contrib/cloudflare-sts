//! The JWT Claims Set (RFC 7519 §4): reading the registered claims, and
//! validating them; and the claims an RFC 9068 access token needs.

use std::ops::Deref;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::oidc::{Error, error::invalid};

/// Clock tolerance for `exp` and `nbf`.
pub(crate) const LEEWAY_SECS: u64 = 60;

/// A JWT Claims Set (RFC 7519 §4): every claim by its name, and the
/// registered ones through their own accessors.
///
/// It derefs to the claims' JSON object, so any claim reads as
/// `claims.get("repository")`.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(transparent)]
pub struct Claims(Map<String, Value>);

impl Claims {
    /// `iss`: who issued it.
    pub fn iss(&self) -> Option<&str> {
        self.0.get("iss").and_then(Value::as_str)
    }

    /// `sub`: whom it's about, unless it's empty, which is no one.
    pub fn sub(&self) -> Option<&str> {
        let sub = self.0.get("sub").and_then(Value::as_str);
        sub.filter(|sub| !sub.is_empty())
    }

    /// `aud`: whom it's for. One audience or several (RFC 7519 §4.1.3).
    pub fn aud(&self) -> impl Iterator<Item = &str> {
        let auds = match self.0.get("aud") {
            Some(Value::Array(auds)) => auds.as_slice(),
            Some(aud) => std::slice::from_ref(aud),
            None => &[],
        };
        auds.iter().filter_map(Value::as_str)
    }

    /// `exp`: when it expires, in seconds since the epoch, rounded down.
    pub fn exp(&self) -> Option<u64> {
        self.seconds("exp")
    }

    /// `nbf`: when it becomes valid, in seconds since the epoch, rounded
    /// down.
    pub fn nbf(&self) -> Option<u64> {
        self.seconds("nbf")
    }

    /// `iat`: when it was issued, in seconds since the epoch, rounded down.
    pub fn iat(&self) -> Option<u64> {
        self.seconds("iat")
    }

    /// `jti`: its unique identifier.
    pub fn jti(&self) -> Option<&str> {
        self.0.get("jti").and_then(Value::as_str)
    }

    /// `client_id`: the OAuth client it was issued to (RFC 8693 §4.3, RFC
    /// 9068 §2.2).
    pub fn client_id(&self) -> Option<&str> {
        self.0.get("client_id").and_then(Value::as_str)
    }

    /// `scope`: the scopes it grants, which the claim lists space-separated
    /// (RFC 8693 §4.2).
    pub fn scope(&self) -> impl Iterator<Item = &str> {
        let scope = self.0.get("scope").and_then(Value::as_str);
        scope
            .unwrap_or_default()
            .split(' ')
            .filter(|s| !s.is_empty())
    }

    /// The claims' JSON object.
    pub fn into_inner(self) -> Map<String, Value> {
        self.0
    }

    fn seconds(&self, name: &str) -> Option<u64> {
        self.0.get(name).and_then(numeric_date).map(|t| t as u64)
    }

    /// Validates its registered claims (RFC 7519 §4.1) for a token from
    /// `issuer` meant for `audience`, at `now`, in seconds since the epoch.
    /// `exp` is required; `nbf` is checked if present.
    pub(crate) fn validate(&self, issuer: &str, audience: &str, now: u64) -> Result<(), Error> {
        self.check_types()?;

        if self.iss() != Some(issuer) {
            return Err(invalid("wrong issuer"));
        }

        // A trailing `/` is ignored, on either side.
        let expected = audience.trim_end_matches('/');
        if !self.aud().any(|aud| aud.trim_end_matches('/') == expected) {
            let got = self.aud().collect::<Vec<_>>().join(", ");
            let got = if got.is_empty() {
                "missing".to_string()
            } else {
                got
            };
            let got: String = got.chars().take(200).collect();
            return Err(Error::InvalidToken(format!(
                "token audience is {got}, expected {audience}"
            )));
        }

        let now = now as f64;
        let leeway = LEEWAY_SECS as f64;
        let Some(exp) = self.0.get("exp").and_then(numeric_date) else {
            return Err(invalid("missing exp"));
        };
        if now >= exp + leeway {
            return Err(Error::InvalidToken("token expired".to_string()));
        }
        if let Some(nbf) = self.0.get("nbf").and_then(numeric_date)
            && nbf > now + leeway
        {
            return Err(Error::InvalidToken("token not valid yet".to_string()));
        }
        Ok(())
    }

    /// That each registered claim it has (RFC 7519 §4.1, RFC 8693 §4) is of
    /// its registered type: a token with an `nbf` that isn't a NumericDate
    /// must not pass for one without.
    fn check_types(&self) -> Result<(), Error> {
        for (name, value) in &self.0 {
            let ok = match name.as_str() {
                "iss" | "sub" | "jti" | "client_id" | "scope" => value.is_string(),
                "aud" => match value {
                    Value::Array(auds) => auds.iter().all(Value::is_string),
                    aud => aud.is_string(),
                },
                "exp" | "nbf" | "iat" => numeric_date(value).is_some(),
                _ => true,
            };
            if !ok {
                return Err(invalid(&format!("malformed {name}")));
            }
        }
        Ok(())
    }
}

impl Deref for Claims {
    type Target = Map<String, Value>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Map<String, Value>> for Claims {
    fn from(claims: Map<String, Value>) -> Self {
        Self(claims)
    }
}

impl From<Claims> for Map<String, Value> {
    fn from(claims: Claims) -> Self {
        claims.0
    }
}

/// A NumericDate (RFC 7519 §2): seconds since the epoch, which may have a
/// fraction. Never negative here.
fn numeric_date(value: &Value) -> Option<f64> {
    value.as_f64().filter(|t| t.is_finite() && *t >= 0.0)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const NOW: u64 = 1_800_000_000;
    const ISSUER: &str = "https://token.actions.githubusercontent.com";
    const AUDIENCE: &str = "https://cloudflare-sts-api.example.com";

    fn claims() -> Map<String, Value> {
        json!({
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": "repo:example-org/app:ref:refs/heads/main",
            "exp": NOW + 300,
            "nbf": NOW - 10,
            "iat": NOW - 10,
            "ref": "refs/heads/main",
        })
        .as_object()
        .unwrap()
        .clone()
    }

    fn validate(claims: Map<String, Value>, now: u64) -> Result<(), Error> {
        Claims::from(claims).validate(ISSUER, AUDIENCE, now)
    }

    #[test]
    fn reads_the_registered_claims() {
        let mut map = claims();
        map.insert("aud".into(), json!(["a", "b"]));
        map.insert("exp".into(), json!(1.8e9 + 0.5));
        map.insert("jti".into(), json!("id-1"));
        let claims = Claims::from(map);
        assert_eq!(claims.iss(), Some(ISSUER));
        assert_eq!(
            claims.sub(),
            Some("repo:example-org/app:ref:refs/heads/main")
        );
        assert_eq!(claims.aud().collect::<Vec<_>>(), ["a", "b"]);
        assert_eq!(claims.exp(), Some(1_800_000_000), "a fraction rounds down");
        assert_eq!(claims.nbf(), Some(NOW - 10));
        assert_eq!(claims.jti(), Some("id-1"));
        assert_eq!(claims.get("ref"), Some(&json!("refs/heads/main")));

        assert_eq!(claims.client_id(), None);
        assert_eq!(claims.scope().count(), 0);

        let mut empty = claims.into_inner();
        empty.insert("sub".into(), json!(""));
        assert_eq!(Claims::from(empty).sub(), None);
    }

    #[test]
    fn reads_the_claims_rfc_8693_registers() {
        let mut map = claims();
        map.insert("client_id".into(), json!("github"));
        map.insert("scope".into(), json!("cache:read  cache:write"));
        let claims = Claims::from(map);
        assert_eq!(claims.client_id(), Some("github"));
        assert_eq!(
            claims.scope().collect::<Vec<_>>(),
            ["cache:read", "cache:write"]
        );
    }

    #[test]
    fn accepts_an_audience_array_and_a_trailing_slash() {
        for aud in [
            json!(["https://other.example.com", AUDIENCE]),
            json!(format!("{AUDIENCE}/")),
        ] {
            let mut claims = claims();
            claims.insert("aud".into(), aud.clone());
            assert_eq!(validate(claims, NOW), Ok(()), "{aud}");
        }
    }

    #[test]
    fn says_what_is_wrong() {
        let cases: [(&str, Value, &str); 6] = [
            (
                "iss",
                json!("https://other.example.com"),
                "invalid token: wrong issuer",
            ),
            (
                "aud",
                json!("sts.amazonaws.com"),
                "token audience is sts.amazonaws.com, expected https://cloudflare-sts-api.example.com",
            ),
            (
                "aud",
                json!([]),
                "token audience is missing, expected https://cloudflare-sts-api.example.com",
            ),
            ("exp", json!(NOW - LEEWAY_SECS), "token expired"),
            ("nbf", json!(NOW + LEEWAY_SECS + 1), "token not valid yet"),
            (
                "nbf",
                json!(NOW as f64 + LEEWAY_SECS as f64 + 0.5),
                "token not valid yet",
            ),
        ];
        for (claim, value, expected) in cases {
            let mut claims = claims();
            claims.insert(claim.into(), value);
            assert_eq!(
                validate(claims, NOW),
                Err(Error::InvalidToken(expected.to_string())),
                "{claim}"
            );
        }

        let mut claims = claims();
        claims.remove("exp");
        assert_eq!(validate(claims, NOW), Err(invalid("missing exp")));
    }

    #[test]
    fn refuses_malformed_registered_claims() {
        for (claim, value) in [
            ("nbf", json!("1800000000")),
            ("nbf", json!(-1)),
            ("exp", json!(null)),
            ("iat", json!(true)),
            ("aud", json!([AUDIENCE, 1])),
            ("sub", json!(1)),
            ("jti", json!({})),
            ("client_id", json!(1)),
            ("scope", json!(["cache:read"])),
        ] {
            let mut claims = claims();
            claims.insert(claim.into(), value.clone());
            assert_eq!(
                validate(claims, NOW),
                Err(invalid(&format!("malformed {claim}"))),
                "{claim}: {value}"
            );
        }
    }

    #[test]
    fn tolerates_clock_skew() {
        let mut claims = claims();
        claims.insert("nbf".into(), json!(NOW + LEEWAY_SECS));
        assert_eq!(validate(claims.clone(), NOW), Ok(()));
        assert_eq!(validate(claims, NOW + 300 + LEEWAY_SECS - 1), Ok(()));
    }
}
