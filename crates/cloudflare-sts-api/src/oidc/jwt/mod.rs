//! JWTs (RFC 7519) in the JWS Compact Serialization (RFC 7515): a token's
//! JOSE [`Header`] and JWT [`Claims`], and decoding one as it was sent.

mod claims;
mod header;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Map, Value};

pub(crate) use self::claims::LEEWAY_SECS;
pub use self::{
    claims::Claims,
    header::{ALGORITHM, Header},
};
use crate::oidc::{Error, error::invalid};

/// A JWT that [`Providers::verify`](crate::oidc::Providers::verify) accepted: its signature checked
/// against its issuer's keys, and its registered claims validated.
#[derive(Clone, Debug, PartialEq)]
pub struct Jwt {
    /// Its JOSE Header.
    pub header: Header,
    /// Its JWT Claims Set.
    pub claims: Claims,
}

/// A JWT as it was sent: decoded, not yet verified.
pub(crate) struct Unverified<'a> {
    pub(crate) jwt: Jwt,
    /// `<header>.<payload>`, the bytes the signature covers.
    pub(crate) signing_input: &'a str,
    pub(crate) signature: Vec<u8>,
}

impl<'a> Unverified<'a> {
    /// Decodes `token`, and validates its JOSE Header (RFC 7519 §7.2): its
    /// `alg` must be RS256, and it may not have a `crit` (RFC 7515 §4.1.11),
    /// since no extension is understood.
    pub(crate) fn decode(token: &'a str) -> Result<Self, Error> {
        let not_a_jwt = || invalid("not a JWT");
        let segment = |s: &str| URL_SAFE_NO_PAD.decode(s).map_err(|_| not_a_jwt());

        let parts: Vec<&str> = token.split('.').collect();
        let [header, payload, signature] = parts[..] else {
            return Err(not_a_jwt());
        };

        let header: Map<String, Value> =
            serde_json::from_slice(&segment(header)?).map_err(|_| not_a_jwt())?;
        let crit = header.contains_key("crit");
        let header: Header =
            serde_json::from_value(Value::Object(header)).map_err(|_| not_a_jwt())?;
        let claims: Claims = serde_json::from_slice(&segment(payload)?).map_err(|_| not_a_jwt())?;
        if header.alg != ALGORITHM {
            return Err(invalid("alg must be RS256"));
        }
        if crit {
            return Err(invalid("crit names extensions that aren't supported"));
        }

        Ok(Self {
            jwt: Jwt { header, claims },
            signing_input: &token[..token.len() - signature.len() - 1],
            signature: segment(signature)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const ISSUER: &str = "https://token.actions.githubusercontent.com";

    fn claims() -> Map<String, Value> {
        json!({ "iss": ISSUER, "aud": "https://cloudflare-sts-api.example.com", "exp": 1_800_000_300 })
            .as_object()
            .unwrap()
            .clone()
    }

    fn segment(value: Value) -> String {
        URL_SAFE_NO_PAD.encode(value.to_string())
    }

    #[test]
    fn decode_splits_a_jwt() {
        let header = segment(json!({ "alg": "RS256", "kid": "key-1", "typ": "JWT" }));
        let payload = segment(Value::Object(claims()));
        let token = format!("{header}.{payload}.c2ln");

        let decoded = Unverified::decode(&token).expect("should decode");
        assert_eq!(
            decoded.jwt.header,
            Header {
                alg: "RS256".into(),
                kid: Some("key-1".into()),
                typ: Some("JWT".into()),
            }
        );
        assert_eq!(decoded.jwt.claims, Claims::from(claims()));
        assert_eq!(decoded.signing_input, format!("{header}.{payload}"));
        assert_eq!(decoded.signature, b"sig");
    }

    #[test]
    fn decode_rejects_anything_else() {
        let payload = segment(json!({ "iss": ISSUER }));
        let with_header = |header: Value| format!("{}.{payload}.c2ln", segment(header));
        let cases = [
            ("gho_notAJwt".to_string(), "not a JWT"),
            ("not.a.jwt".to_string(), "not a JWT"),
            ("a.b.c.d".to_string(), "not a JWT"),
            (
                format!(
                    "{}.{}.c2ln",
                    segment(json!({ "alg": "RS256" })),
                    segment(json!([]))
                ),
                "not a JWT",
            ),
            (with_header(json!({ "alg": "none" })), "alg must be RS256"),
            (with_header(json!({ "alg": "HS256" })), "alg must be RS256"),
            (
                with_header(json!({ "alg": "RS256", "crit": ["exp"], "exp": 1 })),
                "crit names extensions that aren't supported",
            ),
        ];
        for (token, expected) in cases {
            assert_eq!(
                Unverified::decode(&token).err(),
                Some(invalid(expected)),
                "{token}"
            );
        }
    }
}
