//! The JOSE Header (RFC 7515 §4): the parameters a JWT is verified by, and the
//! values the crate gives them.

use serde::Deserialize;

/// What tokens are signed with, and what OIDC verifiers support by default.
pub const ALGORITHM: &str = "RS256";

/// The `typ` of a JWT access token (RFC 9068 §2.1): what a resource server
/// names as its [`Provider::typ`](crate::oidc::Provider::typ) to take nothing else.
pub const AT_JWT: &str = "at+jwt";

/// The JOSE Header parameters (RFC 7515 §4.1) a JWT is verified by.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct Header {
    /// `alg`: `RS256`, the only algorithm accepted.
    pub alg: String,
    /// `kid`: which of its issuer's keys signed it.
    #[serde(default)]
    pub kid: Option<String>,
    /// `typ`: what kind of JWT it is (RFC 8725 §3.11), such as `JWT` or
    /// `at+jwt`.
    #[serde(default)]
    pub typ: Option<String>,
}

impl Header {
    /// Whether its `typ` is `expected`. Media types compare without case, and
    /// with or without their `application/` prefix (RFC 7515 §4.1.9).
    pub fn typ_is(&self, expected: &str) -> bool {
        let media_type = |typ: &str| {
            let typ = typ.to_ascii_lowercase();
            match typ.strip_prefix("application/") {
                Some(subtype) => subtype.to_string(),
                None => typ,
            }
        };
        self.typ
            .as_deref()
            .is_some_and(|typ| media_type(typ) == media_type(expected))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typ_compares_as_a_media_type() {
        let header = |typ: &str| Header {
            alg: ALGORITHM.into(),
            kid: None,
            typ: Some(typ.into()),
        };
        assert!(header("at+jwt").typ_is("at+jwt"));
        assert!(header("application/AT+JWT").typ_is("at+jwt"));
        assert!(header("JWT").typ_is("application/jwt"));
        assert!(!header("JWT").typ_is("at+jwt"));
        assert!(!Header::default().typ_is("JWT"));
    }
}
