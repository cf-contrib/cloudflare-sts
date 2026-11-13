//! What goes wrong: [`Error`], why a token isn't accepted, as RFC 6750 codes
//! it; and [`KeyError`], what WebCrypto refused.

use std::fmt;

/// Why a token isn't accepted, as the error codes of RFC 6750 §3.1 (and RFC
/// 6749 §4.1.2.1, for an issuer that can't be reached) have it.
#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    /// `invalid_token`: malformed, not signed by its issuer's keys, for
    /// another audience, expired, or from an issuer no provider is for.
    InvalidToken(String),
    /// `insufficient_scope`: a valid token none of the
    /// [`ClaimRules`](crate::oidc::ClaimRules) matches. Which would have isn't
    /// said: that's the configuration, not the caller's to probe.
    InsufficientScope {
        /// The token's `iss`.
        issuer: String,
        /// The token's `sub`.
        subject: Option<String>,
    },
    /// `temporarily_unavailable`: the issuer's metadata or keys couldn't be
    /// had. Not the caller's fault.
    TemporarilyUnavailable(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidToken(message) | Self::TemporarilyUnavailable(message) => {
                f.write_str(message)
            }
            Self::InsufficientScope { issuer, .. } => {
                write!(f, "the token matches none of {issuer}'s claim sets")
            }
        }
    }
}

impl std::error::Error for Error {}

/// An [`Error::InvalidToken`] saying what's invalid about it.
pub(crate) fn invalid(what: &str) -> Error {
    Error::InvalidToken(format!("invalid token: {what}"))
}

/// What WebCrypto refused: a key that can't be imported, or a signature it
/// can't make or check.
#[derive(Clone, Debug, PartialEq)]
pub struct KeyError(pub(crate) String);

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for KeyError {}
