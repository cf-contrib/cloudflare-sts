//! OIDC tokens in Cloudflare Workers: verifying them, for any issuer (GitHub
//! Actions, GitLab, Cloudflare Access, or a broker that issues its own), and
//! signing them, for a Worker that is an issuer.
//!
//! Accepting a token takes two steps:
//!
//! 1. [`Providers::verify`] validates it as RFC 7519 §7.2 and RFC 8725 say.
//!    It picks its [`Provider`] by its `iss` claim, which must be one a
//!    provider names exactly, and checks its JOSE [`Header`]. Its RS256
//!    signature is checked with the runtime's WebCrypto against that issuer's
//!    keys, found through its metadata (or a configured `jwks_uri`) and never
//!    through anything in the token. Then its registered [`Claims`] are
//!    validated: `iss`, `aud`, `exp` and `nbf`.
//! 2. [`ClaimRules::authorize`] matches its claims against the policy, which
//!    no RFC says anything about.
//!
//! Keys are cached per isolate, and so is each verified token until it
//! expires: [`verified`] reads it back, so whoever verified a token can hand
//! it to whatever runs next without verifying it again.
//!
//! A Worker that issues its own tokens signs them with a [`SigningKey`], an RSA
//! key imported into WebCrypto, and publishes its [`SigningKey::public_jwk`].
//!
//! The futures aren't `Send`: they hold JavaScript values. A Worker is
//! single-threaded, so a caller that needs `Send`, such as an axum handler,
//! wraps them in `worker::send::SendFuture`.
//!
//! # Modules
//!
//! By role, then by the layers the RFCs draw within it:
//!
//! - `jwt`: the token format both roles share (RFC 7515, RFC 7519, RFC
//!   9068), which knows nothing of providers;
//! - `verify`: the resource server's side: providers and the tokens verified
//!   from them, their `keys` (RFC 7517) and `metadata` (OpenID Connect
//!   Discovery, RFC 8414), and the claim rules' `policy`;
//! - `sign`: the issuer's side;
//! - `crypto`: RS256 through WebCrypto, for both;
//! - `error`: what goes wrong.

mod crypto;
mod error;
mod jwt;
mod sign;
mod verify;

pub use crate::oidc::{
    error::{Error, KeyError},
    jwt::{ALGORITHM, AT_JWT, AccessTokenClaims, Claims, Header, Jwt},
    sign::SigningKey,
    verify::{ClaimRules, Provider, Providers, check_url, verified},
};
