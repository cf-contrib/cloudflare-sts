//! Issuing tokens: a [`SigningKey`], an RSA key imported into WebCrypto,
//! signs JWTs and RFC 9068 access tokens with RS256, and publishes its public
//! half for a JWK Set.

use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use serde_json::{Map, Value, json};
use web_sys::CryptoKey;
use worker::{
    js_sys::{self, Uint8Array},
    wasm_bindgen::{JsCast, JsValue},
};

use crate::oidc::{ALGORITHM, AT_JWT, AccessTokenClaims, Claims, KeyError, crypto};

/// The smallest RSA key accepted, as NIST requires.
const MIN_MODULUS_BITS: usize = 2048;

/// An RSA private key, imported into WebCrypto to sign tokens with RS256.
pub struct SigningKey {
    key: CryptoKey,
    /// The public key, base64url.
    n: String,
    e: String,
    /// The public key's RFC 7638 thumbprint, so a new key gets a new `kid`
    /// without any configuration.
    kid: String,
}

/// A token a [`SigningKey`] signed, with [`sign`](SigningKey::sign) or
/// [`sign_access_token`](SigningKey::sign_access_token).
pub struct SignedToken {
    /// The token, a JWT.
    pub jwt: String,
    /// Its `jti`, which signing gave it.
    pub jti: String,
}

impl SigningKey {
    /// The RSA key in `pem`, a PKCS#8 PEM, as `openssl genpkey -algorithm RSA`
    /// writes it.
    ///
    /// # Errors
    ///
    /// When it isn't an RSA private key in PKCS#8 PEM, or has fewer than 2048
    /// bits.
    pub async fn import(pem: &str) -> Result<Self, KeyError> {
        let not_rsa = || KeyError("not an RSA private key in PKCS#8 PEM".to_string());
        let der = pkcs8_der(pem).ok_or_else(not_rsa)?;

        let subtle = crypto::subtle()?;
        let usages = js_sys::Array::of1(&JsValue::from_str("sign"));
        // Extractable, so its public half can be exported to publish.
        let imported = subtle.import_key_with_object(
            "pkcs8",
            &Uint8Array::from(&der[..]),
            &crypto::rs256()?,
            true,
            &usages,
        );
        let key: CryptoKey = crypto::promised(imported)
            .await
            .map_err(|_| not_rsa())?
            .unchecked_into();
        let jwk = crypto::promised(subtle.export_key("jwk", &key)).await?;
        let jwk: String = js_sys::JSON::stringify(&jwk).map_err(crypto::error)?.into();
        let jwk: Value = serde_json::from_str(&jwk).unwrap_or_default();
        let (Some(n), Some(e)) = (jwk["n"].as_str(), jwk["e"].as_str()) else {
            return Err(not_rsa());
        };

        let bits = URL_SAFE_NO_PAD.decode(n).map_or(0, |n| n.len() * 8);
        if bits < MIN_MODULUS_BITS {
            return Err(KeyError(format!(
                "RSA key is {bits} bits, at least {MIN_MODULUS_BITS} needed"
            )));
        }
        // RFC 7638: the required members, in lexicographic order, without
        // whitespace.
        let canonical = format!(r#"{{"e":"{e}","kty":"RSA","n":"{n}"}}"#);
        let digest =
            crypto::promised(subtle.digest_with_str_and_buffer_source(
                "SHA-256",
                &Uint8Array::from(canonical.as_bytes()),
            ))
            .await?;
        Ok(Self {
            key,
            n: n.to_string(),
            e: e.to_string(),
            kid: URL_SAFE_NO_PAD.encode(Uint8Array::new(&digest).to_vec()),
        })
    }

    /// The public half, as a JWKS publishes it.
    pub fn public_jwk(&self) -> Value {
        json!({ "kty": "RSA", "n": self.n, "e": self.e, "kid": self.kid, "alg": ALGORITHM, "use": "sig" })
    }

    /// Signs `claims` as a JWT access token (RFC 9068): `typ` `at+jwt`, so a
    /// resource server can tell it from any other JWT, with a fresh random
    /// `jti`.
    ///
    /// # Errors
    ///
    /// When WebCrypto fails.
    pub async fn sign_access_token(
        &self,
        claims: AccessTokenClaims,
    ) -> Result<SignedToken, KeyError> {
        self.sign_typed(AT_JWT, claims.into()).await
    }

    async fn sign_typed(&self, typ: &str, claims: Claims) -> Result<SignedToken, KeyError> {
        let jti = crypto::random_uuid()?;
        let mut claims: Map<String, Value> = claims.into();
        claims.insert("jti".to_string(), json!(jti));

        let header = json!({ "alg": ALGORITHM, "kid": self.kid, "typ": typ });
        let signing_input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(Value::Object(claims).to_string())
        );
        let signature = crypto::promised(crypto::subtle()?.sign_with_object_and_buffer_source(
            &crypto::rs256()?,
            &self.key,
            &Uint8Array::from(signing_input.as_bytes()),
        ))
        .await?;
        let signature = URL_SAFE_NO_PAD.encode(Uint8Array::new(&signature).to_vec());
        Ok(SignedToken {
            jwt: format!("{signing_input}.{signature}"),
            jti,
        })
    }
}

/// The DER inside a PKCS#8 PEM.
fn pkcs8_der(pem: &str) -> Option<Vec<u8>> {
    let body = pem
        .trim()
        .strip_prefix("-----BEGIN PRIVATE KEY-----")?
        .strip_suffix("-----END PRIVATE KEY-----")?;
    let base64: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    STANDARD.decode(base64).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_a_pkcs8_pem() {
        let pem = "-----BEGIN PRIVATE KEY-----\nAAEC\nAwQ=\n-----END PRIVATE KEY-----\n";
        assert_eq!(pkcs8_der(pem), Some(vec![0, 1, 2, 3, 4]));
        assert_eq!(
            pkcs8_der("-----BEGIN RSA PRIVATE KEY-----\nAAEC\n-----END RSA PRIVATE KEY-----"),
            None
        );
        assert_eq!(pkcs8_der("not a pem"), None);
    }
}
