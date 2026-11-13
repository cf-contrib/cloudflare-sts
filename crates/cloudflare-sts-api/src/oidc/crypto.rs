//! RS256 (RSASSA-PKCS1-v1_5 with SHA-256) through the runtime's WebCrypto, for
//! verifying and signing alike: no RSA crate ends up in the wasm, and a
//! signing key never leaves WebCrypto.

use serde_json::json;
use web_sys::{CryptoKey, SubtleCrypto, WorkerGlobalScope};
use worker::{
    js_sys::{self, Uint8Array},
    wasm_bindgen::{JsCast, JsValue},
    wasm_bindgen_futures::JsFuture,
};

use crate::oidc::{ALGORITHM, KeyError};

/// Whether `signature` is the RS256 signature of `signing_input` by the RSA
/// public key `n` and `e`, base64url. A signature WebCrypto refuses to check,
/// such as one of the wrong length, isn't.
pub(crate) async fn verify_rs256(
    n: &str,
    e: &str,
    signing_input: &[u8],
    signature: &[u8],
) -> Result<bool, KeyError> {
    let subtle = subtle()?;
    let algorithm = rs256()?;
    let jwk = json!({ "kty": "RSA", "n": n, "e": e, "alg": ALGORITHM });
    let jwk: js_sys::Object = js_sys::JSON::parse(&jwk.to_string())
        .map(JsCast::unchecked_into)
        .map_err(error)?;
    let usages = js_sys::Array::of1(&JsValue::from_str("verify"));
    let key: CryptoKey =
        promised(subtle.import_key_with_object("jwk", &jwk, &algorithm, false, &usages))
            .await?
            .unchecked_into();

    let verified = subtle.verify_with_object_and_buffer_source_and_buffer_source(
        &algorithm,
        &key,
        &Uint8Array::from(signature),
        &Uint8Array::from(signing_input),
    );
    match verified {
        Ok(promise) => {
            Ok(JsFuture::from(promise).await.ok().and_then(|v| v.as_bool()) == Some(true))
        }
        Err(_) => Ok(false),
    }
}

/// A fresh random UUID.
pub(crate) fn random_uuid() -> Result<String, KeyError> {
    let scope = js_sys::global().unchecked_into::<WorkerGlobalScope>();
    Ok(scope.crypto().map_err(error)?.random_uuid())
}

/// What WebCrypto threw, as a [`KeyError`].
pub(crate) fn error(err: JsValue) -> KeyError {
    let why = err
        .dyn_ref::<js_sys::Error>()
        .map(|err| String::from(err.message()))
        .unwrap_or_else(|| format!("{err:?}"));
    KeyError(format!("WebCrypto: {why}"))
}

/// The runtime's `crypto.subtle`.
pub(crate) fn subtle() -> Result<SubtleCrypto, KeyError> {
    let scope = js_sys::global().unchecked_into::<WorkerGlobalScope>();
    Ok(scope.crypto().map_err(error)?.subtle())
}

/// What a WebCrypto call's promise resolves to.
pub(crate) async fn promised(
    promise: Result<js_sys::Promise, JsValue>,
) -> Result<JsValue, KeyError> {
    JsFuture::from(promise.map_err(error)?).await.map_err(error)
}

/// RS256's WebCrypto algorithm.
pub(crate) fn rs256() -> Result<js_sys::Object, KeyError> {
    js_sys::JSON::parse(r#"{"name":"RSASSA-PKCS1-v1_5","hash":"SHA-256"}"#)
        .map(JsCast::unchecked_into)
        .map_err(error)
}
