//! Cloudflare Secrets Store: the three calls the broker makes to write its own
//! Cloudflare token back, for [`rotate`](super::rotate).
//!
//! By hand, over `fetch`, as [`access`](super::access) is, and for the same
//! reason: the generated client's Secrets Store product is twelve operations
//! the Worker would carry for three. The binding itself can only `get`, so a
//! new value goes in over the API, which needs the secret's ID, and the policy
//! only names its store and its name.

use serde::Deserialize;
use serde_json::json;
use worker::Method;

use super::{
    access::{Failure, failure},
    config::CloudflareConfig,
};

/// Secrets listed per page while the broker looks for its own by name.
const PAGE_SIZE: usize = 50;

/// How many pages it looks through before giving up. `search` narrows the list
/// to the name, so the secret is on the first page of any sane store.
const MAX_PAGES: usize = 10;

/// A secret as it's listed or fetched. Never its value: Secrets Store doesn't
/// hand that back, which is the point of it.
#[derive(Debug, Deserialize)]
pub struct Stored {
    pub id: String,
    pub name: String,
    /// The services allowed to use it, `workers` among them for a secret bound
    /// to a Worker.
    ///
    /// `None` for a secret that doesn't say, which the schema allows: the
    /// field isn't required. It is never turned into an empty list, because
    /// writing that back would be writing "no service may use this" over a
    /// secret the Worker reads.
    #[serde(default)]
    pub scopes: Option<Vec<String>>,
    #[serde(default)]
    pub comment: Option<String>,
}

/// Why a write didn't go through, and whether Cloudflare said so for certain.
///
/// The difference decides what the caller may undo. A refusal is proof the
/// secret still holds what it held. Anything else — a request that never
/// arrived, an answer that never came back, a `500` — cannot tell a refusal
/// from a write that took and whose answer was lost, and a caller that treats
/// the two alike will eventually delete the token the secret now holds.
#[derive(Debug)]
pub enum NotWritten {
    /// Cloudflare refused it: the secret is as it was.
    Rejected(Failure),
    /// Whether it applied isn't known.
    Uncertain(Failure),
}

impl std::fmt::Display for NotWritten {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rejected(why) => write!(f, "{why}"),
            Self::Uncertain(why) => write!(f, "{why} (whether it applied isn't known)"),
        }
    }
}

impl CloudflareConfig {
    fn secrets_path(&self, store_id: &str) -> String {
        format!(
            "/accounts/{}/secrets_store/stores/{store_id}/secrets",
            self.account_id()
        )
    }

    /// The secret called `name` in `store_id`, or `None` if the store has no
    /// such secret. Matched exactly: `search` only narrows the pages.
    ///
    /// The policy holds `name` to a character set that goes in a query string
    /// as it is, so it isn't escaped here.
    ///
    /// # Errors
    ///
    /// What Cloudflare answered, or that it didn't.
    pub async fn find_secret(&self, store_id: &str, name: &str) -> Result<Option<Stored>, Failure> {
        for page in 1..=MAX_PAGES {
            let path = format!(
                "{}?page={page}&per_page={PAGE_SIZE}&search={name}",
                self.secrets_path(store_id)
            );
            let (status, body) = self
                .call(Method::Get, &path, None)
                .await
                .map_err(|err| err.to_string())?;
            if !(200..300).contains(&status) || body["success"] != true {
                return Err(failure(status, &body));
            }
            // Not `unwrap_or_default`: a page that can't be read is not a page
            // with nothing on it, and reporting the secret missing would send
            // the caller down the "there's no such secret" path over what is
            // really a shape the broker didn't expect.
            let secrets: Vec<Stored> = serde_json::from_value(body["result"].clone())
                .map_err(|why| format!("secrets.list returned a page it couldn't read: {why}"))?;
            let count = secrets.len();
            if let Some(found) = secrets.into_iter().find(|secret| secret.name == name) {
                return Ok(Some(found));
            }
            if count < PAGE_SIZE {
                break;
            }
        }
        Ok(None)
    }

    /// Writes `value` to `secret`, naming back the scopes and comment it
    /// already has so a patch that replaces what it names can't drop them. A
    /// secret that lost `workers` would stop reaching the Worker that reads
    /// it; one whose scopes this didn't come back with is left unnamed, which
    /// is the only thing that can't make them worse.
    ///
    /// # Errors
    ///
    /// [`NotWritten`], which says whether Cloudflare refused the write or
    /// whether that can't be told. Only a refusal means the secret is
    /// unchanged.
    pub async fn put_secret_value(
        &self,
        store_id: &str,
        secret: &Stored,
        value: &str,
    ) -> Result<(), NotWritten> {
        let mut body = json!({ "value": value });
        if let Some(scopes) = &secret.scopes {
            body["scopes"] = scopes.as_slice().into();
        }
        if let Some(comment) = &secret.comment {
            body["comment"] = comment.as_str().into();
        }
        let path = format!("{}/{}", self.secrets_path(store_id), secret.id);
        // A request that didn't come back says nothing about whether it
        // arrived.
        let (status, body) = self
            .call(Method::Patch, &path, Some(&body))
            .await
            .map_err(|err| NotWritten::Uncertain(err.to_string()))?;
        match status {
            200..=299 if body["success"] == true => Ok(()),
            // Refused, and said so in as many words: Cloudflare doesn't
            // half-apply a patch it answers for.
            200..=299 if body["success"] == false => {
                Err(NotWritten::Rejected(failure(status, &body)))
            }
            400..=499 => Err(NotWritten::Rejected(failure(status, &body))),
            // Everything else says nothing either way. A `2xx` whose body
            // couldn't be read is most likely a write that took — `call`
            // hands back a null body for one it couldn't parse — and a `5xx`
            // may be the store's answer to a write it took as well.
            _ => Err(NotWritten::Uncertain(failure(status, &body))),
        }
    }
}
