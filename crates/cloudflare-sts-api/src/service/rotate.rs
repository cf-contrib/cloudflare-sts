//! Rolling the broker's own Cloudflare token: the opt-in half of the hourly
//! cron, when the policy has a [`RotationConfig`].
//!
//! The broker replaces its token rather than rolling the value in place. A
//! `PUT .../tokens/{id}/value` invalidates the old value the moment it answers,
//! so a Secrets Store write that then failed would leave the Worker holding a
//! dead credential it can't authenticate with to fix. Instead it creates a copy
//! of its own token, writes that into the secret its binding reads, and deletes
//! the one it replaced only once Cloudflare says the binding hands the new one
//! over. Every failure leaves the old token live and the broker serving.
//!
//! The copy is deleted no sooner than `overlap` after the swap, because the R2
//! credentials the broker hands out name it as their `parent_access_key_id`:
//! deleting it takes them with it. The policy's guardrails make `overlap` at
//! least the longest `max_ttl` any profile hands out.
//!
//! # Reachable from the cron only
//!
//! [`rotate`] takes `Env`, because a Workers KV handle isn't `Send` and so
//! can't be held on the [`Config`] the request routers share. That is also the
//! property wanted: no request can begin a rotation.
//!
//! # What it remembers
//!
//! One KV key, `rotation`, beside the policy: a swap in flight, written before
//! Secrets Store is touched, and the tokens waiting out their overlap. A turn
//! that dies mid-swap leaves a record the next one reconciles. Where the record
//! can't say what happened, the broker changes nothing and says so: both tokens
//! are valid, so it keeps serving either way.

use cloudflare::v4::{ApiOpError, HttpClient, IamCreatePayload, IamTokenBase};
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};
use worker::{Date, Env, KvStore};

use super::{
    config::{Config, POLICY_BINDING, RotationConfig},
    secrets::NotWritten,
};

/// The keys the state is under, in the policy's namespace. Terraform writes
/// `config` and `policy` and leaves these alone.
const STATE_KEY: &str = "rotation";

/// The creation intent, under a key of its own.
///
/// It's written in the same breath as the swap's own record — one before the
/// create, one before the write — and Workers KV takes one write per key per
/// second. Sharing a key would have the second refused whenever the two calls
/// between them came back quickly, and a swap that can't record itself is one
/// that undoes itself, so every rotation would abort on a fast API.
const CREATING_KEY: &str = "rotation.creating";

/// What the broker names the tokens it makes for itself, before its own host.
///
/// Deliberately not under `cloudflare-sts:`, the prefix the cleanup and
/// revocation recognize: the broker's own token must not be something a caller
/// can get revoked, or the cron can delete.
const BROKER_PREFIX: &str = "cloudflare-sts-broker:";

/// How much of the broker's host its token names carry. The name is capped at
/// [`NAME_MAX`], and the prefix has to be derived the same way every time or a
/// broker would stop recognising its own tokens.
const HOST_MAX: usize = 64;

/// The longest token name Cloudflare takes, as the handler has it.
const NAME_MAX: usize = 120;

/// Tokens listed per page while the broker looks for its own.
const PAGE_SIZE: usize = 50;

/// How long a replaced token drains for when the policy no longer says.
///
/// Rotation switched off mid-flight leaves the broker finishing a swap with no
/// `overlap` to go by, so it uses longer than the longest-lived thing it could
/// have handed out: a profile's `max_ttl` is capped at 24h.
const MAX_DRAIN: i64 = 25 * 60 * 60;

/// How often the cron that drives this runs, as the Terraform module and
/// `wrangler.toml` set it up. Only used to leave room for another turn before
/// a token runs out.
const CRON_PERIOD: i64 = 60 * 60;

/// Room for the calls a swap makes, and for a request that was already holding
/// the replaced token when the handover was seen and goes on to mint
/// credentials with it.
///
/// Added to the drain window as well as to the expiry lead: the window has to
/// outlast the longest credential that could be minted just after the
/// handover, not just the longest one minted before it.
const MARGIN: i64 = 5 * 60;

/// What the broker remembers between turns of the cron.
#[derive(Debug, Default, Deserialize, Serialize)]
struct State {
    /// A swap that was begun: written before Secrets Store is patched, and
    /// kept until the binding is seen to hand the copy over.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending: Option<Pending>,
    /// The tokens it replaced, waiting out their overlap.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    retiring: Vec<Retiring>,
}

impl State {
    /// Whether there's nothing outstanding, so a broker that no longer rolls
    /// its token has nothing to finish either.
    fn is_empty(&self) -> bool {
        self.pending.is_none() && self.retiring.is_empty()
    }

    /// Whether `token_id` is one this state accounts for, and so isn't a
    /// token nothing knows about.
    fn accounts_for(&self, token_id: &str) -> bool {
        self.pending.as_ref().is_some_and(|pending| {
            pending.new_token_id == token_id || pending.old_token_id == token_id
        }) || self.retiring.iter().any(|e| e.token_id == token_id)
    }
}

/// A copy the broker is about to make, by the name it will carry.
///
/// Written before the create, so a create whose answer never came back still
/// leaves something that knows to go looking. Without it a lost answer would
/// leave a token with the broker's own permissions, no expiry, and nothing
/// anywhere that knew to collect it.
#[derive(Debug, Deserialize, Serialize)]
struct Creating {
    /// The name it will carry, which is how it's found again.
    name: String,
    /// When it was begun, in seconds since the epoch.
    at: i64,
}

/// A swap in flight: the copy that was created, and the token it's meant to
/// replace.
#[derive(Debug, Deserialize, Serialize)]
struct Pending {
    new_token_id: String,
    old_token_id: String,
    /// When it began, in seconds since the epoch.
    at: i64,
    /// What became of the write to Secrets Store.
    ///
    /// The record is kept whatever the answer, until the binding hands the
    /// copy over: it is the only thing that tells the sweep the copy isn't an
    /// orphan, and a handover slower than an overlap would otherwise have the
    /// copy deleted out of the secret that holds it.
    #[serde(default)]
    attempt: Attempt,
}

/// What became of the write a swap makes, which is what says whether its copy
/// may be thrown away.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Attempt {
    /// It isn't known whether the write applied: it was never made, or it was
    /// made and didn't answer. The safe reading, and so the default for a
    /// record that doesn't say.
    #[default]
    Uncertain,
    /// The secret holds what it held: the write wasn't made yet, or Cloudflare
    /// refused it and said so. The copy is in no one's hands.
    Unused,
    /// Secrets Store took it. The copy is what the secret holds, whether or
    /// not the binding has caught up.
    Taken,
}

/// A replaced token, and the earliest it may be deleted.
#[derive(Debug, Deserialize, Serialize)]
struct Retiring {
    token_id: String,
    /// Seconds since the epoch, set on the first turn the binding is seen to
    /// hand over something else.
    ///
    /// `None` until then. The window has to drain the credentials the token
    /// fathered, and it goes on fathering them until the Worker stops reading
    /// it, which is not when the write happened. Starting the clock at the
    /// write would retire it while credentials minted after that were still
    /// alive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    delete_after: Option<i64>,
}

/// Rolls the Cloudflare token if the policy asks for it and it's due, and
/// clears up after the rolls before it.
///
/// A policy with no `rotation`, or one that isn't `enabled`, starts nothing —
/// but it still finishes what an earlier policy started. Switching rotation off
/// in the middle of one would otherwise strand a replaced token: copies are
/// made without an expiry, and the cleanup is deliberately blind to their name,
/// so nothing else would ever delete it.
///
/// # Errors
///
/// What went wrong, for the cron to log. The token the binding hands over is
/// live and untouched on every path out of here, so a failure costs a turn,
/// not the broker.
pub async fn rotate(env: &Env, config: &Config) -> Result<(), String> {
    let rotation = config.policy().rotation();
    let kv = env
        .kv(POLICY_BINDING)
        .map_err(|why| format!("{POLICY_BINDING} can't be read: {why}"))?;
    let mut state = read_state(&kv).await?;
    let mut creating = read_creating(&kv).await?;

    // Never asked to roll, and nothing outstanding: the broker doesn't so much
    // as look at its own token, and spends no call finding that out.
    if !has_work(rotation, &state, creating.is_some()) {
        return Ok(());
    }

    // How long a replaced token drains for. Switched off mid-flight there's no
    // policy to say, so it drains for longer than anything the broker could
    // have handed out.
    let overlap = rotation.map_or(MAX_DRAIN, |rotation| (rotation.overlap / 1000) as i64);

    let cloudflare = config.cloudflare();
    let account_id = cloudflare.account_id();
    let client = cloudflare.client().await.map_err(|err| err.to_string())?;
    let now = now_secs();
    // The broker's own host: what tells its tokens from another broker's in
    // the same account.
    let prefix = broker_prefix(&config.policy().issuer);

    // Which token the binding hands over now. Every decision below turns on
    // this: it's the one thing that says whether a Secrets Store write has
    // reached the Worker.
    let current_id = client
        .accounts_tokens_verify(account_id)
        .await
        .map_err(|err| upstream("tokens.verify", &err))?
        .result
        .ok_or("Cloudflare: tokens.verify returned nothing")?
        .id;

    // A swap that didn't finish. Until it's settled, nothing else happens:
    // there's an extra token about, and which one is bound isn't known.
    if let Some(pending) = state.pending.take() {
        match settle(&client, account_id, pending, &current_id).await? {
            Settled::HandedOver(old_token_id) => {
                info!(
                    event = "rotation.handover",
                    new_token_id = %current_id,
                    old_token_id = %old_token_id,
                    message = "the binding hands over the copy; the token it replaced starts draining",
                );
                // The handover is what this branch *is*, so the deadline is
                // known now. Set here rather than left for `retire` to fill
                // in, which would write the same key twice in a breath and
                // can be refused for it.
                state.retiring.push(Retiring {
                    token_id: old_token_id,
                    delete_after: Some(now + overlap + MARGIN),
                });
                write_state(&kv, &state).await?;
            }
            // The copy is gone, so the swap can't have taken: whatever became
            // of the write, the secret can't be holding a token that no longer
            // exists, or the binding wouldn't have verified at all.
            Settled::Void(pending) => {
                info!(
                    event = "rotation.voided",
                    new_token_id = %pending.new_token_id,
                    old_token_id = %pending.old_token_id,
                    message = "the copy is gone, so the swap never took",
                );
                write_state(&kv, &state).await?;
            }
            // The write was taken and the binding hasn't caught up. The record
            // stays: it's what keeps the sweep off the copy the secret holds.
            Settled::Propagating(pending) => {
                if now - pending.at > overlap {
                    warn!(
                        event = "rotation.waiting",
                        new_token_id = %pending.new_token_id,
                        old_token_id = %pending.old_token_id,
                        waited = now - pending.at,
                        message = "Secrets Store took the copy but the binding still hands over \
                                   the token it replaced; check that `rotation.secret` names the \
                                   secret the Worker is bound to",
                    );
                }
                state.pending = Some(pending);
                return Ok(());
            }
            Settled::Discarded(pending) => {
                info!(
                    event = "rotation.voided",
                    new_token_id = %pending.new_token_id,
                    old_token_id = %pending.old_token_id,
                    message = "the copy was never in anyone's hands, and it's gone now",
                );
                write_state(&kv, &state).await?;
            }
            Settled::Unsettled(pending) => {
                unsettled(&pending, &current_id, now);
                state.pending = Some(pending);
                return Ok(());
            }
        }
    }

    retire(
        &client,
        account_id,
        &kv,
        &mut state,
        &current_id,
        now,
        overlap,
    )
    .await?;
    sweep(
        &client,
        account_id,
        &kv,
        &mut state,
        &mut creating,
        &prefix,
        &current_id,
        now,
        overlap,
    )
    .await?;

    // Switched off with work outstanding: it finishes, and starts nothing.
    let Some(rotation) = rotation else {
        return Ok(());
    };

    // One roll at a time: while a replaced token is still waiting, the broker
    // has nothing to gain from another copy. Nor while an intent is still
    // unanswered — a swap writes its own name over it, and that name is the
    // only thing that can find a copy whose age Cloudflare won't give, or
    // whose prefix predates a change of host.
    if !state.retiring.is_empty() || creating.is_some() {
        return Ok(());
    }

    let current = client
        .accounts_tokens_get(account_id, &current_id)
        .await
        .map_err(|err| upstream("tokens.get", &err))?
        .result
        .ok_or("Cloudflare: tokens.get returned nothing")?;

    // Running out: a token given an `expires_on` shorter than `every` would
    // otherwise first fall due once it had already expired, and a token the
    // broker can't authenticate with is one it can't replace either. Replacing
    // it an overlap early leaves room for the cron to come round and for the
    // credentials it fathered to drain.
    //
    // Judged on its own, not after the age: Cloudflare needn't say when a
    // token was issued, and an expiry that's known and close has to be acted
    // on whether or not the age is.
    // The lead has to cover more than the drain: another turn of the cron has
    // to fit before the token runs out, and the swap's own calls have to fit
    // inside that. An `overlap` alone, at its 1h floor, is exactly the cron
    // period, which would leave a token expiring in 1h1s a single second to be
    // replaced in on the following turn.
    let lead = overlap + CRON_PERIOD + MARGIN;
    let expiring = current
        .expires_on
        .is_some_and(|at| now + lead >= at.timestamp());
    let age = current.issued_on.map(|at| now - at.timestamp());
    let old_enough = age.is_some_and(|age| age >= (rotation.every / 1000) as i64);

    if !old_enough && !expiring {
        if age.is_none() {
            warn!(
                event = "rotation.skipped",
                token_id = %current_id,
                message = "Cloudflare didn't say when the token was issued and it has no \
                           expiry, so there's nothing to tell whether it's due",
            );
        }
        return Ok(());
    }

    swap(
        cloudflare,
        &client,
        &kv,
        &mut state,
        &mut creating,
        &prefix,
        &current_id,
        current,
        age,
        expiring,
        now,
        rotation,
    )
    .await
}

/// What a `pending` record turned out to mean.
enum Settled {
    /// The binding hands over the copy. The token it replaced, to retire.
    HandedOver(String),
    /// The copy no longer exists, so the swap never took.
    Void(Pending),
    /// The write was taken, and the binding hasn't caught up yet.
    Propagating(Pending),
    /// The copy was never in anyone's hands, and it's gone now.
    Discarded(Pending),
    /// It can't be told from here.
    Unsettled(Pending),
}

/// What became of a swap that hasn't been seen through yet.
async fn settle(
    client: &HttpClient,
    account_id: &str,
    pending: Pending,
    current_id: &str,
) -> Result<Settled, String> {
    if pending.new_token_id == current_id {
        return Ok(Settled::HandedOver(pending.old_token_id));
    }
    // The copy may have been deleted by a rollback whose record of itself
    // didn't survive. Workers KV takes one write per key per second, so the
    // write that was to clear this record can be refused; asking Cloudflare
    // what exists is what gets the broker unstuck without a person.
    let exists = match client
        .accounts_tokens_get(account_id, &pending.new_token_id)
        .await
    {
        Ok(_) => true,
        Err(err) if err.api().is_some_and(|api| api.status == 404) => false,
        Err(err) => return Err(upstream("tokens.get", &err)),
    };
    if !exists {
        return Ok(Settled::Void(pending));
    }
    // Whether the binding still hands over the very token this was replacing
    // decides what any of the rest means: a third token says something has
    // happened to the secret that the broker didn't do.
    let replacing = pending.old_token_id == current_id;
    match pending.attempt {
        // Secrets Store took the write, so the copy is what it holds; the
        // binding simply hasn't caught up. Nothing is wrong, and nothing is
        // deleted until it has.
        Attempt::Taken if replacing => Ok(Settled::Propagating(pending)),
        // The write was never made, or was refused and said so, so the secret
        // is as it was and the copy is in no one's hands. Clearing it up here
        // is what gets the broker going again when the discard that should
        // have done it failed.
        Attempt::Unused if replacing => {
            // Only a copy Cloudflare says is gone lets its record go with it:
            // a delete that failed would otherwise leave a token with the
            // broker's own permissions and nothing that knew of it.
            let gone = discard(
                client,
                account_id,
                &pending.new_token_id,
                "the swap was given up on",
            )
            .await;
            if gone {
                Ok(Settled::Discarded(pending))
            } else {
                Ok(Settled::Unsettled(pending))
            }
        }
        _ => Ok(Settled::Unsettled(pending)),
    }
}

/// Says what's known about a swap that can't be settled, and what to do. Both
/// tokens are left alone: one of them is what Secrets Store holds, and from
/// here it can't be told which.
fn unsettled(pending: &Pending, current_id: &str, now: i64) {
    let age = now - pending.at;
    if pending.old_token_id == current_id {
        // The binding still hands over the token the swap was replacing, so
        // the write either didn't take or hasn't propagated. The old token is
        // in use: whatever is done here, it isn't the one to delete.
        error!(
            event = "rotation.unsettled",
            new_token_id = %pending.new_token_id,
            old_token_id = %pending.old_token_id,
            bound_token_id = %current_id,
            age,
            message = "a swap was begun and the binding still hands over the token it was \
                       replacing; if Secrets Store holds the copy, wait for it to propagate, \
                       and if it still holds the replaced token, delete the copy and clear \
                       the `rotation` key. Don't delete the replaced token: it's the one in \
                       use, and the R2 credentials it is the parent of die with it",
        );
        return;
    }
    error!(
        event = "rotation.stuck",
        new_token_id = %pending.new_token_id,
        old_token_id = %pending.old_token_id,
        bound_token_id = %current_id,
        age,
        message = "a swap was begun and the binding hands over neither the copy nor the token \
                   it was replacing; see which of the two Secrets Store holds, delete the \
                   other once the R2 credentials it fathered have expired, and clear the \
                   `rotation` key",
    );
}

/// Deletes the replaced tokens whose overlap has run out. One the binding still
/// hands over is left alone: the write that replaced it hasn't reached the
/// Worker, and deleting it would take the broker with it.
#[allow(clippy::too_many_arguments)]
async fn retire(
    client: &HttpClient,
    account_id: &str,
    kv: &KvStore,
    state: &mut State,
    current_id: &str,
    now: i64,
    overlap: i64,
) -> Result<(), String> {
    let mut deleted = Vec::new();
    let mut changed = false;
    for entry in &mut state.retiring {
        match retirement(entry, current_id, now, overlap) {
            Retirement::Bound => {
                // Overdue by an overlap and more, and still the bound token:
                // the secret the policy names probably isn't the one the
                // Worker reads.
                if entry.delete_after.is_none_or(|at| now - at > overlap) {
                    warn!(
                        event = "rotation.waiting",
                        token_id = %entry.token_id,
                        message = "the replaced token is still the one the binding hands over; \
                                   check that `rotation.secret` names the secret the Worker is \
                                   bound to",
                    );
                }
                // Bound again, so it isn't draining: the window starts over
                // whenever the handover does.
                changed |= entry.delete_after.take().is_some();
            }
            Retirement::Draining(until) => {
                changed |= entry.delete_after.replace(until) != Some(until);
            }
            Retirement::Delete => {
                match client
                    .accounts_tokens_delete(account_id, &entry.token_id)
                    .await
                {
                    Ok(_) => {}
                    // Already gone: nothing to retire.
                    Err(err) if err.api().is_some_and(|api| api.status == 404) => {}
                    Err(err) => return Err(upstream("tokens.delete", &err)),
                }
                info!(event = "rotation.retired", token_id = %entry.token_id);
                deleted.push(entry.token_id.clone());
            }
        }
    }
    if !deleted.is_empty() {
        state.retiring.retain(|e| !deleted.contains(&e.token_id));
        changed = true;
    }
    if changed {
        write_state(kv, state).await?;
    }
    Ok(())
}

/// Deletes tokens the broker named for itself that nothing accounts for.
///
/// A create whose answer was lost, or a turn that died between creating a copy
/// and writing down that it had, leaves a token with the broker's own
/// permissions, no expiry, and a name the cleanup is deliberately blind to.
/// Its name is its identity, so the broker can find it again without having
/// written anything first.
///
/// Only a token that is not the bound one, is in no record, and is older than
/// an overlap is touched, so a swap in flight is never swept out from under
/// itself.
#[allow(clippy::too_many_arguments)]
async fn sweep(
    client: &HttpClient,
    account_id: &str,
    kv: &KvStore,
    state: &mut State,
    creating: &mut Option<Creating>,
    prefix: &str,
    current_id: &str,
    now: i64,
    overlap: i64,
) -> Result<(), String> {
    // Only ever when there's an intent to answer. Every way the broker can
    // leave a copy unaccounted for goes through one — a create whose answer
    // was lost, a record that couldn't be written, a discard that failed — so
    // a turn with no intent has nothing to look for, and listing every token
    // in the account to find that out would spend the invocation's
    // subrequests on the turns that need them for the swap.
    if creating.is_none() {
        return Ok(());
    }

    let mut orphans: Vec<(String, bool)> = Vec::new();
    for page in 1.. {
        let tokens = client
            .accounts_tokens_list_builder(account_id)
            .page(page as f64)
            .per_page(PAGE_SIZE as f64)
            .include_expired(true)
            .send()
            .await
            .map_err(|err| upstream("tokens.list", &err))?
            .result
            .unwrap_or_default();
        let count = tokens.len();
        for token in tokens {
            let (Some(id), Some(name)) = (token.id, token.name) else {
                continue;
            };
            // A copy the intent names is one whose create went unanswered on
            // an earlier turn. The broker wrote that name down itself, so it's
            // proof of ownership on its own: the prefix is derived from the
            // issuer, and a hostname changed since would otherwise leave the
            // copy unrecognised and so uncollected for good. It's also
            // collected whatever its age, which is the only way to collect one
            // Cloudflare won't say the age of.
            let intended = creating.as_ref().is_some_and(|it| it.name == name);
            // `prefix` carries the broker's own host, so another broker's
            // tokens in the same account are not its to collect.
            let mine = intended || name.starts_with(prefix);
            let collectable = intended
                || token
                    .issued_on
                    .is_some_and(|at| now - at.timestamp() > overlap);
            if mine && collectable && id != current_id && !state.accounts_for(&id) {
                orphans.push((id, intended));
            }
        }
        if count < PAGE_SIZE {
            break;
        }
    }
    // Whether everything the intent could have been about is accounted for.
    // It starts true: an intent whose copy was never found names a create that
    // didn't happen, and there's nothing to keep looking for.
    let mut answered = true;
    let mut adopted = false;
    for (id, intended) in orphans {
        // Only the copy the intent names is deleted outright. That one was
        // never written to the secret — the create is what went unanswered —
        // so nothing can have been minted under it.
        //
        // Anything else carrying the broker's prefix has a past this turn
        // knows nothing about: an operator may have put another token in the
        // secret by hand a moment ago, and its age says when it was made, not
        // when it stopped being used. It's taken into `retiring` on a fresh
        // window instead, so the credentials it fathered have time to expire.
        if !intended {
            adopted = true;
            warn!(
                event = "rotation.adopted",
                token_id = %id,
                delete_after = now + overlap + MARGIN,
                message = "a token the broker made for itself that no record accounted for; \
                           it drains before it's deleted, in case it was in use until just now",
            );
            state.retiring.push(Retiring {
                token_id: id,
                delete_after: Some(now + overlap + MARGIN),
            });
            continue;
        }
        match client.accounts_tokens_delete(account_id, &id).await {
            Ok(_) => warn!(
                event = "rotation.swept",
                token_id = %id,
                message = "the copy an unanswered create left behind, which was never in the \
                           secret, deleted",
            ),
            Err(err) if err.api().is_some_and(|api| api.status == 404) => {}
            Err(err) => {
                // The one token the intent exists for, and it's still there.
                answered = false;
                error!(
                    event = "rotation.swept",
                    token_id = %id,
                    detail = %err,
                    message = "the copy couldn't be deleted; the intent naming it is kept so a \
                               later turn can try again",
                );
            }
        }
    }
    if adopted {
        write_state(kv, state).await?;
    }

    // A creation intent is cleared once it's been answered, not once it's been
    // around a while: a copy Cloudflare doesn't say the age of is never old
    // enough on its own, and clearing on a timer would drop the only record of
    // it. Reaching here at all means the intent outlived the turn that wrote
    // it, so whatever carries its name is a copy whose create went unanswered.
    if creating.is_some() && answered {
        *creating = None;
        write_creating(kv, None).await?;
    }
    Ok(())
}

/// Copies the Cloudflare token, writes the copy into the secret the binding
/// reads, and leaves the token it replaced to be retired.
#[allow(clippy::too_many_arguments)]
async fn swap(
    cloudflare: &super::config::CloudflareConfig,
    client: &HttpClient,
    kv: &KvStore,
    state: &mut State,
    creating: &mut Option<Creating>,
    prefix: &str,
    current_id: &str,
    current: IamTokenBase,
    age: Option<i64>,
    expiring: bool,
    now: i64,
    rotation: &RotationConfig,
) -> Result<(), String> {
    let account_id = cloudflare.account_id();
    // `check` requires it of a rotation that's switched on, which is the only
    // kind the policy hands out.
    let Some(wanted) = rotation.secret.as_ref() else {
        return Err("rotation.secret names no secret".into());
    };
    let store_id = &wanted.store_id;

    // The secret is found before anything is created, so a `rotation.secret`
    // that names nothing costs no token.
    let secret = cloudflare
        .find_secret(store_id, &wanted.name)
        .await
        .map_err(|why| format!("Cloudflare: secrets.list: {why}"))?
        .ok_or_else(|| {
            format!(
                "Cloudflare: store {store_id} has no secret called {}",
                wanted.name
            )
        })?;

    let Some(policies) = current.policies else {
        return Err("Cloudflare: tokens.get said nothing about the token's policies".into());
    };
    if current.expires_on.is_some() {
        warn!(
            event = "rotation.expiry_dropped",
            token_id = %current_id,
            message = "the Cloudflare token expires; its replacement won't, because the \
                       rotation period is its lifetime now",
        );
    }

    info!(event = "rotation.started", token_id = %current_id, age = ?age, expiring);

    // Written before the create, so a create whose answer never comes back
    // still leaves the name to find the copy by. The sweep collects it, and
    // because the record counts as work outstanding it goes on doing so even
    // if rotation is switched off in the meantime.
    let name = generation_name(prefix, now);
    *creating = Some(Creating {
        name: name.clone(),
        at: now,
    });
    write_creating(kv, creating.as_ref()).await?;

    let created = client
        .accounts_tokens_create(
            account_id,
            IamCreatePayload {
                condition: current.condition,
                expires_on: None,
                name,
                not_before: None,
                policies,
            },
        )
        .await
        .map_err(|err| upstream("tokens.create", &err))?
        .result;
    let Some((Some(new_token_id), Some(value))) =
        created.map(|created| (created.id, created.value))
    else {
        return Err("Cloudflare: tokens.create returned nothing".into());
    };

    // Everything after this either finishes the swap or undoes it.
    let undo = |why: String| async {
        discard(client, account_id, &new_token_id, "the swap didn't finish").await;
        Err(why)
    };

    // The copy must work before it's anyone's only credential.
    if let Err(err) = cloudflare
        .client_as(&value)
        .accounts_tokens_verify(account_id)
        .await
    {
        return undo(upstream("tokens.verify (the copy)", &err)).await;
    }

    // Written before the secret is patched, so a turn that dies here leaves
    // the next one something to settle. Its own key, so this and the write
    // before the create can't be taken for one key written twice in a second.
    state.pending = Some(Pending {
        new_token_id: new_token_id.clone(),
        old_token_id: current_id.to_string(),
        at: now,
        // Written before the patch and saying so: a turn that stops during it
        // leaves a record that doesn't claim to know, because a record saying
        // the secret is untouched would have a later turn delete a copy the
        // secret may by then be holding. Only an answer moves it off this.
        attempt: Attempt::Uncertain,
    });
    if let Err(why) = write_state(kv, state).await {
        state.pending = None;
        return undo(why).await;
    }

    if let Err(why_not_written) = cloudflare.put_secret_value(store_id, &secret, &value).await {
        let why = format!("Cloudflare: secrets.patch: {why_not_written}");
        return match why_not_written {
            // Refused, and Cloudflare said so: the secret holds what it held,
            // and the copy is in no one's hands. It's deleted — but the record
            // of it stays until it's gone, because a discard that fails, or a
            // turn that stops between the two, would otherwise leave a token
            // with the broker's own permissions and nothing that knew of it.
            // `settle` finds the copy gone and clears the record, or finds it
            // there and tries the discard again.
            NotWritten::Rejected(_) => {
                // Cloudflare said no, so the secret is as it was and the copy
                // is in no one's hands. Recorded before the delete is tried,
                // so a turn that stops here leaves a record that says the copy
                // can go rather than one that daren't touch it.
                if let Some(pending) = &mut state.pending {
                    pending.attempt = Attempt::Unused;
                }
                // Recorded first, so a turn that stops here leaves a record
                // saying the copy can go. But the discard is tried whether or
                // not that lands: Cloudflare refused the write, so the copy is
                // provably in no one's hands, and a record stuck at `uncertain`
                // beside a live copy is a turn that reports `unsettled` for
                // ever. Once the copy is gone the existing 404 reconciliation
                // clears the record.
                let recorded = write_state(kv, state).await;
                discard(client, account_id, &new_token_id, "the write was refused").await;
                match recorded {
                    Ok(()) => Err(why),
                    Err(recording) => Err(format!("{why}; and recording that: {recording}")),
                }
            }
            // It can't be told whether the write applied. If it did and the
            // copy were deleted, the secret would hold a token that no longer
            // exists and the broker would go down as it propagated. Both
            // tokens stay, the record stays saying as much, and the next turn
            // settles it on what the binding hands over.
            // It can't be told whether the write applied, which is what the
            // record already says. Nothing to write, and nothing to delete:
            // the next turn settles it on what the binding hands over.
            NotWritten::Uncertain(_) => Err(why),
        };
    }

    // Taken. The record stays until the binding is seen to hand the copy over:
    // it's the only thing that tells the sweep the copy isn't an orphan, and a
    // handover slower than an overlap would otherwise have it deleted out of
    // the secret that holds it. `settle` moves the replaced token to retiring
    // on the turn the handover shows up.
    if let Some(pending) = &mut state.pending {
        pending.attempt = Attempt::Taken;
    }
    // The record superseded the intent the moment the copy had an ID, so the
    // intent goes. A write refused here leaves a record still saying the
    // outcome is unknown, which the next turn settles on the handover: safe,
    // if noisier than it need be.
    write_state(kv, state).await?;
    *creating = None;
    write_creating(kv, None).await?;
    info!(
        event = "rotation.swapped",
        old_token_id = %current_id,
        new_token_id = %new_token_id,
        secret = %secret.name,
        expiring,
    );
    Ok(())
}

/// Deletes a copy the broker is giving up on, and says whether it's gone —
/// which is the only thing that lets the record of it go too. A turn that
/// can't delete it leaves the record for one that can.
async fn discard(client: &HttpClient, account_id: &str, token_id: &str, reason: &str) -> bool {
    match client.accounts_tokens_delete(account_id, token_id).await {
        Ok(_) => {
            info!(event = "rotation.discarded", token_id, reason);
            true
        }
        // Already gone is gone.
        Err(err) if err.api().is_some_and(|api| api.status == 404) => true,
        Err(err) => {
            error!(
                event = "rotation.discarded",
                token_id,
                reason,
                detail = %err,
                message = "the copy couldn't be deleted; the record of it is kept so a later \
                           turn can try again",
            );
            false
        }
    }
}

/// Whether a turn has anything to do.
///
/// Being switched off is not enough on its own: a swap that was already made
/// still has a replaced token to delete, and copies are made without an expiry
/// and under a name the cleanup is deliberately blind to, so nothing else
/// would ever collect it.
fn has_work(rotation: Option<&RotationConfig>, state: &State, creating: bool) -> bool {
    rotation.is_some() || !state.is_empty() || creating
}

/// What a turn does with a token that's retiring. The one place this is
/// decided, so there's nowhere for a second opinion to disagree with it.
#[derive(Debug, PartialEq, Eq)]
enum Retirement {
    /// Still the token the binding hands over, so it goes on fathering
    /// credentials and its window hasn't begun. Never deleted, however
    /// overdue: deleting it would take the broker with it.
    Bound,
    /// The handover has been seen. Its window runs to this.
    Draining(i64),
    /// Drained: the credentials it fathered have expired, so it may go.
    Delete,
}

fn retirement(entry: &Retiring, current_id: &str, now: i64, overlap: i64) -> Retirement {
    if entry.token_id == current_id {
        return Retirement::Bound;
    }
    match entry.delete_after {
        // First turn it isn't the bound token: that's when it stopped
        // fathering credentials, so that's when the window starts.
        None => Retirement::Draining(now + overlap + MARGIN),
        Some(at) if at > now => Retirement::Draining(at),
        Some(_) => Retirement::Delete,
    }
}

/// What the broker recognises its own tokens by: the prefix, then its own
/// host, which is the one thing that tells two brokers in an account apart.
///
/// Tokens are listed account-wide, so a bare `cloudflare-sts-broker:` would
/// have each broker take the other's live token for an orphan and delete it.
/// The host is cut to [`HOST_MAX`] and anything outside a hostname's alphabet
/// replaced, with a digest of the whole of it so two hosts that differ past
/// the cut still differ here. Derived the same way every time, or a broker
/// would stop recognising its own tokens.
fn broker_prefix(issuer: &str) -> String {
    let host = issuer
        .split_once("://")
        .map_or(issuer, |(_, rest)| rest)
        .split(['/', ':'])
        .next()
        .unwrap_or_default();
    // The host is for whoever reads the dashboard; the digest is what makes it
    // an identity. Cutting the host alone would give two deployments sharing a
    // long first label the same prefix, and each would then take the other's
    // live token for an orphan.
    let readable: String = host
        .chars()
        .take(HOST_MAX)
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    format!("{BROKER_PREFIX}{readable}.{:08x}:", digest(issuer))
}

/// FNV-1a over `text`, cut to 32 bits. Taken over the whole issuer, so two
/// brokers that differ only past the readable part — a longer host, another
/// port — still differ here.
///
/// Not a cryptographic hash and not asked to be: it only has to keep two
/// hostnames in one account from being taken for each other, and anyone who
/// could choose a hostname to collide with yours can already deploy Workers
/// into the account.
fn digest(text: &str) -> u32 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x1000_0000_01b3;
    let hash = text.bytes().fold(OFFSET, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(PRIME)
    });
    (hash >> 32) as u32 ^ hash as u32
}

/// What a token the broker makes for itself is called.
fn generation_name(prefix: &str, now: i64) -> String {
    let name = format!("{prefix}{now}");
    name.chars().take(NAME_MAX).collect()
}

fn now_secs() -> i64 {
    (Date::now().as_millis() / 1000) as i64
}

/// The state, or a fresh one. A key that can't be parsed is not overwritten
/// silently: it fails, because it may name a token nothing else knows about.
async fn read_state(kv: &KvStore) -> Result<State, String> {
    let raw = kv
        .get(STATE_KEY)
        .text()
        .await
        .map_err(|why| format!("{POLICY_BINDING}: `{STATE_KEY}` can't be read: {why}"))?;
    match raw {
        None => Ok(State::default()),
        Some(raw) => serde_json::from_str(&raw)
            .map_err(|why| format!("{POLICY_BINDING}: `{STATE_KEY}` isn't valid state: {why}")),
    }
}

/// The creation intent, if a turn left one behind.
async fn read_creating(kv: &KvStore) -> Result<Option<Creating>, String> {
    let raw = kv
        .get(CREATING_KEY)
        .text()
        .await
        .map_err(|why| format!("{POLICY_BINDING}: `{CREATING_KEY}` can't be read: {why}"))?;
    match raw.as_deref().map(str::trim).filter(|raw| !raw.is_empty()) {
        None => Ok(None),
        Some(raw) => serde_json::from_str(raw)
            .map_err(|why| format!("{POLICY_BINDING}: `{CREATING_KEY}` isn't valid state: {why}")),
    }
}

async fn write_creating(kv: &KvStore, creating: Option<&Creating>) -> Result<(), String> {
    let body = match creating {
        Some(creating) => serde_json::to_string(creating).map_err(|why| why.to_string())?,
        // Nothing to collect. Emptied rather than deleted, which
        // `read_creating` reads back the same way, with one fewer call to go
        // wrong.
        None => String::new(),
    };
    kv.put(CREATING_KEY, body)
        .map_err(|why| format!("{POLICY_BINDING}: `{CREATING_KEY}` can't be written: {why}"))?
        .execute()
        .await
        .map_err(|why| format!("{POLICY_BINDING}: `{CREATING_KEY}` can't be written: {why}"))
}

async fn write_state(kv: &KvStore, state: &State) -> Result<(), String> {
    let body = serde_json::to_string(state).map_err(|why| why.to_string())?;
    kv.put(STATE_KEY, body)
        .map_err(|why| format!("{POLICY_BINDING}: `{STATE_KEY}` can't be written: {why}"))?
        .execute()
        .await
        .map_err(|why| format!("{POLICY_BINDING}: `{STATE_KEY}` can't be written: {why}"))
}

/// A Cloudflare API failure, as the handler words them.
fn upstream<E: std::fmt::Debug>(what: &str, err: &ApiOpError<E>) -> String {
    let why = match err {
        ApiOpError::Api(api) => format!("returned {}", api.status),
        ApiOpError::Transport(err) => err.to_string(),
    };
    format!("Cloudflare: {what}: {why}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::handler::TOKEN_PREFIX;

    /// The broker's own tokens must not look like the ones it mints, or the
    /// cleanup would delete them and a caller could get one revoked.
    #[test]
    fn names_its_own_tokens_outside_the_minted_prefix() {
        assert!(!BROKER_PREFIX.starts_with(TOKEN_PREFIX));
        let prefix = broker_prefix("https://sts.example.com");
        let name = generation_name(&prefix, 1_800_000_000);
        assert!(
            name.starts_with("cloudflare-sts-broker:sts.example.com."),
            "{name}"
        );
        assert!(name.ends_with(":1800000000"), "{name}");
        assert!(!name.starts_with(TOKEN_PREFIX));
        assert!(name.chars().count() <= NAME_MAX);
    }

    /// Tokens are listed account-wide, so the name has to say which broker
    /// made it: without that, two brokers in one account would each take the
    /// other's live token for an orphan and delete it.
    #[test]
    fn tells_its_own_tokens_from_another_brokers_in_the_same_account() {
        let mine = broker_prefix("https://sts.example.com");
        let theirs = broker_prefix("https://other-sts.example.com");
        assert_ne!(mine, theirs);
        assert!(!generation_name(&theirs, 1_800_000_000).starts_with(&mine));
        assert!(!generation_name(&mine, 1_800_000_000).starts_with(&theirs));

        // Derived the same way every time, or a broker stops recognising its
        // own tokens between turns.
        assert_eq!(mine, broker_prefix("https://sts.example.com"));
        // The readable part is the host alone, but the digest is over the
        // whole issuer, so two brokers on one host and different ports are
        // still told apart.
        let (bare, ported) = (
            broker_prefix("http://127.0.0.1"),
            broker_prefix("http://127.0.0.1:8790"),
        );
        assert!(
            bare.starts_with("cloudflare-sts-broker:127.0.0.1."),
            "{bare}"
        );
        assert!(
            ported.starts_with("cloudflare-sts-broker:127.0.0.1."),
            "{ported}"
        );
        assert_ne!(bare, ported);

        // Nothing outside a hostname's alphabet survives into a name.
        let odd = broker_prefix("https://a_b~c.example.com");
        assert!(
            odd.chars()
                .all(|c| c.is_ascii_alphanumeric() || "-.:".contains(c)),
            "{odd}"
        );
        // A long host is cut, and the name still fits what Cloudflare takes.
        let long = broker_prefix(&format!("https://{}.example.com", "x".repeat(200)));
        assert!(generation_name(&long, 1_800_000_000).chars().count() <= NAME_MAX);

        // Two hosts that differ only past the cut are still told apart: the
        // readable part is the same, the digest of the whole of it isn't.
        let label = "y".repeat(63);
        let (one, two) = (
            broker_prefix(&format!("https://{label}.example.com")),
            broker_prefix(&format!("https://{label}.other.com")),
        );
        assert_ne!(one, two, "a cut host must not make two deployments one");

        // The integration tests build token names by hand, so they carry this
        // prefix as a literal. Pinned here so the two can't drift apart in
        // silence: `tests/config.toml`'s issuer is this one.
        assert_eq!(
            broker_prefix("http://127.0.0.1:8790"),
            "cloudflare-sts-broker:127.0.0.1.ec92f4d1:"
        );
    }

    #[test]
    fn keeps_what_it_must_across_a_turn() {
        let state = State {
            pending: Some(Pending {
                new_token_id: "new".into(),
                old_token_id: "old".into(),
                at: 1_800_000_000,
                attempt: Attempt::Taken,
            }),
            retiring: vec![Retiring {
                token_id: "older".into(),
                delete_after: Some(1_800_003_600),
            }],
        };
        let json = serde_json::to_string(&state).expect("it serializes");
        let read: State = serde_json::from_str(&json).expect("it reads back");
        assert_eq!(read.pending.expect("pending").new_token_id, "new");
        assert_eq!(read.retiring[0].delete_after, Some(1_800_003_600));

        // An empty state is an empty object, and reads back as one.
        let empty = serde_json::to_string(&State::default()).expect("it serializes");
        assert_eq!(empty, "{}");
        let read: State = serde_json::from_str(&empty).expect("it reads back");
        assert!(read.pending.is_none() && read.retiring.is_empty());
        assert!(read.is_empty());

        // A token whose window hasn't started is written without one, and a
        // record from before the field existed reads back the same way.
        let waiting = serde_json::to_string(&State {
            pending: None,
            retiring: vec![Retiring {
                token_id: "old".into(),
                delete_after: None,
            }],
        })
        .expect("it serializes");
        assert_eq!(waiting, r#"{"retiring":[{"token_id":"old"}]}"#);
        let read: State = serde_json::from_str(&waiting).expect("it reads back");
        assert_eq!(read.retiring[0].delete_after, None);
        assert!(!read.is_empty());
    }

    fn entry(token_id: &str, delete_after: Option<i64>) -> Retiring {
        Retiring {
            token_id: token_id.into(),
            delete_after,
        }
    }

    /// The one deletion that could take the broker down with it: the token the
    /// binding still hands over, however long ago it was replaced.
    #[test]
    fn never_retires_the_token_the_binding_still_hands_over() {
        let now = 1_800_000_000;
        let overlap = 2 * 60 * 60;

        // Replaced, drained, and no longer bound: gone.
        assert_eq!(
            retirement(&entry("old", Some(now - 1)), "new", now, overlap),
            Retirement::Delete
        );
        assert_eq!(
            retirement(&entry("old", Some(now)), "new", now, overlap),
            Retirement::Delete
        );

        // Draining: the R2 credentials it fathered may still be in use.
        assert_eq!(
            retirement(&entry("old", Some(now + 1)), "new", now, overlap),
            Retirement::Draining(now + 1)
        );

        // However overdue, it's what the binding hands over: the write that
        // replaced it hasn't reached the Worker, so it stays, and it isn't
        // draining either.
        assert_eq!(
            retirement(&entry("old", Some(now - 86_400)), "old", now, overlap),
            Retirement::Bound
        );
        assert_eq!(
            retirement(&entry("old", None), "old", now, overlap),
            Retirement::Bound
        );
    }

    /// The drain window runs from the handover, not from the write that caused
    /// it: until the Worker stops reading the old token, it goes on fathering
    /// credentials that have to outlive it.
    #[test]
    fn starts_the_drain_when_the_binding_hands_over() {
        let now = 1_800_000_000;
        let overlap = 2 * 60 * 60;

        // Its first turn as something other than the bound token sets the
        // window, from now.
        assert_eq!(
            retirement(&entry("old", None), "new", now, overlap),
            Retirement::Draining(now + overlap + MARGIN)
        );
        // Set once, it isn't pushed back on every later turn.
        assert_eq!(
            retirement(&entry("old", Some(now + 60)), "new", now + 30, overlap),
            Retirement::Draining(now + 60)
        );
    }

    /// Switching rotation off mid-swap must not strand the replaced token:
    /// it has no expiry, and the cleanup is deliberately blind to its name, so
    /// a turn that bailed out early would leave it valid for good.
    #[test]
    fn finishes_what_it_started_even_once_it_is_switched_off() {
        let outstanding = State {
            pending: None,
            retiring: vec![entry("replaced", None)],
        };
        assert!(has_work(None, &outstanding, false));
        assert!(has_work(
            None,
            &State {
                pending: Some(Pending {
                    new_token_id: "copy".into(),
                    old_token_id: "replaced".into(),
                    at: 0,
                    attempt: Attempt::Unused,
                }),
                retiring: vec![],
            },
            false
        ));

        // A copy the broker was about to make, whose answer never came back,
        // is work too: nothing else would ever collect it.
        assert!(has_work(None, &State::default(), true));

        // Nothing outstanding and nothing asked for: it doesn't even look.
        assert!(!has_work(None, &State::default(), false));
    }

    /// Only a token the broker named for itself, that nothing accounts for,
    /// is ever swept.
    #[test]
    fn accounts_for_the_tokens_it_knows_about() {
        let state = State {
            pending: Some(Pending {
                new_token_id: "copy".into(),
                old_token_id: "replaced".into(),
                at: 0,
                attempt: Attempt::Unused,
            }),
            retiring: vec![entry("older", None)],
        };
        for known in ["copy", "replaced", "older"] {
            assert!(state.accounts_for(known), "{known}");
        }
        assert!(!state.accounts_for("orphan"));
        assert!(!State::default().accounts_for("orphan"));
    }
}
