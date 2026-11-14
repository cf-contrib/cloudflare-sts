//! Who may get what: the Cedar half of the policy.
//!
//! The configuration says what the broker trusts and what a profile hands out;
//! the Cedar policy says which callers get it. A request to Cedar is:
//!
//! - **principal** `Caller::"<sub>"`, the token's subject;
//! - **action** `Admit::Action::"<provider>"` once the token is verified, to let a
//!   provider's tokens in at all (where the tenant is pinned), then
//!   `Profile::Action::"<name>"`, for the profile it asks for;
//! - **resource** `Audience::"https://api.cloudflare.com"`, always: what a profile
//!   issues for. A policy can leave it unconstrained;
//! - **context** the token's claims, each a string or a set of strings:
//!   numbers and booleans are written as JSON writes them, so an ID is
//!   `"100000001"` whether the issuer sent it quoted or not. Claims that are
//!   anything else, objects say, aren't in it.
//!
//! Cedar denies unless a `permit` matches and no `forbid` does. Parsing
//! checks what Cedar can't: every policy has a unique `@id`, so a log line can
//! name the policy that decided; a `permit` names its actions, so none lets
//! everything in; and a policy names only providers and profiles that exist,
//! so a misspelt one is an error, not a silent deny. The caller of
//! [`Authz::check`] adds that every provider has a `permit` for its `Admit`.

use std::{collections::BTreeSet, str::FromStr};

use cedar_policy::{
    ActionConstraint, Authorizer, Context, Decision, Effect, Entities, EntityId, EntityTypeName,
    EntityUid, PolicySet, Request,
};
use serde_json::{Map, Value, json};

/// The action type for letting a provider's tokens in.
const ADMIT: &str = "Admit::Action";
/// The action type for getting a profile.
const PROFILE: &str = "Profile::Action";
/// The one resource a request is for: Cloudflare's own credentials. It was
/// once one of several, an audience a profile issued for, and keeps its type's
/// name so a policy that names it still reads.
const RESOURCE: &str = "https://api.cloudflare.com";

/// A parsed Cedar policy.
#[derive(Debug, Default)]
pub struct Authz {
    set: PolicySet,
}

/// What Cedar decided, and which policies decided it.
#[derive(Debug, PartialEq)]
pub struct Verdict {
    pub allowed: bool,
    /// The `@id`s of the policies that decided it: the `permit`s that
    /// allowed, or the `forbid`s that denied. None when nothing matched.
    pub policies: Vec<String>,
}

impl Authz {
    /// The policy in `text`.
    ///
    /// # Errors
    ///
    /// When it isn't Cedar, or a policy has no `@id`, or a repeated one, or a
    /// `permit` doesn't name its actions.
    pub fn parse(text: &str) -> Result<Self, String> {
        let set = PolicySet::from_str(text).map_err(|err| format!("policy: {err}"))?;
        let mut ids = BTreeSet::new();
        for policy in set.policies() {
            let id = policy
                .annotation("id")
                .filter(|id| !id.is_empty())
                .ok_or_else(|| {
                    format!(
                        "policy: every policy needs an @id, such as @id(\"ci-apply\"): {} has none",
                        describe(policy.id())
                    )
                })?;
            if !ids.insert(id.to_string()) {
                return Err(format!("policy: @id(\"{id}\") is on two policies"));
            }
            if policy.effect() == Effect::Permit
                && matches!(policy.action_constraint(), ActionConstraint::Any)
            {
                return Err(format!(
                    "policy {id}: a permit must name its actions, as Admit::Action::\"<provider>\" or Profile::Action::\"<name>\""
                ));
            }
        }
        Ok(Self { set })
    }

    /// What parsing can't check, against the providers and profiles the
    /// configuration names: that every provider has a `permit` for its
    /// `Admit` (the guardrail that pins a tenant), every enabled profile one
    /// for itself, and no policy names an action that doesn't exist.
    ///
    /// # Errors
    ///
    /// The first problem found.
    pub fn check<'a>(
        &self,
        providers: impl IntoIterator<Item = &'a str>,
        profiles: impl IntoIterator<Item = (&'a str, bool)>,
    ) -> Result<(), String> {
        let providers: Vec<&str> = providers.into_iter().collect();
        let profiles: Vec<(&str, bool)> = profiles.into_iter().collect();

        for policy in self.set.policies() {
            for action in actions(policy.action_constraint()) {
                let (kind, name) = (action.type_name().to_string(), action.id().unescaped());
                let known = match kind.as_str() {
                    ADMIT => providers.contains(&name),
                    PROFILE => profiles.iter().any(|(profile, _)| *profile == name),
                    _ => {
                        return Err(format!(
                            "policy {}: action {action} must be Admit::Action::\"<provider>\" or Profile::Action::\"<name>\"",
                            self.id_of(policy)
                        ));
                    }
                };
                if !known {
                    return Err(format!(
                        "policy {}: {action} names no {} in the configuration",
                        self.id_of(policy),
                        if kind == ADMIT { "provider" } else { "profile" }
                    ));
                }
            }
        }

        let permitted = |kind: &str, name: &str| {
            self.set.policies().any(|policy| {
                policy.effect() == Effect::Permit
                    && actions(policy.action_constraint())
                        .iter()
                        .any(|a| a.type_name().to_string() == kind && a.id().unescaped() == name)
            })
        };
        for provider in providers {
            if !permitted(ADMIT, provider) {
                return Err(format!(
                    "provider {provider} has no policy admitting it: add a permit for Admit::Action::\"{provider}\" that pins your tenant"
                ));
            }
        }
        for (profile, enabled) in profiles {
            if enabled && !permitted(PROFILE, profile) {
                return Err(format!(
                    "profile {profile} has no policy allowing anyone: add a permit for Profile::Action::\"{profile}\""
                ));
            }
        }
        Ok(())
    }

    /// Whether the token with `claims` may be let in by `provider`.
    pub fn admit(&self, provider: &str, claims: &Map<String, Value>) -> Verdict {
        self.decide(ADMIT, provider, claims)
    }

    /// Whether the token with `claims` may get `profile`.
    pub fn profile(&self, profile: &str, claims: &Map<String, Value>) -> Verdict {
        self.decide(PROFILE, profile, claims)
    }

    fn decide(&self, kind: &str, name: &str, claims: &Map<String, Value>) -> Verdict {
        let denied = Verdict {
            allowed: false,
            policies: Vec::new(),
        };
        let sub = claims
            .get("sub")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let Ok(context) = Context::from_json_value(context(claims), None) else {
            return denied;
        };
        let Ok(request) = Request::new(
            uid("Caller", sub),
            uid(kind, name),
            uid("Audience", RESOURCE),
            context,
            None,
        ) else {
            return denied;
        };
        let response = Authorizer::new().is_authorized(&request, &self.set, &Entities::empty());
        // An error in a policy, a type mismatch say, leaves that policy
        // unmatched, which is a deny unless another permits: it never allows.
        Verdict {
            allowed: response.decision() == Decision::Allow,
            policies: response
                .diagnostics()
                .reason()
                .filter_map(|id| self.set.policy(id))
                .map(|policy| self.id_of(policy))
                .collect(),
        }
    }

    fn id_of(&self, policy: &cedar_policy::Policy) -> String {
        policy
            .annotation("id")
            .map_or_else(|| describe(policy.id()), str::to_string)
    }
}

fn describe(id: &cedar_policy::PolicyId) -> String {
    id.to_string()
}

fn uid(kind: &str, id: &str) -> EntityUid {
    // The types are ours and valid; the ID is anything.
    EntityUid::from_type_name_and_id(
        EntityTypeName::from_str(kind).expect("a valid type name"),
        EntityId::from_str(id).expect("an entity ID is infallible"),
    )
}

/// The actions a policy's scope names.
fn actions(constraint: ActionConstraint) -> Vec<EntityUid> {
    match constraint {
        ActionConstraint::Any => Vec::new(),
        ActionConstraint::Eq(action) => vec![action],
        ActionConstraint::In(actions) => actions,
    }
}

/// The token's claims as Cedar's context: strings and sets of strings.
fn context(claims: &Map<String, Value>) -> Value {
    fn scalar(value: &Value) -> Option<String> {
        match value {
            Value::String(text) => Some(text.clone()),
            Value::Number(number) => Some(number.to_string()),
            Value::Bool(flag) => Some(flag.to_string()),
            _ => None,
        }
    }

    let record: Map<String, Value> = claims
        .iter()
        .filter_map(|(name, value)| {
            let value = match value {
                Value::Array(values) => {
                    let all: Option<Vec<String>> = values.iter().map(scalar).collect();
                    json!(all?)
                }
                other => json!(scalar(other)?),
            };
            Some((name.clone(), value))
        })
        .collect();
    Value::Object(record)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims() -> Map<String, Value> {
        json!({
            "sub": "repo:example-org/app:ref:refs/heads/main",
            "repository": "example-org/app",
            "repository_owner_id": 100000001,
            "ref": "refs/heads/main",
            "email_verified": true,
            "groups": ["cache-readers", "cache-uploaders"],
            "actor_matrix": { "nested": "dropped" },
        })
        .as_object()
        .unwrap()
        .clone()
    }

    fn authz(text: &str) -> Authz {
        Authz::parse(text).expect("the policy should parse")
    }

    const POLICY: &str = r#"
        @id("pin")
        permit (principal, action == Admit::Action::"github", resource)
        when { context.repository_owner_id == "100000001" };

        @id("deploy")
        permit (principal, action == Profile::Action::"deploy", resource)
        when { context.repository like "example-org/*" && context.ref == "refs/heads/main" };

        @id("no-forks")
        forbid (principal, action, resource)
        when { context has fork && context.fork == "true" };
    "#;

    #[test]
    fn allows_what_a_permit_matches_and_names_it() {
        let authz = authz(POLICY);
        assert_eq!(
            authz.admit("github", &claims()),
            Verdict {
                allowed: true,
                policies: vec!["pin".into()]
            },
            "a number is compared as written, as a string"
        );
        assert_eq!(
            authz.profile("deploy", &claims()),
            Verdict {
                allowed: true,
                policies: vec!["deploy".into()]
            }
        );
    }

    #[test]
    fn denies_unless_something_permits() {
        let authz = authz(POLICY);
        let mut dev = claims();
        dev.insert("ref".into(), "refs/heads/dev".into());
        assert!(!authz.profile("deploy", &dev).allowed);
        assert!(
            !authz.profile("nope", &claims()).allowed,
            "an action no policy names"
        );
        let mut other = claims();
        other.insert("repository_owner_id".into(), json!("999"));
        assert!(!authz.admit("github", &other).allowed);
        other.remove("repository_owner_id");
        assert!(
            !authz.admit("github", &other).allowed,
            "a missing claim never matches"
        );
    }

    #[test]
    fn a_forbid_beats_a_permit_and_is_named() {
        let authz = authz(POLICY);
        let mut fork = claims();
        fork.insert("fork".into(), json!(true));
        assert_eq!(
            authz.profile("deploy", &fork),
            Verdict {
                allowed: false,
                policies: vec!["no-forks".into()]
            }
        );
    }

    #[test]
    fn matches_a_set_claim_and_nothing_nested() {
        let authz = authz(
            r#"@id("g") permit (principal, action == Profile::Action::"p", resource)
               when { context.groups.contains("cache-uploaders") };
               @id("n") permit (principal, action == Profile::Action::"q", resource)
               when { context has actor_matrix };"#,
        );
        assert!(authz.profile("p", &claims()).allowed);
        assert!(
            !authz.profile("q", &claims()).allowed,
            "an object claim isn't in the context"
        );
    }

    #[test]
    fn a_type_error_in_a_policy_never_allows() {
        let authz = authz(
            r#"@id("bad") permit (principal, action == Profile::Action::"p", resource)
               when { context.repository.contains("x") };"#,
        );
        assert!(!authz.profile("p", &claims()).allowed);
    }

    #[test]
    fn rejects_unsafe_policies() {
        let cases = [
            ("permit (principal, action, resource);", "needs an @id"),
            (
                r#"@id("a") permit (principal, action, resource);"#,
                "a permit must name its actions",
            ),
            (
                r#"@id("a") permit (principal, action == Profile::Action::"x", resource);
                   @id("a") permit (principal, action == Profile::Action::"y", resource);"#,
                "@id(\"a\") is on two policies",
            ),
            ("not cedar", "policy:"),
        ];
        for (text, expected) in cases {
            let err = Authz::parse(text).unwrap_err();
            assert!(err.contains(expected), "{text}: {err}");
        }
    }

    #[test]
    fn checks_the_policy_against_the_configuration() {
        let check = |text: &str, providers: &[&str], profiles: &[(&str, bool)]| {
            authz(text)
                .check(providers.iter().copied(), profiles.iter().copied())
                .unwrap_err()
        };
        let both = r#"
            @id("a") permit (principal, action == Admit::Action::"github", resource);
            @id("b") permit (principal, action == Profile::Action::"deploy", resource);"#;
        assert!(authz(both).check(["github"], [("deploy", true)]).is_ok());
        assert!(
            check(both, &["github", "gitlab"], &[("deploy", true)])
                .contains("provider gitlab has no policy admitting it")
        );
        assert!(
            check(both, &["github"], &[("deploy", true), ("other", true)])
                .contains("profile other has no policy allowing anyone")
        );
        assert!(
            authz(both)
                .check(["github"], [("deploy", true), ("off", false)])
                .is_ok(),
            "a disabled profile needs none"
        );
        assert!(
            check(both, &["github"], &[("depoly", true)]).contains("names no profile"),
            "a misspelt name is an error, not a silent deny"
        );
        let wrong = r#"@id("w") forbid (principal, action == Action::"x", resource);"#;
        assert!(check(wrong, &["github"], &[]).contains("must be Admit::Action::"));
        let typo = r#"
            @id("a") permit (principal, action == Admit::Action::"github", resource);
            @id("t") forbid (principal, action == Admit::Action::"githb", resource);"#;
        assert!(check(typo, &["github"], &[]).contains("names no provider"));
    }
}
