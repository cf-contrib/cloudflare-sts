//! The policy: what a JWT's claims must be to be let in. Ours, not any
//! RFC's: [`ClaimRules::authorize`] applies it to a token
//! [`Providers::verify`](crate::oidc::Providers::verify) accepted.

use std::{collections::BTreeMap, ops::Deref};

use serde::Deserialize;
use serde_json::{Map, Value};

use crate::oidc::{Claims, Error};

/// The claim rules a token must match one of: a provider's, or anything else
/// a configuration lets a token in by. Written as a JSON array of
/// [`ClaimRule`]s, which configurations call claim sets.
///
/// Deserializing doesn't check it isn't empty: [`check`](Self::check) does,
/// saying where. An empty list lets nothing in either way.
#[derive(Debug, Default, Deserialize)]
#[serde(transparent)]
pub struct ClaimRules(Vec<ClaimRule>);

impl ClaimRules {
    /// The index of the first rule `claims` match: what lets a verified
    /// token in.
    ///
    /// # Errors
    ///
    /// [`Error::InsufficientScope`] when none does.
    pub fn authorize(&self, claims: &Claims) -> Result<usize, Error> {
        self.0
            .iter()
            .position(|rule| rule.matches(claims))
            .ok_or_else(|| Error::InsufficientScope {
                issuer: claims.iss().unwrap_or_default().to_string(),
                subject: claims.sub().map(String::from),
            })
    }

    /// Whether `claims` match any rule.
    pub fn matches(&self, claims: &Map<String, Value>) -> bool {
        self.0.iter().any(|rule| rule.matches(claims))
    }

    /// The claims any rule matches on.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.0.iter().flat_map(ClaimRule::names)
    }

    /// What deserializing can't check: that there's a rule at all. `at` is
    /// where the rules are, for the message.
    ///
    /// # Errors
    ///
    /// When there's none.
    pub fn check(&self, at: &str) -> Result<(), String> {
        if self.0.is_empty() {
            return Err(format!("{at} must contain at least one claim set"));
        }
        Ok(())
    }
}

impl Deref for ClaimRules {
    type Target = [ClaimRule];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Vec<ClaimRule>> for ClaimRules {
    fn from(rules: Vec<ClaimRule>) -> Self {
        Self(rules)
    }
}

/// Claim name to pattern: a rule a JWT Claims Set matches when every claim
/// it names does. Configurations call it a claim set.
///
/// Written as a JSON object: `{ "repository_owner_id": "100000001", "ref":
/// "refs/heads/*" }`. Each value is a non-empty string, a number or a
/// boolean, matched exactly, or as a prefix when a string ends in one `*`.
/// `*_id` claims must match exactly.
#[derive(Debug, Deserialize)]
#[serde(try_from = "Map<String, Value>")]
pub struct ClaimRule(BTreeMap<String, Pattern>);

impl TryFrom<Map<String, Value>> for ClaimRule {
    type Error = String;

    fn try_from(raw: Map<String, Value>) -> Result<Self, String> {
        if raw.is_empty() {
            return Err("a claim set must match at least one claim".to_string());
        }

        let mut claims = BTreeMap::new();
        for (claim, value) in raw {
            // IDs may be written as JSON numbers; most issuers send strings.
            let pattern = match value {
                Value::String(s) if !s.is_empty() => s,
                Value::Number(n) if n.is_u64() => n.to_string(),
                Value::Bool(b) => b.to_string(),
                _ => {
                    return Err(format!(
                        "claim {claim} must be a non-empty string, a number or a boolean"
                    ));
                }
            };
            // Patterns stay narrow: a prefix, at most, and never for an ID.
            let pattern = Pattern::parse(&pattern)
                .filter(|pattern| !is_id_claim(&claim) || matches!(pattern, Pattern::Exact(_)))
                .ok_or_else(|| {
                    if is_id_claim(&claim) {
                        format!("claim {claim}: ID claims must match exactly")
                    } else {
                        format!("claim {claim}: * may only end a pattern, after a prefix")
                    }
                })?;
            claims.insert(claim, pattern);
        }
        Ok(Self(claims))
    }
}

impl ClaimRule {
    /// Whether `claims` match every claim in the rule. A [`Claims`] derefs to
    /// the map this takes.
    pub fn matches(&self, claims: &Map<String, Value>) -> bool {
        self.0
            .iter()
            .all(|(claim, pattern)| match claims.get(claim) {
                // A list claim (`groups`, `amr`) matches if any entry does.
                Some(Value::Array(values)) => {
                    values.iter().any(|value| pattern.matches_value(value))
                }
                Some(value) => pattern.matches_value(value),
                None => false,
            })
    }

    /// The claims it matches on.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.0.keys().map(String::as_str)
    }
}

/// A claim's expected value: exact, or a prefix written with one trailing
/// `*` (`example-org/*`).
#[derive(Debug, PartialEq)]
enum Pattern {
    Exact(String),
    Prefix(String),
}

impl Pattern {
    /// `None` for a `*` anywhere but at the end of a non-empty prefix.
    fn parse(pattern: &str) -> Option<Self> {
        match pattern.strip_suffix('*') {
            Some(prefix) if !prefix.is_empty() && !prefix.contains('*') => {
                Some(Self::Prefix(prefix.to_string()))
            }
            Some(_) => None,
            None if pattern.contains('*') => None,
            None => Some(Self::Exact(pattern.to_string())),
        }
    }

    fn matches(&self, value: &str) -> bool {
        match self {
            Self::Exact(expected) => value == expected,
            Self::Prefix(prefix) => value.starts_with(prefix.as_str()),
        }
    }

    /// Numbers and booleans compare as they're written in JSON.
    fn matches_value(&self, value: &Value) -> bool {
        match value {
            Value::String(s) => self.matches(s),
            Value::Number(n) => self.matches(&n.to_string()),
            Value::Bool(b) => self.matches(if *b { "true" } else { "false" }),
            _ => false,
        }
    }
}

fn is_id_claim(claim: &str) -> bool {
    claim.ends_with("_id")
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn rule(value: Value) -> Result<ClaimRule, String> {
        serde_json::from_value(value).map_err(|err| err.to_string())
    }

    fn claims() -> Map<String, Value> {
        json!({
            "iss": "https://token.actions.githubusercontent.com",
            "sub": "repo:example-org/app:ref:refs/heads/main",
            "repository": "example-org/app",
            "repository_id": "200000002",
            "repository_owner_id": "100000001",
            "ref": "refs/heads/main",
            "groups": ["cache-readers", "cache-uploaders"],
            "email_verified": true,
        })
        .as_object()
        .unwrap()
        .clone()
    }

    #[test]
    fn rejects_bad_rules() {
        let cases = [
            (json!({}), "a claim set must match at least one claim"),
            (
                json!({ "repository_id": "2000*" }),
                "claim repository_id: ID claims must match exactly",
            ),
            (json!({ "ref": "" }), "non-empty string"),
            (json!({ "ref": null }), "non-empty string"),
            (json!({ "ref": -1 }), "non-empty string"),
            (json!({ "ref": "*" }), "claim ref: * may only end a pattern"),
            (json!({ "ref": "*main" }), "may only end a pattern"),
            (json!({ "ref": "refs/*/main" }), "may only end a pattern"),
            (json!({ "ref": "refs/**" }), "may only end a pattern"),
        ];
        for (value, expected) in cases {
            let err = rule(value.clone()).unwrap_err();
            assert!(err.contains(expected), "{value}: {err}");
        }
    }

    fn rules(value: Value) -> ClaimRules {
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn authorize_returns_the_first_matching_rule() {
        let rules = rules(json!([
            { "ref": "refs/heads/release" },
            { "repository_owner_id": "100000001" },
            { "ref": "refs/heads/*" },
        ]));
        assert_eq!(rules.authorize(&claims().into()), Ok(1));
        assert!(rules.matches(&claims()));
        assert_eq!(
            rules.names().collect::<Vec<_>>(),
            ["ref", "repository_owner_id", "ref"]
        );
    }

    #[test]
    fn authorize_refuses_when_no_rule_matches() {
        let err = rules(json!([{ "ref": "refs/heads/release" }]))
            .authorize(&claims().into())
            .unwrap_err();
        assert_eq!(
            err,
            Error::InsufficientScope {
                issuer: "https://token.actions.githubusercontent.com".to_string(),
                subject: Some("repo:example-org/app:ref:refs/heads/main".to_string()),
            }
        );
        assert_eq!(
            err.to_string(),
            "the token matches none of https://token.actions.githubusercontent.com's claim sets"
        );
        let none = ClaimRules::default();
        assert!(
            none.authorize(&claims().into()).is_err(),
            "no rules, no access"
        );
        assert!(!none.matches(&claims()));
        assert_eq!(
            none.check("providers[0].claims"),
            Err("providers[0].claims must contain at least one claim set".to_string())
        );
    }

    #[test]
    fn pattern_is_exact_or_a_trailing_prefix() {
        let parse = |p| Pattern::parse(p).unwrap();
        assert!(parse("example-org/*").matches("example-org/app"));
        assert!(parse("refs/heads/*").matches("refs/heads/feature/x"));
        assert!(parse("refs/heads/main").matches("refs/heads/main"));
        assert!(!parse("refs/heads/main").matches("refs/heads/main2"));
        assert!(!parse("example-org/*").matches("other-org/app"));
        // Regex metacharacters are literal.
        assert!(parse("a.b*").matches("a.bc"));
        assert!(!parse("a.b*").matches("axbc"));
        for pattern in ["*", "*x", "a*b", "a**"] {
            assert_eq!(Pattern::parse(pattern), None, "{pattern}");
        }
    }

    #[test]
    fn needs_every_claim_to_match() {
        let rule =
            rule(json!({ "repository": "example-org/*", "ref": "refs/heads/main" })).unwrap();
        assert!(rule.matches(&claims()));

        let mut other_ref = claims();
        other_ref.insert("ref".into(), "refs/heads/dev".into());
        assert!(!rule.matches(&other_ref));
        other_ref.remove("ref");
        assert!(!rule.matches(&other_ref), "a missing claim never matches");
    }

    #[test]
    fn matches_lists_numbers_and_booleans() {
        let matches = |value: Value| rule(value).unwrap().matches(&claims());
        assert!(
            matches(json!({ "groups": "cache-uploaders" })),
            "a list matches if any entry does"
        );
        assert!(
            matches(json!({ "email_verified": true })),
            "booleans compare as written"
        );
        assert!(
            matches(json!({ "repository_id": 200000002 })),
            "numbers compare as written"
        );
        assert!(!matches(json!({ "groups": "admins" })));
        assert!(
            !matches(json!({ "repository_id": "2000000021" })),
            "IDs compare exactly"
        );
    }
}
