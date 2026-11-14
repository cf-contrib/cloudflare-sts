//! End-to-end tests of the Worker under `wrangler dev`, with the OIDC issuers
//! and Cloudflare replaced by the stand-ins in `helper`, and the policy in
//! `tests/config.toml` and `tests/policy.cedar`. Run with `tests/run.sh`.

#![cfg(feature = "integration")]

mod helper;

use axum::http::Method;
use helper::*;
use serde_json::{Value, json};

fn token_id(reply: &Reply) -> String {
    reply.json()["token_id"]
        .as_str()
        .expect("a token_id")
        .to_string()
}

fn minted_policies(id: &str) -> Value {
    world().cloudflare.tokens[id].policies.clone()
}

fn r2_bodies() -> Vec<Value> {
    world()
        .cloudflare
        .requests
        .iter()
        .filter(|r| r.path.ends_with("/r2/temp-access-credentials"))
        .map(|r| r.body.clone().unwrap())
        .collect()
}

fn token_count() -> usize {
    world().cloudflare.tokens.len()
}

mod token_exchange_for_jobs {
    use super::*;

    #[tokio::test]
    async fn mints_a_scoped_expiring_token() {
        let _t = start().await;
        let before = now();
        let res = job_token(
            &sign(github_claims(json!({}))),
            &[("scope", "workers-deploy")],
        )
        .await;
        assert_eq!(res.status, 200, "{}", res.text);
        assert_eq!(res.cache_control.as_deref(), Some("no-store"));

        let body = res.json();
        assert_eq!(body["scope"], "workers-deploy");
        assert_eq!(body["account_id"], ACCOUNT_ID);
        assert!(body["access_token"].as_str().unwrap().starts_with("value-"));
        assert_matches(
            &body,
            json!({ "issued_token_type": ACCESS_TOKEN, "token_type": "Bearer" }),
        );

        let created = world().cloudflare.tokens[&token_id(&res)].clone();
        assert_eq!(
            created.name,
            "cloudflare-sts:github:repo:example-org/api:environment:prod"
        );
        assert_eq!(
            created.policies,
            json!([{
                "effect": "allow",
                "permission_groups": [{ "id": "pg-workers-scripts-write" }],
                "resources": { (format!("com.cloudflare.api.account.{ACCOUNT_ID}")): "*" },
            }])
        );
        // The default ttl is 15m, sent to Cloudflare without fractional seconds.
        let expires_on = created.expires_on.unwrap();
        assert_eq!(expires_on.len(), 20, "{expires_on}");
        assert!(expires_on.ends_with('Z'));
        let expires_at = body["expires_at"].as_u64().unwrap();
        assert!(expires_at - before > 14 * 60 && expires_at - before <= 15 * 60 + 1);
    }

    #[tokio::test]
    async fn uses_the_single_matching_profile_when_none_is_named() {
        let _t = start().await;
        let res = job_token(&sign(github_claims(json!({}))), &[]).await;
        assert_eq!(res.status, 200);
        assert_eq!(res.json()["scope"], "workers-deploy");
    }

    #[tokio::test]
    async fn resolves_permission_names_to_ids_and_passes_resources_through() {
        let _t = start().await;
        let claims = github_claims(
            json!({ "repository": "example-org/infra", "repository_id": "200000002" }),
        );
        let res = job_token(&sign(claims), &[("scope", "example-org/infra:ci.apply")]).await;
        assert_eq!(res.status, 200);
        // The form body percent-encodes `/` and `:`; the name arrives intact.
        assert_eq!(res.json()["scope"], "example-org/infra:ci.apply");
        assert_eq!(
            minted_policies(&token_id(&res)),
            json!([{
                "effect": "allow",
                "permission_groups": [{ "id": "pg-zone-write" }, { "id": "pg-dns-write" }],
                "resources": { (format!("com.cloudflare.api.account.zone.{ZONE_ID}")): "*" },
            }])
        );
    }

    #[tokio::test]
    async fn clamps_the_requested_ttl_to_max_ttl() {
        let _t = start().await;
        let res = job_token(&sign(github_claims(json!({}))), &[("ttl", "12h")]).await;
        let body = res.json();
        assert!(body["expires_at"].as_u64().unwrap() - now() <= 60 * 60 + 1);
        assert!(body["expires_in"].as_u64().unwrap() <= 60 * 60);
    }

    #[tokio::test]
    async fn writes_an_audit_line_without_secrets() {
        let t = start().await;
        let res = job_token(&sign(github_claims(json!({}))), &[]).await;
        let body = res.json();
        let mint = t.audit("token.mint").await.expect("a token.mint line");
        assert_matches(
            &mint,
            json!({
                "profile": "workers-deploy",
                "sub": "repo:example-org/api:environment:prod",
                // Only the claims the profile forwards.
                "claims": {
                    "repository": "example-org/api",
                    "repository_owner_id": OWNER_ID,
                    "ref": "refs/heads/main",
                    "environment": "prod",
                },
                "token_id": body["token_id"],
            }),
        );
        assert!(!t.log().contains(body["access_token"].as_str().unwrap()));
    }

    #[tokio::test]
    async fn rejects_a_request_without_a_subject_token() {
        let t = start().await;
        let res = post_form(
            "/oauth/token",
            &[("grant_type", GRANT), ("subject_token_type", ID_TOKEN)],
        )
        .await;
        assert_eq!(res.status, 400);
        assert_error(&res, "invalid_request");
        assert_refused(&t.deny().await, "invalid_request", "");
    }

    #[tokio::test]
    async fn refuses_a_jwt_for_another_audience() {
        let _t = start().await;
        let jwt = sign_with(
            &issuer("actions"),
            github_claims(json!({})),
            "sts.amazonaws.com",
            300,
        );
        assert_eq!(job_token(&jwt, &[]).await.status, 400);
    }

    #[tokio::test]
    async fn refuses_a_repo_outside_the_pinned_owner_with_a_generic_body() {
        let t = start().await;
        let claims = github_claims(json!({ "repository_owner_id": "999999" }));
        let res = job_token(&sign(claims), &[]).await;
        assert_eq!(res.status, 400);
        assert_error(&res, "invalid_request");
        assert_refused(
            &t.deny().await,
            "invalid_request",
            "the policy doesn't admit the token to provider github",
        );
        assert_eq!(token_count(), 1); // only the Cloudflare token
    }

    #[tokio::test]
    async fn refuses_when_several_profiles_match_and_none_is_named() {
        let t = start().await;
        let claims = github_claims(
            json!({ "repository": "example-org/infra", "repository_id": "200000002" }),
        );
        assert_eq!(job_token(&sign(claims), &[]).await.status, 400);
        assert_refused(&t.deny().await, "invalid_request", "all match the token");
    }

    #[tokio::test]
    async fn refuses_a_named_profile_that_doesnt_match() {
        let t = start().await;
        let res = job_token(
            &sign(github_claims(json!({}))),
            &[("scope", "example-org/infra:ci.apply")],
        )
        .await;
        assert_eq!(res.status, 400);
        let deny = t.deny().await;
        assert_matches(&deny, json!({ "profile": "example-org/infra:ci.apply" }));
        assert_refused(&deny, "invalid_scope", "scope ");
    }

    #[tokio::test]
    async fn rejects_bad_fields() {
        let _t = start().await;
        let long = "x".repeat(1025);
        let jwt = sign(github_claims(json!({})));
        let cases: [&[(&str, &str)]; 4] = [
            &[("ttl", "forever")],
            &[("ttl", "600")],
            &[("scope", "a"), ("scope", "b")],
            &[("scope", &long)],
        ];
        for fields in cases {
            assert_eq!(job_token(&jwt, fields).await.status, 400, "{fields:?}");
        }
    }

    #[tokio::test]
    async fn fails_when_a_permission_name_is_unknown() {
        let t = start().await;
        let claims = github_claims(json!({ "environment": "misspelled" }));
        let res = job_token(&sign(claims), &[]).await;
        assert_eq!(res.status, 500);
        assert_refused(
            &t.deny().await,
            "server_error",
            "no permission group is named Workers Scrpts Write",
        );
    }

    #[tokio::test]
    async fn picks_the_right_scope_for_a_permission_name_shared_by_two_groups() {
        let _t = start().await;
        let claims = github_claims(json!({ "environment": "lb-account" }));
        let res = job_token(&sign(claims), &[]).await;
        assert_eq!(res.status, 200, "{}", res.text);
        assert_eq!(
            minted_policies(&token_id(&res))[0]["permission_groups"],
            json!([{ "id": "pg-lb-write-account" }])
        );
    }

    #[tokio::test]
    async fn picks_the_zone_scoped_group_for_zone_resources() {
        let _t = start().await;
        let claims = github_claims(json!({ "environment": "lb-zone" }));
        let res = job_token(&sign(claims), &[]).await;
        assert_eq!(res.status, 200, "{}", res.text);
        assert_eq!(
            minted_policies(&token_id(&res))[0]["permission_groups"],
            json!([{ "id": "pg-lb-write-zone" }])
        );
    }

    #[tokio::test]
    async fn fails_when_the_cloudflare_api_does_without_retrying_the_create() {
        let t = start().await;
        world().cloudflare.fail_create = true;
        let res = job_token(&sign(github_claims(json!({}))), &[]).await;
        assert_eq!(res.status, 503);
        // The caller is told it's upstream, not what failed; the audit log says.
        assert_error(&res, "temporarily_unavailable");
        assert!(
            !res.json()["error_description"]
                .as_str()
                .unwrap()
                .contains("tokens.create"),
            "{}",
            res.text
        );
        assert_refused(
            &t.deny().await,
            "temporarily_unavailable",
            "Cloudflare: tokens.create: returned 500",
        );
        let creates = world()
            .cloudflare
            .requests
            .iter()
            .filter(|r| r.method == "POST")
            .count();
        assert_eq!(creates, 1);
    }
}

mod token_exchange_for_jobs_with_a_bucket {
    use super::*;

    /// A token from a state repo's job in `environment`, which picks the
    /// test policy's profile of that name.
    fn state_repo(environment: &str, overrides: Value) -> String {
        let mut claims = github_claims(
            json!({ "repository": "example-org/state-app", "environment": environment }),
        );
        merge(&mut claims, overrides);
        sign(claims)
    }

    #[tokio::test]
    async fn issues_prefix_limited_credentials_for_a_profile_with_only_a_bucket() {
        let _t = start().await;
        let before = now();
        let res = job_token(
            &state_repo("state", json!({})),
            &[("scope", "terraform-state")],
        )
        .await;
        assert_eq!(res.status, 200, "{}", res.text);
        let body = res.json();
        let expires_on = body["bucket"]["expires_on"].as_str().unwrap().to_string();
        assert_eq!(
            body,
            json!({
                "issued_token_type": R2_CREDENTIALS,
                "token_type": "N_A",
                "expires_in": body["expires_in"],
                "expires_at": body["expires_at"],
                "account_id": ACCOUNT_ID,
                "scope": "terraform-state",
                "bucket": {
                    "name": "org-terraform-state",
                    "access_key_id": CLOUDFLARE_TOKEN_ID,
                    "secret_access_key": "r2-secret-value",
                    "session_token": "r2-session-token-value",
                    "prefixes": ["github.com/example-org/state-app/"],
                    "endpoint": format!("https://{ACCOUNT_ID}.r2.cloudflarestorage.com"),
                    "expires_on": expires_on,
                },
            })
        );
        assert_eq!(expires_on.len(), 20, "{expires_on}");
        let expires_at = body["expires_at"].as_u64().unwrap();
        assert!(expires_at - before > 14 * 60 && expires_at - before <= 15 * 60 + 1);
        assert_eq!(
            r2_bodies(),
            [json!({
                "bucket": "org-terraform-state",
                "parentAccessKeyId": CLOUDFLARE_TOKEN_ID,
                "permission": "object-read-write",
                "ttlSeconds": 900.0,
                "prefixes": ["github.com/example-org/state-app/"],
            })]
        );
        assert_eq!(token_count(), 1); // no API token minted
    }

    #[tokio::test]
    async fn covers_the_whole_bucket_without_prefixes_and_honours_the_requested_ttl() {
        let _t = start().await;
        let res = job_token(&state_repo("whole-bucket", json!({})), &[("ttl", "2h")]).await;
        assert_eq!(res.json()["bucket"]["prefixes"], json!([]));
        assert_eq!(
            r2_bodies()[0],
            json!({ "bucket": "org-terraform-state", "parentAccessKeyId": CLOUDFLARE_TOKEN_ID, "permission": "object-read-only", "ttlSeconds": 1800.0 })
        );
    }

    #[tokio::test]
    async fn mints_a_token_and_credentials_that_expire_together_for_a_profile_with_both() {
        let _t = start().await;
        let res = job_token(&state_repo("state-and-deploy", json!({})), &[]).await;
        assert_eq!(res.status, 200, "{}", res.text);
        let body = res.json();
        assert!(
            world()
                .cloudflare
                .tokens
                .contains_key(body["token_id"].as_str().unwrap())
        );
        assert_eq!(body["bucket"]["prefixes"], json!(["200000003/"]));
        assert_eq!(r2_bodies()[0]["ttlSeconds"], json!(600.0));
        let bucket_expiry = chrono_secs(body["bucket"]["expires_on"].as_str().unwrap());
        assert!((bucket_expiry - body["expires_at"].as_i64().unwrap()).abs() <= 1);
    }

    #[tokio::test]
    async fn deletes_the_token_when_the_credentials_cant_be_created() {
        let t = start().await;
        world().cloudflare.fail_r2 = true;
        let res = job_token(&state_repo("state-and-deploy", json!({})), &[]).await;
        assert_eq!(res.status, 503);
        assert_error(&res, "temporarily_unavailable");
        assert_eq!(token_count(), 1); // the minted token was deleted
        assert_matches(
            &t.audit("token.revoke").await.unwrap(),
            json!({ "reason": "discarded" }),
        );
        assert!(t.audits("r2.issued").await.is_empty());
    }

    #[tokio::test]
    async fn refuses_without_calling_cloudflare_when_a_claim_cant_be_used_in_the_prefix() {
        let t = start().await;
        let res = job_token(
            &state_repo(
                "owner-state",
                json!({ "repository_owner": "../example-org" }),
            ),
            &[],
        )
        .await;
        assert_eq!(res.status, 400);
        assert_error(&res, "invalid_request");
        let deny = t.deny().await;
        assert_matches(&deny, json!({ "profile": "owner-state" }));
        assert_refused(&deny, "invalid_request", "bucket org-terraform-state: ");
        assert!(world().cloudflare.calls().is_empty());
    }

    #[tokio::test]
    async fn writes_an_r2_issued_audit_line_without_secrets() {
        let t = start().await;
        let res = job_token(&state_repo("state", json!({})), &[]).await;
        let expires_at = res.json()["expires_at"].clone();
        assert_eq!(
            t.audit("r2.issued").await.unwrap(),
            json!({
                "level": "INFO",
                "event": "r2.issued",
                "provider": "github",
                "profile": "terraform-state",
                "sub": "repo:example-org/api:environment:prod",
                "claims": {
                    "environment": "state",
                    "repository": "example-org/state-app",
                    "repository_owner_id": OWNER_ID,
                },
                "bucket": "org-terraform-state",
                "prefixes": ["github.com/example-org/state-app/"],
                "permission": "object-read-write",
                "expires_at": expires_at,
            })
        );
        assert!(!t.log().contains("r2-secret-value"));
        assert!(!t.log().contains("r2-session-token-value"));
    }
}

/// Seconds since the epoch of an RFC 3339 timestamp.
fn chrono_secs(rfc3339: &str) -> i64 {
    chrono::DateTime::parse_from_rfc3339(rfc3339)
        .unwrap()
        .timestamp()
}

mod revocation {
    use super::*;

    async fn minted() -> Value {
        job_token(&sign(github_claims(json!({}))), &[]).await.json()
    }

    #[tokio::test]
    async fn deletes_a_token_the_broker_minted() {
        let t = start().await;
        let token = minted().await;
        let res = revoke(token["access_token"].as_str()).await;
        assert_eq!(res.status, 200);
        assert_eq!(res.text, "");
        assert!(
            !world()
                .cloudflare
                .tokens
                .contains_key(token["token_id"].as_str().unwrap())
        );
        assert_matches(
            &t.audit("token.revoke").await.unwrap(),
            json!({ "token_id": token["token_id"] }),
        );
    }

    #[tokio::test]
    async fn succeeds_when_the_token_is_already_gone_or_never_existed() {
        let _t = start().await;
        let token = minted().await;
        revoke(token["access_token"].as_str()).await;
        assert_eq!(revoke(token["access_token"].as_str()).await.status, 200);
        assert_eq!(revoke(Some("never-existed")).await.status, 200);
    }

    #[tokio::test]
    async fn refuses_to_delete_tokens_the_broker_didnt_mint() {
        let _t = start().await;
        let foreign = world()
            .cloudflare
            .add(None, "ci deploy (manual)", None, None, "active");
        // Not the broker's, so an invalid token to it: 200, as RFC 7009 has it.
        assert_eq!(revoke(Some(&foreign.value)).await.status, 200);
        assert!(world().cloudflare.tokens.contains_key(&foreign.id));
    }

    #[tokio::test]
    async fn refuses_to_delete_the_cloudflare_token() {
        let _t = start().await;
        assert_eq!(revoke(Some(CLOUDFLARE_TOKEN)).await.status, 200);
        assert!(
            world()
                .cloudflare
                .calls()
                .iter()
                .all(|call| call.method != "DELETE")
        );
    }

    #[tokio::test]
    async fn rejects_a_request_without_a_token() {
        let _t = start().await;
        assert_eq!(revoke(None).await.status, 400);
    }

    #[tokio::test]
    async fn rejects_json() {
        let _t = start().await;
        let res = post_raw(
            "/oauth/revoke",
            "application/json",
            json!({ "token": "x" }).to_string(),
        )
        .await;
        assert_eq!(res.status, 400);
    }
}

mod health {
    use cloudflare_sts_sdk::v1::HealthClient;

    use super::*;

    #[tokio::test]
    async fn is_live_and_ready() {
        let _t = start().await;
        let health = HealthClient::new(BROKER);
        assert!(health.is_live().await.expect("the request failed"));
        assert!(health.is_ready().await.expect("the request failed"));
        assert_eq!(
            call(Method::GET, "/health/ready")
                .await
                .cache_control
                .as_deref(),
            Some("no-store")
        );
    }
}

mod exchange_requests {
    use super::*;

    #[tokio::test]
    async fn exchanges_a_jobs_oidc_token_for_a_cloudflare_api_token() {
        let t = start().await;
        let before = now();
        let res = job_token(
            &sign(github_claims(json!({}))),
            &[("scope", "workers-deploy")],
        )
        .await;
        assert_eq!(res.status, 200);
        let body = res.json();
        assert_eq!(
            body,
            json!({
                "access_token": body["access_token"],
                "issued_token_type": ACCESS_TOKEN,
                "token_type": "Bearer",
                "expires_in": body["expires_in"],
                "expires_at": body["expires_at"],
                "token_id": body["token_id"],
                "account_id": ACCOUNT_ID,
                "scope": "workers-deploy",
            })
        );
        let expires_in = body["expires_in"].as_u64().unwrap();
        assert!(expires_in > 14 * 60 && expires_in <= 15 * 60);
        assert!(body["expires_at"].as_u64().unwrap() - before <= 15 * 60 + 1);
        assert_matches(
            &t.audit("token.mint").await.unwrap(),
            json!({ "provider": "github", "profile": "workers-deploy", "token_id": body["token_id"] }),
        );
    }

    #[tokio::test]
    async fn accepts_the_jwt_token_type_and_the_cloudflare_audience() {
        let _t = start().await;
        let jwt = sign(github_claims(json!({})));
        let res = post_form(
            "/oauth/token",
            &[
                ("grant_type", GRANT),
                ("subject_token", &jwt),
                ("subject_token_type", JWT_TYPE),
                ("audience", "https://api.cloudflare.com"),
            ],
        )
        .await;
        assert_eq!(res.status, 200, "{}", res.text);
        assert_eq!(res.json()["scope"], "workers-deploy");
    }

    #[tokio::test]
    async fn rejects_what_it_doesnt_support_without_calling_anyone() {
        type Case<'a> = (&'a str, &'a [(&'a str, &'a str)], &'a str, &'a str);
        let cases: [Case; 9] = [
            (
                "another grant type",
                &[("grant_type", "client_credentials")],
                "unsupported_grant_type",
                "",
            ),
            (
                "no subject token",
                &[("subject_token", "")],
                "invalid_request",
                "",
            ),
            (
                "an unsupported subject token type",
                &[(
                    "subject_token_type",
                    "urn:ietf:params:oauth:token-type:saml2",
                )],
                "invalid_request",
                "",
            ),
            // Only OIDC tokens: a GitHub user token isn't one.
            (
                "an access token",
                &[(
                    "subject_token_type",
                    "urn:ietf:params:oauth:token-type:access_token",
                )],
                "invalid_request",
                "",
            ),
            (
                "another audience",
                &[("audience", "https://cache.example.com")],
                "invalid_target",
                "no profile is for audience",
            ),
            (
                "an actor token",
                &[("actor_token", "x"), ("actor_token_type", ID_TOKEN)],
                "invalid_request",
                "",
            ),
            (
                "a JWT for Cloudflare",
                &[("requested_token_type", JWT_TYPE)],
                "invalid_target",
                "can't be issued for https://api.cloudflare.com",
            ),
            (
                "an empty audience",
                &[("audience", "")],
                "invalid_request",
                "",
            ),
            (
                "an unsupported requested token type",
                &[(
                    "requested_token_type",
                    "urn:ietf:params:oauth:token-type:refresh_token",
                )],
                "invalid_request",
                "",
            ),
        ];
        // A valid token: the layer verifies it before anything else is looked at.
        let jwt = sign(github_claims(json!({})));
        for (case, overrides, code, says) in cases {
            let t = start().await;
            let mut form: Vec<(&str, &str)> = vec![
                ("grant_type", GRANT),
                ("subject_token", &jwt),
                ("subject_token_type", ID_TOKEN),
            ];
            for (key, value) in overrides {
                form.retain(|(k, _)| k != key);
                form.push((key, value));
            }
            let res = post_form("/oauth/token", &form).await;
            assert_eq!(res.status, 400, "{case}");
            assert_error(&res, code);
            let deny = t.deny().await;
            assert_eq!(deny["error"], code, "{case}: {deny}");
            assert!(
                deny["message"].as_str().unwrap_or_default().contains(says),
                "{case}: {deny}"
            );
            assert!(world().cloudflare.calls().is_empty(), "{case}");
            drop(t);
        }
    }

    #[tokio::test]
    async fn rejects_a_body_thats_not_form_encoded() {
        for content_type in ["application/json", "text/plain"] {
            let t = start().await;
            let res = post_raw(
                "/oauth/token",
                content_type,
                json!({ "grant_type": GRANT }).to_string(),
            )
            .await;
            assert_eq!(res.status, 400, "{content_type}");
            assert_refused(
                &t.deny().await,
                "invalid_request",
                "the body must be form-encoded",
            );
            drop(t);
        }
    }

    #[tokio::test]
    async fn refuses_a_token_that_isnt_a_valid_oidc_token() {
        let t = start().await;
        let res = job_token("not-a-jwt", &[]).await;
        assert_eq!(res.status, 400);
        assert_refused(
            &t.deny().await,
            "invalid_request",
            "invalid token: not a JWT",
        );
        assert!(world().cloudflare.calls().is_empty());
    }
}

mod people {
    use super::*;

    /// The client ID of the `access` stand-in, an Access for SaaS OIDC app:
    /// its ID tokens' audience.
    const CLIENT_ID: &str = "test-access-client-id";

    /// An ID token from the `access` stand-in for `email`, as cf-vault's login
    /// gets one.
    fn id_token(email: &str) -> String {
        let claims = json!({ "sub": "user-0001", "email": email, "name": "Alice" });
        sign_with(&issuer("access"), claims, CLIENT_ID, 300)
    }

    #[tokio::test]
    async fn the_metadata_says_where_people_sign_in() {
        let _t = start().await;
        let res = call(Method::GET, "/.well-known/oauth-authorization-server").await;
        assert_eq!(res.status, 200);
        // Only the providers with a client ID: not GitHub Actions or GitLab.
        assert_eq!(
            res.json()["identity_providers"],
            json!([{ "name": "access", "issuer": issuer("access"), "client_id": CLIENT_ID }])
        );
    }

    #[tokio::test]
    async fn exchanges_a_persons_id_token_for_their_profile() {
        let t = start().await;
        let res = job_token(
            &id_token("alice@example.com"),
            &[("scope", "example-org/app:tofu-plan")],
        )
        .await;
        assert_eq!(res.status, 200, "{}", res.text);
        let body = res.json();
        assert_eq!(body["issued_token_type"], R2_CREDENTIALS);
        // An Access token carries no repository: the prefix is the profile's own.
        assert_eq!(
            body["bucket"]["prefixes"],
            json!(["github.com/example-org/app/"])
        );
        assert_eq!(token_count(), 1); // no API token minted
        assert_matches(
            &t.audit("r2.issued").await.unwrap(),
            json!({ "provider": "access", "profile": "example-org/app:tofu-plan", "sub": "user-0001" }),
        );
    }

    #[tokio::test]
    async fn refuses_a_person_a_profile_for_ci() {
        let t = start().await;
        let res = job_token(
            &id_token("alice@example.com"),
            &[("scope", "example-org/infra:ci.apply")],
        )
        .await;
        assert_eq!(res.status, 400);
        assert_refused(
            &t.deny().await,
            "invalid_scope",
            "scope example-org/infra:ci.apply isn't for provider access",
        );
    }

    #[tokio::test]
    async fn refuses_someone_the_profile_doesnt_name() {
        let t = start().await;
        let res = job_token(&id_token("mallory@example.com"), &[]).await;
        assert_eq!(res.status, 400);
        assert_refused(
            &t.deny().await,
            "invalid_request",
            "no profile matches the token",
        );
    }
}

mod providers {
    use super::*;

    /// A GitLab CI job's claims, in GitLab's names.
    fn gitlab_claims(overrides: Value) -> Value {
        let mut claims = json!({
            "sub": "project_path:group/app:ref_type:branch:ref:main",
            "namespace_id": "4000001",
            "project_id": "500000001",
            "project_path": "group/app",
            "ref": "main",
            "ref_protected": "true",
        });
        merge(&mut claims, overrides);
        claims
    }

    /// A test with the GitLab stand-in, whose profiles are `gitlab-deploy`,
    /// `gitlab-cache` and `gitlab-state`.
    async fn setup() -> (Test, String) {
        (start().await, issuer("gitlab"))
    }

    fn gitlab_token(gitlab: &str, claims: Value) -> String {
        sign_with(gitlab, claims, AUDIENCE, 300)
    }

    #[tokio::test]
    async fn exchanges_another_issuers_token_found_by_its_iss_and_checked_with_its_keys() {
        let (t, gitlab) = setup().await;
        let res = job_token(&gitlab_token(&gitlab, gitlab_claims(json!({}))), &[]).await;
        assert_eq!(res.status, 200, "{}", res.text);
        assert_eq!(res.json()["scope"], "gitlab-deploy");
        // Named after the provider and the token's subject: GitLab's has no repo or run.
        assert_eq!(
            world().cloudflare.tokens[&token_id(&res)].name,
            "cloudflare-sts:gitlab:project_path:group/app:ref_type:branch:ref:main"
        );
        assert_matches(
            &t.audit("token.mint").await.unwrap(),
            json!({ "provider": "gitlab", "profile": "gitlab-deploy", "sub": "project_path:group/app:ref_type:branch:ref:main" }),
        );
    }

    #[tokio::test]
    async fn holds_every_token_to_its_providers_admit_policy() {
        let (t, gitlab) = setup().await;
        let res = job_token(
            &gitlab_token(&gitlab, gitlab_claims(json!({ "namespace_id": "4000002" }))),
            &[],
        )
        .await;
        assert_eq!(res.status, 400);
        let deny = t.deny().await;
        assert_matches(&deny, json!({ "provider": "gitlab" }));
        assert_refused(
            &deny,
            "invalid_request",
            "the policy doesn't admit the token to provider gitlab",
        );
    }

    #[tokio::test]
    async fn never_gives_a_token_from_one_provider_anothers_profile() {
        let (t, gitlab) = setup().await;
        let res = job_token(
            &gitlab_token(&gitlab, gitlab_claims(json!({}))),
            &[("scope", "workers-deploy")],
        )
        .await;
        assert_eq!(res.status, 400);
        assert_refused(
            &t.deny().await,
            "invalid_scope",
            "scope workers-deploy isn't for provider gitlab",
        );
    }

    #[tokio::test]
    async fn refuses_a_token_from_an_issuer_no_provider_is_for() {
        let (t, _) = setup().await;
        let jwt = sign_with(
            "https://other.example.com",
            github_claims(json!({})),
            AUDIENCE,
            300,
        );
        assert_eq!(job_token(&jwt, &[]).await.status, 400);
        assert_refused(
            &t.deny().await,
            "invalid_request",
            "no provider is for issuer https://other.example.com",
        );
    }

    #[tokio::test]
    async fn fails_when_the_discovery_document_names_another_issuer() {
        let t = start().await;
        let mismatched = issuer("mismatched");
        assert_eq!(
            job_token(&gitlab_token(&mismatched, gitlab_claims(json!({}))), &[])
                .await
                .status,
            503
        );
        let deny = t.deny().await;
        assert_refused(
            &deny,
            "temporarily_unavailable",
            "is for issuer https://evil.example.com",
        );
    }

    #[tokio::test]
    async fn takes_the_keys_from_jwks_uri_when_its_set_not_from_discovery() {
        let _t = start().await;
        // Its discovery document names another issuer; jwks_uri never reads it.
        let pinned = gitlab_token(&issuer("pinned"), gitlab_claims(json!({})));
        let res = job_token(&pinned, &[("audience", CACHE)]).await;
        assert_eq!(res.status, 200, "{}", res.text);
        assert_eq!(res.json()["scope"], "pinned-cache");
    }

    #[tokio::test]
    async fn refuses_a_token_without_the_typ_its_provider_names() {
        let t = start().await;
        let typed = gitlab_token(&issuer("typed"), gitlab_claims(json!({})));
        let res = job_token(&typed, &[("audience", CACHE)]).await;
        assert_eq!(res.status, 400, "{}", res.text);
        assert_refused(
            &t.deny().await,
            "invalid_request",
            "invalid token: typ must be at+jwt",
        );
    }

    /// Any claim can fill a bucket prefix, not only GitHub's: GitLab's
    /// `project_path` spans segments, as the template's one placeholder.
    #[tokio::test]
    async fn fills_bucket_prefixes_from_another_issuers_claims() {
        let (_t, gitlab) = setup().await;
        let claims = gitlab_claims(json!({ "project_path": "group/sub/app" }));
        let res = job_token(&gitlab_token(&gitlab, claims), &[("scope", "gitlab-state")]).await;
        assert_eq!(res.status, 200, "{}", res.text);
        assert_eq!(
            res.json()["bucket"]["prefixes"],
            json!(["gitlab.com/group/sub/app/", "4000001/500000001/"])
        );
    }

    #[tokio::test]
    async fn issues_another_providers_caller_a_service_token_with_the_matched_claims() {
        let (_t, gitlab) = setup().await;
        let res = job_token(
            &gitlab_token(&gitlab, gitlab_claims(json!({}))),
            &[("audience", CACHE)],
        )
        .await;
        assert_eq!(res.status, 200, "{}", res.text);
        let (_, claims) = verify_broker_token(res.json()["access_token"].as_str().unwrap()).await;
        assert_matches(
            &claims,
            json!({
                "iss": AUDIENCE,
                "aud": CACHE,
                "sub": "project_path:group/app:ref_type:branch:ref:main",
                "provider": "gitlab",
                "profile": "gitlab-cache",
                // What the profile forwards, so the service can match on it too.
                "project_path": "group/app",
                "namespace_id": "4000001",
            }),
        );
        // Claims the profile doesn't forward stay behind.
        assert!(claims.get("project_id").is_none());
    }
}

mod tokens_for_other_services {
    use super::*;

    /// A test of the `nix-push` profile, for the cache.
    async fn setup() -> Test {
        start().await
    }

    async fn for_cache(subject_token: &str, token_type: &str, extra: &[(&str, &str)]) -> Reply {
        let mut form = vec![
            ("grant_type", GRANT),
            ("subject_token", subject_token),
            ("subject_token_type", token_type),
            ("audience", CACHE),
        ];
        form.extend_from_slice(extra);
        post_form("/oauth/token", &form).await
    }

    #[tokio::test]
    async fn issues_a_job_a_token_the_service_can_verify_with_the_brokers_keys() {
        let t = setup().await;
        let sub = "repo:example-org/api:environment:prod";
        let res = for_cache(&sign(github_claims(json!({ "sub": sub }))), ID_TOKEN, &[]).await;
        assert_eq!(res.status, 200, "{}", res.text);
        let body = res.json();
        assert_eq!(
            body,
            json!({
                "access_token": body["access_token"],
                "issued_token_type": ACCESS_TOKEN,
                "token_type": "Bearer",
                "expires_in": body["expires_in"],
                "expires_at": body["expires_at"],
                "scope": "nix-push",
            })
        );
        let (header, claims) = verify_broker_token(body["access_token"].as_str().unwrap()).await;
        // An RFC 9068 access token.
        assert_matches(&header, json!({ "alg": "RS256", "typ": "at+jwt" }));
        assert_matches(
            &claims,
            json!({
                "iss": AUDIENCE,
                "aud": CACHE,
                "sub": sub,
                "client_id": "github",
                "provider": "github",
                "profile": "nix-push",
                // What the profile forwards, so the service can match on it too.
                "repository_owner_id": OWNER_ID,
                "ref": "refs/heads/main",
            }),
        );
        // Nothing else of the job's token.
        assert!(
            claims.get("repository").is_none() && claims.get("run_id").is_none(),
            "{claims}"
        );
        assert!(claims["jti"].is_string() && claims["iat"].is_u64());
        // Only the identity: no API token, no R2 credentials.
        assert!(world().cloudflare.calls().is_empty());
        assert_matches(
            &t.audit("token.issue").await.unwrap(),
            json!({ "provider": "github", "profile": "nix-push", "audience": CACHE, "jti": claims["jti"] }),
        );
    }

    #[tokio::test]
    async fn never_outlives_the_jobs_oidc_token() {
        let _t = setup().await;
        let before = now();
        let jwt = sign_with(&issuer("actions"), github_claims(json!({})), AUDIENCE, 120);
        let body = for_cache(&jwt, ID_TOKEN, &[]).await.json();
        // The profile's ttl is 15m; the GitHub token's 2m wins.
        let lives = body["expires_at"].as_u64().unwrap() - before;
        assert!(lives > 60 && lives <= 2 * 60 + 1, "{lives}");
    }

    #[tokio::test]
    async fn publishes_its_metadata_and_only_the_public_key() {
        let _t = setup().await;
        let res = call(Method::GET, "/.well-known/oauth-authorization-server").await;
        assert_eq!(res.status, 200);
        assert_eq!(res.cache_control.as_deref(), Some("public, max-age=300"));
        assert_matches(
            &res.json(),
            json!({
                "issuer": AUDIENCE,
                "jwks_uri": format!("{AUDIENCE}/.well-known/jwks"),
                "token_endpoint": format!("{AUDIENCE}/oauth/token"),
                "revocation_endpoint": format!("{AUDIENCE}/oauth/revoke"),
                "response_types_supported": [],
                "grant_types_supported": [GRANT],
            }),
        );

        // The same issuer and keys, for services that only read OpenID
        // Connect Discovery.
        let res = call(Method::GET, "/.well-known/openid-configuration").await;
        assert_eq!(res.status, 200);
        assert_eq!(res.cache_control.as_deref(), Some("public, max-age=300"));
        assert_matches(
            &res.json(),
            json!({
                "issuer": AUDIENCE,
                "jwks_uri": format!("{AUDIENCE}/.well-known/jwks"),
                "response_types_supported": ["id_token"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["RS256"],
            }),
        );

        let jwks = call(Method::GET, "/.well-known/jwks").await.json();
        let keys = jwks["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 1);
        // Only the public members: no d, p, q or the CRT values.
        let mut members: Vec<&String> = keys[0].as_object().unwrap().keys().collect();
        members.sort();
        assert_eq!(members, ["alg", "e", "kid", "kty", "n", "use"]);
        let res = for_cache(&sign(github_claims(json!({}))), ID_TOKEN, &[]).await;
        let (header, _) = verify_broker_token(res.json()["access_token"].as_str().unwrap()).await;
        assert_eq!(header["kid"], keys[0]["kid"]);
    }

    #[tokio::test]
    async fn rejects_an_audience_no_profile_is_for() {
        let t = setup().await;
        let jwt = sign(github_claims(json!({})));
        let res = post_form(
            "/oauth/token",
            &[
                ("grant_type", GRANT),
                ("subject_token", &jwt),
                ("subject_token_type", ID_TOKEN),
                ("audience", "https://other.example.com"),
            ],
        )
        .await;
        assert_eq!(res.status, 400);
        assert_refused(
            &t.deny().await,
            "invalid_target",
            "no profile is for audience",
        );
    }

    #[tokio::test]
    async fn refuses_a_cloudflare_profile_named_for_the_service() {
        let t = setup().await;
        let res = for_cache(
            &sign(github_claims(json!({}))),
            ID_TOKEN,
            &[("scope", "workers-deploy")],
        )
        .await;
        assert_eq!(res.status, 400);
        assert_refused(
            &t.deny().await,
            "invalid_request",
            &format!("profile workers-deploy isn't for {CACHE}"),
        );
    }

    #[tokio::test]
    async fn rejects_a_cloudflare_token_type_requested_for_the_service() {
        let _t = setup().await;
        let res = for_cache(
            &sign(github_claims(json!({}))),
            ID_TOKEN,
            &[("requested_token_type", R2_CREDENTIALS)],
        )
        .await;
        assert_eq!(res.status, 400);
    }
}

#[tokio::test]
async fn serves_only_the_apis_routes() {
    let _t = start().await;
    for path in ["/v1/token", "/v1/revoke", "/"] {
        assert_eq!(post_form(path, &[]).await.status, 404, "{path}");
    }
    assert_eq!(call(Method::GET, "/oauth/token").await.status, 405);
}

#[tokio::test]
async fn the_scheduled_cleanup_deletes_only_expired_broker_tokens() {
    let _t = start().await;
    let at = |offset: i64| {
        chrono::DateTime::from_timestamp(now() as i64 + offset, 0)
            .unwrap()
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    };
    let (expired, live, foreign) = {
        let mut world = world();
        let cf = &mut world.cloudflare;
        (
            cf.add(
                None,
                "cloudflare-sts:example-org/api:1:1",
                None,
                Some(at(-60)),
                "expired",
            ),
            cf.add(
                None,
                "cloudflare-sts:example-org/api:2:1",
                None,
                Some(at(60)),
                "active",
            ),
            cf.add(None, "someone else's", None, Some(at(-60)), "expired"),
        )
    };
    let res = call(Method::GET, "/__scheduled?cron=17+*+*+*+*").await;
    assert_eq!(res.status, 200, "{}", res.text);
    let world = world();
    assert!(!world.cloudflare.tokens.contains_key(&expired.id));
    assert!(world.cloudflare.tokens.contains_key(&live.id));
    assert!(world.cloudflare.tokens.contains_key(&foreign.id));
    assert!(
        world
            .cloudflare
            .requests
            .iter()
            .any(|r| r.method == "GET" && r.path.ends_with("/tokens"))
    );
}
