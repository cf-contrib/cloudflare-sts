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
    async fn accepts_the_jwt_subject_token_type() {
        let _t = start().await;
        let jwt = sign(github_claims(json!({})));
        let res = post_form(
            "/oauth/token",
            &[
                ("grant_type", GRANT),
                ("subject_token", &jwt),
                ("subject_token_type", JWT_TYPE),
            ],
        )
        .await;
        assert_eq!(res.status, 200, "{}", res.text);
        assert_eq!(res.json()["scope"], "workers-deploy");
    }

    #[tokio::test]
    async fn rejects_what_it_doesnt_support_without_calling_anyone() {
        type Case<'a> = (&'a str, &'a [(&'a str, &'a str)], &'a str, &'a str);
        let cases: [Case; 8] = [
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
            // The broker issues Cloudflare's credentials only: no audience to ask for.
            (
                "an audience",
                &[("audience", "https://cache.example.com")],
                "invalid_request",
                "",
            ),
            (
                "an actor token",
                &[("actor_token", "x"), ("actor_token_type", ID_TOKEN)],
                "invalid_request",
                "",
            ),
            (
                "a JWT as the requested token type",
                &[("requested_token_type", JWT_TYPE)],
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
    async fn the_metadata_names_no_identity_providers() {
        let _t = start().await;
        let res = call(Method::GET, "/.well-known/oauth-authorization-server").await;
        assert_eq!(res.status, 200);
        // Sign-in is the client's: cf-vault is told the provider and client
        // in its own profile, so the broker has none to list.
        assert!(res.json().get("identity_providers").is_none());
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

    /// A test with the GitLab stand-in, whose profiles are `gitlab-deploy`
    /// and `gitlab-state`.
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
        let res = job_token(&pinned, &[]).await;
        assert_eq!(res.status, 200, "{}", res.text);
        assert_eq!(res.json()["scope"], "pinned-state");
    }

    #[tokio::test]
    async fn refuses_a_token_without_the_typ_its_provider_names() {
        let t = start().await;
        let typed = gitlab_token(&issuer("typed"), gitlab_claims(json!({})));
        let res = job_token(&typed, &[]).await;
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

mod several_scopes {
    use super::*;

    /// A job in the environment the `combo-*` profiles are for.
    fn combo() -> String {
        sign(github_claims(json!({ "environment": "combo" })))
    }

    #[tokio::test]
    async fn combines_tokens_and_a_bucket_into_one_grant() {
        let _t = start().await;
        let res = job_token(&combo(), &[("scope", "combo-deploy combo-lb combo-state")]).await;
        assert_eq!(res.status, 200, "{}", res.text);
        let body = res.json();
        assert_eq!(body["scope"], "combo-deploy combo-lb combo-state");
        assert!(body["access_token"].as_str().unwrap().starts_with("value-"));
        assert_eq!(body["bucket"]["name"], "org-terraform-state");
        // One token with both profiles' policies, and one set of bucket credentials
        assert_eq!(
            minted_policies(&token_id(&res)).as_array().unwrap().len(),
            2
        );
        assert_eq!(token_count(), 2); // the Cloudflare token, and the one minted
        assert_eq!(r2_bodies().len(), 1);
    }

    #[tokio::test]
    async fn takes_each_scope_once_in_the_order_given() {
        let _t = start().await;
        let res = job_token(&combo(), &[("scope", "combo-lb  combo-deploy combo-lb")]).await;
        assert_eq!(res.status, 200, "{}", res.text);
        assert_eq!(res.json()["scope"], "combo-lb combo-deploy");
    }

    #[tokio::test]
    async fn refuses_two_buckets_without_calling_cloudflare() {
        let t = start().await;
        let res = job_token(&combo(), &[("scope", "combo-state combo-state-two")]).await;
        assert_eq!(res.status, 400);
        assert_error(&res, "invalid_scope");
        assert_refused(
            &t.deny().await,
            "invalid_scope",
            "each have a bucket, and R2 credentials are for one",
        );
        assert!(world().cloudflare.calls().is_empty());
        assert_eq!(token_count(), 1); // only the Cloudflare token
    }

    #[tokio::test]
    async fn refuses_them_all_when_one_isnt_allowed() {
        let t = start().await;
        // `workers-deploy` is for the prod environment, not this one
        let res = job_token(&combo(), &[("scope", "combo-deploy workers-deploy")]).await;
        assert_eq!(res.status, 400);
        assert_error(&res, "invalid_scope");
        assert_refused(
            &t.deny().await,
            "invalid_scope",
            "scope workers-deploy doesn't match the token",
        );
        assert!(world().cloudflare.calls().is_empty());
        assert_eq!(token_count(), 1);
    }

    #[tokio::test]
    async fn refuses_an_unknown_scope_as_invalid_scope() {
        let _t = start().await;
        let res = job_token(&combo(), &[("scope", "combo-deploy nope")]).await;
        assert_eq!(res.status, 400);
        assert_error(&res, "invalid_scope");
        assert!(world().cloudflare.calls().is_empty());
    }
}

mod access_service_tokens {
    use super::*;

    const HOST: &str = "cloudflare-nix-api.example.com";

    /// A job in the environment the `combo-*` profiles are for.
    fn combo() -> String {
        sign(github_claims(json!({ "environment": "combo" })))
    }

    fn service_tokens() -> usize {
        world().cloudflare.service_tokens.len()
    }

    #[tokio::test]
    async fn issues_a_service_token_tagged_with_the_applications_host() {
        let _t = start().await;
        let res = job_token(&combo(), &[("scope", "combo-access")]).await;
        assert_eq!(res.status, 200, "{}", res.text);
        let body = res.json();

        // Only a service token: no API token, no bucket
        assert_eq!(
            body["issued_token_type"],
            "urn:cloudflare-sts:params:oauth:token-type:access_service_token"
        );
        assert!(body.get("access_token").is_none() && body.get("bucket").is_none());
        assert_eq!(token_count(), 1);

        let access = &body["access"];
        assert_eq!(access["audience"], format!("https://{HOST}"));
        let world = world();
        let stored = world
            .cloudflare
            .service_tokens
            .get(access["token_id"].as_str().unwrap())
            .expect("the service token exists");
        assert_eq!(access["client_id"], stored.client_id.as_str());
        assert_eq!(access["client_secret"], stored.client_secret.as_str());
        assert!(
            stored.name.starts_with("cloudflare-sts:github:"),
            "{}",
            stored.name
        );
        // What an Access `service_token_tag` rule matches
        assert_eq!(stored.tags, json!({ "cloudflare-sts-audience": HOST }));
        // The profile's 15 minutes
        assert_eq!(stored.duration, "900s");
    }

    #[tokio::test]
    async fn gives_a_service_token_at_least_the_ten_minutes_cloudflare_does() {
        let _t = start().await;
        let res = job_token(&combo(), &[("scope", "combo-access"), ("ttl", "1m")]).await;
        assert_eq!(res.status, 200, "{}", res.text);
        let world = world();
        let stored = world.cloudflare.service_tokens.values().next().unwrap();
        assert_eq!(stored.duration, "600s");
    }

    #[tokio::test]
    async fn combines_with_a_token_in_one_grant() {
        let _t = start().await;
        let res = job_token(&combo(), &[("scope", "combo-deploy combo-access")]).await;
        assert_eq!(res.status, 200, "{}", res.text);
        let body = res.json();
        assert_eq!(body["scope"], "combo-deploy combo-access");
        assert!(body["access_token"].is_string() && body["access"]["client_id"].is_string());
        assert_eq!(
            body["issued_token_type"],
            "urn:ietf:params:oauth:token-type:access_token"
        );
        assert_eq!((token_count(), service_tokens()), (2, 1));
    }

    #[tokio::test]
    async fn refuses_two_applications_without_calling_cloudflare() {
        let _t = start().await;
        let res = job_token(&combo(), &[("scope", "combo-access combo-access-two")]).await;
        assert_eq!(res.status, 400);
        assert_error(&res, "invalid_scope");
        assert!(world().cloudflare.calls().is_empty());
    }

    #[tokio::test]
    async fn deletes_the_token_when_the_service_token_cant_be_created() {
        let t = start().await;
        world().cloudflare.fail_access = true;
        let res = job_token(&combo(), &[("scope", "combo-deploy combo-access")]).await;
        assert_eq!(res.status, 503);
        assert_error(&res, "temporarily_unavailable");
        // Half a grant isn't handed out: the API token was deleted
        assert_eq!((token_count(), service_tokens()), (1, 0));
        assert_matches(
            &t.audit("token.revoke").await.unwrap(),
            json!({ "reason": "discarded" }),
        );
        assert!(t.audits("access.issued").await.is_empty());
    }

    #[tokio::test]
    async fn writes_an_audit_line_without_the_secret() {
        let t = start().await;
        let res = job_token(&combo(), &[("scope", "combo-access")]).await;
        let body = res.json();
        let line = t
            .audit("access.issued")
            .await
            .expect("an access.issued line");
        assert_matches(
            &line,
            json!({
                "profile": "combo-access",
                "audience": format!("https://{HOST}"),
                "token_id": body["access"]["token_id"],
            }),
        );
        let text = line.to_string();
        let secret = body["access"]["client_secret"].as_str().unwrap();
        assert!(!text.contains(secret), "the secret is in the log: {text}");
    }

    #[tokio::test]
    async fn revokes_a_service_token_by_its_id() {
        let _t = start().await;
        let issued = job_token(&combo(), &[("scope", "combo-access")])
            .await
            .json();
        let id = issued["access"]["token_id"].as_str().unwrap();
        let res = revoke_access(id).await;
        assert_eq!(res.status, 200, "{}", res.text);
        assert_eq!(service_tokens(), 0);
        // Again, or one that never was: still 200, RFC 7009's
        assert_eq!(revoke_access(id).await.status, 200);
        assert_eq!(revoke_access("nope").await.status, 200);
        // An ID that isn't one is never put in a path
        assert_eq!(revoke_access("../tokens").await.status, 200);
    }

    #[tokio::test]
    async fn doesnt_revoke_a_service_token_the_broker_didnt_mint() {
        let _t = start().await;
        let foreign = world()
            .cloudflare
            .add_service_token("someone else's", "2099-01-01T00:00:00Z".into());
        let res = revoke_access(&foreign.id).await;
        assert_eq!(res.status, 200, "{}", res.text);
        assert!(world().cloudflare.service_tokens.contains_key(&foreign.id));
    }

    #[tokio::test]
    async fn the_scheduled_cleanup_deletes_only_expired_broker_service_tokens() {
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
                cf.add_service_token("cloudflare-sts:github:1", at(-60)),
                cf.add_service_token("cloudflare-sts:github:2", at(300)),
                cf.add_service_token("someone else's", at(-60)),
            )
        };
        let res = call(Method::GET, "/__scheduled?cron=17+*+*+*+*").await;
        assert_eq!(res.status, 200, "{}", res.text);
        let world = world();
        assert!(!world.cloudflare.service_tokens.contains_key(&expired.id));
        assert!(world.cloudflare.service_tokens.contains_key(&live.id));
        assert!(world.cloudflare.service_tokens.contains_key(&foreign.id));
    }
}

/// Replacing the broker's own Cloudflare token, which `tests/config.toml`
/// switches on.
///
/// The rotation keeps its state in Workers KV, and reaches most of that state
/// only across turns of the cron, or hours later when an overlap runs out. Each
/// test sets it with `set_rotation_state` before it fires the cron, so it
/// starts the broker where it means to and inherits nothing from the last one.
mod rotation {
    use super::*;

    const MONTH: i64 = 31 * 24 * 3600;
    const HOUR: i64 = 3600;

    /// What this broker names its own tokens by: its host, then a digest of
    /// its whole issuer, so two brokers in one account never collect each
    /// other's. The digest is `broker_prefix`'s, over `tests/config.toml`'s
    /// issuer — spelled out here because the test binary can't call into the
    /// Worker to derive it, and pinned by a unit test in `service::rotate` so
    /// the two can't drift apart in silence.
    const BROKER_PREFIX: &str = "cloudflare-sts-broker:127.0.0.1.ec92f4d1:";
    const BROKER_TOKEN_NAME: &str = "cloudflare-sts-broker:127.0.0.1.ec92f4d1:1700000000";

    /// Clears everything the broker remembers between turns.
    fn clear_rotation_state() {
        set_rotation_state(&json!({}));
        set_creating(&json!(null));
    }

    /// Fires the cron, as Cloudflare would.
    async fn cron() {
        let res = call(Method::GET, "/__scheduled?cron=17+*+*+*+*").await;
        assert_eq!(res.status, 200, "{}", res.text);
    }

    /// Makes the broker's Cloudflare token `seconds` old.
    fn age_the_token(seconds: i64) {
        let mut world = world();
        let token = world
            .cloudflare
            .tokens
            .get_mut(CLOUDFLARE_TOKEN_ID)
            .expect("the broker's token");
        token.issued_on = Some(at(-seconds));
    }

    /// A token an earlier turn of the cron could have left behind.
    fn earlier_token(name: &str) -> String {
        world().cloudflare.add(None, name, None, None, "active").id
    }

    /// The tokens the broker has made for itself.
    fn broker_tokens() -> Vec<StoredToken> {
        world()
            .cloudflare
            .tokens
            .values()
            .filter(|t| t.name.starts_with(BROKER_PREFIX))
            .cloned()
            .collect()
    }

    /// The one token the broker has made for itself.
    #[track_caller]
    fn the_copy() -> StoredToken {
        match broker_tokens().as_slice() {
            [copy] => copy.clone(),
            made => panic!("exactly one copy should have been made: {made:?}"),
        }
    }

    fn has(token_id: &str) -> bool {
        world().cloudflare.tokens.contains_key(token_id)
    }

    #[tokio::test]
    async fn replaces_its_own_cloudflare_token_when_it_falls_due() {
        let t = start().await;
        clear_rotation_state();
        // The write doesn't reach the Worker until the test says so, which is
        // what it's like while Secrets Store propagates.
        world().cloudflare.propagate_secret = false;

        // Young enough: the cron leaves it alone, and makes no copy.
        cron().await;
        assert!(broker_tokens().is_empty());
        assert_eq!(
            world().cloudflare.secrets[SECRET_ID].value,
            CLOUDFLARE_TOKEN
        );

        // Due, but the policy's secret isn't in the store: it gives up before
        // it creates anything, so there's nothing left over.
        age_the_token(MONTH);
        world().cloudflare.secrets.clear();
        cron().await;
        let failed = t.audit("rotation.failed").await.expect("a rotation.failed");
        assert!(
            failed["message"]
                .as_str()
                .is_some_and(|m| m.contains("no secret called cloudflare-token")),
            "{failed}"
        );
        assert!(
            broker_tokens().is_empty(),
            "nothing should be created before the secret is found"
        );

        // Due, the secret is there, but Secrets Store refuses the write and
        // says so: the secret holds what it held, so the copy is deleted again
        // and the broker is left as it was. This is the path an in-place roll
        // couldn't come back from.
        {
            let mut world = world();
            *world = World::new();
            world.cloudflare.propagate_secret = false;
            world.cloudflare.secret_patch = SecretPatch::Refused;
        }
        age_the_token(MONTH);
        cron().await;
        assert!(
            t.audits("rotation.failed")
                .await
                .iter()
                .any(|line| line["message"]
                    .as_str()
                    .is_some_and(|m| m.contains("secrets.patch"))),
            "{}",
            t.log()
        );
        assert!(
            broker_tokens().is_empty(),
            "a copy that couldn't be written should be deleted again: {:?}",
            broker_tokens()
        );
        assert!(
            has(CLOUDFLARE_TOKEN_ID),
            "the token it was replacing should be untouched"
        );

        // Due, and everything works: a copy of the token, with its policies,
        // goes into the secret the binding reads.
        {
            let mut world = world();
            *world = World::new();
            world.cloudflare.propagate_secret = false;
            world
                .cloudflare
                .tokens
                .get_mut(CLOUDFLARE_TOKEN_ID)
                .expect("the broker's token")
                .policies = json!([{
                "effect": "allow",
                "permission_groups": [{ "id": "pg-workers-scripts-write" }],
                "resources": { "com.cloudflare.api.account.0123456789abcdef0123456789abcdef": "*" },
            }]);
        }
        age_the_token(MONTH);
        cron().await;

        let swapped = t
            .audit("rotation.swapped")
            .await
            .expect("a rotation.swapped");
        assert_eq!(swapped["old_token_id"], CLOUDFLARE_TOKEN_ID);
        let copy = the_copy();
        assert_eq!(swapped["new_token_id"], copy.id);
        {
            let world = world();
            assert_eq!(
                copy.policies, world.cloudflare.tokens[CLOUDFLARE_TOKEN_ID].policies,
                "the copy should carry the same policies"
            );
            let secret = &world.cloudflare.secrets[SECRET_ID];
            assert_eq!(secret.value, copy.value, "the copy should be in the secret");
            assert_eq!(
                secret.scopes,
                json!(["workers"]),
                "the scopes should survive the write, or the binding would stop reading it"
            );
            assert_eq!(
                secret.comment.as_deref(),
                Some("the broker's Cloudflare token"),
                "the comment should survive the write"
            );
        }
        assert!(
            has(CLOUDFLARE_TOKEN_ID),
            "the replaced token should outlive the swap by its overlap"
        );

        // Nothing is retiring yet, and the record still names the copy. Both
        // matter: the window can't start until the Worker stops reading the
        // replaced token, and a record that forgot the copy would let the
        // sweep delete the very token Secrets Store now holds.
        let state = rotation_state();
        assert!(
            state["retiring"].is_null(),
            "nothing drains until the handover: {state}"
        );
        assert_eq!(state["pending"]["new_token_id"], copy.id, "{state}");
        assert_eq!(
            state["pending"]["old_token_id"], CLOUDFLARE_TOKEN_ID,
            "{state}"
        );
        assert_eq!(
            state["pending"]["attempt"], "taken",
            "a write that was taken is what tells a slow handover from a lost one: {state}"
        );

        // The write hasn't reached the Worker yet, so the next turn finds the
        // token it replaced is still the one in use. It deletes nothing, and
        // doesn't start another swap.
        cron().await;
        assert_eq!(the_copy().id, copy.id, "no second copy");
        assert!(
            has(CLOUDFLARE_TOKEN_ID),
            "the token the binding still hands over must never be deleted"
        );

        // Now it has. The copy is what the broker authenticates as, and the one
        // it replaced waits out the rest of its overlap.
        world().cloudflare.bound_value = copy.value.clone();
        cron().await;
        assert_eq!(the_copy().id, copy.id, "still no second copy");
        assert!(
            has(CLOUDFLARE_TOKEN_ID),
            "the replaced token should wait out its whole overlap"
        );
        // Now that the handover has been seen, the record moves on and the
        // window runs — for longer than the overlap, because a request that
        // was already holding the replaced token can still mint with it just
        // after the handover is seen.
        let state = rotation_state();
        assert!(
            state["retiring"][0]["delete_after"]
                .as_i64()
                .is_some_and(|at| at - now() as i64 > 2 * HOUR),
            "the drain should outlast the 2h overlap this policy sets: {state}"
        );
        assert!(state["pending"].is_null(), "the swap is done: {state}");
        assert_eq!(
            state["retiring"][0]["token_id"], CLOUDFLARE_TOKEN_ID,
            "{state}"
        );
        assert!(
            state["retiring"][0]["delete_after"]
                .as_i64()
                .is_some_and(|at| at > now() as i64),
            "the drain window should start at the handover: {state}"
        );
        assert!(
            t.audits("rotation.retired").await.is_empty(),
            "nothing is retired before its overlap runs out"
        );

        // Its overlap is two hours out. Bring it forward rather than wait, and
        // the next turn deletes it: the swap is finished, on the state the
        // broker wrote for itself.
        set_rotation_state(&json!({
            "retiring": [{ "token_id": CLOUDFLARE_TOKEN_ID, "delete_after": now() as i64 - 1 }],
        }));
        cron().await;
        let retired = t
            .audit("rotation.retired")
            .await
            .expect("a rotation.retired");
        assert_eq!(retired["token_id"], CLOUDFLARE_TOKEN_ID);
        assert!(
            !has(CLOUDFLARE_TOKEN_ID),
            "the replaced token should be deleted once its overlap has run out"
        );
        assert!(has(&copy.id), "the copy that replaced it stays");
    }

    /// The one deletion that would take the broker down with it: the token the
    /// binding still hands over. However overdue, it stays.
    #[tokio::test]
    async fn never_deletes_the_token_the_binding_still_hands_over() {
        let t = start().await;
        // Overdue by an overlap and more, and still what the Worker reads,
        // which is what a `rotation.secret` naming the wrong secret looks like.
        set_rotation_state(&json!({
            "retiring": [{
                "token_id": CLOUDFLARE_TOKEN_ID,
                "delete_after": now() as i64 - 3 * HOUR,
            }],
        }));

        cron().await;

        assert!(
            has(CLOUDFLARE_TOKEN_ID),
            "the bound token must never be deleted, however overdue"
        );
        assert!(
            t.audits("rotation.retired").await.is_empty(),
            "nothing should have been retired"
        );

        // And it says which secret to go and look at.
        let waiting = t
            .audit("rotation.waiting")
            .await
            .expect("a rotation.waiting");
        assert_eq!(waiting["token_id"], CLOUDFLARE_TOKEN_ID);
        assert!(
            waiting["message"]
                .as_str()
                .is_some_and(|m| m.contains("rotation.secret")),
            "it should say where to look: {waiting}"
        );
        // Jammed, not rolling on: a swap that hasn't settled starts no other.
        assert!(broker_tokens().is_empty(), "{:?}", broker_tokens());
    }

    /// A turn that died between writing the secret and recording that it had.
    /// The next turn sees the binding hands over the copy, and finishes the job.
    #[tokio::test]
    async fn finishes_a_swap_a_previous_turn_left_in_the_middle() {
        let t = start().await;
        let previous = earlier_token("the hand-made token");
        set_rotation_state(&json!({
            "pending": {
                "new_token_id": CLOUDFLARE_TOKEN_ID,
                "old_token_id": previous,
                "at": now() as i64 - 600,
            },
        }));

        cron().await;

        let line = t
            .audit("rotation.handover")
            .await
            .expect("a rotation.handover");
        assert_eq!(line["new_token_id"], CLOUDFLARE_TOKEN_ID);
        assert_eq!(line["old_token_id"], previous);
        assert!(
            has(&previous),
            "the token it replaced starts its overlap now, it isn't deleted on the spot"
        );

        // Settled into a retirement, so the turn stops there rather than
        // stacking another swap on top of it.
        age_the_token(MONTH);
        cron().await;
        assert!(
            t.audits("rotation.swapped").await.is_empty(),
            "a token still retiring should hold off the next swap"
        );
    }

    /// A write whose answer is lost may still have applied. Discarding the
    /// copy on the strength of a failure would then leave the secret holding a
    /// token that no longer exists, and take the broker down as it propagated.
    #[tokio::test]
    async fn keeps_both_tokens_when_it_cant_tell_whether_the_write_applied() {
        let t = start().await;
        clear_rotation_state();
        {
            let mut world = world();
            // It applies, and then the answer goes missing: the worst case,
            // and the one a caller that treats every failure as a refusal
            // gets wrong.
            world.cloudflare.secret_patch = SecretPatch::AppliedThenLost;
            world.cloudflare.propagate_secret = false;
        }
        age_the_token(MONTH);

        cron().await;

        let failed = t.audit("rotation.failed").await.expect("a rotation.failed");
        assert!(
            failed["message"]
                .as_str()
                .is_some_and(|m| m.contains("whether it applied isn't known")),
            "it should say the outcome is unknown: {failed}"
        );
        let copy = the_copy();
        assert!(
            has(&copy.id),
            "the copy must survive a write that may have applied"
        );
        assert!(
            has(CLOUDFLARE_TOKEN_ID),
            "and so must the token it replaces"
        );
        assert_eq!(
            world().cloudflare.secrets[SECRET_ID].value,
            copy.value,
            "the write had in fact applied"
        );

        // Once the Worker picks the copy up, the next turn sees the swap did
        // land after all and finishes it, with no one having had to intervene.
        world().cloudflare.bound_value = copy.value.clone();
        cron().await;
        let line = t
            .audit("rotation.handover")
            .await
            .expect("a rotation.handover");
        assert_eq!(line["old_token_id"], CLOUDFLARE_TOKEN_ID);
        assert!(has(&copy.id) && has(CLOUDFLARE_TOKEN_ID));
    }

    /// A swap whose write didn't take leaves the old token bound. Saying
    /// "delete the other" there would be advice to delete the token in use.
    #[tokio::test]
    async fn says_the_write_hasnt_taken_while_the_replaced_token_is_still_bound() {
        let t = start().await;
        let copy = earlier_token(BROKER_TOKEN_NAME);
        set_rotation_state(&json!({
            "pending": {
                "new_token_id": copy,
                "old_token_id": CLOUDFLARE_TOKEN_ID,
                "at": now() as i64 - 600,
            },
        }));

        cron().await;

        let line = t
            .audit("rotation.unsettled")
            .await
            .expect("a rotation.unsettled");
        assert_eq!(line["bound_token_id"], CLOUDFLARE_TOKEN_ID);
        let said = line["message"].as_str().unwrap_or_default();
        assert!(
            said.contains("Don't delete the replaced token"),
            "it must not advise deleting the token in use: {said}"
        );
        assert!(
            t.audits("rotation.stuck").await.is_empty(),
            "the two cases are told apart: this one knows which token is bound"
        );
        assert!(has(&copy) && has(CLOUDFLARE_TOKEN_ID), "nothing is deleted");
    }

    /// A copy whose record didn't survive is still findable: the broker names
    /// its own tokens, so it can recognise one nothing accounts for.
    #[tokio::test]
    async fn gives_an_unaccounted_copy_a_window_before_deleting_it() {
        let t = start().await;
        // Not `clear_rotation_state`: this sets the intent below, and clearing
        // it first would be two writes to that key in a breath, which Workers
        // KV is entitled to refuse — the same limit the broker works around.
        set_rotation_state(&json!({}));
        let orphan = earlier_token(BROKER_TOKEN_NAME);
        let foreign = earlier_token("someone else's token");
        // Older than an overlap, so its age alone says nothing about when it
        // stopped being used.
        for id in [&orphan, &foreign] {
            world().cloudflare.tokens.get_mut(id).unwrap().issued_on = Some(at(-3 * HOUR));
        }
        // Something for the sweep to answer, so it looks at all.
        set_creating(&json!({
            "name": "cloudflare-sts-broker:127.0.0.1.ec92f4d1:1600000000",
            "at": now() as i64 - 3 * HOUR,
        }));

        cron().await;

        // Not deleted: an operator may have put another token in the secret by
        // hand a moment ago, and its age says when it was made, not when it
        // stopped being read.
        let adopted = t
            .audit("rotation.adopted")
            .await
            .expect("a rotation.adopted");
        assert_eq!(adopted["token_id"], orphan);
        assert!(has(&orphan), "it drains before it goes");
        let state = rotation_state();
        assert_eq!(state["retiring"][0]["token_id"], orphan, "{state}");
        assert!(
            state["retiring"][0]["delete_after"]
                .as_i64()
                .is_some_and(|at| at - now() as i64 > 2 * HOUR),
            "on a fresh window, not its age: {state}"
        );
        assert!(
            has(&foreign),
            "a token the broker didn't name for itself is never touched"
        );
        assert!(
            has(CLOUDFLARE_TOKEN_ID),
            "nor is the one the binding hands over"
        );
    }

    /// A `2xx` whose body can't be read is not Cloudflare saying no. Treating
    /// it as a refusal would discard the copy the secret may already hold.
    #[tokio::test]
    async fn keeps_the_copy_when_a_write_answers_with_something_unreadable() {
        let t = start().await;
        clear_rotation_state();
        {
            let mut world = world();
            world.cloudflare.secret_patch = SecretPatch::AppliedThenUnreadable;
            world.cloudflare.propagate_secret = false;
        }
        age_the_token(MONTH);

        cron().await;

        let copy = the_copy();
        assert!(
            has(&copy.id),
            "an unreadable answer says nothing, so the copy stays"
        );
        assert_eq!(
            world().cloudflare.secrets[SECRET_ID].value,
            copy.value,
            "the write had in fact applied"
        );
        let failed = t.audit("rotation.failed").await.expect("a rotation.failed");
        assert!(
            failed["message"]
                .as_str()
                .is_some_and(|m| m.contains("whether it applied isn't known")),
            "{failed}"
        );

        // And it finishes once the binding catches up.
        world().cloudflare.bound_value = copy.value.clone();
        cron().await;
        t.audit("rotation.handover").await.expect("a handover");
    }

    /// The lead before an expiry has to fit another turn of the cron and the
    /// swap's own calls, not just the drain. An overlap at its 1h floor is
    /// exactly the cron period, so a token expiring just past it would get
    /// seconds to be replaced in.
    #[tokio::test]
    async fn replaces_an_expiring_token_a_whole_cron_turn_before_it_lapses() {
        let t = start().await;
        clear_rotation_state();
        {
            let mut world = world();
            world.cloudflare.propagate_secret = false;
            let token = world
                .cloudflare
                .tokens
                .get_mut(CLOUDFLARE_TOKEN_ID)
                .expect("the broker's token");
            // Young, and past the 2h overlap this policy sets, but not past
            // an overlap plus another turn of the cron.
            token.issued_on = Some(at(-60));
            token.expires_on = Some(at(2 * HOUR + 30 * 60));
        }

        cron().await;

        let swapped = t
            .audit("rotation.swapped")
            .await
            .expect("a rotation.swapped");
        assert_eq!(swapped["expiring"], true, "{swapped}");
    }

    /// A swap whose write was refused keeps its record until the copy is
    /// really gone. A discard that fails would otherwise leave a token with
    /// the broker's own permissions and nothing that knew of it.
    #[tokio::test]
    async fn keeps_the_record_of_a_refused_swap_until_its_copy_is_gone() {
        let t = start().await;
        let copy = earlier_token(BROKER_TOKEN_NAME);
        set_rotation_state(&json!({
            "pending": {
                "new_token_id": copy,
                "old_token_id": CLOUDFLARE_TOKEN_ID,
                "at": now() as i64 - 600,
                "attempt": "unused",
            },
        }));

        cron().await;

        // The secret is as it was, so the copy is in no one's hands: the turn
        // deletes it and clears the record, rather than reporting a jam.
        assert!(!has(&copy), "the copy should be discarded");
        t.audit("rotation.voided").await.expect("a rotation.voided");
        assert!(
            t.audits("rotation.unsettled").await.is_empty(),
            "a swap whose write never took isn't unsettled"
        );
        assert_eq!(rotation_state(), json!({}), "the record should be cleared");
    }

    /// The rotation goes before the cleanup. The cleanup lists every token and
    /// deletes each expired one, so a backlog can spend the invocation's
    /// subrequests; an hour of expired tokens lying about costs nothing beside
    /// a provisioning token left to expire with nothing able to replace it.
    #[tokio::test]
    async fn rolls_its_own_token_before_clearing_up_after_the_others() {
        let t = start().await;
        clear_rotation_state();
        world().cloudflare.propagate_secret = false;
        // Something for the cleanup to find, so both halves have work.
        world().cloudflare.add(
            None,
            "cloudflare-sts:github:1",
            None,
            Some(at(-60)),
            "expired",
        );
        age_the_token(MONTH);

        cron().await;

        let rotated = t
            .audit_order("rotation.swapped")
            .await
            .expect("a rotation.swapped");
        let cleaned = t.audit_order("cleanup.done").await.expect("a cleanup.done");
        assert!(
            rotated < cleaned,
            "the rotation should run first: rotation at {rotated}, cleanup at {cleaned}"
        );
    }

    /// A copy whose create went unanswered is found by the name the broker
    /// wrote down, even once its own hostname has changed: that name is the
    /// broker's own record, so it's proof enough of whose the token is.
    #[tokio::test]
    async fn sweeps_a_copy_its_intent_names_whatever_the_prefix_says_now() {
        let t = start().await;
        set_rotation_state(&json!({}));
        // Named for a host this broker no longer answers on, and with no age
        // for Cloudflare to report: unreachable by either of the sweep's other
        // two ways in.
        let orphan = earlier_token("cloudflare-sts-broker:was.example.com.00000000:1700000000");
        world()
            .cloudflare
            .tokens
            .get_mut(&orphan)
            .unwrap()
            .issued_on = None;
        set_creating(&json!({
            "name": "cloudflare-sts-broker:was.example.com.00000000:1700000000",
            "at": now() as i64 - 3 * HOUR,
        }));

        cron().await;

        let swept = t.audit("rotation.swept").await.expect("a rotation.swept");
        assert_eq!(swept["token_id"], orphan);
        assert!(
            !has(&orphan),
            "the copy its intent names should be collected"
        );
        assert_eq!(creating_state(), json!(null), "and the intent cleared");
    }

    /// An intent is cleared once it's been answered, not once it's been around
    /// a while: a sweep that couldn't delete the copy has to leave the only
    /// record of it behind.
    #[tokio::test]
    async fn keeps_an_intent_whose_copy_it_couldnt_delete() {
        let t = start().await;
        set_rotation_state(&json!({}));
        let orphan = earlier_token(BROKER_TOKEN_NAME);
        {
            let mut world = world();
            world.cloudflare.tokens.get_mut(&orphan).unwrap().issued_on = None;
            world.cloudflare.fail_token_delete = true;
        }
        set_creating(&json!({ "name": BROKER_TOKEN_NAME, "at": now() as i64 - 3 * HOUR }));
        // Due as well, so a swap would be attempted — and would write its own
        // name over the intent, losing the only way back to this copy.
        age_the_token(MONTH);

        cron().await;

        assert!(
            has(&orphan),
            "the delete failed, so the copy is still there"
        );
        assert_eq!(
            creating_state()["name"],
            BROKER_TOKEN_NAME,
            "the intent naming it must not be cleared on a delete that failed"
        );
        assert!(
            t.audits("rotation.swapped").await.is_empty(),
            "an unanswered intent must hold off a swap: its name is the only way back to the copy"
        );
        assert!(
            broker_tokens().iter().all(|token| token.id == orphan),
            "and so no second copy: {:?}",
            broker_tokens()
        );

        // Once deleting works again, a later turn collects it.
        world().cloudflare.fail_token_delete = false;
        cron().await;
        t.audit("rotation.swept").await.expect("a rotation.swept");
        assert!(!has(&orphan));
        assert_eq!(creating_state(), json!(null), "and the intent is cleared");
    }

    /// A record written before the write must not claim the secret is
    /// untouched: a turn that stops mid-write would leave a later one deleting
    /// a copy the secret may by then be holding.
    #[tokio::test]
    async fn records_a_write_it_hasnt_answered_for_as_unknown() {
        let t = start().await;
        clear_rotation_state();
        {
            let mut world = world();
            world.cloudflare.propagate_secret = false;
            // The write never comes back, so the record is whatever was put
            // there before it.
            world.cloudflare.secret_patch = SecretPatch::AppliedThenLost;
        }
        age_the_token(MONTH);

        cron().await;

        t.audit("rotation.failed").await.expect("a rotation.failed");
        let state = rotation_state();
        assert_eq!(
            state["pending"]["attempt"], "uncertain",
            "a write with no answer must leave a record that doesn't claim to know: {state}"
        );
        assert!(has(&the_copy().id), "and the copy stays");
    }

    /// A refused write whose copy can't be deleted must leave the record of
    /// the copy behind. Clearing it would leave a token with the broker's own
    /// permissions and nothing anywhere that knew of it.
    #[tokio::test]
    async fn keeps_the_record_when_the_copy_it_gave_up_on_cant_be_deleted() {
        let t = start().await;
        clear_rotation_state();
        {
            let mut world = world();
            world.cloudflare.propagate_secret = false;
            world.cloudflare.secret_patch = SecretPatch::Refused;
            world.cloudflare.fail_token_delete = true;
        }
        age_the_token(MONTH);

        cron().await;

        let copy = the_copy();
        assert!(
            has(&copy.id),
            "the discard failed, so the copy is still there"
        );
        let state = rotation_state();
        assert_eq!(
            state["pending"]["new_token_id"], copy.id,
            "the record must outlive a discard that failed: {state}"
        );
        assert_eq!(state["pending"]["attempt"], "unused", "{state}");

        // A later turn retries the discard. While deleting still fails, the
        // record has to survive that too: a turn that cleared it on a delete
        // it hadn't managed would lose the copy all over again.
        age_the_token(0);
        cron().await;
        assert!(has(&copy.id), "still there, still failing to delete");
        let state = rotation_state();
        assert_eq!(
            state["pending"]["new_token_id"], copy.id,
            "a retry that failed must not clear the record either: {state}"
        );

        // Once deleting works again, the next turn finishes the job without
        // anyone having to go and look.
        world().cloudflare.fail_token_delete = false;
        age_the_token(0);
        cron().await;
        assert!(
            !has(&copy.id),
            "the copy should be discarded on a later turn"
        );
        t.audit("rotation.voided").await.expect("a rotation.voided");
        assert_eq!(rotation_state(), json!({}), "and the record cleared");
    }

    /// `attempt: taken` says the write went through, not that the secret still
    /// holds the copy. A third token in the binding means something happened
    /// that the broker didn't do, and it has to say so rather than wait.
    #[tokio::test]
    async fn stops_calling_it_propagation_when_a_third_token_is_bound() {
        let t = start().await;
        let copy = earlier_token(BROKER_TOKEN_NAME);
        let replaced = earlier_token("the token it was replacing");
        set_rotation_state(&json!({
            "pending": {
                "new_token_id": copy,
                "old_token_id": replaced,
                "at": now() as i64 - 600,
                "attempt": "taken",
            },
        }));

        cron().await;

        let stuck = t.audit("rotation.stuck").await.expect("a rotation.stuck");
        assert_eq!(stuck["bound_token_id"], CLOUDFLARE_TOKEN_ID, "{stuck}");
        assert!(
            t.audits("rotation.waiting").await.is_empty(),
            "a third token isn't a slow handover"
        );
        assert!(has(&copy) && has(&replaced), "nothing is deleted");
    }

    /// A secret that doesn't name its own scopes must not come back with an
    /// empty list written over it: that would say "no service may use this"
    /// about the secret the Worker reads.
    #[tokio::test]
    async fn leaves_the_scopes_alone_on_a_secret_that_doesnt_name_them() {
        let t = start().await;
        clear_rotation_state();
        {
            let mut world = world();
            world.cloudflare.propagate_secret = false;
            world.cloudflare.secrets.get_mut(SECRET_ID).unwrap().scopes = json!(null);
        }
        age_the_token(MONTH);

        cron().await;

        // It's still found: a shape the broker didn't expect is not a secret
        // that isn't there.
        let swapped = t
            .audit("rotation.swapped")
            .await
            .expect("a rotation.swapped");
        assert_eq!(swapped["secret"], SECRET_NAME);

        // Taken before the guard: `the_copy` locks the world too, and the lock
        // isn't reentrant.
        let copy = the_copy();
        let world = world();
        let secret = &world.cloudflare.secrets[SECRET_ID];
        assert_eq!(secret.value, copy.value, "the copy is in the secret");
        assert_eq!(
            secret.scopes,
            json!(null),
            "scopes it didn't come back with must be left unnamed, not emptied"
        );
        let patch = world
            .cloudflare
            .requests
            .iter()
            .rfind(|r| r.method == "PATCH")
            .expect("a patch");
        assert!(
            patch.body.as_ref().is_some_and(|b| b["scopes"].is_null()),
            "the patch should not name scopes at all: {:?}",
            patch.body
        );
    }

    /// Cloudflare needn't say when a token was issued. One whose expiry is
    /// known and close still has to be replaced, or the broker reaches the
    /// point where it can't authenticate to replace anything.
    #[tokio::test]
    async fn replaces_a_token_thats_expiring_even_when_its_age_is_unknown() {
        let t = start().await;
        clear_rotation_state();
        {
            let mut world = world();
            world.cloudflare.propagate_secret = false;
            let token = world
                .cloudflare
                .tokens
                .get_mut(CLOUDFLARE_TOKEN_ID)
                .expect("the broker's token");
            // Young by any reckoning, but Cloudflare doesn't say, and it runs
            // out inside the overlap.
            token.issued_on = None;
            token.expires_on = Some(at(HOUR));
        }

        cron().await;

        let swapped = t
            .audit("rotation.swapped")
            .await
            .expect("a rotation.swapped");
        assert_eq!(swapped["expiring"], true, "{swapped}");
        assert_eq!(swapped["old_token_id"], CLOUDFLARE_TOKEN_ID);
        assert!(
            t.audits("rotation.skipped").await.is_empty(),
            "an unknown age must not stop a known expiry being acted on"
        );
    }

    /// A handover slower than an overlap must not cost the broker the copy
    /// Secrets Store already holds. The record keeps naming it until the
    /// binding catches up, which is the only thing standing between the sweep
    /// and the live token.
    #[tokio::test]
    async fn never_sweeps_the_copy_while_the_binding_is_slow_to_hand_over() {
        let t = start().await;
        clear_rotation_state();
        world().cloudflare.propagate_secret = false;
        age_the_token(MONTH);

        cron().await;
        let copy = the_copy();
        t.audit("rotation.swapped").await.expect("a swap");

        // Older than an overlap and not the bound token: everything the sweep
        // looks for, except that the record accounts for it.
        world()
            .cloudflare
            .tokens
            .get_mut(&copy.id)
            .unwrap()
            .issued_on = Some(at(-3 * HOUR));
        // An intent goes in so the sweep actually runs, leaving the record as
        // the only thing standing between it and the copy.
        set_creating(&json!({
            "name": "cloudflare-sts-broker:127.0.0.1.ec92f4d1:1600000000",
            "at": now() as i64 - 3 * HOUR,
        }));
        cron().await;

        assert!(
            has(&copy.id),
            "the copy Secrets Store holds must never be swept, however slow the handover"
        );
        assert!(t.audits("rotation.swept").await.is_empty());
        let state = rotation_state();
        assert_eq!(
            state["pending"]["new_token_id"], copy.id,
            "the record is what keeps the sweep off it: {state}"
        );

        // And it still finishes once the binding catches up.
        world().cloudflare.bound_value = copy.value.clone();
        cron().await;
        t.audit("rotation.handover").await.expect("a handover");
    }

    /// A handover that never comes is a misconfigured `rotation.secret`, not a
    /// broker that should go on waiting silently.
    #[tokio::test]
    async fn says_so_when_a_taken_write_never_reaches_the_binding() {
        let t = start().await;
        let copy = earlier_token(BROKER_TOKEN_NAME);
        set_rotation_state(&json!({
            "pending": {
                "new_token_id": copy,
                "old_token_id": CLOUDFLARE_TOKEN_ID,
                "at": now() as i64 - 3 * HOUR,
                "attempt": "taken",
            },
        }));

        cron().await;

        let waiting = t
            .audit("rotation.waiting")
            .await
            .expect("a rotation.waiting");
        assert_eq!(waiting["new_token_id"], copy, "{waiting}");
        assert!(
            waiting["message"]
                .as_str()
                .is_some_and(|m| m.contains("rotation.secret")),
            "it should say where to look: {waiting}"
        );
        // A write that was taken isn't unsettled: the broker knows the secret
        // holds the copy, it's the binding that hasn't caught up.
        assert!(t.audits("rotation.unsettled").await.is_empty());
        assert!(has(&copy) && has(CLOUDFLARE_TOKEN_ID), "nothing is deleted");
    }

    /// Tokens are listed account-wide. A broker that swept on the bare prefix
    /// would delete another broker's live provisioning token and take it
    /// offline, so the name carries the host it was made by.
    #[tokio::test]
    async fn never_sweeps_another_brokers_token_in_the_same_account() {
        let t = start().await;
        clear_rotation_state();
        let theirs =
            earlier_token("cloudflare-sts-broker:other-sts.example.com.1234abcd:1700000000");
        let mine = earlier_token(BROKER_TOKEN_NAME);

        for id in [&theirs, &mine] {
            world().cloudflare.tokens.get_mut(id).unwrap().issued_on = Some(at(-3 * HOUR));
        }
        // The intent names this broker's own copy, so the sweep both runs and
        // deletes that one outright.
        set_creating(&json!({ "name": BROKER_TOKEN_NAME, "at": now() as i64 - 3 * HOUR }));

        cron().await;

        assert!(
            has(&theirs),
            "another broker's live token must never be swept"
        );
        assert!(!has(&mine), "its own orphan still is");

        let swept = t.audit("rotation.swept").await.expect("a rotation.swept");
        assert_eq!(swept["token_id"], mine);
        assert!(
            t.audits("rotation.adopted").await.is_empty(),
            "another broker's token isn't taken over either"
        );
    }

    /// A token still draining is accounted for, so the sweep leaves it even
    /// though it's older than an overlap and isn't the bound one. Deleting it
    /// early would cut short the R2 credentials it fathered, which is the one
    /// thing the drain window exists to prevent.
    #[tokio::test]
    async fn never_sweeps_a_token_thats_still_draining() {
        let t = start().await;
        let draining = earlier_token(BROKER_TOKEN_NAME);
        world()
            .cloudflare
            .tokens
            .get_mut(&draining)
            .unwrap()
            .issued_on = Some(at(-3 * HOUR));
        set_rotation_state(&json!({
            "retiring": [{ "token_id": draining, "delete_after": now() as i64 + HOUR }],
        }));
        // An intent outstanding, so the sweep runs and its guards are the only
        // thing keeping it off the draining token.
        set_creating(&json!({
            "name": "cloudflare-sts-broker:127.0.0.1.ec92f4d1:1600000000",
            "at": now() as i64 - 3 * HOUR,
        }));

        cron().await;

        assert!(
            has(&draining),
            "a token still inside its drain window must not be swept away"
        );
        assert!(t.audits("rotation.swept").await.is_empty());
        assert!(t.audits("rotation.retired").await.is_empty());
    }

    /// A rollback whose record of itself didn't survive — Workers KV takes one
    /// write per key per second, so the write that was to clear it can be
    /// refused. Asking Cloudflare what still exists is what gets the broker
    /// going again without a person.
    #[tokio::test]
    async fn clears_a_swap_whose_copy_no_longer_exists() {
        let t = start().await;
        set_rotation_state(&json!({
            "pending": {
                "new_token_id": "tok-deleted-copy",
                "old_token_id": CLOUDFLARE_TOKEN_ID,
                "at": now() as i64 - 600,
            },
        }));

        cron().await;

        let line = t.audit("rotation.voided").await.expect("a rotation.voided");
        assert!(
            line["message"]
                .as_str()
                .is_some_and(|m| m.contains("never took")),
            "{line}"
        );
        assert!(
            t.audits("rotation.unsettled").await.is_empty(),
            "a swap whose copy is gone isn't unsettled, it's void"
        );
        assert_eq!(rotation_state(), json!({}), "the record should be cleared");

        // And it isn't jammed: the next turn is free to roll again.
        age_the_token(MONTH);
        cron().await;
        t.audit("rotation.swapped")
            .await
            .expect("a rotation.swapped");
    }

    /// A turn died mid-swap and the binding hands over neither token, so which
    /// of the two Secrets Store holds can't be told from here. Deleting the
    /// wrong one would brick the broker, so it deletes neither and says so.
    #[tokio::test]
    async fn changes_nothing_when_it_cant_tell_which_token_a_swap_left_bound() {
        let t = start().await;
        let copy = earlier_token(BROKER_TOKEN_NAME);
        let old = earlier_token("the hand-made token");
        set_rotation_state(&json!({
            "pending": { "new_token_id": copy, "old_token_id": old, "at": now() as i64 - 600 },
        }));

        cron().await;

        let stuck = t.audit("rotation.stuck").await.expect("a rotation.stuck");
        assert_eq!(stuck["new_token_id"], copy);
        assert_eq!(stuck["old_token_id"], old);
        assert_eq!(
            stuck["bound_token_id"], CLOUDFLARE_TOKEN_ID,
            "it should say which token the binding does hand over"
        );
        assert!(
            stuck["message"]
                .as_str()
                .is_some_and(|m| m.contains("delete the other")),
            "it should say what to do: {stuck}"
        );
        assert!(has(&copy) && has(&old), "neither token should be deleted");

        // And there it stays: due or not, nothing else happens until a person
        // clears the key.
        age_the_token(MONTH);
        cron().await;
        assert!(
            t.audits("rotation.swapped").await.is_empty(),
            "a swap it can't account for should hold off the next"
        );
    }
}
