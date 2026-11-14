# cloudflare-sts-api

> The broker, the Worker half of [cloudflare-sts](../..), in Rust: verifies an
> OIDC token from an issuer you trust (GitHub Actions, GitLab CI, Cloudflare
> Access, …), checks it against your Cedar policy, and mints a short-lived
> Cloudflare API token with exactly that profile's permissions, R2 credentials
> limited to the caller's key prefix, or both. It knows no issuer by name: who
> may do what is in the Cedar policy.

[![CI](https://github.com/cf-contrib/cloudflare-sts/actions/workflows/ci.yml/badge.svg)](https://github.com/cf-contrib/cloudflare-sts/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)

> [!NOTE]
> **Pre-1.0.** The policy format and the API may still change between minor
> versions. Version 1 to 3 policies need [migrating](#migration-from-version-3).

```yaml
version: 3
issuer: https://cloudflare-sts-api.example.com    # the broker's URL

providers:
  - name: com.github.actions
    issuer: https://token.actions.githubusercontent.com
    audience: https://cloudflare-sts-api.example.com
    claims:
      - repository_owner_id: "100000001"     # your org's numeric ID, required of every token

profiles:
  - name: example-org/app:ci.deploy          # the deploy job in example-org/app's ci.yml
    claims:
      - repository_id: "200000003"           # example-org/app
        ref: refs/heads/main
        environment: prod
    ttl: 15m
    token:
      policies:
        - permissions: ["Workers Scripts Write"]
          resources:
            com.cloudflare.api.account.0123456789abcdef0123456789abcdef: "*"
```

A job in `example-org/app` (repo `200000003`), on `main`, in the `prod` environment, gets a 15-minute token that can deploy Workers in the account. Any other job is refused with `400` (`invalid_request`).

## Deploy

1. **Create the Cloudflare token.** In the Cloudflare dashboard, create an **account-owned** API token with **Account API Tokens Write**. If any profile has a [`bucket`](#buckets), also give it R2 permissions covering what the buckets delegate. It's the broker's only long-lived credential. This is the one manual step: automating it would need a token that can create tokens. Store it in [Secrets Store](https://developers.cloudflare.com/secrets-store/) so it never passes through your deploy tooling:
   ```sh
   wrangler secrets-store secret create <store-id> --name cloudflare-sts-cloudflare-token --scopes workers --remote
   ```
2. **Look up numeric IDs.** Pin IDs, not names, because a deleted repo or org name can be re-registered by someone else. For GitHub Actions:
   ```sh
   gh api orgs/<org> --jq .id           # the GitHub Actions provider's repository_owner_id
   gh api repos/<org>/<repo> --jq .id   # a profile's repository_id
   ```
3. **Deploy** the released Worker with the [Terraform module](../../deployment/terraform) (`//deployment/terraform?ref=<version>`). It downloads the release (optionally pinned to a checksum), stores your policy in a Workers KV namespace bound to it, and sets up the other bindings, the workers.dev URL (or an optional custom domain) and the cron. To deploy a build of your own, build it and point the module's `worker_dir` at it:
   ```sh
   worker-build --release   # then worker_dir = ".../crates/cloudflare-sts-api/build"
   ```
4. **Check** that `<url>/health/ready` returns `200` (`https://cloudflare-sts-api.<subdomain>.workers.dev`, or your custom domain): the policy was accepted and the secrets can be read. A `500` means the policy was rejected or a binding is wrong, and a `503` that a secret can't be read; the reasons are in Workers Logs.

## Bindings

| Binding | Type | Required | Description |
|---|---|---|---|
| `CLOUDFLARE_STS_API_ACCOUNT_ID` | plain text | yes | Account the Cloudflare token belongs to and tokens are minted in. |
| `CLOUDFLARE_STS_API_POLICY_KV` | Workers KV namespace | yes | Holds the [policy](#policy) under two keys: `config`, the TOML (or JSON), and `policy`, the Cedar. No size limit to speak of (a Worker variable held 5 KB). Each isolate keeps the policy it read for a minute. |
| `CLOUDFLARE_STS_API_CLOUDFLARE_TOKEN` | Secrets Store secret | yes | Account-owned token with Account API Tokens Write, plus R2 permissions covering what profiles' buckets delegate. Read on every request, so rotating the secret takes effect without a redeploy. Anything else, such as a plain `wrangler secret`, is refused with `500`. |
| `CLOUDFLARE_STS_API_SIGNING_KEY` | Secrets Store secret | for profiles with an `audience` | RSA private key (at least 2048 bits), as a PKCS#8 PEM, the broker signs [its own tokens](#tokens-for-other-services) with. Without it the broker issues none, publishes no keys, and those profiles fail closed with `500`. Bound as anything else, it's refused with `500`, as the Cloudflare token is. |

The hourly cron (`17 * * * *` in the examples) deletes expired `cloudflare-sts:*` tokens.

The Terraform module builds `config` from its `oidc_providers`, `profiles`
and `defaults` variables, takes `policy` from its `cedar_policy`, and writes
both to the KV namespace it binds. Under `wrangler dev`, they're the
integration tests' `tests/config.toml` and `tests/policy.cedar`, which
`tests/run.sh` puts in the local namespace. By hand:
`wrangler kv key put config --path config.toml --namespace-id <id>`, then
`policy` the same way.

**A policy change takes effect within about two minutes**, not at once: an isolate holds
the policy it read for 60 seconds, and KV's own edge cache can serve the previous
value for up to 60 more. That includes switching a profile off with
`enabled = false`, so for an incident revoke the Cloudflare token instead (see
[Buckets](#buckets)), which cuts off every credential within seconds. The policy
is no longer part of a Worker version: rolling the Worker back doesn't roll it
back.

It fails closed. Once an isolate's policy has expired, a KV read that fails, or a
policy that's missing or invalid, is a `500` on every request; the broker never
serves a policy it has held past its minute. The two keys are read one after the
other, so a change to both can briefly be seen half done. That fails closed too:
a profile with no permit, or a permit for one that's gone, is refused when the
policy loads, and the next read, a minute on, picks up both.

**Moving from a version that took `CLOUDFLARE_STS_API_POLICY`** (a version 3 policy; see [Migration](#migration-from-version-3)): upgrade the
Terraform module, which creates the namespace and writes the policy. A Worker
that still has the old variable is refused (`500`, with where it went in the log), so
a stale deployment is never mistaken for a working one.

The bindings are read on every request. An unset account, an unreadable or invalid policy, or a
Cloudflare token or signing key outside Secrets Store is a `500` on every route, the health
endpoints' too, with the first problem in a `misconfigured` log line, such as
`{"level":"ERROR","event":"misconfigured","message":"CLOUDFLARE_STS_API_POLICY_KV: provider com.github.actions has no policy admitting it: add a permit for Admit::Action::\\"com.github.actions\\" that pins your tenant"}`.

## Policy

The policy is two files, kept in the `config` and `policy` keys of the [KV namespace](#bindings): what the broker trusts and hands out, in TOML, and who gets it, in [Cedar](https://www.cedarpolicy.com).

`config.toml` (JSON works too, which is what the Terraform module writes):

```toml
version = 4
issuer  = "https://cloudflare-sts-api.example.com"   # REQUIRED: the broker's URL, as its own tokens name it: an origin, no trailing /

[defaults]
ttl     = "15m"   # default 15m
max_ttl = "1h"    # default 1h, at most 24h

[[providers]]
name     = "com.github.actions"                                # GitHub Actions
issuer   = "https://token.actions.githubusercontent.com"       # GitHub Enterprise Cloud: .../<enterprise>
audience = "https://cloudflare-sts-api.example.com"            # what the action asks GitHub for: the broker's URL

[[providers]]
name     = "com.gitlab"                                        # GitLab CI, with id_tokens: { aud: <the broker's URL> }
issuer   = "https://gitlab.com"
audience = "https://cloudflare-sts-api.example.com"

[[providers]]
name      = "com.cloudflare.access"                            # people, through an Access for SaaS OIDC application
issuer    = "https://example.cloudflareaccess.com/cdn-cgi/access/sso/oidc/<client-id>"
client_id = "<client-id>"                                      # people sign in as this client: see People

# What each profile hands out. Who gets it is in policy.cedar.
[[profiles]]
name     = "example-org/infra:ci.apply"        # the apply job in example-org/infra's ci.yml
provider = "com.github.actions"

[[profiles.token.policies]]
permissions = ["Zone Write", "Zone WAF Write", "DNS Write"]
resources   = { "com.cloudflare.api.account.zone.fedcba9876543210fedcba9876543210" = "*" }   # example.com

[[profiles]]
name     = "example-org:workers-deploy"        # any repo in the org: named for its purpose
provider = "com.github.actions"

[[profiles.token.policies]]
permissions = ["Workers Scripts Write"]
resources   = { "com.cloudflare.api.account.0123456789abcdef0123456789abcdef" = "*" }

[[profiles]]
name     = "group/app:deploy"                  # the deploy job in group/app's .gitlab-ci.yml
provider = "com.gitlab"
ttl      = "5m"                                # for everything the profile hands out

[[profiles.token.policies]]
effect      = "allow"                          # the default; "deny" carves out exceptions
permissions = ["Workers Scripts Write"]
resources   = { "com.cloudflare.api.account.0123456789abcdef0123456789abcdef" = "*" }

[[profiles]]
name     = "example-org:terraform-state"       # no token: only R2 credentials
provider = "com.github.actions"
bucket   = { name = "org-terraform-state", permission = "object-read-write", prefixes = ["{repository_owner_id}/{repository_id}/"] }

[[profiles]]
name     = "infra-admins:tofu-plan"            # for people, through Access
provider = "com.cloudflare.access"
max_ttl  = "1h"
bucket   = { name = "org-terraform-state", permission = "object-read-only" }
```

`policy.cedar`:

```cedar
// Every provider is admitted by a permit that pins your tenant, by ID. Without
// one the broker refuses to start: GitHub gives anyone's repos a token.
@id("admit-github")
permit (principal, action == Admit::Action::"com.github.actions", resource)
when { context.repository_owner_id == "100000001" };               // your org's numeric ID

@id("admit-gitlab")
permit (principal, action == Admit::Action::"com.gitlab", resource)
when { context.namespace_id == "4000001" };                        // your group's ID

@id("admit-access")
permit (principal, action == Admit::Action::"com.cloudflare.access", resource)
when { context.iss == "https://example.cloudflareaccess.com/cdn-cgi/access/sso/oidc/<client-id>" };   // the app is the pin

// A forbid beats every permit: written once, it holds for every profile.
@id("no-pull-request-target")
forbid (principal, action, resource)
when { context has event_name && context.event_name == "pull_request_target" };

@id("apply-from-main")
permit (principal, action == Profile::Action::"example-org/infra:ci.apply", resource)
when {
  context.repository_id == "200000002" &&                         // example-org/infra
  context.ref == "refs/heads/main" &&
  context.environment == "prod"                                   // pair with required reviewers on the environment
};

@id("workers-deploy")
permit (principal, action == Profile::Action::"example-org:workers-deploy", resource)
when {
  context.repository like "example-org/*" &&                      // a * may go anywhere in a like pattern
  context has environment && context.environment == "prod" &&
  (context.ref == "refs/heads/main" || context.ref like "refs/heads/release/*")
};

@id("gitlab-deploy")
permit (principal, action == Profile::Action::"group/app:deploy", resource)
when { context.project_path == "group/app" && context.ref_protected == "true" };

@id("state-from-main")
permit (principal, action == Profile::Action::"example-org:terraform-state", resource)
when { context.ref == "refs/heads/main" };

@id("infra-admins")
permit (principal, action == Profile::Action::"infra-admins:tofu-plan", resource)
when { ["alice@example.com", "bob@example.com"].contains(context.email) };
```

A profile has a `token`, a `bucket`, or both, for callers with a token from its `provider`. A profile with an `audience` instead issues the broker's own token for that service: see [Tokens for other services](#tokens-for-other-services).

To switch a profile off, for example during an incident, set `enabled = false`. It stays in the policy but never matches, and a request naming it is refused (`invalid_request`). Remember [how long a change takes](#bindings).

The broker checks the policy on every load. If it's invalid, the broker fails closed and every request gets `500`. Unknown fields are refused too, so a misspelt one is never silently ignored.

### Providers

A provider is an OIDC issuer you trust to vouch for a caller. `providers` is a list, like `profiles`:

| Field | |
|---|---|
| `name` | Required, unique. Profiles name it in `provider`, and the Cedar policy in `Admit::Action::"<name>"`. |
| `issuer` | Required. The tokens' `iss`, exactly. `https://`, or plain `http://` on `127.0.0.1`, `localhost` or `[::1]` for local development. One provider per issuer. |
| `audience` | Required, unless there's a `client_id`. The tokens' `aud` must contain it. Use one only the broker accepts, such as its URL: for GitHub Actions, not GitHub's default `https://github.com/<owner>`, so a token requested for AWS or GCP can't be replayed here. |
| `jwks_uri` | Optional. Otherwise the keys come from the issuer's metadata: its `/.well-known/openid-configuration`, or, if it has none, its RFC 8414 `/.well-known/oauth-authorization-server`, which must name the same issuer. They never come from a URL in the token. |
| `typ` | Optional. The `typ` its tokens must have ([RFC 8725 §3.11](https://www.rfc-editor.org/rfc/rfc8725#section-3.11)), such as `at+jwt` to take only another broker's access tokens, so another kind of token its issuer signs can't pass for one. Unset takes any. |
| `client_id` | Optional. The OAuth client [people](#people) sign in to it as, for an ID token the broker takes: a provider with one is listed in the metadata. It's also the `audience`, which can then be left out. |

`audience` is a field, not a claim, because it says whether the token is meant for the broker at all: it's checked with the signature, `iss` and expiry, before the Cedar policy sees the token. Either failing is `400` (`invalid_request`), as RFC 8693 has it for a subject token that's invalid or that the policy doesn't take.

**Pin the tenant.** GitHub Actions, gitlab.com and HCP Terraform issue tokens to anyone's projects, and the broker URL is public. Every provider needs a `permit` for its `Admit` action that pins yours, by ID: `repository_owner_id` for GitHub Actions, `namespace_id` or `project_id` for gitlab.com, `terraform_organization_id` for HCP Terraform. The broker refuses a provider with none, but it can't tell which claims pin a tenant: that's yours to get right.

A profile's `provider` can be left out when the policy has exactly one provider. Tokens are RS256.

### The Cedar policy

A caller's token is checked in two steps, each a request to Cedar, which denies unless a `permit` matches and no `forbid` does:

1. **Admit**, once the token is verified: action `Admit::Action::"<provider>"`. This is where the tenant is pinned. A token that fails is `invalid_request`, "the policy doesn't admit the token".
2. **Profile**, for the profiles it gets: action `Profile::Action::"<name>"`. If the request names `scope`s, every one must be allowed, or the request is `invalid_scope` and nothing is issued. Otherwise exactly one profile of the provider and audience must be, or the request is `invalid_request`. The description says which.

Cedar wants an action's type to end in `Action`, hence the namespaces. The request is:

| | |
|---|---|
| `principal` | `Caller::"<sub>"`, the token's subject. |
| `action` | `Admit::Action::"<provider>"` or `Profile::Action::"<profile>"`. |
| `resource` | `Audience::"<audience>"`, what the profile issues for: `https://api.cloudflare.com` for Cloudflare credentials. |
| `context` | The token's claims, each a string, or a set of strings if it's a list in the token (`groups`, `amr`). Numbers and booleans are strings as JSON writes them, so an ID is `"100000001"` whether the issuer quoted it or not: always compare with strings. Claims that are objects aren't in it. Reach a claim with a name Cedar can't write, such as a URL, with `context["https://example.com/claim"]`. |

- **A claim the token doesn't have** errors where it's read, and an error makes that policy not match: a `permit` never allows because of it, but a `forbid` doesn't deny either. Guard with `context has claim && ...` where a claim is optional, and in any `forbid`.
- **Patterns:** `==` is exact. `like` takes a `*` anywhere in a string, matching anything, including across `/`. Keep ID claims (`*_id`) to `==`.
- **Every policy has an `@id`**, unique, and the audit log names the policies that decided a request (`policy`) instead of a position that changes when someone adds one above.
- **A `permit` names its actions**, as `Admit::Action::"<provider>"` or `Profile::Action::"<name>"`, so none lets everything in. A `forbid` may leave them open, to hold for all.
- **Names are checked against the configuration.** A policy naming a provider or profile that doesn't exist is an error, not a silent deny, and so is a provider or an enabled profile that nothing permits.
- **Nothing here changes what a profile hands out.** Cedar decides who; the TOML decides what. A profile's `forward_claims` says which of the caller's claims a token for [another service](#tokens-for-other-services) carries, and which the audit log shows.

### People

The broker takes OIDC tokens only. For people, use an identity provider that issues them an ID token, such as a [Cloudflare Access for SaaS](https://developers.cloudflare.com/cloudflare-one/applications/configure-apps/saas-apps/generic-oidc-saas/) OIDC application, as a public client with PKCE and the redirect `http://127.0.0.1:8250/callback`. A provider for it is like any other, and its profiles match on its tokens' claims, such as `email`. terraform-cloudflare-access's [`saas-oidc`](https://github.com/tf-contrib/terraform-cloudflare-access/tree/main/modules/saas-oidc) module creates the application and its policy, and the [Terraform module's README](../../deployment/terraform#people) shows the provider to give the broker.

Give that provider the `client_id` people sign in as, and the broker's [metadata](#http-api) lists it in `identity_providers`, with its name and issuer. An ID token's `aud` is the client it was issued to, so the `client_id` is the provider's `audience` too: leave `audience` out, or set it to the same. Several providers can have one. [cf-vault](https://github.com/cf-contrib/cf-vault) reads the list, so the broker's URL and profile are all a person sets, with `provider = "<name>"` to pick one when there are several.

Access's ID tokens carry `email`, `sub` and the application's `iss`, and last 5 minutes, whatever the application's access token lifetime ([#53](https://github.com/cf-contrib/cloudflare-sts/issues/53)). For a sign-in that lasts, give the application a refresh token lifetime (`saas-oidc`'s `refresh_token_lifetime`): cf-vault then renews the login without a browser. Access does not list `offline_access` in its metadata, so cf-vault has to ask for it: `scopes = ["openid", "email", "offline_access"]` in the profile.

Keep people's profiles to what they need locally, such as read-only state, and keep `apply` in CI behind `environment: prod` with required reviewers.

### Migration from version 3

Version 3 policies, one JSON or YAML document with `claims` on providers and profiles, are refused (`500`, with `version must be 4` in the log). Split them in two:

| Version 3 | Version 4 |
|---|---|
| `version: 3`, one document | `version = 4` in `config` (TOML, or JSON), and a Cedar policy in `policy` |
| `claims: [...]` on a provider | a `permit` for `Admit::Action::"<provider>"` in the Cedar policy |
| `claims: [...]` on a profile | a `permit` for `Profile::Action::"<name>"`: `{ a: x, b: y }` is `context.a == "x" && context.b == "y"`, several sets are `\|\|`, a trailing `*` is `like "prefix*"` |
| a token's matched claims, copied and logged | `forward_claims = ["repository", "ref"]` on the profile: Cedar can't say which claims a policy looked at |
| the policy in a Worker variable | the KV namespace, keys `config` and `policy` (see [Bindings](#bindings)) |

Terraform's `oidc_providers` and `profiles` lose their `claims`, and the module takes a `cedar_policy` instead.

### Permissions

`permissions` are permission-group names as the [permission groups API](https://developers.cloudflare.com/api/resources/accounts/subresources/tokens/subresources/permission_groups/) returns them, e.g. `"DNS Write"` or `"Workers Scripts Write"`. The broker looks up their IDs with the Cloudflare token when it mints a token. To see the full list:

```sh
curl -H "Authorization: Bearer <token>" \
  "https://api.cloudflare.com/client/v4/accounts/<account_id>/tokens/permission_groups"
```

- An unknown name fails the mint with `500` (`server_error`). It's never silently dropped.
- If a name exists at several scopes, the broker uses the one matching the resources' scope (account, zone or R2 bucket).

### Resources

`resources` is Cloudflare's own token resources format, passed through as written. Common forms:

| Grants | `resources` |
|---|---|
| The whole account | `com.cloudflare.api.account.<account_id>: "*"` |
| One zone | `com.cloudflare.api.account.zone.<zone_id>: "*"` |
| Every zone in the account | `com.cloudflare.api.account.<account_id>: { com.cloudflare.api.account.zone.*: "*" }` |

Keys must start with `com.cloudflare.`, and account keys must name `CLOUDFLARE_STS_API_ACCOUNT_ID`. A policy's `resources` are all `"*"` values or all nested maps, as Cloudflare takes them. Add a comment with the zone's name next to each zone ID so reviewers can tell them apart. With the Terraform module, write `"com.cloudflare.api.account.${var.account_id}"`.

### Buckets

A profile's `bucket` gets the job [temporary R2 credentials](https://developers.cloudflare.com/r2/api/s3/temporary-credentials/) for that bucket, optionally limited to key prefixes built from the job's claims. One shared bucket can then hold every repo's Terraform state, with each repo limited to its own prefix:

```yaml
    bucket:
      name: org-terraform-state           # a valid R2 bucket name
      permission: object-read-write       # or object-read-only; admin levels aren't allowed
      prefixes: ["github.com/{repository}/"]
```

- **One bucket per profile,** so the action always exports its credentials under the same names, `CLOUDFLARE_R2_*`. A request for several scopes may name at most one profile with a bucket; a job that needs two buckets uses two profiles, in two jobs.

- **Placeholders** are `{claim}`, not `${claim}`, so HCL leaves them alone. Any claim can fill one: `{repository}` from GitHub Actions, `{project_path}` from GitLab, `{email}`… They're filled in from the verified token, never from the request.
- **Prefixes** must end in `/`, so `github.com/org/site/` doesn't also cover `github.com/org/site-old/`. They can't start with `/` or contain `*`, `..`, empty or `.` segments, or control characters, and each placeholder must be a whole path segment (`tfstate/{repository_id}/`, not `tfstate-{repository_id}/`), so two repos can never end up with the same prefix. These are checked when the policy loads.
- **Claims** filling a placeholder must be a string or a number made of path segments of `A-Z`, `a-z`, `0-9`, `.`, `_` and `-`. A value can span several segments (`example-org/app`) only when it's the template's one placeholder; with several, each must fill exactly one, so two callers can never fill a template to the same prefix. The filled-in prefix is checked again. Otherwise the request is refused (`invalid_request`), before anything is minted.
- **Without `prefixes`** the credentials cover the whole bucket.
- **Lifetime:** the profile's `ttl`, capped at its `max_ttl`, with the request's `ttl` still honoured. That's the same as the token's, in a profile with both. The credentials **can't be revoked early**, so keep TTLs short.
- **Parent token:** the Cloudflare token calls `temp-access-credentials` with its own ID as the parent, as in [Cloudflare's example](https://developers.cloudflare.com/r2/examples/authenticate-r2-temp-credentials/), and the credentials can't exceed its permissions. Give it **Workers R2 Storage Write** (R2's "Admin Read & Write"), which is known to work. Cloudflare asks for "at least the permissions you plan to delegate", so an R2 permission limited to the profiles' buckets may be enough, but that hasn't been tried. Without an R2 permission the endpoint refuses the token with code `10000`, which the broker reports as `503` (`temporarily_unavailable`; `Cloudflare: temporaryCredentials.create: returned 403` in the audit log). Admin Read & Write is account-wide, but it doesn't widen what a leaked Cloudflare token can do: with Account API Tokens Write it could already mint itself a token with any R2 permission. The policy still only hands out `object-*` permissions. Revoking or rolling the Cloudflare token cuts off every credential issued from it within seconds, including those of jobs running at that moment. That's the emergency switch.
- **With both** `token` and `bucket`, the broker mints the token first. If the credentials then can't be created, it deletes the token and replies `503`.

**Renamed and reused repo names.** A prefix built from `{repository}` moves when the repo is renamed, and a deleted repo's name can be taken by a new repo in the org, which would then get the old repo's state. `{repository_owner_id}/{repository_id}/` doesn't change on a rename and is never reused.

**What `bucket` doesn't cover:** admin operations such as creating or listing buckets. For those, grant R2 permissions in the profile's `token` and derive S3 credentials from `CLOUDFLARE_API_TOKEN` in a step: the access key ID is the token's ID, and the secret is the SHA-256 of the token value. Buckets in a jurisdiction (`eu`, `fedramp`) need a different endpoint than the one the broker returns.

### Tokens for other services

A profile with `audience: <service URL>` gives the caller a token the broker signs itself, for another service that trusts the broker, such as [cloudflare-nix](https://github.com/cf-contrib/cloudflare-nix). It has no `token` or `bucket`: who may use the service is decided by the Cedar policy, like any other.

```toml
[[profiles]]
name           = "example-org/app:ci.build"
provider       = "com.github.actions"
audience       = "https://cloudflare-nix-api.example.com"
forward_claims = ["repository_id", "ref"]   # what the service may match on
ttl            = "15m"
```

```cedar
@id("ci-build")
permit (principal, action == Profile::Action::"example-org/app:ci.build", resource)
when { context.repository_id == "200000003" && context.ref == "refs/heads/main" };   // example-org/app
```

The caller asks for it with [`audience`](#token-exchange) set to the service's URL, and gets a JWT access token the broker signed, as RFC 9068 has it: `typ: at+jwt`, so a service can tell it from any other JWT, and `alg: RS256`, which verifiers support by default.

- `iss` is the broker's URL (the policy's `issuer`), `aud` the service, `sub` the caller's `sub` from its issuer (`<provider>:unknown` if its token has none), and `client_id` the provider's name: the caller doesn't authenticate as a client, so the provider that vouched for it stands in.
- `provider` and `profile` name where the caller came from and what allowed it, `jti` is unique, and `iat`, `nbf` and `exp` are when it was issued, valid from and until.
- Verified claims are copied under their issuer's names, so a service can match on them: every claim the profile's `forward_claims` name. Nothing else, so an issuer's other claims (such as GitLab's `user_email`) stay behind.
- It lasts the profile's `ttl`, but never past the caller's OIDC token, which lasts minutes. Exchange again for a fresh one: there are no refresh tokens. A subject token already past its `exp`, though accepted within the clock tolerance, gets nothing (`invalid_request`, `the subject token has expired`).

Services find the public key at [`/.well-known/jwks`](#http-api), or through the broker's metadata: RFC 8414's at [`/.well-known/oauth-authorization-server`](#http-api), or OpenID Connect Discovery's at [`/.well-known/openid-configuration`](#http-api) for services that only read that, such as AWS IAM, Google Cloud Workload Identity Federation and Vault. They should check `typ` (`at+jwt`), `iss`, `aud`, `exp` and the `RS256` algorithm, as RFC 9068 §4 says. The broker isn't a full OpenID Provider: tokens come from exchange only, so, as for GitHub's and Kubernetes' issuers, its discovery document has no authorization endpoint. A service that verifies these tokens names the broker as a provider with `typ` `at+jwt`.

The key is an RSA private key, at least 2048 bits, in Secrets Store, bound as `CLOUDFLARE_STS_API_SIGNING_KEY` (`signing_key_secret` in the [Terraform module](../../deployment/terraform)):

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out signing-key.pem
wrangler secrets-store secret create <store-id> --name cloudflare-sts-signing-key --scopes workers   # paste the PEM
rm signing-key.pem
```

Its `kid` is the public key's thumbprint, so replacing the secret rotates the key. Tokens signed with the old key stop verifying once services refetch the JWKS, and they're short-lived anyway.

### TTL and names

- Durations look like `90s`, `15m`, `1h`, `1h30m`: each unit once, largest first.
- `ttl` and `max_ttl` go on the profile, and apply to its token and bucket alike.
- A requested `ttl` above the profile's `max_ttl` is clamped. Below `1m`, or unparseable, is a `400`. In the policy, a `ttl` below `1m` is refused when it loads.
- Provider names are 1–64 characters of `A-Z`, `a-z`, `0-9`, `_`, `.` and `-`, starting with a letter or digit, and unique. They go into minted tokens' names, which `:` separates, and into `client_id`.
- Profile names are 1–255 characters of `A-Z`, `a-z`, `0-9`, `_`, `.`, `:`, `/` and `-`, starting with a letter or digit, and unique, so a name can say whose the profile is: `example-org/app:ci.deploy`. See [Naming](#naming).
- Minted tokens are named `cloudflare-sts:<provider>:<sub>`, at most 120 characters.

### Naming

These are recommendations: the broker enforces only the characters and the length.

**Profiles: `<who>:<what>`.** `<who>` is the narrowest caller the profile's claims pin, written as its issuer writes it:

| Caller | `<who>` | From the claim |
|---|---|---|
| A GitHub Actions repo | `<owner>/<repo>` | `repository` |
| Every repo in a GitHub org (`repository: "example-org/*"`) | `<owner>` | `repository_owner` |
| A GitLab project | `<group>/<project>` | `project_path` |
| People through Cloudflare Access | a team or role, such as `infra-admins` | the profile's `email` set |

`<what>` is the job, for a CI job: `<workflow>.<job>`, the workflow file's name without `.yml`, then the job's id. GitHub job ids can't contain `.`, so the last `.` separates the job even when the workflow's name has dots in it. GitLab has a single `.gitlab-ci.yml`, so it's just `<job>`. For an org-wide profile, or one for people, it's the purpose, such as `workers-deploy` or `tofu-plan`.

| Profile | Name |
|---|---|
| The `deploy` job in `example-org/app`'s `ci.yml` | `example-org/app:ci.deploy` |
| Workers deploys from `main` in any org repo | `example-org:workers-deploy` |
| The GitLab `deploy` job in `group/app` | `group/app:deploy` |
| `tofu plan` for people, through Access | `infra-admins:tofu-plan` |

- **Name the job, not the tool:** `ci.apply`, not `ci.tofu-apply`. When the job is renamed, rename the profile with it.
- **One job, one profile, unless it needs several.** A job that needs a token and a bucket can ask for both profiles as one `scope`. A job that needs two buckets uses two profiles, in two jobs.
- **The name enforces nothing; the claims do.** Derive the name from the claims, so the two can't drift. In Terraform, build `name`, `repository_id` and `workflow_ref` from the same locals.

**Providers: the issuing service, reverse-DNS.** `com.github.actions`, `com.gitlab`, `com.cloudflare.access`. That reads like the policy's resource keys (`com.cloudflare.api.account.<id>`) and, in the broker's own tokens, like the client identifier it is in `client_id`. A longer name takes more of a minted token's 120 characters, `cloudflare-sts:<provider>:<sub>`, which is cut to fit.

**Bucket prefixes: the caller's path, under its issuer's host.** `github.com/{repository}/`, `gitlab.com/{project_path}/`. Such a prefix is readable, and can't collide across providers. But it moves when the repo is renamed or transferred, and a deleted repo's name can be reused: where that matters, use IDs, as the policy above does (see [Buckets](#buckets)).

### Guardrails

These are enforced when the policy loads, so an unsafe policy never serves a request:

1. **Every provider is pinned.** The Cedar policy must `permit` every provider's `Admit` action, and a token must pass it whatever profile it asks for. Pin the tenant there for issuers that give tokens to anyone's projects (see [Providers](#providers)).
2. **Every policy is named and scoped.** Each has a unique `@id`, and a `permit` names its provider or profile, so none lets everything in. A policy naming a provider or profile that doesn't exist is refused, and so is an enabled profile that nothing permits.
3. **No token-management permissions.** Granting (`effect: allow`) any permission group whose name contains `API Tokens`, in any case, is rejected, so a job can't turn its short-lived token into a long-lived one. A `deny` may name one.
4. **TTLs are capped.** `max_ttl` is at most 24h, and `ttl` can't exceed it.
5. **Audiences are kept apart.** A request only matches profiles for its `audience`. A profile for another service can't hand out Cloudflare credentials, and its audience must be a bare origin other than the broker's own.

## HTTP API

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/oauth/token` | `subject_token` in the body | [Token exchange](#token-exchange) (RFC 8693) of an OIDC token. What the action uses. |
| `POST` | `/oauth/revoke` | `token` in the body | [Revoke](#revocation) (RFC 7009) a token the broker minted. What the action's post step uses. |
| `GET` | `/.well-known/oauth-authorization-server` | public | The broker's Authorization Server Metadata (RFC 8414): its issuer, key and endpoint URLs, for services that verify [its tokens](#tokens-for-other-services). Its endpoints' auth methods are `none`: callers don't authenticate as clients. With providers that have a `client_id`, also `identity_providers: [{ name, issuer, client_id }]`, where [people](#people) sign in. |
| `GET` | `/.well-known/openid-configuration` | public | The same issuer and keys as OpenID Provider Metadata (OpenID Connect Discovery 1.0), for services that only read that. |
| `GET` | `/.well-known/jwks` | public | The public key the broker signs its own tokens with. Empty without `CLOUDFLARE_STS_API_SIGNING_KEY`. |
| `GET` | `/health/live` | public | `200` whenever the Worker's bindings are valid. |
| `GET` | `/health/ready` | public | `200` when the Worker's bindings are valid and its secrets can be read: the Cloudflare token, and the signing key if one is bound. `503` otherwise, with why in Workers Logs (`unready`). It doesn't call Cloudflare's API, so it can't tell a revoked token from a good one. |

Bodies are form-encoded and at most 16 KiB; anything else, such as a JSON body, is `400` (`invalid_request`). Every response is `Cache-Control: no-store`, except the discovery endpoints' `200`s, which are `public, max-age=300`.

### Token exchange

`POST /oauth/token` is an [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693) token exchange, form-encoded. The token goes in the body, and `subject_token_type` says whose it is. [`stsv1.yaml`](../cloudflare-sts-sdk/openapi/sts/v1/stsv1.yaml) is the contract.

```sh
curl -sS https://cloudflare-sts-api.example.com/oauth/token \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d subject_token="$GITHUB_OIDC_TOKEN" \
  -d subject_token_type=urn:ietf:params:oauth:token-type:id_token \
  -d scope=example-org:workers-deploy
```

| Parameter | |
|---|---|
| `grant_type` | `urn:ietf:params:oauth:grant-type:token-exchange` |
| `subject_token` | An OIDC token from a provider's issuer |
| `subject_token_type` | `urn:ietf:params:oauth:token-type:id_token` or `urn:ietf:params:oauth:token-type:jwt` |
| `audience` | Optional. `https://api.cloudflare.com`, the default, for Cloudflare credentials; or a service's URL for [the broker's own token](#tokens-for-other-services) |
| `requested_token_type` | Optional. For Cloudflare, `urn:ietf:params:oauth:token-type:access_token` or `urn:cloudflare-sts:params:oauth:token-type:r2_credentials`; for a service, `urn:ietf:params:oauth:token-type:jwt` or `…:access_token` |
| `scope` | Optional. The profiles to get, space-delimited ([RFC 6749 §3.3](https://www.rfc-editor.org/rfc/rfc6749#section-3.3)); the caller must be allowed every one, see [Several scopes](#several-scopes). If omitted, exactly one profile must match |
| `ttl` | Optional. Requested lifetime such as `10m` or `1h`, clamped to the profile's `max_ttl` |

Delegation (`actor_token`), audiences no profile is for, and other token types are refused with `400`, not ignored.

The response has the standard fields plus the broker's own:

```json
{
  "access_token": "…",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "token_type": "Bearer",
  "expires_in": 900,
  "expires_at": 1790597700,
  "token_id": "…",
  "account_id": "0123456789abcdef0123456789abcdef",
  "scope": "example-org:workers-deploy",
  "bucket": { "name": "…", "access_key_id": "…", "secret_access_key": "…", "session_token": "…", "prefixes": ["…"], "endpoint": "…", "expires_on": "…" }
}
```

`scope` says which profiles were granted, space-delimited, in the order asked for.

`requested_token_type` doesn't choose what's issued: the profile does. It only refuses a type the audience can't have (`invalid_target`), so a profile with a `token` and a `bucket` answers `access_token` even if `r2_credentials` was asked for.

`bucket` is there when the profile has one. A profile with only a bucket has no bearer token, so it returns no `access_token` or `token_id`, with `issued_token_type` `urn:cloudflare-sts:params:oauth:token-type:r2_credentials` and `token_type` `N_A`. For a service's audience, `access_token` is the broker's JWT access token, `issued_token_type` is `urn:ietf:params:oauth:token-type:access_token` (or `…:jwt`, if that's what `requested_token_type` asked for), and there's no `token_id`, `account_id` or `bucket`.

Errors are the same as on every route.

### Several scopes

`scope` can name several profiles, as a space-delimited list. The caller must be allowed every one: if any is unknown, disabled, for another provider or audience, or not allowed by the policy, the request is `invalid_scope` and nothing is issued. Asking twice for the same profile is asking once.

Profiles for Cloudflare's audience are combined into one grant:

- **Token:** their `token.policies` together, as one token, so it can do what each of them could.
- **Bucket:** at most one of them may have a `bucket`, because the credentials are for one bucket. Two is `invalid_scope`.
- **Lifetime:** the shortest `ttl` and the shortest `max_ttl` among them, so nothing outlives what any of them allows.

A profile for another service's audience gives the broker's own token with that profile's claims, so a request for it takes exactly one scope.

```sh
curl -sS https://cloudflare-sts-api.example.com/oauth/token \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d subject_token="$GITHUB_OIDC_TOKEN" \
  -d subject_token_type=urn:ietf:params:oauth:token-type:id_token \
  --data-urlencode "scope=example-org:workers-deploy example-org:terraform-state"
```

### Revocation

`POST /oauth/revoke` is an [RFC 7009](https://www.rfc-editor.org/rfc/rfc7009) revocation, form-encoded, with the token in `token` (`token_type_hint`, if sent, must be `access_token`, and is otherwise ignored). Holding the token is the proof. It answers `200` with no body whether the token was revoked, was already gone, was never valid, or isn't one the broker minted (one not named `cloudflare-sts:*`, including the Cloudflare token), which it never deletes: to the broker that's an invalid token, which RFC 7009 answers with `200` too. The audit log says which (`token.revoke`, `reason: not_minted`).

```sh
curl -sS https://cloudflare-sts-api.example.com/oauth/revoke -d token="$CLOUDFLARE_API_TOKEN"
```

**Errors:** OAuth errors (RFC 6749 §5.2), `{ "error": "<code>", "error_description": "<what went wrong>" }`, as RFC 8693 and RFC 7009 have them:

- `400 invalid_request`: a malformed request, a subject token that's invalid, or one the policy doesn't take (RFC 8693 §2.2.2)
- `400 invalid_target`: an `audience` the broker issues nothing for, or can't issue the requested token type for (RFC 8693)
- `400 unsupported_grant_type`: a `grant_type` other than token exchange
- `500 server_error`: the broker is misconfigured or failed
- `503 temporarily_unavailable`: Cloudflare or the subject token's issuer failed

For the caller's own mistakes (400) the description says what was wrong, for example `no profile matches the token`, `profiles a, b all match the token: name one`, `unknown profile x`, `profile example-org:workers-deploy isn't for provider com.gitlab`, `profile x is disabled` or `profile x doesn't match the token`. That tells a caller with a valid token which profile names exist. For the broker's faults (500, 503) the description is generic, and the logs say why.

**Contract:** [`stsv1.tsp`](../cloudflare-sts-sdk/openapi/sts/v1/stsv1.tsp), in TypeSpec, compiled to the OpenAPI document [`stsv1.yaml`](../cloudflare-sts-sdk/openapi/sts/v1/stsv1.yaml). The Worker's types, server and router are generated from it, and requests that don't fit it are refused (`400`) before any handler runs. The action's [`api.ts`](../../action/src/api.ts) mirrors it.

## Security

| Threat | Mitigation |
|---|---|
| Forged or tampered JWT | Signature checked against the issuer's JWKS (RS256 only), plus `iss`, `aud`, `exp` and `nbf` with 60s tolerance |
| A repo outside your org asks for a token | Every provider needs an `Admit` permit; pin your tenant's ID there |
| A token from an issuer you don't trust | Only issuers listed as providers are accepted, by exact `iss`, with keys from that issuer's own metadata or `jwks_uri` |
| Deleted repo or org re-registered by an attacker | Pin numeric IDs, not names |
| Malicious PR code gets a prod token | Require `ref == "refs/heads/main"` and `environment == "prod"`, with required reviewers on the environment. Fork PRs don't get `id-token: write` on `pull_request`. Add a `forbid` for `event_name == "pull_request_target"`, once, for every profile. |
| Stolen minted token | 15m default TTL, revoked at job end, expired tokens deleted hourly |
| Stolen R2 credentials | Limited to one bucket and the repo's prefixes, and short-lived. They can't be revoked one by one; rolling the Cloudflare token revokes all of them |
| One repo reaches another's R2 keys | Prefixes must end in `/`, placeholders fill whole segments from verified claims with a fixed character set, and both the template and the result are checked. Prefer ID-based prefixes |
| Stolen JWT replayed | Short JWT lifetime and a custom audience |
| Stolen broker-issued token | Valid for one service (`aud`), and never longer than the job's OIDC token it came from |
| Signing key exfiltrated | Kept in Secrets Store like the Cloudflare token. Replace the secret to rotate it: the new key gets a new `kid`, and services stop accepting the old one once they refetch the JWKS |
| One caller reaches another's R2 keys through a prefix claim | A value spans path segments only as a template's one placeholder, and every filled-in prefix is checked again |
| Cloudflare token exfiltrated | Kept in Secrets Store, so it isn't in Terraform state or CI. Only code running in the Worker can read it. Restrict who can deploy Workers in the broker's account, rotate the Cloudflare token, and consider a dedicated account per trust domain. |
| Token flooding | Only callers the policy allows can mint. Tokens are short-lived, revoked at job end, and cleaned up hourly. There's no rate limit yet (see [Limitations](#limitations)). |

### Audit log

The broker logs with [`tracing`](https://docs.rs/tracing), as JSON lines that Workers Logs indexes by field. Every mint, issue and denial is one line, with its `event` and, once the token is verified, the caller's `provider`, their token's `sub`, and in `claims` the claims their profile's `forward_claims` name. The policies that allowed or forbade a request are named by their `@id` in `policy.allow` and `policy.forbid` lines. Token values, R2 secrets and JWTs are never logged:

```json
{"level":"INFO","event":"token.mint","provider":"com.github.actions","profile":"example-org:workers-deploy","sub":"repo:example-org/app:environment:prod","claims":"{\"environment\":\"prod\",\"ref\":\"refs/heads/main\",\"repository\":\"example-org/app\",\"repository_owner_id\":\"100000001\"}","token_id":"<token-id>","expires_at":1790961140}
```

`claims` is JSON text, since which claims a policy names is up to the policy. `expires_at` is in seconds since the epoch, as the exchange's response has it.

R2 credentials are `r2.issued`, with the bucket, the filled-in prefixes and the permission:

```json
{"level":"INFO","event":"r2.issued","provider":"com.github.actions","profile":"example-org:terraform-state","sub":"repo:example-org/app:ref:refs/heads/main","claims":"{\"ref\":\"refs/heads/main\",\"repository_owner_id\":\"100000001\"}","bucket":"org-terraform-state","prefixes":"[\"100000001/200000003/\"]","permission":"object-read-write","expires_at":1790961140}
```

A token for another service is `token.issue`, with the audience and the token's `jti`, never the token:

```json
{"level":"INFO","event":"token.issue","provider":"com.github.actions","profile":"example-org/app:ci.build","sub":"repo:example-org/app:ref:refs/heads/main","claims":"{\"ref\":\"refs/heads/main\",\"repository_owner_id\":\"100000001\"}","audience":"https://cloudflare-nix-api.example.com","jti":"<uuid>","expires_at":1790960440}
```

Denials are `token.deny`, a warning, with the response's `error`, and its `error_description` as `message`. For the broker's own faults, the message is the full one the caller doesn't get:

```json
{"level":"WARN","event":"token.deny","provider":"com.github.actions","profile":"example-org:workers-deploy","sub":"repo:example-org/app:environment:prod","claims":"{\"repository\":\"example-org/app\",\"repository_owner_id\":\"100000001\"}","error":"temporarily_unavailable","message":"Cloudflare: tokens.create: returned 500"}
```

- **Request problems** (`invalid_request`, `invalid_scope`, `invalid_target`, `unsupported_grant_type`): what the contract refuses, such as another `grant_type`, `actor_token`, a missing field or a JSON body; an invalid subject token, or one from an issuer no provider is for; a `ttl` or `audience` that doesn't fit.
- **The policy didn't allow it** (`invalid_request`, or `invalid_scope` for a scope): the policy doesn't admit the token to its provider, no profile matches, several do and none is named, a claim can't fill a bucket prefix. A `scope` the caller can't have, or that names an unknown or disabled profile or one for another provider or audience, is `invalid_scope`.
- **Configuration or upstream faults** (`server_error`, `temporarily_unavailable`): a secret that can't be read, an unknown permission name, an issuer's keys, Cloudflare failing.

The other events:

| `event` | Fields | |
|---|---|---|
| `token.revoke` | `token_id`, or `reason` | A revocation: the token deleted, or `already_gone`, `not_minted` (the token isn't the broker's), `discarded` (deleted because the profile's R2 credentials failed) or `discard_failed` |
| `token.cleanup` | `token_id`, `name`, `expires_at` | The cron deleted an expired token |
| `cleanup.done` | `deleted` | The cron's run, and how many it deleted |
| `cleanup.failed` | `error`, `message` | The cron's run failed |
| `misconfigured` | `message` | The bindings or the policy are invalid: the first problem |
| `unready` | `message` | `/health/ready` answered `503`: a secret can't be read, and why |

## Limitations

- **One account per broker.** Tokens are minted in `CLOUDFLARE_STS_API_ACCOUNT_ID` only. Deploy one broker per account.
- **RS256 only, one provider per issuer.** Issuers that sign with another algorithm (such as ES256) aren't supported yet. To serve several GitHub orgs, admit them all in the provider's `permit`: `["100000001", "100000002"].contains(context.repository_owner_id)`.
- **OIDC tokens only.** People need an identity provider that issues them one, such as [Cloudflare Access](#people). Rules on a person's role in a GitHub repo can't be expressed: their tokens don't carry it.
- **The tenant pin is yours to get right.** The broker requires every provider to have an `Admit` permit, but knows no issuer's tenant claim by name.
- **One signing key at a time.** Rotating it can't publish the old and new keys side by side, so a token signed just before the rotation fails at a service that has already refetched the JWKS. They're short-lived, and the caller can exchange again.
- **No JWT replay cache.** A stolen JWT can be exchanged again until it expires. The custom audience and its short lifetime limit this.
- **Resource IDs aren't checked up front.** Apart from the account check, a wrong zone ID is only caught when Cloudflare rejects the mint (`503`).
- **Permission names can change.** Cloudflare can rename a permission group. Profiles using the old name fail closed (`500`) until the policy is updated.
- **Secrets Store is required, and in open beta.** The Cloudflare token is only accepted from Secrets Store, so a plain Worker secret can't end up in Terraform state or deploy tooling. Accounts without Secrets Store can't run the broker yet.
- **R2 credentials can't be revoked early.** They last their TTL; only rolling the Cloudflare token cuts them all off. One bucket per grant, and only buckets outside a jurisdiction.
- **No rate limit.** A workflow the policy allows can mint as often as it runs. Each token expires within minutes, is revoked at job end and cleaned up hourly, but a compromised workflow could still create many tokens at once. Cloudflare's rate-limit binding was tried and didn't enforce a 30-per-minute limit against ~85 requests a minute, so it was left out. An exact per-repository limit (e.g. a Durable Object) may come later.

## Code

The crate is laid out as cloudflare-nix's Worker is:

| | |
|---|---|
| `src/lib.rs` | The start, fetch and scheduled events: the JSON logger, the configuration, then the SDK's two routers over it, the token endpoints under the auth layer and the discovery endpoints under `cache_publicly`, and the health endpoints, all under `OAuthResponseLayer`. |
| `src/service/config.rs` | The bindings and the policy from KV, read in `Config::load` only, and the configuration's format: providers, profiles, bucket prefixes, and the guardrails parsing checks. |
| `src/service/authz.rs` | The Cedar half of the policy: parsing it, checking it against the configuration, and asking it who may be admitted and who gets which profile. |
| `src/oidc/` | OIDC tokens in the Worker, verified and signed: the JWT format (RFC 7515, 7519, 9068), providers found by `iss` with their keys from the issuer's metadata (RFC 7517, 8414, OpenID Connect Discovery), and RS256 through the runtime's WebCrypto, for verifying and for signing the broker's own tokens. |
| `src/service/layer.rs` | Exchange auth, as a tower layer over `oidc`: the subject token's provider by `iss`, RS256 against the issuer's keys with WebCrypto, the standard claims, and whether the policy admits it. And `OAuthResponseLayer`, OAuth's rules for every response: the generated validation's refusals as `invalid_request`, and `Cache-Control: no-store`; `cache_publicly`, the discovery endpoints' `public, max-age=300`. |
| `src/service/handler.rs` | The generated API's implementation, a handler per trait. `TokenServiceHandler`: the exchange (profiles, Cloudflare tokens and R2 credentials through [cloudflare-rs](https://github.com/cf-contrib/cloudflare-rs), the broker's own tokens), revocation, and the cleanup the cron runs. `DiscoveryServiceHandler`: the RFC 8414 and OpenID Connect Discovery metadata, and the keys. |

## Development

`nix develop` at the repository root has the toolchain.

`cargo test` runs the unit tests. The integration tests run the Worker under
`wrangler dev` against stand-ins for the OIDC issuers and Cloudflare that the
tests serve and control:

```sh
tests/run.sh
```

It creates made-up secrets in a local Secrets Store, starts `wrangler dev` on
port 8790, serves the stand-ins on 8791, and runs the tests one at a time.
`wrangler.toml` is that setup, as in cloudflare-nix: a build with the
`stand-ins` feature, which takes Cloudflare's API from
`CLOUDFLARE_STS_API_CLOUDFLARE_URL` (a release build never reads it), and a
policy whose providers are the stand-ins' issuers. So a plain `wrangler dev`
serves it too, against the stand-ins while the tests run.

## License

[MIT](../../LICENSE)
