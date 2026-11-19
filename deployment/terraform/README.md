# cloudflare-sts Terraform module

> The Terraform / OpenTofu half of [cloudflare-sts](../..): deploys the released
> broker, a Rust Worker, to Cloudflare, with its bindings, hourly cleanup cron, and
> a workers.dev URL (or, optionally, a custom domain). No `wrangler` or local
> build is needed.

```hcl
module "cloudflare_sts_api" {
  source = "git::https://github.com/cf-contrib/cloudflare-sts.git//deployment/terraform?ref=v0.23.2" # x-release-please-version

  account_id              = var.account_id
  hostname                = "cloudflare-sts-api.example.workers.dev"
  cloudflare_token_secret = { secret_store_id = var.secret_store_id, secret_name = "cloudflare-sts-cloudflare-token" }

  oidc_providers = [
    {
      name   = "com.github.actions"
      issuer = "https://token.actions.githubusercontent.com"
    },
  ]

  profiles = [
    {
      name = "example-org/app:ci.deploy"
      token = { policies = [{
        permissions = ["Workers Scripts Write"]
        resources   = { "com.cloudflare.api.account.${var.account_id}" = "*" }
      }] }
    },
  ]

  # Who gets what: a permit for every provider (pinning your org) and profile.
  cedar_policy = file("${path.module}/policy.cedar")
}

output "cloudflare_sts_api_url" {
  value = module.cloudflare_sts_api.url
}
```

The module is released with the action and the broker from the same tag, and
by default deploys the broker of the release its `ref` points to.

## Prerequisites

- Terraform or OpenTofu >= 1.9.
- The **Cloudflare token**, an account-owned API token with
  **Account API Tokens Write** (see the [broker's README](../../crates/cloudflare-sts-api#deploy)),
  stored in [Secrets Store](https://developers.cloudflare.com/secrets-store/) (open beta).
  If any profile has a `bucket`, the token also needs R2 permissions
  covering what it delegates: it creates their credentials and is
  their parent (see [Buckets](../../crates/cloudflare-sts-api#buckets)).
  If any profile has an `access`, it also needs **Access: Service Tokens Write**
  (see [Access service tokens](../../crates/cloudflare-sts-api#access-service-tokens)).
  With `token_rotation` enabled, it also needs **Secrets Store Write**, to find
  and rewrite its own secret (see
  [Rotating the Cloudflare token](../../crates/cloudflare-sts-api#rotating-the-cloudflare-token)).
- A separate API token for *deploying*, exported as `CLOUDFLARE_API_TOKEN`, with:
  - **Account → Workers Scripts: Edit**
  - **Account → Secrets Store: Edit**, to bind the Cloudflare token's secret
  - **Account → Workers KV Storage: Edit**, for the namespace that holds the policy (the
    `config` and `policy` keys): without it the apply fails with `Authentication error`
    (code `10000`) creating the namespace
  - **Zone → Workers Routes: Edit** on the broker's zone, only for a custom domain (not tested yet)

  The first two were enough for a workers.dev deploy in testing, before the policy moved to KV.
- (Optional) `GITHUB_TOKEN` if you hit anonymous GitHub API rate limits.

## Usage

```sh
# Store the Cloudflare token once. Wrangler prompts for the value.
wrangler secrets-store store list --remote     # note the store ID
wrangler secrets-store secret create <store-id> --name cloudflare-sts-cloudflare-token --scopes workers --remote

$EDITOR main.tf                                # oidc_providers and profiles; see Policy below

export CLOUDFLARE_API_TOKEN=...                # deploy token, not the broker's Cloudflare token
tofu init
tofu apply
curl -fsS "$(tofu output -raw cloudflare_sts_api_url)/health/ready"   # 500 if the policy is wrong, 503 if a secret can't be read
```

Terraform only references the secret by store ID and name. The token's value
never enters Terraform state or the plan. Rotate it by replacing the secret in
Secrets Store; the broker reads it on every request. Or set `token_rotation`
and have the broker replace it for you:

```hcl
token_rotation = {
  enabled = true
  every   = "30d" # how old the Cloudflare token may get
  overlap = "25h" # how long the one it replaces stays alive after the handover
}
```

The module points it at the same secret as the binding, so the two can't name
different ones. The broker's token then needs **Secrets Store Write**, and on an
existing deployment this goes in a [second apply](#upgrading-and-pinning). What
it does, and why it replaces the token rather than rolling it in place, is in
the [broker's README](../../crates/cloudflare-sts-api#rotating-the-cloudflare-token).

### Checking it's ready

The module doesn't check the broker itself. To have every plan and apply warn
when it isn't ready, add
[terraform-http-check](https://github.com/tf-contrib/terraform-http-check)
beside it:

```hcl
module "cloudflare_sts_api_ready" {
  source = "git::https://github.com/tf-contrib/terraform-http-check.git?ref=v0.1.0"

  url  = "${module.cloudflare_sts_api.url}/health/ready"
  hint = "503 if a secret can't be read, 500 if a binding or the policy is wrong. Workers Logs says why (event unready or misconfigured)."
}
```

A secret Secrets Store won't hand over then shows up in your apply, not in the
first job that asks for a token. It's a warning, never an error, and gives up
within about 25s on a broker it can't reach. Leave it out where plans can't
reach the broker, such as runners whose egress is allowlisted.


## URL

`hostname` decides where the broker is served. It's bare and lowercase: no
scheme, port or path.

- A `*.workers.dev` hostname serves it on workers.dev. It must be
  `<worker_name>.<subdomain>.workers.dev`, with your account's subdomain: find it
  in the dashboard under Workers & Pages, or with
  `GET /accounts/<account_id>/workers/subdomain`. Leave `zone_id` unset.
- Any other hostname is a custom domain and needs `zone_id`. The broker is then
  served on that domain only, and workers.dev is disabled.

Either way the broker is reachable on exactly one URL, the `url` output, which is also the OIDC audience.

## Policy

The policy is three variables and a Cedar file (see the [broker's
README](../../crates/cloudflare-sts-api#policy)): what the broker trusts and
hands out, as HCL, and who gets it, as Cedar.

- `oidc_providers`: the OIDC issuers the broker trusts. Typed, and checked at
  plan time. `audience` defaults to the broker's URL, which is what the action
  asks for. For people signing in through Cloudflare Access, see
  [People](#people).
- `profiles`: what callers may get. Untyped, because a token policy's
  `resources` are flat in one profile and nested in another, as Cloudflare
  takes them; the plan checks each has a name, and the broker checks the rest.
  `forward_claims` names the caller's claims the audit log shows.
- `defaults`: the TTLs of profiles that don't set their own.
- `cedar_policy`: who gets what, as Cedar text. It must permit
  `Admit::Action::"<provider>"` for every provider, pinning your organization,
  and `Profile::Action::"<name>"` for every profile, each policy with an `@id`.
  The broker refuses a policy that leaves one out, so a typo in a name is an
  error, not a silent deny.

The module fills in the rest: the configuration's `version`, and its `issuer`,
the broker's URL.

```hcl
  oidc_providers = [{
    name   = "com.github.actions"
    issuer = "https://token.actions.githubusercontent.com"
  }]

  profiles = [
    {
      name = "example-org/app:ci.deploy"
      token = { policies = [{
        permissions = ["Workers Scripts Write"]
        resources   = { "com.cloudflare.api.account.${var.account_id}" = "*" }
      }] }
    },
    {
      name = "terraform-state" # every repo gets its own prefix in one shared bucket
      bucket = {
        name       = "org-terraform-state"
        permission = "object-read-write"
        prefixes   = ["{repository_owner_id}/{repository_id}/"] # filled in by the broker, per job
      }
    },
  ]

  cedar_policy = file("${path.module}/policy.cedar")
```

with `policy.cedar` next to it, a plain Cedar file your editor and `cedar
validate` can read, and whose diff is the review:

```cedar
@id("admit-github")
permit (principal, action == Admit::Action::"com.github.actions", resource)
when { context.repository_owner_id == "100000001" };               // your org's numeric ID

@id("app-deploy")
permit (principal, action == Profile::Action::"example-org/app:ci.deploy", resource)
when { context.repository_id == "200000003" && context.ref == "refs/heads/main" };   // example-org/app

@id("state-from-main")
permit (principal, action == Profile::Action::"terraform-state", resource)
when { context.ref == "refs/heads/main" };
```

IDs rarely change, so writing them in the file is usually best. To take them
from data sources instead, use `templatefile` and wrap each value in
`jsonencode`, so it's a properly escaped Cedar string and can't change what
the policy means:

```hcl
  cedar_policy = templatefile("${path.module}/policy.cedar.tftpl", {
    owner_id = data.github_organization.org.id
  })
```

```cedar
when { context.repository_owner_id == ${jsonencode(tostring(owner_id))} };
```

A profile's name must match between `profiles` and the Cedar policy. The
broker checks it when it loads the policy, not Terraform when it plans, so a
typo fails closed (`500`, `/health/ready` says why) after the apply.

Bucket prefixes use the broker's own `{claim}` placeholders, which HCL leaves
alone. Don't write `${repository}`: Terraform would try to fill it in and fail
the plan.

The configuration is compact JSON under the key `config` of a Workers KV
namespace the module creates, and the Cedar policy is under `policy`, bound as
`CLOUDFLARE_STS_API_POLICY_KV`. It has no size
limit to speak of, so 50 repos' profiles fit. A policy change updates the key
and creates no Worker version, and takes effect within about two minutes: the
Worker holds it for a minute, and KV's edge cache can add another. It doesn't
roll back with the Worker. To cut off access at once, revoke the Cloudflare
token. See the [broker's README](../../crates/cloudflare-sts-api#bindings).

## People

People sign in with [cf-vault](https://github.com/cf-contrib/cf-vault) through an
identity provider that issues them an ID token. For Cloudflare Access, the
[`saas-oidc`](https://github.com/tf-contrib/terraform-cloudflare-access/tree/main/modules/saas-oidc)
module of terraform-cloudflare-access creates the application, a public client
with PKCE, and the policy that says who may sign in. Give the broker a provider
for it:

```hcl
module "cloudflare_access_saas_oidc" {
  source = "git::https://github.com/tf-contrib/terraform-cloudflare-access.git//modules/saas-oidc?ref=v0.1.0"

  account_id    = var.account_id
  team_name     = "example" # example.cloudflareaccess.com
  name          = "cloudflare-sts"
  redirect_uris = ["http://127.0.0.1:8250/callback"] # where cf-vault listens
  emails        = ["alice@example.com", "bob@example.com"]
}

module "cloudflare_sts_api" {
  # ...
  oidc_providers = [
    # ... CI's providers
    {
      name     = "com.cloudflare.access"
      issuer   = module.cloudflare_access_saas_oidc.issuer
      audience = module.cloudflare_access_saas_oidc.client_id # people's ID tokens' audience: the client they sign in as
    },
  ]

  profiles = [
    {
      name     = "infra-admins:tofu-plan"
      provider = "com.cloudflare.access"
      max_ttl  = "1h"
      bucket   = { name = "org-terraform-state", permission = "object-read-only" }
    },
  ]
}
```

In the Cedar policy, the provider's `Admit` permit pins the application's own
issuer (`context.iss`), and the profile's permit names the people, by `email`
(`["alice@example.com", "bob@example.com"].contains(context.email)`). Then, on
each person's machine:

```toml
# ~/.config/cf-vault/config.toml
[people]
type = "oauth2"
account_id = "<account id>"

[people.oauth2]
# Where to sign in: the same issuer as the broker's provider, and the client.
issuer    = "https://example.cloudflareaccess.com/cdn-cgi/access/sso/oidc/<client id>"
client_id = "<client id>"
# Access accepts offline_access (a refresh token) but does not list it
scopes = ["openid", "email", "offline_access"]

[people.oauth2.exchange]
token_endpoint      = "https://cloudflare-sts-api.example.com/oauth/token"
revocation_endpoint = "https://cloudflare-sts-api.example.com/oauth/revoke"
scopes              = ["infra-admins:tofu-plan"]
```

```sh
cf-vault login -p people
cf-vault exec -p people -- tofu plan
```

Access decides who can sign in; the broker's profiles decide what each person
gets. Keep people's profiles to what they need locally, such as read-only
state, and leave applies to CI.

Upgrading from the Access module that was in this repo (before v0.18.0):

- Switch its `source` to the one above.
- Add `name = "cloudflare-sts"` and
  `redirect_uris = ["http://127.0.0.1:8250/callback"]`, which were its
  defaults.
- Replace `module.<name>.provider` with the provider above.
- If you rename the module block, add a `moved` block from its old address, so
  the application, and with it its client ID and issuer, stays.

## Upgrading and pinning

The module's `ref` pins the broker too: `?ref=vX.Y.Z` deploys that release's
Worker. To upgrade, bump the `ref`, run `tofu init -upgrade`, then `apply` to
upload a new Worker version and shift all traffic to it. Keep the action's
version in your workflows on the same release.

A release has the Worker's two modules, `index.js` and the wasm (as base64 text,
`index_bg.wasm.base64`), and a `SHA256SUMS` of them. The plan
fails if a download doesn't match `SHA256SUMS`. To pin the artifacts too, set
`checksums_sha256` to the SHA-256 of the release's `SHA256SUMS`:

```sh
curl -fsSL https://github.com/cf-contrib/cloudflare-sts/releases/download/v0.23.2/SHA256SUMS | sha256sum # x-release-please-version
```

Set `release_tag = "latest"` to track the newest release instead.

**Turning on `token_rotation` takes two applies.** The policy goes into Workers
KV before the new Worker version is promoted, and a Worker that predates
`rotation` refuses a policy with a field it doesn't know, so a single apply that
both upgrades the broker and enables rotation can leave the running Worker
failing every request until the deployment catches up — or for good, if the
apply fails in between.

First bump the `ref` and apply, leaving `token_rotation` out:

```hcl
module "cloudflare_sts_api" {
  source = "git::https://github.com/cf-contrib/cloudflare-sts.git//deployment/terraform?ref=v0.23.2" # x-release-please-version
  # ...
}
```

```sh
tofu init -upgrade && tofu apply
curl -fsS "$(tofu output -raw cloudflare_sts_api_url)/health/ready"
```

Then, once it's serving, add the input to the same block and apply again:

```hcl
module "cloudflare_sts_api" {
  # ...
  token_rotation = { enabled = true }
}
```

It goes in the module block rather than on the command line: `token_rotation` is
this module's input, and `-var` sets a root variable, so it would either fail as
undeclared or quietly leave rotation off. Putting it in the block is also what
makes it stick for the next apply.

A deployment already on a version that understands `rotation` can enable it in
one apply. The same goes for any later release that adds a policy field.

Upgrading from 0.22: the Worker no longer has a signing key, so delete any
`signing_key_secret` you passed and the secret it named, and drop `audience`
from profiles (use `access` to reach an application behind Access). A provider
for people has no `client_id`: its `audience` is the client ID. See the
[broker's README](../../crates/cloudflare-sts-api#migration-from-022).

Upgrading from cf-sts (before v0.18.0): the Worker's bindings are now
`CLOUDFLARE_STS_API_*` (were `CF_STS_API_*`), minted tokens are named
`cloudflare-sts:…`, and the R2 token type is
`urn:cloudflare-sts:params:oauth:token-type:r2_credentials`. Nothing takes the
old names. `worker_name` now defaults to `cloudflare-sts-api`: if you relied on
the default, set `worker_name = "cf-sts"` to keep the Worker, and with it its
workers.dev URL, which is the OIDC audience. Revoke and the cleanup no longer
touch `cf-sts:*` tokens; the ones left expire on their own, or delete them in
the dashboard. From cf-oidc-exchange (before v0.14.0), the same holds for its
`CF_OIDC_EXCHANGE_API_*` bindings, `cf-oidc:*` tokens and
`worker_name = "cf-oidc-exchange"`.

To deploy a build of your own (an unreleased branch, a fork), build the Worker
and set `worker_dir` to the result. Nothing is downloaded then:

```sh
cd crates/cloudflare-sts-api
worker-build --release   # worker_dir = ".../crates/cloudflare-sts-api/build"
```

## Inputs

| Variable | Required | Default | Description |
|---|---|---|---|
| `account_id` | yes | | Cloudflare account ID. The broker runs here and mints tokens for it. |
| `hostname` | yes | | `<worker_name>.<subdomain>.workers.dev`, or a custom domain. |
| `zone_id` | for a custom domain | `null` | Zone ID of the zone holding a custom-domain `hostname`. |
| `cloudflare_token_secret` | yes | | `{ secret_store_id, secret_name }` of the Secrets Store secret holding the Cloudflare token. With a profile's `bucket`, the token also needs R2 permissions covering what it delegates. |
| `token_rotation` | no | `null` | `{ enabled, every?, overlap? }`: have the broker replace its own Cloudflare token, into the secret above. `every` defaults to `30d`, `overlap` to `25h`; the overlap must be longer than the longest `max_ttl` a profile hands out, and at most half of `every`. The broker's token then needs **Secrets Store Write**. Enable it in a [second apply](#upgrading-and-pinning). See [Rotating the Cloudflare token](../../crates/cloudflare-sts-api#rotating-the-cloudflare-token). |
| `oidc_providers` | yes | | The OIDC issuers the broker trusts: `{ name, issuer, audience?, jwks_uri?, typ? }` each. `audience` defaults to the broker's URL; for [people](../../crates/cloudflare-sts-api#people) it is the client they sign in as. See [Policy](#policy). |
| `profiles` | yes | | What callers may get, in the configuration's format: `name`, `provider`, `forward_claims`, `token`, `bucket`, `access`, `ttl`, `max_ttl`, `enabled`. See [Policy](#policy). |
| `cedar_policy` | yes | | Who gets what: Cedar text with a permit for `Admit::Action::"<provider>"` for every provider, pinning your org, and `Profile::Action::"<name>"` for every profile, each with an `@id`. See [Policy](#policy). |
| `defaults` | no | `{}` | `{ ttl?, max_ttl? }`: the TTLs of profiles that don't set their own. |
| `worker_dir` | no | `null` | A local build (`index.js`, `index_bg.wasm`) to deploy instead of a release. |
| `release_tag` | no | the module's release | Release to deploy, or `latest`. |
| `checksums_sha256` | no | `null` | Expected SHA-256 of the release's `SHA256SUMS`. |
| `worker_name` | no | `cloudflare-sts-api` | Worker script name. |
| `worker_compatibility_date` | no | `2026-08-15` | Workers compatibility date. |

## Outputs

| Output | Description |
|---|---|
| `url` | The broker's URL: use it as the action's `url`. It's the policy's `issuer`, and providers' `audience` unless they name another. |
| `worker_name` | The Worker's script name. |
| `release_tag` | The release deployed, or `local` with `worker_dir`. |
| `worker_modules_sha256` | SHA-256 of each module the Worker version uploads, `index.js` and `index_bg.wasm` (of the wasm's base64 text). The plan shows the modules themselves only as `(sensitive value)`: this says which one changed. |

## Notes

- Workers Logs is enabled so the audit log is kept. Add Logpush if you need it
  for longer.
- Worker bindings are reset on every version upload, so every binding the broker
  needs is declared here.
- `tofu test` plans the module with mocked providers (no credentials needed) and
  checks the bindings (the Cloudflare token's),
  both URL modes and the `hostname` and `zone_id` checks, local artifacts,
  checksums, and the policy built from its variables: what it fills in, what it
  leaves out, its size, and that `token_rotation` reaches the policy naming the
  secret the Worker is bound to, with the periods it would refuse rejected in
  the plan rather than by the broker.
