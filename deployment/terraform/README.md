# cloudflare-sts Terraform module

> The Terraform / OpenTofu half of [cloudflare-sts](../..): deploys the released
> broker, a Rust Worker, to Cloudflare, with its bindings, hourly cleanup cron, and
> a workers.dev URL (or, optionally, a custom domain). No `wrangler` or local
> build is needed.

```hcl
module "cloudflare_sts_api" {
  source = "git::https://github.com/cf-contrib/cloudflare-sts.git//deployment/terraform?ref=v0.21.1" # x-release-please-version

  account_id              = var.account_id
  hostname                = "cloudflare-sts-api.example.workers.dev"
  cloudflare_token_secret = { secret_store_id = var.secret_store_id, secret_name = "cloudflare-sts-cloudflare-token" }

  oidc_providers = [
    {
      name   = "com.github.actions"
      issuer = "https://token.actions.githubusercontent.com"
      claims = [{ repository_owner_id = "100000001" }] # pin the provider: your numeric org ID
    },
  ]

  profiles = [
    {
      name   = "example-org/app:ci.deploy"
      claims = [{ repository_id = "200000003", ref = "refs/heads/main", environment = "prod" }] # example-org/app
      token = { policies = [{
        permissions = ["Workers Scripts Write"]
        resources   = { "com.cloudflare.api.account.${var.account_id}" = "*" }
      }] }
    },
  ]
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
- A separate API token for *deploying*, exported as `CLOUDFLARE_API_TOKEN`, with:
  - **Account → Workers Scripts: Edit**
  - **Account → Secrets Store: Edit**, to bind the Cloudflare token's secret, and the signing key's if set
  - **Zone → Workers Routes: Edit** on the broker's zone, only for a custom domain (not tested yet)

  The first two were enough for a workers.dev deploy in testing.
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
Secrets Store; the broker reads it on every request.

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

The policy is three variables, as cloudflare-nix's module takes its providers,
in the policy's own format (see the [broker's README](../../crates/cloudflare-sts-api#policy)):

- `oidc_providers`: the OIDC issuers the broker trusts. Typed, and checked at
  plan time: every provider needs at least one claim set, and none may be empty. `audience` defaults to the
  broker's URL, which is what the action asks for. For people signing in
  through Cloudflare Access, see [People](#people).
- `profiles`: what callers may get. Untyped, because a token policy's
  `resources` are flat in one profile and nested in another, as Cloudflare
  takes them; the plan checks each has a name and a claim set, and the broker
  checks the rest.
- `defaults`: the TTLs of profiles that don't set their own.

The module fills in the rest: the policy's `version`, and its `issuer`, the
broker's URL. Since it's plain HCL, IDs can come from data sources, so none are
hard-coded:

```hcl
  oidc_providers = [{
    name   = "com.github.actions"
    issuer = "https://token.actions.githubusercontent.com"
    claims = [{ repository_owner_id = data.github_organization.org.id }]
  }]

  profiles = [
    {
      name   = "${data.github_repository.app.full_name}:ci.deploy" # from the same repo as its claims
      claims = [{ repository_id = data.github_repository.app.repo_id }]
      token = { policies = [{
        permissions = ["Workers Scripts Write"]
        resources   = { "com.cloudflare.api.account.${var.account_id}" = "*" }
      }] }
    },
    {
      name   = "terraform-state" # every repo gets its own prefix in one shared bucket
      claims = [{ ref = "refs/heads/main" }]
      bucket = {
        name       = "org-terraform-state"
        permission = "object-read-write"
        prefixes   = ["{repository_owner_id}/{repository_id}/"] # filled in by the broker, per job
      }
    },
  ]
```

Bucket prefixes use the broker's own `{claim}` placeholders, which HCL leaves
alone. Don't write `${repository}`: Terraform would try to fill it in and fail
the plan.

A policy kept in a file still works: `profiles = yamldecode(file("${path.module}/policy.yaml")).profiles`.

The policy is bound as `CLOUDFLARE_STS_API_POLICY`, compact JSON. A Worker
variable holds at most 5 KB, and the plan fails on a policy over that. Every
policy change creates a new Worker version.

## People

People sign in to the [CLI](../../crates/cloudflare-sts-cli) through an
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
  redirect_uris = ["http://127.0.0.1:8250/callback"] # where the CLI listens
  emails        = ["alice@example.com", "bob@example.com"]
}

module "cloudflare_sts_api" {
  # ...
  oidc_providers = [
    # ... CI's providers
    {
      name      = "com.cloudflare.access"
      issuer    = module.cloudflare_access_saas_oidc.issuer
      client_id = module.cloudflare_access_saas_oidc.client_id # people's ID tokens' audience
      claims    = [{ iss = module.cloudflare_access_saas_oidc.issuer }]
    },
  ]

  profiles = [
    {
      name     = "infra-admins:tofu-plan"
      provider = "com.cloudflare.access"
      claims   = [{ email = "alice@example.com" }, { email = "bob@example.com" }]
      max_ttl  = "1h"
      bucket   = { name = "org-terraform-state", permission = "object-read-only" }
    },
  ]
}
```

The provider's one claim set pins the application's own issuer; the profiles
name the people, by `email`. Then, on each person's machine:

```sh
cloudflare-sts login --url https://cloudflare-sts-api.example.com
cloudflare-sts exec --url https://cloudflare-sts-api.example.com --profile infra-admins:tofu-plan -- tofu plan
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
curl -fsSL https://github.com/cf-contrib/cloudflare-sts/releases/download/v0.21.1/SHA256SUMS | sha256sum # x-release-please-version
```

Set `release_tag = "latest"` to track the newest release instead.

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
| `signing_key_secret` | for profiles with an `audience` | `null` | `{ secret_store_id, secret_name }` of the Secrets Store secret holding the RSA key the broker signs its own tokens with. See [Tokens for other services](../../crates/cloudflare-sts-api#tokens-for-other-services). |
| `oidc_providers` | yes | | The OIDC issuers the broker trusts: `{ name, issuer, audience?, jwks_uri?, typ?, client_id?, claims }` each. `audience` defaults to the `client_id` [people](../../crates/cloudflare-sts-api#people) sign in as, if there is one, and otherwise to the broker's URL. See [Policy](#policy). |
| `profiles` | yes | | What callers may get, in the policy's format. See [Policy](#policy). |
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
  checks the bindings (the Cloudflare token's, and the signing key's when set),
  both URL modes and the `hostname` and `zone_id` checks, local artifacts,
  checksums, and the policy built from its variables: what it fills in, what it
  leaves out, and its size.
