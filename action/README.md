# cloudflare-sts action

> The GitHub Action half of [cloudflare-sts](..): exchange the job's OIDC token for
> a short-lived Cloudflare API token and/or R2 credentials, export them, and revoke
> the token when the job ends.

[![CI](https://github.com/cf-contrib/cloudflare-sts/actions/workflows/ci.yml/badge.svg)](https://github.com/cf-contrib/cloudflare-sts/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../LICENSE)

> [!NOTE]
> **Pre-1.0.** Inputs may still change between minor versions.

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: prod
    permissions:
      contents: read
      id-token: write # required: lets the job request an OIDC token
    steps:
      - uses: actions/checkout@v6
      - uses: cf-contrib/cloudflare-sts@v0.21.1 # x-release-please-version
        with:
          url: https://cloudflare-sts-api.example.com
          profile: example-org/app:ci.deploy
      - run: npx wrangler deploy
```

It needs a deployed [broker](../crates/cloudflare-sts-api) whose policy allows this workflow.

## Versions

Pin a release. Before 1.0 there's no floating `v0` tag, because a minor release may contain breaking changes:

```yaml
- uses: cf-contrib/cloudflare-sts@v0.21.1 # x-release-please-version
```

For the strictest setup, pin the commit SHA the tag points to, and let Dependabot's `github-actions` updates keep it current:

```yaml
- uses: cf-contrib/cloudflare-sts@<commit-sha> # vX.Y.Z
```

A floating `v1` tag will follow each release from 1.0 on.

## Inputs

| Input     | Required | Description                                                                                                                                                    |
| --------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `url`     | yes      | Broker base URL, e.g. `https://cloudflare-sts-api.example.com`. Its origin is the OIDC audience and must equal the GitHub provider's `audience` in the policy. |
| `profile` | no       | Policy profile to request (not an AWS profile). Recommended when more than one profile could match.                                                            |
| `ttl`     | no       | Requested lifetime such as `5m` or `1h`. Defaults to the profile's `ttl`, capped at its `max_ttl`.                                                             |

## What it does

- **Main step:**
  - requests an OIDC token for the broker's origin, trying up to 3 times on network errors and `5xx`. Every request, this and the broker's, times out after 30 seconds;
  - asks the broker for a Cloudflare token (not retried, because minting isn't idempotent);
  - masks the token and the OIDC token;
  - exports `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` for the rest of the job. For a profile with only a `bucket` there's no token, and only `CLOUDFLARE_ACCOUNT_ID` is exported;
  - when the profile has a `bucket`, also exports its [S3 credentials](#r2-over-the-s3-api) as `CLOUDFLARE_R2_*`, and masks the secret and session token;
  - logs the token ID, profile and expiry (none of them secret), so a run can be matched to the broker's audit log:

    ```
    cloudflare-sts: minted token 3f2a… (profile example-org/app:ci.deploy, expires 2026-09-28T12:15:00Z)
    cloudflare-sts: issued R2 credentials for bucket org-terraform-state under 100000001/200000003/ (profile example-org:terraform-state, expires 2026-09-28T12:15:00Z)
    ```

- **Post step:** revokes the token, if there is one. It runs even when the job fails. A failed revoke is a warning, not an error: the token expires on its own and the broker's cron deletes it. R2 credentials can't be revoked; the post step logs when they expire:

  ```
  cloudflare-sts: R2 temporary credentials can't be revoked; they expire at 2026-09-28T12:15:00Z
  cloudflare-sts: revoked token 3f2a…
  ```

None of this can be switched off: what's exported is decided by the profile. Exported values are also in the `env` context, so actions that take credentials as inputs can use `${{ env.CLOUDFLARE_API_TOKEN }}`.

## Examples

### With `cloudflare/wrangler-action`

`wrangler-action` sets `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` from its own inputs. If you omit them it overwrites the exported values with empty strings, so pass them explicitly:

```yaml
- uses: cf-contrib/cloudflare-sts@v0.21.1 # x-release-please-version
  with:
    url: https://cloudflare-sts-api.example.com
    profile: example-org/app:ci.deploy
- uses: cloudflare/wrangler-action@v3
  with:
    apiToken: ${{ env.CLOUDFLARE_API_TOKEN }}
    accountId: ${{ env.CLOUDFLARE_ACCOUNT_ID }}
```

### Terraform / OpenTofu apply

```yaml
- uses: cf-contrib/cloudflare-sts@v0.21.1 # x-release-please-version
  with:
    url: https://cloudflare-sts-api.example.com
    profile: example-org/infra:ci.apply
    ttl: 30m
- run: tofu apply -auto-approve # the cloudflare provider reads CLOUDFLARE_API_TOKEN
```

### R2 over the S3 API

When the matched profile has a [`bucket`](../crates/cloudflare-sts-api#buckets), the broker returns temporary R2 credentials for it, limited to its key prefixes. The action exports them under R2 names, and leaves the job's `AWS_*` variables alone:

| Variable                          | Value                                                                                      |
| --------------------------------- | ------------------------------------------------------------------------------------------ |
| `CLOUDFLARE_R2_ACCESS_KEY_ID`     | the access key ID (not secret, not masked)                                                 |
| `CLOUDFLARE_R2_SECRET_ACCESS_KEY` | the secret access key, masked                                                              |
| `CLOUDFLARE_R2_SESSION_TOKEN`     | the session token, masked. The credentials are temporary, so clients need it               |
| `CLOUDFLARE_R2_ENDPOINT`          | `https://<account_id>.r2.cloudflarestorage.com`                                            |
| `CLOUDFLARE_R2_BUCKET`            | the bucket's name                                                                          |
| `CLOUDFLARE_R2_PREFIXES`          | the filled-in prefixes as JSON, e.g. `["100000001/200000003/"]`; `[]` for the whole bucket |
| `CLOUDFLARE_R2_PREFIX`            | the filled-in prefix, e.g. `100000001/200000003/`, if there's exactly one; otherwise empty |

S3 tools read `AWS_*`, so map the credentials in the step that runs them:

```yaml
- uses: cf-contrib/cloudflare-sts@v0.21.1 # x-release-please-version
  with:
    url: https://cloudflare-sts-api.example.com
    profile: example-org:terraform-state
- run: aws s3 cp plan.out "s3://$CLOUDFLARE_R2_BUCKET/${CLOUDFLARE_R2_PREFIX}plan.out"
  env:
    AWS_ACCESS_KEY_ID: ${{ env.CLOUDFLARE_R2_ACCESS_KEY_ID }}
    AWS_SECRET_ACCESS_KEY: ${{ env.CLOUDFLARE_R2_SECRET_ACCESS_KEY }}
    AWS_SESSION_TOKEN: ${{ env.CLOUDFLARE_R2_SESSION_TOKEN }}
    AWS_ENDPOINT_URL_S3: ${{ env.CLOUDFLARE_R2_ENDPOINT }}
    AWS_REGION: auto
```

- **One bucket per profile.** A job that needs two buckets uses two profiles in two jobs, as in [Two scopes: two jobs](#two-scopes-two-jobs): a second run of the action in the same job replaces the first one's `CLOUDFLARE_R2_*`.
- **No revocation.** The credentials last as long as the profile's `ttl` (or the requested `ttl`, capped at `max_ttl`), so keep it short.

### Two scopes: two jobs

```yaml
jobs:
  dns:
    runs-on: ubuntu-latest
    environment: prod
    permissions: { contents: read, id-token: write }
    steps:
      - uses: actions/checkout@v6
      - uses: cf-contrib/cloudflare-sts@v0.21.1 # x-release-please-version
        with: { url: https://cloudflare-sts-api.example.com, profile: example-org/app:ci.dns }
      - run: ./scripts/update-dns.sh

  deploy:
    needs: dns
    runs-on: ubuntu-latest
    environment: prod
    permissions: { contents: read, id-token: write }
    steps:
      - uses: actions/checkout@v6
      - uses: cf-contrib/cloudflare-sts@v0.21.1 # x-release-please-version
        with: { url: https://cloudflare-sts-api.example.com, profile: example-org/app:ci.deploy }
      - run: npx wrangler deploy
```

## Troubleshooting

| Error                                                                        | Cause                                                                                                                                                                                                                         |
| ---------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `OIDC unavailable: add permissions: id-token: write to the job`              | The job can't request an OIDC token. Add the permission. Fork PRs on `pull_request` never get it.                                                                                                                             |
| `OIDC token request failed: <status>`                                        | The runner's token endpoint refused the request, or still failed after 3 tries.                                                                                                                                               |
| `cloudflare-sts broker returned 400 (invalid_request: …)`                    | The broker rejected the OIDC token, usually because `url` doesn't match the GitHub provider's `audience` in the policy; or no profile allows this workflow, or the named `profile` doesn't match. The description says which. |
| `cloudflare-sts broker returned 503 (temporarily_unavailable: …)`            | The Cloudflare API or the subject token's issuer failed; the broker's log (`token.deny`) says which. For a profile with a `bucket`, it's usually a Cloudflare token without enough R2 permissions on it.                      |
| `cloudflare-sts broker returned 500 (server_error: …)`                       | The broker's policy or bindings are invalid. The broker's logs say why.                                                                                                                                                       |
| `cloudflare-sts broker returned 404: the broker doesn't serve /oauth/token…` | `url` isn't the broker, or the broker is from an older release than the action. Deploy the broker from the action's release.                                                                                                  |
| `cloudflare-sts broker returned an invalid response: missing …`              | The broker answered `200` without what the action needs: a broker from another release, or something else at `url`.                                                                                                           |
| `url must use https`                                                         | Plain `http` is only accepted for `localhost`, `127.0.0.1` and `[::1]`.                                                                                                                                                       |
| `AccessDenied` from S3 on some keys                                          | The credentials only cover the bucket's prefixes: keep every key under `$CLOUDFLARE_R2_PREFIX`.                                                                                                                               |

## Limitations

- **R2 credentials can't be revoked.** They expire at the end of their TTL.
- **One token per job.** Every step in a job can read the runner, so a second scope in the same job wouldn't be isolated. Use two jobs.
- **No outputs.** The values are in `env`; outputs would just be a second name for them.
- **Masking isn't isolation.** The token is hidden in logs, but any step in the job, including third-party actions and PR code, can use it until the post step revokes it. Keep profiles for prod behind `environment` protection.
- **Needs a `node24` runner.** The action runs straight from the tag's checkout, with no build step and nothing installed.

## License

[MIT](../LICENSE)
