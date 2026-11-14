# Changelog

## [0.23.0](https://github.com/cf-contrib/cloudflare-sts/compare/v0.22.0...v0.23.0) (2026-11-14)


### ⚠ BREAKING CHANGES

* a provider's client_id (and the audience it filled in), and identity_providers in /.well-known/oauth-authorization-server, are removed. A cf-vault profile that names only the broker's issuer needs oauth2.issuer, oauth2.client_id and the exchange endpoints.
* the `profile` request parameter, the `profile` response field and the action's `profile` input are replaced by `scope`.

### Features

* ask for profiles with a space-delimited scope, several at once ([#128](https://github.com/cf-contrib/cloudflare-sts/issues/128)) ([5d72ac3](https://github.com/cf-contrib/cloudflare-sts/commit/5d72ac3488201eff289b9b8af577798534d79232))
* issue Cloudflare Access service tokens for an application ([#130](https://github.com/cf-contrib/cloudflare-sts/issues/130)) ([2eccef4](https://github.com/cf-contrib/cloudflare-sts/commit/2eccef437ad5a94b8cb4f04ffcc3ddbf91ba40f1))
* keep the broker to STS: no sign-in discovery, no tokens of its own ([#131](https://github.com/cf-contrib/cloudflare-sts/issues/131)) ([ff00ad8](https://github.com/cf-contrib/cloudflare-sts/commit/ff00ad82353cd0fccbf3209077c988963e6efea1))

## [0.22.0](https://github.com/cf-contrib/cloudflare-sts/compare/v0.21.1...v0.22.0) (2026-11-13)


### ⚠ BREAKING CHANGES

* version 3 policies are refused. Split them into config.toml and policy.cedar; the Terraform module's providers and profiles lose `claims` and it takes a `cedar_policy`. See Migration from version 3.
* CLOUDFLARE_STS_API_POLICY is no longer read; a Worker that still has it is refused. Upgrade the Terraform module. A policy change now takes about two minutes and doesn't roll back with the Worker.

### Features

* read the policy from Workers KV, not a Worker variable ([#125](https://github.com/cf-contrib/cloudflare-sts/issues/125)) ([2911688](https://github.com/cf-contrib/cloudflare-sts/commit/2911688daa5d8d75755f2b25d1c2f30d78c3be20))
* TOML configuration and a Cedar policy, in place of claim sets ([#126](https://github.com/cf-contrib/cloudflare-sts/issues/126)) ([826f9f8](https://github.com/cf-contrib/cloudflare-sts/commit/826f9f8056e985171b198992f7a89a78d74acc64))

## [0.21.1](https://github.com/cf-contrib/cloudflare-sts/compare/v0.21.0...v0.21.1) (2026-11-09)


### Bug Fixes

* **ci:** merge with the App token so main gets its CI run ([#117](https://github.com/cf-contrib/cloudflare-sts/issues/117)) ([b4bc8f8](https://github.com/cf-contrib/cloudflare-sts/commit/b4bc8f8a7121eae6484c2f8762f6f0abf7dca8ca))
* **nix:** the package builds its own aws-lc, as nixpkgs links the system one since its November release ([a455ad0](https://github.com/cf-contrib/cloudflare-sts/commit/a455ad05903d2956789fc8912e243302f8ad8dd7))

## [0.21.0](https://github.com/cf-contrib/cloudflare-sts/compare/v0.20.0...v0.21.0) (2026-10-08)


### Features

* keep a sign-in with the provider's refresh tokens ([#101](https://github.com/cf-contrib/cloudflare-sts/issues/101)) ([7a88cdf](https://github.com/cf-contrib/cloudflare-sts/commit/7a88cdffe3eb78d7b266c33bc3543c430d18af52))

## [0.20.0](https://github.com/cf-contrib/cloudflare-sts/compare/v0.19.0...v0.20.0) (2026-10-08)


### Features

* keep the Worker's modules out of the plan ([#99](https://github.com/cf-contrib/cloudflare-sts/issues/99)) ([6a93b32](https://github.com/cf-contrib/cloudflare-sts/commit/6a93b32288f95871b8db15921f9fe6b63c853fab))

## [0.19.0](https://github.com/cf-contrib/cloudflare-sts/compare/v0.18.0...v0.19.0) (2026-10-08)


### ⚠ BREAKING CHANGES

* the Terraform module no longer warns when the broker isn't ready. Add tf-contrib/terraform-http-check with url = "${module.<name>.url}/health/ready" to keep the warning.

### Features

* leave the readiness check to terraform-http-check ([#97](https://github.com/cf-contrib/cloudflare-sts/issues/97)) ([90ac7ce](https://github.com/cf-contrib/cloudflare-sts/commit/90ac7ceb25a72e8a58ba33959e7af8618847c98d))

## [0.18.0](https://github.com/cf-contrib/cloudflare-sts/compare/v0.17.0...v0.18.0) (2026-10-08)


### ⚠ BREAKING CHANGES

* deployment/terraform/modules/access is gone. Use tofu-contrib/terraform-cloudflare-access//modules/saas-oidc with name = "cloudflare-sts" and redirect_uris = ["http://127.0.0.1:8250/callback"], its old defaults, and build the provider from its issuer and client_id outputs.
* nothing takes the old names. The Worker's bindings are CLOUDFLARE_STS_API_* (were CF_STS_API_*), and the CLI reads CLOUDFLARE_STS_CLI_* (was CF_STS_CLI_*). Minted tokens are named cloudflare-sts:…, and revoke and the hourly cleanup no longer touch cf-sts:… tokens. The R2 token type is urn:cloudflare-sts:params:oauth:token-type:r2_credentials. The Terraform module's worker_name defaults to cloudflare-sts-api: set worker_name = "cf-sts" to keep an existing Worker and its workers.dev URL, the OIDC audience. The Access module's name defaults to cloudflare-sts.

### Features

* rename the project cloudflare-sts ([#92](https://github.com/cf-contrib/cloudflare-sts/issues/92)) ([6fed0fc](https://github.com/cf-contrib/cloudflare-sts/commit/6fed0fcca076ee851de570a88ee476dc1196f98a))
* sign people in with terraform-cloudflare-access ([#95](https://github.com/cf-contrib/cloudflare-sts/issues/95)) ([8e08455](https://github.com/cf-contrib/cloudflare-sts/commit/8e08455b993cbd1ee947e84efd727c457d117642))

## [0.17.0](https://github.com/cf-contrib/cf-sts/compare/v0.16.0...v0.17.0) (2026-10-07)


### Features

* keep an Access sign-in for 8h ([#90](https://github.com/cf-contrib/cf-sts/issues/90)) ([4471b5b](https://github.com/cf-contrib/cf-sts/commit/4471b5b3ce3b90349f99a17066f300160c8ace2e)), closes [#53](https://github.com/cf-contrib/cf-sts/issues/53)

## [0.16.0](https://github.com/cf-contrib/cf-sts/compare/v0.15.0...v0.16.0) (2026-10-07)


### Features

* an Access module, for signing people in ([#88](https://github.com/cf-contrib/cf-sts/issues/88)) ([daff6c5](https://github.com/cf-contrib/cf-sts/commit/daff6c5ddb068d1d3a61a38c84d95f2bafc5b02c)), closes [#53](https://github.com/cf-contrib/cf-sts/issues/53)
* ready only while the config checks out ([#87](https://github.com/cf-contrib/cf-sts/issues/87)) ([67ce5bb](https://github.com/cf-contrib/cf-sts/commit/67ce5bbed333a4794b4469628feb60d6d4173cc1))

## [0.15.0](https://github.com/cf-contrib/cf-sts/compare/v0.14.0...v0.15.0) (2026-10-07)


### Features

* the cf-sts CLI, for people ([#85](https://github.com/cf-contrib/cf-sts/issues/85)) ([cb2a4c7](https://github.com/cf-contrib/cf-sts/commit/cb2a4c722d91be4fe0c656002d61eb120a4d6171))

## [0.14.0](https://github.com/cf-contrib/cf-sts/compare/v0.13.0...v0.14.0) (2026-10-07)


### ⚠ BREAKING CHANGES

* nothing takes the old names. The Worker's bindings are CF_STS_API_* (were CF_OIDC_EXCHANGE_API_*). Minted tokens are named cf-sts:…, and revoke and the hourly cleanup no longer touch cf-oidc:… tokens. The R2 token type is urn:cf-sts:params:oauth:token-type:r2_credentials. The Terraform module's worker_name defaults to cf-sts: set worker_name = "cf-oidc-exchange" to keep an existing Worker and its workers.dev URL, the OIDC audience.

### Code Refactoring

* rename the project cf-sts ([#82](https://github.com/cf-contrib/cf-sts/issues/82)) ([147a690](https://github.com/cf-contrib/cf-sts/commit/147a690dad9c0569d2fa48ebc0c365c8ca51571e))

## [0.13.0](https://github.com/cf-contrib/cf-oidc-exchange/compare/v0.12.0...v0.13.0) (2026-10-06)


### Features

* allow : and / in profile names ([d855533](https://github.com/cf-contrib/cf-oidc-exchange/commit/d855533df6fff854304ecd50eb6d6c5a03b3d386)), closes [#78](https://github.com/cf-contrib/cf-oidc-exchange/issues/78)

## [0.12.0](https://github.com/cf-contrib/cf-oidc-exchange/compare/v0.11.0...v0.12.0) (2026-10-05)


### ⚠ BREAKING CHANGES

* the action no longer exports AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN, AWS_SECURITY_TOKEN, AWS_ENDPOINT_URL_S3, AWS_REGION or AWS_DEFAULT_REGION. A step that runs S3 tools sets them from CLOUDFLARE_R2_* itself.

### Features

* export R2 credentials as CLOUDFLARE_R2_*, not AWS_* ([a9cdd33](https://github.com/cf-contrib/cf-oidc-exchange/commit/a9cdd335d4d4c0209a0cdd51ecbfc16f061a54f1)), closes [#74](https://github.com/cf-contrib/cf-oidc-exchange/issues/74)

## [0.11.0](https://github.com/cf-contrib/cf-oidc-exchange/compare/v0.10.0...v0.11.0) (2026-10-04)


### Features

* an OpenID Connect discovery document, for services that read only that ([10195aa](https://github.com/cf-contrib/cf-oidc-exchange/commit/10195aa1cb6f2e97735baeda16d884b8dc092631))

## [0.10.0](https://github.com/cf-contrib/cf-oidc-exchange/compare/v0.9.0...v0.10.0) (2026-10-03)


### ⚠ BREAKING CHANGES

* the module's policy_file and policy_vars variables are gone; pass oidc_providers, profiles and defaults instead, with "com.cloudflare.api.account.${var.account_id}" in place of ${account_id} and the module's audience default in place of ${broker_url}.

### Features

* a provider may name the typ its tokens must have ([49a4374](https://github.com/cf-contrib/cf-oidc-exchange/commit/49a4374a18582b5a0cdac169aeb18675c919668e))
* the Terraform module takes the policy as variables, as cf-nix-cache's does ([45b8100](https://github.com/cf-contrib/cf-oidc-exchange/commit/45b8100a5e5180ff8b12ed261b8a28c33445e4cb))

## [0.9.0](https://github.com/cf-contrib/cf-oidc-exchange/compare/v0.8.0...v0.9.0) (2026-10-03)


### ⚠ BREAKING CHANGES

* workflows pass the broker's URL as url, not broker-url, and a token exchange's requested_token_type and issued_token_type for R2 credentials are urn:cf-oidc-exchange:params:oauth:token-type:r2-credentials.
* log lines have level, event and the event's fields; the matched claims are in claims, and expires_on is expires_at.
* the Worker takes its policy from the CF_OIDC_EXCHANGE_API_POLICY variable, at most 5 KB, which the Terraform module binds; releases no longer have entry.js, and index.js is the main module. A bad policy is logged as its first problem. Unknown routes are a bare 404, and the wrong method a 405.
* policies are version 3, with claims as lists of claim sets; versions 1 and 2 are refused. The access_token subject token type and the repository parameter are gone from /oauth/token, which no longer answers 404.
* the Worker reads its Cloudflare token from CF_OIDC_EXCHANGE_API_CLOUDFLARE_TOKEN, and the Terraform module takes it as cloudflare_token_secret instead of broker_token_secret.
* an invalid policy, an unset account or a broker token that isn't a Secrets Store binding now fails every request with 500 misconfigured, /health/live and /health/ready included, with why logged, rather than only the API's routes.
* error bodies are { "error": code, "message": ... }, as in cf-nix-cache, and the internal code is internal_error. For a caller's own mistake the message says what was wrong; for a fault of the broker's it's generic, with why in the logs. Audit lines record error and message instead of reason and detail.
* GET /healthz is gone. GET /health/live answers 200 while the Worker serves; GET /health/ready answers 200, or 503 with no body when the policy or a secret is wrong or the check takes over 2s.
* the repository is cf-contrib/cf-oidc-exchange, so the action is uses: cf-contrib/cf-oidc-exchange@<version> and the Terraform module's source is .../cf-oidc-exchange.git//deployment/terraform. The Worker's bindings are CF_OIDC_EXCHANGE_API_ACCOUNT_ID, CF_OIDC_EXCHANGE_API_BROKER_TOKEN and CF_OIDC_EXCHANGE_API_SIGNING_KEY (the module sets them). The module's default worker_name is cf-oidc-exchange: set worker_name = "cf-auth" to keep an existing workers.dev hostname.
* the broker is the Rust Worker. Its token exchange and revocation take form-encoded bodies only, as RFC 8693 and RFC 7009 have it; JSON is refused with 400. The Terraform module moved from //packages/cf-oidc-broker/terraform to //deployment/terraform; broker_file is now worker_dir (a worker-build directory) and broker_sha256 is now checksums_sha256 (the SHA-256 of the release's SHA256SUMS). Releases no longer attach broker.js.

### Features

* cf-oidc-jwt, OIDC token verification for Workers ([4b549e7](https://github.com/cf-contrib/cf-oidc-exchange/commit/4b549e7fcbe7615a07f63feb76bb3b276024d6be))
* OIDC only, with cf-nix-cache's claim sets ([d7b0809](https://github.com/cf-contrib/cf-oidc-exchange/commit/d7b08097df1d568a11126cb92fa15d78c746585c))
* port the policy to Rust ([c341106](https://github.com/cf-contrib/cf-oidc-exchange/commit/c341106f482108c04db5ac70d22adafe12a3419c))
* release and deploy the Rust Worker, and remove the TypeScript broker ([9da105c](https://github.com/cf-contrib/cf-oidc-exchange/commit/9da105ccfa4bcc4214656752d4f60f910596236c))
* rename cf-oidc-auth to cf-oidc-exchange ([085f5d9](https://github.com/cf-contrib/cf-oidc-exchange/commit/085f5d9159c4dd1c3140715aca60af0df966fee5))
* the action's input is url, and R2 credentials' token type cf-oidc-exchange's ([bf33175](https://github.com/cf-contrib/cf-oidc-exchange/commit/bf331752364019088e1d87a3c93483f2476df87e))
* the broker's flows in the Rust Worker ([a847ab9](https://github.com/cf-contrib/cf-oidc-exchange/commit/a847ab959e3c327ae4f2a8d6d55a9d45debf2372))


### Code Refactoring

* health endpoints from the SDK, like grpc-rust-template ([d38fdbd](https://github.com/cf-contrib/cf-oidc-exchange/commit/d38fdbde6aa9b96b13aab4b18e7321fd7624ee3b))
* lay the Worker out as cf-nix-cache-api's ([3e816b1](https://github.com/cf-contrib/cf-oidc-exchange/commit/3e816b1bf8774c16ea95990c39c8e8f2ba266ecf))
* log with tracing, as JSON lines ([96ee8c0](https://github.com/cf-contrib/cf-oidc-exchange/commit/96ee8c06ab4692a782e0db6fa082324b68a89e18))
* name the broker token the Cloudflare token, and keep the policy in the config ([c9380eb](https://github.com/cf-contrib/cf-oidc-exchange/commit/c9380eb29207ccd41789212f2a3964b2e1d690b3))
* read the bindings into a Config, as cf-nix-cache does ([c3ede99](https://github.com/cf-contrib/cf-oidc-exchange/commit/c3ede993b8e9406feca3f6fccc682388b2e2fa2e))
* the handler as cf-nix-cache's, with the spec's errors ([3f97217](https://github.com/cf-contrib/cf-oidc-exchange/commit/3f9721744448570657067b3ae9c020b972bdc47a))

## [0.8.0](https://github.com/cf-contrib/cf-oidc-auth/compare/v0.7.0...v0.8.0) (2026-10-02)


### ⚠ BREAKING CHANGES

* version 1 policies are refused. The github: block becomes a list of providers (name, issuer, audience, jwks_uri, claims) with a top-level issuer (the broker's URL); issuer https://github.com means people's GitHub tokens. github.owner_id becomes the provider's claims.repository_owner_id, subject: users a profile for the https://github.com provider, match: is renamed claims: and takes one value or a list, and token.ttl/token.max_ttl move to the profile. See the broker README's migration table.
* POST /v1/actions/token, /v1/users/token and /v1/revoke are removed. Get credentials with an RFC 8693 token exchange at POST /oauth/token and revoke them at POST /oauth/revoke (RFC 7009); the action from this release does. Deploy the broker and upgrade the action together.
* a match pattern may only end in one * after a prefix, such as example-org/*. A bare *, a leading one or one in the middle is refused when the policy loads ("* is only allowed once, at the end, after a prefix").

### Features

* broker-issued tokens for other services, with discovery and JWKS ([#37](https://github.com/cf-contrib/cf-oidc-auth/issues/37)) ([d0bf8f7](https://github.com/cf-contrib/cf-oidc-auth/commit/d0bf8f76234917b7740708999ae703976fbcc992))
* OAuth endpoints: token exchange at /oauth/token, revocation at /oauth/revoke ([bad9004](https://github.com/cf-contrib/cf-oidc-auth/commit/bad90041ebcb06e1b52ce77fc2f1d4120249c6da))
* policy version 2, with identity providers ([#39](https://github.com/cf-contrib/cf-oidc-auth/issues/39)) ([dacaebc](https://github.com/cf-contrib/cf-oidc-auth/commit/dacaebc2e68067c07a69ad537e50f7ce75384831))
* profiles can be switched off with enabled: false ([#35](https://github.com/cf-contrib/cf-oidc-auth/issues/35)) ([dcdfc0f](https://github.com/cf-contrib/cf-oidc-auth/commit/dcdfc0f90388672b50acba110f07e3b8f9798e88))
* stricter match wildcards, and enabled: false on profiles ([#35](https://github.com/cf-contrib/cf-oidc-auth/issues/35)) ([dcdfc0f](https://github.com/cf-contrib/cf-oidc-auth/commit/dcdfc0f90388672b50acba110f07e3b8f9798e88))

## [0.7.0](https://github.com/cf-contrib/cf-oidc-auth/compare/v0.6.0...v0.7.0) (2026-10-01)


### ⚠ BREAKING CHANGES

* `subject: user`, released in 0.6.0, is now `subject: users`, so a profile's subject is also its route. A policy still using `user` fails to load with "subject: must be actions or users".

### Bug Fixes

* name the people subject users, like its route ([#31](https://github.com/cf-contrib/cf-oidc-auth/issues/31)) ([2323713](https://github.com/cf-contrib/cf-oidc-auth/commit/2323713bb47ef39b55344284f0d92ad63bb3317d))

## [0.6.0](https://github.com/cf-contrib/cf-oidc-auth/compare/v0.5.0...v0.6.0) (2026-10-01)


### ⚠ BREAKING CHANGES

* POST /v1/token is removed in favour of POST /v1/actions/token. Actions pinned at 0.5.0 or older get a 404 from this broker; upgrade the action with the broker.

### Features

* let people get credentials with their GitHub token ([#29](https://github.com/cf-contrib/cf-oidc-auth/issues/29)) ([55a552c](https://github.com/cf-contrib/cf-oidc-auth/commit/55a552ce64406e8f477c92b74769b48b438b025f)), closes [#28](https://github.com/cf-contrib/cf-oidc-auth/issues/28)

## [0.5.0](https://github.com/cf-contrib/cf-oidc-auth/compare/v0.4.2...v0.5.0) (2026-09-30)


### Features

* grant R2 access with a buckets list, and ttl on the profile ([#25](https://github.com/cf-contrib/cf-oidc-auth/issues/25)) ([07ed1fd](https://github.com/cf-contrib/cf-oidc-auth/commit/07ed1fd87b284b9001ffe070b415037b62de2c16))
* prefix-scoped R2 temporary credentials in profiles ([#23](https://github.com/cf-contrib/cf-oidc-auth/issues/23)) ([3d293fa](https://github.com/cf-contrib/cf-oidc-auth/commit/3d293fa1eb91473ea30535937fe7c59595ca00c5)), closes [#22](https://github.com/cf-contrib/cf-oidc-auth/issues/22)
* several buckets per profile, exported as AWS profiles ([#27](https://github.com/cf-contrib/cf-oidc-auth/issues/27)) ([82ec113](https://github.com/cf-contrib/cf-oidc-auth/commit/82ec113a87abed3cfd8143cc10db735d1037e21a)), closes [#26](https://github.com/cf-contrib/cf-oidc-auth/issues/26)

## [0.4.2](https://github.com/cf-contrib/cf-oidc-auth/compare/v0.4.1...v0.4.2) (2026-09-30)


### Bug Fixes

* **broker:** ship the policy as policy.json next to broker.js ([#17](https://github.com/cf-contrib/cf-oidc-auth/issues/17)) ([2ff0aed](https://github.com/cf-contrib/cf-oidc-auth/commit/2ff0aed255efe207a8742fe0d714990df98a8cc4))
* consistent names for the Secrets Store ID, bindings, token prefix and wrangler Worker ([#18](https://github.com/cf-contrib/cf-oidc-auth/issues/18)) ([c4b3f86](https://github.com/cf-contrib/cf-oidc-auth/commit/c4b3f86ee4cd8512b770e31369d3594aaa629b9c))
* name the Secrets Store ID secret_store_id and the wrangler Worker cf-oidc-broker ([c4b3f86](https://github.com/cf-contrib/cf-oidc-auth/commit/c4b3f86ee4cd8512b770e31369d3594aaa629b9c))
* rename the broker bindings to CF_OIDC_BROKER_* and the cf-auth: prefix to cf-oidc: ([c4b3f86](https://github.com/cf-contrib/cf-oidc-auth/commit/c4b3f86ee4cd8512b770e31369d3594aaa629b9c))
* **terraform:** name the resources broker and the URL output url ([#20](https://github.com/cf-contrib/cf-oidc-auth/issues/20)) ([1398229](https://github.com/cf-contrib/cf-oidc-auth/commit/1398229f578f91e8b02cf2a039349c1e063ff5b0))
* **terraform:** name the resources this ([#21](https://github.com/cf-contrib/cf-oidc-auth/issues/21)) ([9f2fafe](https://github.com/cf-contrib/cf-oidc-auth/commit/9f2fafec6128acf1d4547ff7467518945e16ffdc))

## [0.4.1](https://github.com/cf-contrib/cf-oidc-auth/compare/v0.4.0...v0.4.1) (2026-09-30)


### Bug Fixes

* rename policy rules to profiles ([#15](https://github.com/cf-contrib/cf-oidc-auth/issues/15)) ([25bd573](https://github.com/cf-contrib/cf-oidc-auth/commit/25bd573e17b7bd68bc66458e73cd3bb4039d13b0))

## [0.4.0](https://github.com/cf-contrib/cf-oidc-auth/compare/v0.3.0...v0.4.0) (2026-09-29)


### Features

* **terraform:** detect workers.dev from hostname ([#13](https://github.com/cf-contrib/cf-oidc-auth/issues/13)) ([56908b9](https://github.com/cf-contrib/cf-oidc-auth/commit/56908b9f114374d9c43920918e0a485b6a2e4538))

## [0.3.0](https://github.com/cf-contrib/cf-auth/compare/v0.2.0...v0.3.0) (2026-09-29)


### ⚠ BREAKING CHANGES

* **terraform:** the module moved from //examples/terraform to //packages/cf-auth-terraform, policy_file has no default, and release_tag defaults to the module's release instead of "latest".

### Features

* **terraform:** ship the Terraform module as packages/cf-auth-terraform ([#9](https://github.com/cf-contrib/cf-auth/issues/9)) ([10a3694](https://github.com/cf-contrib/cf-auth/commit/10a36941028c456ad0aef5426040d6de6a7d7118))

## [0.2.0](https://github.com/cf-contrib/cf-auth/compare/v0.1.0...v0.2.0) (2026-09-29)


### Features

* **action:** export S3-compatible R2 credentials with r2-credentials input ([#7](https://github.com/cf-contrib/cf-auth/issues/7)) ([98d8a43](https://github.com/cf-contrib/cf-auth/commit/98d8a43a2fc308384be5027e3dc3055862ebd1b5))

## 0.1.0 (2026-09-29)


### Features

* GitHub Actions OIDC broker and action for the Cloudflare API ([6109c27](https://github.com/cf-contrib/cf-auth/commit/6109c27a09ab32bf3d3f09425952c0464d97b779))


### Bug Fixes

* restore vitest 4 and start releases at 0.1.0 ([#5](https://github.com/cf-contrib/cf-auth/issues/5)) ([3515144](https://github.com/cf-contrib/cf-auth/commit/351514403aafca511e61bee3d8b552f1e68e7856))
