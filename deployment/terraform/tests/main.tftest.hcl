# Plans the module with mocked providers: no credentials or network needed.
# Covers the Cloudflare token binding, URL modes, the release and local artifacts, their
# checksums, and the policy the module builds from its variables: what it fills
# in, what it leaves out, and that it's kept in KV, so its size is no limit.
mock_provider "cloudflare" {}
mock_provider "github" {}
mock_provider "http" {} # the release downloads, overridden below

override_data {
  target = data.github_release.this
  values = {
    assets = [
      {
        name                 = "index.js"
        browser_download_url = "https://example.com/index.js"
        content_type         = "application/octet-stream"
        created_at           = "2026-10-02T00:00:00Z"
        id                   = 2
        label                = ""
        node_id              = "RA_test2"
        size                 = 1
        updated_at           = "2026-10-02T00:00:00Z"
        url                  = "https://api.github.com/repos/cf-contrib/cloudflare-sts/releases/assets/2"
      },
      {
        name                 = "index_bg.wasm.base64"
        browser_download_url = "https://example.com/index_bg.wasm.base64"
        content_type         = "application/octet-stream"
        created_at           = "2026-10-02T00:00:00Z"
        id                   = 3
        label                = ""
        node_id              = "RA_test3"
        size                 = 1
        updated_at           = "2026-10-02T00:00:00Z"
        url                  = "https://api.github.com/repos/cf-contrib/cloudflare-sts/releases/assets/3"
      },
      {
        name                 = "SHA256SUMS"
        browser_download_url = "https://example.com/SHA256SUMS"
        content_type         = "application/octet-stream"
        created_at           = "2026-10-02T00:00:00Z"
        id                   = 4
        label                = ""
        node_id              = "RA_test4"
        size                 = 1
        updated_at           = "2026-10-02T00:00:00Z"
        url                  = "https://api.github.com/repos/cf-contrib/cloudflare-sts/releases/assets/4"
      },
    ]
  }
}

# A release whose files match its SHA256SUMS.
override_data {
  target = data.http.index_js
  values = { response_body = "export default {};" }
}

override_data {
  target = data.http.index_bg_wasm
  values = { response_body = "AGFzbQEAAAA=" }
}

override_data {
  target = data.http.sha256sums
  values = {
    response_body = <<-EOT
      9f085b1079ab38f776bbb3930dfd067a838ca3e0483aff8625f88837e8ed964c  index.js
      037e64cdc23d28f2d300b10174f8398968910e7520c8e68ad5eaa581f05a0137  index_bg.wasm.base64
    EOT
  }
}

variables {
  cedar_policy            = <<-EOT
    @id("admit-github") permit (principal, action == Admit::Action::"github", resource) when { context.repository_owner_id == "100000001" };
    @id("allow-workers-deploy") permit (principal, action == Profile::Action::"workers-deploy", resource);
  EOT
  cloudflare_token_secret = { secret_store_id = "00000000000000000000000000000000", secret_name = "cloudflare-sts-cloudflare-token" }
  account_id              = "0123456789abcdef0123456789abcdef"
  hostname                = "cloudflare-sts-api.example.workers.dev"
  oidc_providers = [
    { name = "github", issuer = "https://token.actions.githubusercontent.com" },
  ]
  profiles = [
    {
      name = "workers-deploy"
      token = { policies = [{
        permissions = ["Workers Scripts Write"]
        resources   = { "com.cloudflare.api.account.0123456789abcdef0123456789abcdef" = "*" }
      }] }
    },
  ]
}

run "secrets_store_binding" {
  command = plan


  assert {
    condition = anytrue([
      for b in cloudflare_worker_version.this.bindings :
      b.name == "CLOUDFLARE_STS_API_CLOUDFLARE_TOKEN" && b.type == "secrets_store_secret" && b.secret_name == "cloudflare-sts-cloudflare-token"
    ])
    error_message = "the Cloudflare token should be a Secrets Store binding"
  }

  assert {
    condition     = length([for b in cloudflare_worker_version.this.bindings : b if b.type == "secret_text"]) == 0
    error_message = "no secret_text binding should be created"
  }
}

run "no_signing_key_by_default" {
  command = plan

  assert {
    condition     = length([for b in cloudflare_worker_version.this.bindings : b if b.name == "CLOUDFLARE_STS_API_SIGNING_KEY"]) == 0
    error_message = "the signing key should only be bound when signing_key_secret is set"
  }
}

run "signing_key_binding" {
  command = plan

  variables {
    signing_key_secret = { secret_store_id = "00000000000000000000000000000000", secret_name = "cloudflare-sts-signing-key" }
  }

  assert {
    condition = anytrue([
      for b in cloudflare_worker_version.this.bindings :
      b.name == "CLOUDFLARE_STS_API_SIGNING_KEY" && b.type == "secrets_store_secret" && b.secret_name == "cloudflare-sts-signing-key"
    ])
    error_message = "the signing key should be a Secrets Store binding"
  }
}

run "policy_is_built_from_the_variables" {
  command = plan

  assert {
    condition = anytrue([
      for b in cloudflare_worker_version.this.bindings :
      b.name == "CLOUDFLARE_STS_API_POLICY_KV" && b.type == "kv_namespace"
    ])
    error_message = "the policy should be bound as a KV namespace"
  }

  assert {
    condition     = cloudflare_workers_kv.config.key_name == "config" && cloudflare_workers_kv.config.value == local.config_json
    error_message = "the configuration should be stored under the key `config`, as JSON"
  }

  assert {
    condition     = cloudflare_workers_kv.policy.key_name == "policy" && strcontains(cloudflare_workers_kv.policy.value, "Admit::Action::\"github\"")
    error_message = "the Cedar policy should be stored as given, under the key `policy`"
  }

  assert {
    condition     = jsondecode(local.config_json).version == 4 && jsondecode(local.config_json).profiles[0].name == "workers-deploy"
    error_message = "the policy should be version 4, with the profiles as given"
  }

  assert {
    condition     = !contains(keys(jsondecode(local.config_json).providers[0]), "jwks_uri") && !contains(keys(jsondecode(local.config_json).providers[0]), "typ") && !contains(keys(jsondecode(local.config_json)), "defaults") && !contains(keys(jsondecode(local.config_json).providers[0]), "client_id")
    error_message = "unset fields should be left out, not null: the broker refuses a null"
  }
}

run "takes_a_client_id_as_the_audience" {
  command = plan

  variables {
    oidc_providers = [
      { name = "github", issuer = "https://token.actions.githubusercontent.com" },
      { name = "access", issuer = "https://example.cloudflareaccess.com/cdn-cgi/access/sso/oidc/abc", client_id = "abc" },
    ]
  }

  assert {
    condition     = jsondecode(local.config_json).providers[1].client_id == "abc" && jsondecode(local.config_json).providers[1].audience == "abc"
    error_message = "a client_id should reach the policy, as the provider's audience too"
  }
}

run "rejects_a_client_id_that_isnt_the_audience" {
  command = plan

  variables {
    oidc_providers = [
      { name = "access", issuer = "https://example.cloudflareaccess.com", audience = "https://cloudflare-sts-api.example.com", client_id = "abc" },
    ]
  }

  expect_failures = [var.oidc_providers]
}

run "takes_a_providers_own_audience_jwks_uri_typ_and_defaults" {
  command = plan

  variables {
    oidc_providers = [
      { name = "gitlab", issuer = "https://gitlab.com", audience = "https://cloudflare-sts-api.example.com/", jwks_uri = "https://gitlab.com/oauth/discovery/keys", typ = "at+jwt" },
    ]
    defaults = { ttl = "10m" }
  }

  assert {
    condition     = jsondecode(local.config_json).providers[0].audience == "https://cloudflare-sts-api.example.com/" && jsondecode(local.config_json).providers[0].jwks_uri == "https://gitlab.com/oauth/discovery/keys"
    error_message = "a provider's own audience and jwks_uri should be kept"
  }

  assert {
    condition     = jsondecode(local.config_json).providers[0].typ == "at+jwt"
    error_message = "a provider's typ should reach the policy"
  }

  assert {
    condition     = jsondecode(local.config_json).defaults == { ttl = "10m" }
    error_message = "defaults should hold only what's set"
  }
}

run "rejects_an_empty_cedar_policy" {
  command = plan

  variables {
    cedar_policy = "  \n"
  }

  expect_failures = [var.cedar_policy]
}

run "rejects_a_profile_without_a_name" {
  command = plan

  variables {
    profiles = [{ name = "" }]
  }

  expect_failures = [var.profiles]
}

run "accepts_a_policy_over_5_kb" {
  command = plan

  variables {
    profiles = [
      for i in range(40) : {
        name = "repo-${i}"
        token = { policies = [{
          permissions = ["Workers Scripts Write"]
          resources   = { "com.cloudflare.api.account.0123456789abcdef0123456789abcdef" = "*" }
        }] }
      }
    ]
  }

  assert {
    condition     = length(local.config_json) > 5120
    error_message = "the test policy should be over what a Worker variable holds"
  }
}

run "workers_dev" {
  command = plan

  assert {
    condition     = length(cloudflare_workers_custom_domain.this) == 0 && cloudflare_worker.this.subdomain.enabled
    error_message = "a workers.dev deploy should have no custom domain"
  }

  assert {
    condition     = output.url == "https://cloudflare-sts-api.example.workers.dev"
    error_message = "url should be the workers.dev URL"
  }

  assert {
    condition     = jsondecode(local.config_json).issuer == "https://cloudflare-sts-api.example.workers.dev" && jsondecode(local.config_json).providers[0].audience == "https://cloudflare-sts-api.example.workers.dev"
    error_message = "the policy's issuer and the provider's audience should be the broker's URL"
  }
}

run "custom_domain" {
  command = plan

  variables {
    hostname = "cloudflare-sts-api.example.com"
    zone_id  = "fedcba9876543210fedcba9876543210"
  }

  assert {
    condition     = length(cloudflare_workers_custom_domain.this) == 1 && !cloudflare_worker.this.subdomain.enabled
    error_message = "a custom domain deploy should disable workers.dev"
  }

  assert {
    condition     = output.url == "https://cloudflare-sts-api.example.com"
    error_message = "url should be the custom domain"
  }
}

run "workers_dev_follows_worker_name" {
  command = plan

  variables {
    worker_name = "auth"
    hostname    = "auth.example.workers.dev"
  }

  assert {
    condition     = output.url == "https://auth.example.workers.dev"
    error_message = "a workers.dev hostname matching worker_name should be accepted"
  }
}

run "rejects_a_workers_dev_name_mismatch" {
  command = plan

  variables {
    hostname = "auth.example.workers.dev"
  }

  expect_failures = [var.hostname]
}

run "rejects_a_url" {
  command = plan

  variables {
    hostname = "https://cloudflare-sts-api.example.workers.dev"
  }

  expect_failures = [var.hostname]
}

run "rejects_a_custom_domain_without_zone_id" {
  command = plan

  variables {
    hostname = "cloudflare-sts-api.example.com"
  }

  expect_failures = [var.zone_id]
}

run "rejects_zone_id_on_workers_dev" {
  command = plan

  variables {
    zone_id = "fedcba9876543210fedcba9876543210"
  }

  expect_failures = [var.zone_id]
}

run "uploads_the_release" {
  command = plan

  assert {
    condition     = cloudflare_worker_version.this.main_module == "index.js"
    error_message = "index.js should be the main module"
  }

  assert {
    condition = alltrue([
      for name, type in {
        "index.js"      = "application/javascript+module"
        "index_bg.wasm" = "application/wasm"
      } : anytrue([for m in cloudflare_worker_version.this.modules : m.name == name && m.content_type == type])
    ])
    error_message = "index.js and index_bg.wasm should be uploaded"
  }

  assert {
    condition     = anytrue([for m in cloudflare_worker_version.this.modules : m.name == "index_bg.wasm" && m.content_base64 == "AGFzbQEAAAA="])
    error_message = "the release's base64 wasm should be uploaded as the wasm module"
  }
}

run "pins_the_release" {
  command = plan

  variables {
    checksums_sha256 = "c153336c0d57f29adad2594f0d9203287fc5ba40a8649cfe54fb4120f09fa797"
  }
}

run "rejects_a_checksum_mismatch" {
  command = plan

  variables {
    checksums_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
  }

  expect_failures = [cloudflare_worker_version.this]
}

run "rejects_a_file_that_doesnt_match_sha256sums" {
  command = plan

  override_data {
    target = data.http.index_js
    values = { response_body = "export default { tampered: true };" }
  }

  expect_failures = [cloudflare_worker_version.this]
}

run "local_worker_dir" {
  command = plan

  variables {
    worker_dir = "tests/fixtures/worker"
  }

  assert {
    condition     = length(data.github_release.this) == 0 && length(data.http.index_js) == 0
    error_message = "a local worker_dir should skip the release download"
  }

  assert {
    condition     = anytrue([for m in cloudflare_worker_version.this.modules : m.name == "index_bg.wasm" && m.content_base64 == filebase64("tests/fixtures/worker/index_bg.wasm")])
    error_message = "the local wasm should be uploaded"
  }

  assert {
    condition     = output.release_tag == "local"
    error_message = "release_tag should say local"
  }
}

run "profiles_of_any_shape" {
  command = plan

  # A bucket's prefixes with the broker's {claim} placeholders, which HCL leaves alone, and
  # token resources flat in one profile and nested in another.
  variables {
    profiles = [
      {
        name = "terraform-state"
        ttl  = "30m"
        bucket = {
          name       = "org-terraform-state"
          permission = "object-read-write"
          prefixes   = ["github.com/{repository}/"]
        }
      },
      {
        name = "deploy-with-state"
        token = { policies = [{
          permissions = ["Workers Scripts Write"]
          resources   = { "com.cloudflare.api.account.0123456789abcdef0123456789abcdef" = "*" }
        }] }
        bucket = {
          name       = "org-terraform-state"
          permission = "object-read-write"
          prefixes   = ["{repository_owner_id}/{repository_id}/"]
        }
      },
      {
        name = "every-zone"
        token = { policies = [{
          permissions = ["DNS Write"]
          resources   = { "com.cloudflare.api.account.0123456789abcdef0123456789abcdef" = { "com.cloudflare.api.account.zone.*" = "*" } }
        }] }
      },
    ]
  }

  assert {
    condition     = jsondecode(local.config_json).profiles[0].bucket.prefixes == ["github.com/{repository}/"]
    error_message = "a single-claim placeholder should reach the policy unchanged"
  }

  assert {
    condition     = jsondecode(local.config_json).profiles[1].bucket.prefixes == ["{repository_owner_id}/{repository_id}/"]
    error_message = "multi-claim placeholders should reach the policy unchanged"
  }

  assert {
    condition     = jsondecode(local.config_json).profiles[2].token.policies[0].resources["com.cloudflare.api.account.0123456789abcdef0123456789abcdef"]["com.cloudflare.api.account.zone.*"] == "*"
    error_message = "nested resources should reach the policy beside flat ones"
  }
}
