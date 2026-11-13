locals {
  custom_domain = !endswith(var.hostname, ".workers.dev")

  # The broker's URL: the issuer of its own tokens, and the audience of the
  # tokens it takes, unless a provider names another.
  broker_url = "https://${var.hostname}"
}

# Worker script. It's reachable on exactly one URL, the OIDC audience: its
# workers.dev URL, or the custom domain if hostname is one.
resource "cloudflare_worker" "this" {
  account_id = var.account_id
  name       = var.worker_name

  subdomain = {
    enabled = !local.custom_domain
  }

  # The audit log goes to Workers Logs.
  observability = {
    enabled = true
    logs = {
      enabled         = true
      invocation_logs = false
    }
  }
}

locals {
  # The configuration, as the broker reads it from the config key of its KV
  # namespace (JSON is TOML's equal there; Terraform has no TOML encoder). The
  # module fills in what the deployment decides, and leaves out what's unset:
  # the broker takes a missing field, not a null one.
  policy = merge(
    {
      version = 4
      issuer  = local.broker_url
      providers = [
        for provider in var.oidc_providers : {
          for key, value in merge(provider, { audience = coalesce(provider.audience, provider.client_id, local.broker_url) }) :
          key => value if value != null
        }
      ]
      profiles = var.profiles
    },
    { for key, value in { defaults = local.defaults } : key => value if length(value) > 0 },
  )
  defaults    = { for key, value in var.defaults : key => value if value != null }
  config_json = jsonencode(local.policy)
}

# The policy lives in Workers KV, not in a Worker variable (5 KB at most), so it
# can be as long as it needs to be: the configuration under `config`, the Cedar
# policy under `policy`. The Worker reads them on a miss and holds them for a
# minute: a change takes effect within about two, with no new version.
resource "cloudflare_workers_kv_namespace" "policy" {
  account_id = var.account_id
  title      = "${var.worker_name}-policy"
}

resource "cloudflare_workers_kv" "config" {
  account_id   = var.account_id
  namespace_id = cloudflare_workers_kv_namespace.policy.id
  key_name     = "config"
  value        = local.config_json
}

resource "cloudflare_workers_kv" "policy" {
  account_id   = var.account_id
  namespace_id = cloudflare_workers_kv_namespace.policy.id
  key_name     = "policy"
  value        = var.cedar_policy
}

# Upload a new version on every artifact or binding change.
resource "cloudflare_worker_version" "this" {
  account_id         = var.account_id
  worker_id          = cloudflare_worker.this.id
  compatibility_date = var.worker_compatibility_date
  main_module        = "index.js"

  lifecycle {
    precondition {
      condition     = local.release_ok
      error_message = "The release's files don't match its SHA256SUMS, or SHA256SUMS doesn't match checksums_sha256."
    }
  }

  modules = [
    {
      name           = "index.js"
      content_type   = "application/javascript+module"
      content_base64 = sensitive(base64encode(local.index_js))
    },
    {
      name           = "index_bg.wasm"
      content_type   = "application/wasm"
      content_base64 = sensitive(local.wasm_base64)
    },
  ]

  bindings = concat([
    {
      name = "CLOUDFLARE_STS_API_ACCOUNT_ID"
      type = "plain_text"
      text = var.account_id
    },
    {
      name         = "CLOUDFLARE_STS_API_POLICY_KV"
      type         = "kv_namespace"
      namespace_id = cloudflare_workers_kv_namespace.policy.id
    },
    {
      # Only ever from Secrets Store, so the token never enters Terraform state.
      name        = "CLOUDFLARE_STS_API_CLOUDFLARE_TOKEN"
      type        = "secrets_store_secret"
      store_id    = var.cloudflare_token_secret.secret_store_id
      secret_name = var.cloudflare_token_secret.secret_name
    },
    ], var.signing_key_secret == null ? [] : [
    {
      # The key the broker signs its own tokens with, for profiles with an audience.
      name        = "CLOUDFLARE_STS_API_SIGNING_KEY"
      type        = "secrets_store_secret"
      store_id    = var.signing_key_secret.secret_store_id
      secret_name = var.signing_key_secret.secret_name
    },
  ])
}

# Promote the new version to 100% of traffic.
resource "cloudflare_workers_deployment" "this" {
  account_id  = var.account_id
  script_name = cloudflare_worker.this.name
  strategy    = "percentage"

  # The policy is there before the first request: without it every one is a 500.
  depends_on = [cloudflare_workers_kv.config, cloudflare_workers_kv.policy]

  versions = [
    {
      percentage = 100
      version_id = cloudflare_worker_version.this.id
    },
  ]
}

resource "cloudflare_workers_custom_domain" "this" {
  count = local.custom_domain ? 1 : 0

  account_id = var.account_id
  zone_id    = var.zone_id
  hostname   = var.hostname
  service    = cloudflare_worker.this.name

  depends_on = [cloudflare_workers_deployment.this]
}

# Hourly cleanup of expired cloudflare-sts:* tokens.
resource "cloudflare_workers_cron_trigger" "this" {
  account_id  = var.account_id
  script_name = cloudflare_worker.this.name
  schedules   = [{ cron = "17 * * * *" }]

  depends_on = [cloudflare_workers_deployment.this]
}
