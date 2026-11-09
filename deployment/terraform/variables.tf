variable "account_id" {
  type        = string
  description = "Cloudflare account ID. The broker runs here and mints tokens for this account."
}

variable "hostname" {
  type        = string
  description = "The broker's hostname, which is also the OIDC audience: <worker_name>.<subdomain>.workers.dev, or a custom domain such as cloudflare-sts-api.example.com (needs zone_id)."

  validation {
    condition     = can(regex("^[a-z0-9-]+(\\.[a-z0-9-]+)+$", var.hostname))
    error_message = "hostname must be a bare lowercase hostname, without a scheme, port or path."
  }

  validation {
    condition     = !endswith(var.hostname, ".workers.dev") || (startswith(var.hostname, "${var.worker_name}.") && length(split(".", var.hostname)) == 4)
    error_message = "A workers.dev hostname must be ${var.worker_name}.<subdomain>.workers.dev: Cloudflare serves the Worker under its name."
  }
}

variable "zone_id" {
  type        = string
  description = "Zone ID of the zone that holds a custom-domain hostname. Not used for workers.dev."
  default     = null

  validation {
    condition     = (var.zone_id == null) == endswith(var.hostname, ".workers.dev")
    error_message = "Set zone_id for a custom domain, and not for a workers.dev hostname."
  }
}

variable "cloudflare_token_secret" {
  type = object({
    secret_store_id = string
    secret_name     = string
  })
  description = "Secrets Store secret holding the Cloudflare token: an account-owned token with \"Account API Tokens Write\", plus R2 permissions covering what profiles' buckets delegate (it creates those credentials and is their parent). Terraform only references it; the value never enters state."
}

variable "signing_key_secret" {
  type = object({
    secret_store_id = string
    secret_name     = string
  })
  description = "Secrets Store secret holding the RSA private key (PKCS#8 PEM, at least 2048 bits, e.g. from `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072`) the broker signs its own tokens with. Needed only for profiles with an audience. Terraform only references it; the value never enters state."
  default     = null
}

variable "oidc_providers" {
  type = list(object({
    name      = string
    issuer    = string
    audience  = optional(string)
    jwks_uri  = optional(string)
    typ       = optional(string)
    client_id = optional(string)
    claims    = list(map(string))
  }))
  description = "The OIDC issuers whose tokens the broker takes: the policy's providers. Each has a name for profiles to refer to, its issuer, the audience its tokens must have (the broker's URL by default, which is what the action asks for), optionally where its keys are, the typ its tokens must have (such as at+jwt), and, for one people sign in with, the client_id they sign in as, which is then its audience; and the claim sets every token from it must match one of. See the broker's README."

  validation {
    condition     = length(var.oidc_providers) > 0
    error_message = "Name at least one provider."
  }

  validation {
    condition     = alltrue([for provider in var.oidc_providers : length(provider.claims) > 0 && alltrue([for set in provider.claims : length(set) > 0])])
    error_message = "Every provider needs at least one claim set, pinning it to your organization, and no claim set may be empty."
  }

  validation {
    condition     = alltrue([for provider in var.oidc_providers : provider.audience == null || provider.client_id == null || provider.audience == provider.client_id])
    error_message = "A provider with a client_id has it as its audience: leave audience out."
  }
}

variable "profiles" {
  # Untyped: a token policy's resources are flat or nested maps, as Cloudflare
  # takes them, and no one Terraform type holds both. The broker checks them.
  type        = any
  description = "What callers may get: the policy's profiles. A list of objects, each with a name, claim sets, and a token, a bucket or a service's audience, as the broker's README describes."

  validation {
    condition     = try(length(var.profiles) > 0 && alltrue([for profile in var.profiles : length(profile.name) > 0 && length(profile.claims) > 0]), false)
    error_message = "profiles must be a list of objects, each with a name and at least one claim set."
  }
}

variable "defaults" {
  type = object({
    ttl     = optional(string)
    max_ttl = optional(string)
  })
  description = "The TTLs of profiles that don't set their own, as durations such as 15m or 1h. Otherwise the broker's own: 15m, and at most 1h."
  default     = {}
}

variable "release_tag" {
  type        = string
  description = "cloudflare-sts release to deploy, e.g. v1.2.3, or \"latest\". Defaults to the release this module comes from."
  default     = "v0.21.1" # x-release-please-version
}

variable "worker_dir" {
  type        = string
  description = "Path to a locally built Worker: a directory with index.js and index_bg.wasm, as worker-build --release writes them. Deploys it instead of downloading a release."
  default     = null
}

variable "checksums_sha256" {
  type        = string
  description = "Expected SHA-256 of the release's SHA256SUMS, which every downloaded file is checked against. Set it to pin the artifacts."
  default     = null
}

variable "worker_name" {
  type        = string
  description = "Cloudflare Worker script name."
  default     = "cloudflare-sts-api"
}

variable "worker_compatibility_date" {
  type        = string
  description = "Workers runtime compatibility date."
  default     = "2026-08-15"
}
