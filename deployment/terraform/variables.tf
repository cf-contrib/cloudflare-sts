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
  description = "Secrets Store secret holding the Cloudflare token: an account-owned token with \"Account API Tokens Write\", plus R2 permissions covering what profiles' buckets delegate (it creates those credentials and is their parent), plus \"Access: Service Tokens Write\" if any profile has an `access`, plus \"Secrets Store Write\" if token_rotation is enabled (the broker writes its replacement back here). Terraform only references it; the value never enters state."
}

variable "token_rotation" {
  type = object({
    enabled = optional(bool, false)
    every   = optional(string, "30d")
    overlap = optional(string, "25h")
  })
  description = "Opt in to the broker replacing its own Cloudflare token. On the hourly cron it copies the token, writes the copy into the Secrets Store secret above, and deletes the one it replaced `overlap` after the Worker is seen to have picked the copy up; `every` is how old the token may get first. The overlap must outlast the longest `max_ttl` a profile hands out, because deleting the replaced token invalidates the R2 credentials it is the parent of, and be at most half of `every`. Leave unset and the broker never touches its own token. Its token then needs \"Secrets Store Write\". Enable it in a separate apply, after the Worker is already running a version that understands it: see Upgrading."
  default     = null

  # The broker checks these again when it loads the policy, and is the
  # authority; these mirror its bounds so a mistake is a plan error rather than
  # a deployed policy the Worker refuses. `d`, `h`, `m`, `s`, largest first,
  # each at most once, at least one of them.
  #
  # Written as `cond ? ... : true` rather than `null || ...`, and wrapped in
  # `try`: a logical operator that evaluates both sides would otherwise reach
  # into a null `token_rotation`, and `sum([])` on an empty match would fail
  # with its own error instead of the message below.
  validation {
    condition = var.token_rotation == null ? true : try(
      can(regex("^([0-9]+d)?([0-9]+h)?([0-9]+m)?([0-9]+s)?$", var.token_rotation.every))
      && length(regexall("[0-9]+[dhms]", var.token_rotation.every)) > 0
      && sum([for p in regexall("([0-9]+)([dhms])", var.token_rotation.every) : tonumber(p[0]) * lookup({ d = 86400, h = 3600, m = 60, s = 1 }, p[1], 0)]) >= 86400
      && sum([for p in regexall("([0-9]+)([dhms])", var.token_rotation.every) : tonumber(p[0]) * lookup({ d = 86400, h = 3600, m = 60, s = 1 }, p[1], 0)]) <= 31536000
    , false)
    error_message = "token_rotation.every must be a duration between 1d and 365d, largest unit first, such as 30d, 720h or 1d12h."
  }

  validation {
    condition = var.token_rotation == null ? true : try(
      can(regex("^([0-9]+d)?([0-9]+h)?([0-9]+m)?([0-9]+s)?$", var.token_rotation.overlap))
      && length(regexall("[0-9]+[dhms]", var.token_rotation.overlap)) > 0
      && sum([for p in regexall("([0-9]+)([dhms])", var.token_rotation.overlap) : tonumber(p[0]) * lookup({ d = 86400, h = 3600, m = 60, s = 1 }, p[1], 0)]) >= 3600
    , false)
    error_message = "token_rotation.overlap must be a duration of at least 1h, largest unit first, such as 25h or 1d1h."
  }

  # Only meaningful once both parse. A duration that doesn't is reported by its
  # own check above, so this one passes rather than piling on a second message.
  validation {
    condition = var.token_rotation == null ? true : try(
      sum([for p in regexall("([0-9]+)([dhms])", var.token_rotation.overlap) : tonumber(p[0]) * lookup({ d = 86400, h = 3600, m = 60, s = 1 }, p[1], 0)]) * 2
      <= sum([for p in regexall("([0-9]+)([dhms])", var.token_rotation.every) : tonumber(p[0]) * lookup({ d = 86400, h = 3600, m = 60, s = 1 }, p[1], 0)])
    , true)
    error_message = "token_rotation.overlap must be at most half of token_rotation.every."
  }
}

variable "oidc_providers" {
  type = list(object({
    name     = string
    issuer   = string
    audience = optional(string)
    jwks_uri = optional(string)
    typ      = optional(string)
  }))
  description = "The OIDC issuers whose tokens the broker takes: the policy's providers. Each has a name for profiles to refer to, its issuer, the audience its tokens must have (the broker's URL by default, which is what the action asks for), optionally where its keys are, and the typ its tokens must have (such as at+jwt). For one people sign in with, the audience is the client they sign in as. Which of a provider's tokens get in is the `cedar_policy`'s: it must admit every provider. See the broker's README."

  validation {
    condition     = length(var.oidc_providers) > 0
    error_message = "Name at least one provider."
  }
}

variable "profiles" {
  # Untyped: a token policy's resources are flat or nested maps, as Cloudflare
  # takes them, and no one Terraform type holds both. The broker checks them.
  type        = any
  description = "What callers may get: the policy's profiles. A list of objects, each with a name, optionally the forward_claims to show in the audit log, and a token, a bucket, an access (an Access service token), or a mix, as the broker's README describes. Who gets each is the `cedar_policy`'s."

  validation {
    condition     = try(length(var.profiles) > 0 && alltrue([for profile in var.profiles : length(profile.name) > 0]), false)
    error_message = "profiles must be a list of objects, each with a name."
  }
}

variable "cedar_policy" {
  type        = string
  description = "Who gets what, as a Cedar policy: a permit for `Admit::Action::\"<provider>\"` for every provider, pinning your organization, and a permit for `Profile::Action::\"<name>\"` for every profile, each policy with an @id. Usually file(\"$${path.module}/policy.cedar\"). The broker refuses a policy that leaves a provider or a profile without one. See the broker's README."

  validation {
    condition     = trimspace(var.cedar_policy) != ""
    error_message = "cedar_policy must not be empty: without a permit, nobody gets anything."
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
  default     = "v0.23.2" # x-release-please-version
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
