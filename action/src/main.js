// @ts-check
/** @typedef {import("./api.js").TokenExchangeRequest} TokenExchangeRequest */
/** @typedef {import("./api.js").TokenExchangeResponse} TokenExchangeResponse */
/** @typedef {import("./api.js").Error} BrokerError */
import { brokerURL, fail, idToken, input, mask, waitUntilAdmitted, warning, write } from "./runner.js";

/** Hints for the errors a misconfigured workflow or policy usually produces, by OAuth error code. */
const HINTS = /** @type {Record<string, string>} */ ({
  invalid_request:
    "check that url matches the GitHub provider's audience in the policy, and that the policy allows this workflow",
  server_error: "the broker is misconfigured; check its logs",
  temporarily_unavailable: "Cloudflare or GitHub's OIDC issuer failed; try again",
});

/** A broker that answers 404 isn't one that serves /oauth/token. */
const NOT_FOUND = "the broker doesn't serve /oauth/token; deploy the broker from the same release as the action";

/** Formats a Unix time in seconds like the broker's RFC 3339 timestamps, e.g. `2026-09-28T12:15:00Z`. */
const rfc3339 = (/** @type {number} */ seconds) => new Date(seconds * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");

/**
 * Fails unless every field is a non-empty string, rather than export "undefined".
 * @param {object} obj @param {readonly string[]} fields @param {string} [at]
 */
function requireStrings(obj, fields, at = "") {
  for (const field of fields) {
    const value = /** @type {Record<string, unknown>} */ (obj)[field];
    if (typeof value !== "string" || value === "") {
      throw new Error(`cloudflare-sts broker returned an invalid response: missing ${at}${field}`);
    }
  }
}

try {
  const broker = brokerURL(input("url"));
  const jwt = await idToken(broker.origin);
  mask(jwt);

  /** @type {TokenExchangeRequest} */
  const body = {
    grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
    subject_token: jwt,
    subject_token_type: "urn:ietf:params:oauth:token-type:id_token",
    // The profiles, separated by spaces or newlines, are sent as one space-delimited `scope` (RFC 6749 §3.3).
    scope: input("scopes").split(/\s+/).filter(Boolean).join(" ") || undefined,
    ttl: input("ttl") || undefined,
  };

  // No retry: minting isn't idempotent. A token orphaned by a failed request is removed by the broker's cron cleanup.
  // Form-encoded, as RFC 8693 has it; parameters left unset aren't sent.
  const form = new URLSearchParams();
  for (const [key, value] of Object.entries(body)) if (value !== undefined) form.set(key, value);
  const response = await fetch(new URL("/oauth/token", broker), {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: form,
    signal: AbortSignal.timeout(30_000),
  });
  if (!response.ok) {
    const { error, error_description } = /** @type {Partial<BrokerError>} */ (await response.json().catch(() => ({})));
    const said = [error, error_description].filter(Boolean).join(": ");
    const hint = response.status === 404 ? NOT_FOUND : HINTS[error ?? ""];
    throw new Error(
      `cloudflare-sts broker returned ${response.status}${said ? ` (${said})` : ""}${hint ? `: ${hint}` : ""}`,
    );
  }

  // The action asks for Cloudflare credentials, whose response always names the account.
  const t = /** @type {TokenExchangeResponse & { account_id: string }} */ (await response.json());
  requireStrings(t, ["account_id"]);
  // A profile with only a bucket has no token.
  if (t.access_token !== undefined || t.token_id !== undefined) {
    requireStrings(t, ["access_token", "token_id"]);
    if (!Number.isFinite(t.expires_at))
      throw new Error("cloudflare-sts broker returned an invalid response: missing expires_at");
  }
  const b = t.bucket;
  if (b !== undefined) {
    requireStrings(
      b,
      ["name", "access_key_id", "secret_access_key", "session_token", "endpoint", "expires_on"],
      "bucket.",
    );
    if (!Array.isArray(b.prefixes)) {
      throw new Error("cloudflare-sts broker returned an invalid response: missing bucket.prefixes");
    }
  }
  const a = t.access;
  if (a !== undefined) {
    requireStrings(a, ["token_id", "client_id", "client_secret", "audience", "expires_on"], "access.");
  }
  if (t.access_token === undefined && b === undefined && a === undefined) {
    throw new Error("cloudflare-sts broker returned an invalid response: missing token, bucket and access");
  }

  write("GITHUB_ENV", "CLOUDFLARE_ACCOUNT_ID", t.account_id);
  if (t.access_token !== undefined && t.token_id !== undefined) {
    mask(t.access_token);
    write("GITHUB_ENV", "CLOUDFLARE_API_TOKEN", t.access_token);
    write("GITHUB_STATE", "token", t.access_token); // read by post.js as STATE_token
    write("GITHUB_STATE", "token_id", t.token_id);
    console.log(`cloudflare-sts: minted token ${t.token_id} (scope ${t.scope}, expires ${rfc3339(t.expires_at)})`);
  }

  if (b !== undefined) {
    mask(b.secret_access_key);
    mask(b.session_token);
    // Under R2 names, not AWS_*, so the job's AWS credentials are left alone. A step
    // that runs S3 tools maps them to AWS_* itself.
    write("GITHUB_ENV", "CLOUDFLARE_R2_ACCESS_KEY_ID", b.access_key_id);
    write("GITHUB_ENV", "CLOUDFLARE_R2_SECRET_ACCESS_KEY", b.secret_access_key);
    write("GITHUB_ENV", "CLOUDFLARE_R2_SESSION_TOKEN", b.session_token);
    write("GITHUB_ENV", "CLOUDFLARE_R2_ENDPOINT", b.endpoint);
    write("GITHUB_ENV", "CLOUDFLARE_R2_BUCKET", b.name);
    write("GITHUB_ENV", "CLOUDFLARE_R2_PREFIXES", JSON.stringify(b.prefixes));
    // Only meaningful for exactly one prefix; CLOUDFLARE_R2_PREFIXES has them all.
    write("GITHUB_ENV", "CLOUDFLARE_R2_PREFIX", b.prefixes.length === 1 ? (b.prefixes[0] ?? "") : "");

    write("GITHUB_STATE", "r2_expires_on", b.expires_on);
    const scope = b.prefixes.length > 0 ? ` under ${b.prefixes.join(", ")}` : "";
    console.log(
      `cloudflare-sts: issued R2 credentials for bucket ${b.name}${scope} (scope ${t.scope}, expires ${b.expires_on})`,
    );
  }

  if (a !== undefined) {
    mask(a.client_secret);
    write("GITHUB_ENV", "CF_ACCESS_CLIENT_ID", a.client_id);
    write("GITHUB_ENV", "CF_ACCESS_CLIENT_SECRET", a.client_secret);
    write("GITHUB_STATE", "access_token_id", a.token_id);
    console.log(
      `cloudflare-sts: issued an Access service token for ${a.audience} (scope ${t.scope}, expires ${a.expires_on})`,
    );
    // Cloudflare takes a few seconds to honor it: the job's first request would be turned away.
    if (!(await waitUntilAdmitted(a.audience, a.client_id, a.client_secret))) {
      warning(`cloudflare-sts: Access hasn't admitted the service token for ${a.audience} yet; the job goes on`);
    }
  }
} catch (err) {
  fail(err);
}
