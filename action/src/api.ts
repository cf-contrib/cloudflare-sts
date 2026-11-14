// The broker's HTTP contract, as the action uses it: types only, which the action
// type-checks against. The contract is crates/cloudflare-sts-sdk's TypeSpec
// (openapi/sts/v1/stsv1.tsp); keep this file in step.

/** What the presented `subject_token` is: an OIDC token, as `id_token` or `jwt`. */
export type SubjectTokenType = "urn:ietf:params:oauth:token-type:id_token" | "urn:ietf:params:oauth:token-type:jwt";

/**
 * What comes back: a Cloudflare API token, only R2 credentials for a profile without a
 * `token`, or, for another service's audience, a JWT access token (RFC 9068) the broker
 * signed: `access_token`, or `jwt` if that's what was requested.
 */
export type IssuedTokenType =
  | "urn:ietf:params:oauth:token-type:access_token"
  | "urn:cloudflare-sts:params:oauth:token-type:r2_credentials"
  | "urn:cloudflare-sts:params:oauth:token-type:access_service_token"
  | "urn:ietf:params:oauth:token-type:jwt";

/**
 * Body of `POST /oauth/token`, an RFC 8693 token exchange, form-encoded. `scope` is
 * the profiles to get, space-delimited, and `ttl` is the broker's own extension parameter.
 */
export interface TokenExchangeRequest {
  grant_type: "urn:ietf:params:oauth:grant-type:token-exchange";
  subject_token: string;
  subject_token_type: SubjectTokenType;
  /**
   * `https://api.cloudflare.com` (the default) for Cloudflare credentials, or the URL of a
   * service the policy issues the broker's own tokens for.
   */
  audience?: string | undefined;
  requested_token_type?: IssuedTokenType | undefined;
  scope?: string | undefined;
  ttl?: string | undefined;
}

/**
 * `200` response of `POST /oauth/token`. A profile with only a `bucket` has no bearer token,
 * so it returns no `access_token` and `token_type: "N_A"`, with the credentials in `bucket`.
 * For another service's audience, `access_token` is a JWT access token (RFC 9068, `typ`
 * `at+jwt`) the broker signed, verifiable with the keys its metadata
 * (`/.well-known/oauth-authorization-server`, RFC 8414) names.
 */
export interface TokenExchangeResponse {
  access_token?: string;
  issued_token_type: IssuedTokenType;
  token_type: "Bearer" | "N_A";
  /** Seconds until the token, or the R2 credentials, expire. */
  expires_in: number;
  /** Unix time in seconds. */
  expires_at: number;
  /** The Cloudflare API token's ID, present with `access_token`. */
  token_id?: string;
  /** The Cloudflare account, for the Cloudflare audience. */
  account_id?: string;
  scope: string;
  bucket?: BucketCredentials;
  /** The Access service token, for a profile with `access`. */
  access?: AccessCredentials;
}

/**
 * Body of `POST /oauth/revoke`, an RFC 7009 revocation, form-encoded. Answers `200`
 * whether the token was revoked, already gone, never valid, or not one the broker minted,
 * which it never deletes.
 */
export interface TokenRevocationRequest {
  token: string;
  /**
   * `access_token` (the default, and ignored): only Cloudflare API tokens the broker minted
   * can be revoked. With the `access_service_token` URN, `token` is the service token's ID.
   */
  token_type_hint?: "access_token" | "urn:cloudflare-sts:params:oauth:token-type:access_service_token" | undefined;
}

/**
 * A Cloudflare Access service token for `audience`, sent as the `CF-Access-Client-Id` and
 * `CF-Access-Client-Secret` headers. Cloudflare takes a few seconds to honor a new one.
 */
export interface AccessCredentials {
  /** The service token's ID, which revoking it takes. */
  token_id: string;
  client_id: string;
  client_secret: string;
  /** The application the token is for. */
  audience: string;
  /** RFC 3339 timestamp. */
  expires_on: string;
}

/** S3 credentials for the profile's R2 bucket, limited to `prefixes`. They can't be revoked; they expire. */
export interface BucketCredentials {
  /** The bucket's name. */
  name: string;
  access_key_id: string;
  secret_access_key: string;
  session_token: string;
  /** Filled in from the caller's claims. Empty means the whole bucket. */
  prefixes: string[];
  /** `https://<account_id>.r2.cloudflarestorage.com` */
  endpoint: string;
  /** RFC 3339 timestamp. */
  expires_on: string;
}

/**
 * RFC 6749's error codes (§5.2, and §4.1.2.1 for the broker's own faults) and RFC 8693's
 * `invalid_target`.
 */
export type ErrorCode =
  | "invalid_request"
  | "invalid_target"
  | "invalid_scope"
  | "unsupported_grant_type"
  | "server_error"
  | "temporarily_unavailable";

/**
 * Body of every non-2xx response: an OAuth error (RFC 6749 §5.2). 400 for the caller's own
 * mistakes, whose description says what was wrong; 500 or 503 for the broker's faults, whose
 * description is generic.
 */
export interface Error {
  error: ErrorCode;
  error_description: string;
}
