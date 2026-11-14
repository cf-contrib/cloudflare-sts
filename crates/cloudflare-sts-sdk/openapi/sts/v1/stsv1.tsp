// The broker's OAuth contract. It compiles to stsv1.yaml beside it, which
// crates/cloudflare-sts-sdk generates the Rust types, server and client from;
// keep action/src/api.ts, which the action type-checks against, in step.
import "@typespec/http";
import "@typespec/openapi";
import "@typespec/openapi3";
import "@typespec/versioning";

using Http;
using OpenAPI;
using Versioning;

/**
 * Bodies are form-encoded, at most 16 KiB, and errors are OAuth errors (RFC 6749 §5.2),
 * as RFC 8693 and RFC 7009 have it. Every response is `Cache-Control: no-store`, but
 * the discovery endpoints' `200`s.
 *
 * Exchanges an OIDC token for short-lived Cloudflare credentials (RFC 8693 token exchange
 * at `POST /oauth/token`), and revokes them (RFC 7009 at `POST /oauth/revoke`). Clients
 * find the endpoints through its metadata (RFC 8414).
 */
@service(#{ title: "cloudflare-sts" })
@server("https://cloudflare-sts-api.example.com")
@tagMetadata(
  "TokenService",
  #{
    description: "Token exchange and revocation: the OAuth token and revocation endpoints.",
  }
)
@tagMetadata(
  "DiscoveryService",
  #{
    description: "The broker's metadata, public, for clients that find its endpoints.",
  }
)
@versioned(Versions)
namespace STS.v1;

enum Versions {
  v1,
}

model TokenRevocationRequest {
  /**
   * The Cloudflare API token, as the exchange returned it in `access_token`; or, with
   * the `access_service_token` hint, the service token's ID (`access.token_id`).
   */
  @minLength(1)
  @maxLength(8192)
  token: string;

  /**
   * `access_token` (the default, and ignored), or the `access_service_token` URN to
   * revoke an Access service token. Only what the broker minted can be revoked.
   */
  token_type_hint?:
    | "access_token"
    | "urn:cloudflare-sts:params:oauth:token-type:access_service_token";
}

model TokenExchangeRequest {
  grant_type: "urn:ietf:params:oauth:grant-type:token-exchange";

  /** An OIDC token from an issuer the policy names as a provider. */
  @minLength(1)
  @maxLength(8192)
  subject_token: string;

  /** An OIDC token, as `id_token` or `jwt`. */
  subject_token_type:
    | "urn:ietf:params:oauth:token-type:id_token"
    | "urn:ietf:params:oauth:token-type:jwt";

  /**
   * Checked, not used to choose: what's issued is what the profile has. `access_token`,
   * `r2_credentials` or `access_service_token`. Any other is `invalid_target`.
   */
  requested_token_type?: IssuedTokenType;

  /**
   * The profiles to get, as a space-delimited list (RFC 6749 §3.3, RFC 8693 §2.1). The
   * caller must be allowed every one, or the request is `invalid_scope` and nothing is
   * issued. Profiles are combined into one grant: their token policies together, and at
   * most one bucket and one access. If omitted, exactly one profile must match.
   */
  @maxLength(1024)
  scope?: string;

  /**
   * Requested lifetime such as `10m` or `1h`, capped at the profile's `max_ttl`. If
   * omitted, the profile's `ttl`. Below `1m`, or unparseable, is `invalid_request`.
   */
  @maxLength(16)
  ttl?: string;
}

/**
 * What the exchange issues: a Cloudflare API token (`access_token`), R2 credentials
 * alone (`r2_credentials`), or an Access service token alone (`access_service_token`).
 */
union IssuedTokenType {
  "urn:ietf:params:oauth:token-type:access_token",
  "urn:cloudflare-sts:params:oauth:token-type:r2_credentials",
  "urn:cloudflare-sts:params:oauth:token-type:access_service_token",
}

model TokenExchangeResponse {
  /**
   * The Cloudflare API token, absent for a profile with only a bucket or an access.
   */
  access_token?: string;

  /**
   * `access_token` with an `access_token`; without one, `r2_credentials` with a bucket or
   * else `access_service_token`.
   */
  issued_token_type: IssuedTokenType;

  /** `Bearer` with an `access_token`, or `N_A` without one (RFC 8693 §2.2.1). */
  token_type: "Bearer" | "N_A";

  /** Seconds until the token, or the R2 credentials, expire. */
  @minValue(0)
  expires_in: integer;

  /** When the token, or the R2 credentials, expire: Unix time in seconds. */
  expires_at: integer;

  /** The Cloudflare API token's ID, present with `access_token`. */
  token_id?: string;

  /** The Cloudflare account. */
  account_id?: string;

  /** The profiles that were granted, space-delimited (RFC 8693 §2.2.1). */
  scope: string;

  /** The R2 credentials, for a profile with a bucket. */
  bucket?: BucketCredentials;

  /** The Access service token, for a profile with `access`. */
  access?: AccessCredentials;
}

/**
 * A Cloudflare Access service token for the profile's `access.audience`: sent as the
 * `CF-Access-Client-Id` and `CF-Access-Client-Secret` headers. It's created for the job
 * and deleted by revoking it. Cloudflare takes a moment, a few seconds, to honor a
 * new one.
 */
model AccessCredentials {
  /** The service token's ID, which revoking it takes. */
  token_id: string;

  client_id: string;
  client_secret: string;

  /** The application the token is for: the profile's `access.audience`. */
  audience: string;

  expires_on: utcDateTime;
}

/** S3 credentials for the profile's R2 bucket, limited to `prefixes`. They can't be revoked; they expire. */
model BucketCredentials {
  name: string;
  access_key_id: string;
  secret_access_key: string;
  session_token: string;

  /** Filled in from the caller's claims. Empty means the whole bucket. */
  prefixes: string[];

  /** `https://<account_id>.r2.cloudflarestorage.com` */
  endpoint: string;

  expires_on: utcDateTime;
}

/** Authorization Server Metadata (RFC 8414 §2). */
model AuthorizationServerMetadata {
  /** Exactly the `iss` of the broker's tokens, so no trailing slash. */
  issuer: string;

  token_endpoint: url;
  revocation_endpoint: url;

  /** Empty, since there's no authorization endpoint for a response type to be for. */
  response_types_supported: string[];

  /** Token exchange only: `urn:ietf:params:oauth:grant-type:token-exchange`. */
  grant_types_supported: string[];

  /** `none`: callers don't authenticate as clients; the subject token is the proof. */
  token_endpoint_auth_methods_supported?: string[];

  /** `none`: holding the token is the proof. */
  revocation_endpoint_auth_methods_supported?: string[];
}

/** An OAuth error response (RFC 6749 §5.2). */
model Error {
  error: ErrorCode;

  /** What went wrong. */
  error_description: string;
}

/**
 * RFC 6749's error codes (§5.2, and §4.1.2.1 for the broker's own faults) and RFC
 * 8693's `invalid_target`.
 */
enum ErrorCode {
  invalid_request,
  invalid_scope,
  invalid_target,
  unsupported_grant_type,
  server_error,
  temporarily_unavailable,
}

// The errors, as an OAuth error (RFC 6749 §5.2) each. For the caller's own
// mistakes, the description says what was wrong; for the broker's faults it's
// generic, and the broker's logs say why.

/**
 * The caller's mistake: the description says what was wrong. A request that doesn't fit
 * this contract, such as a JSON body, is `invalid_request` too.
 */
@error
model BadRequest {
  @statusCode _: 400;
  @body body: Error;
}

/** The broker is misconfigured or failed (`server_error`); its logs say why. */
@error
model InternalServerError {
  @statusCode _: 500;
  @body body: Error;
}

/** Cloudflare or the subject token's issuer failed (`temporarily_unavailable`); the broker's logs say which. */
@error
model ServiceUnavailable {
  @statusCode _: 503;
  @body body: Error;
}

alias Errors = BadRequest | InternalServerError | ServiceUnavailable;

// A 200 with `T` as its body, described by `Description`.
@doc(Description)
model Ok<T, Description extends valueof string> {
  @statusCode _: 200;
  @body body: T;
}

// A 200 with no body, described by `Description`.
@doc(Description)
model Empty<Description extends valueof string> {
  @statusCode _: 200;
}

/** Issued. A profile with only a bucket returns no `access_token` and `token_type` `N_A`. */
model TokenIssued {
  @statusCode _: 200;
  @header("Cache-Control") cacheControl: "no-store";
  @body body: TokenExchangeResponse;
}

@tag("TokenService")
interface TokenService {
  /**
   * The subject token is in the body, not an `Authorization` header. Which profiles
   * apply follows the policy: every profile named in `scope` must match the caller,
   * otherwise exactly one profile must. Anything unsupported, such as `actor_token`, is
   * refused rather than ignored. An invalid subject token, or one the policy doesn't take,
   * is `invalid_request`, as RFC 8693 §2.2.2 has it; a `requested_token_type` the broker
   * doesn't issue is `invalid_target`, and a `scope` that names an unknown profile, or one
   * the caller can't have, or profiles that can't be combined, is `invalid_scope`.
   */
  @summary("Exchange an OIDC token for a Cloudflare API token and/or R2 credentials.")
  @operationId("exchangeToken")
  @route("/oauth/token")
  @post
  exchangeToken(
    @header contentType: "application/x-www-form-urlencoded",
    @body body: TokenExchangeRequest,
  ): TokenIssued | Errors;

  /**
   * Holding the token is the proof. Answers `200` whether the token was revoked, already
   * gone, never valid, or not one the broker minted, which it never deletes: to the
   * broker, that's an invalid token, which RFC 7009 §2.2 answers with `200` too.
   */
  @summary("Revoke a Cloudflare API token the broker minted.")
  @operationId("revokeToken")
  @route("/oauth/revoke")
  @post
  revokeToken(
    @header contentType: "application/x-www-form-urlencoded",
    @body body: TokenRevocationRequest,
  ):
    | Empty<"Revoked, already gone, never valid, or not the broker's. No body.">
    | Errors;
}

@tag("DiscoveryService")
interface DiscoveryService {
  /** Tokens come from exchange only, so there's no authorization endpoint. */
  @summary("The broker's Authorization Server Metadata (RFC 8414), with its endpoints.")
  @operationId("metadata")
  @route("/.well-known/oauth-authorization-server")
  @get
  getMetadata():
    | Ok<AuthorizationServerMetadata, "The metadata. Cacheable for 5 minutes.">
    | InternalServerError;
}
