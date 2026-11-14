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
 * Exchanges an OIDC token for short-lived Cloudflare credentials, or for an access token
 * the broker signs for another service (RFC 8693 token exchange at `POST /oauth/token`;
 * RFC 9068), and revokes Cloudflare tokens (RFC 7009 at `POST /oauth/revoke`). Services
 * find the keys to verify the broker's tokens through its metadata (RFC 8414, or OpenID
 * Connect Discovery for those that only read that).
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
    description: "The broker's metadata and keys, public, for the services that verify its tokens.",
  }
)
@versioned(Versions)
namespace STS.v1;

enum Versions {
  v1,
}

model TokenRevocationRequest {
  /** The Cloudflare API token, as the exchange returned it in `access_token`. */
  @minLength(1)
  @maxLength(8192)
  token: string;

  /** If sent, `access_token`, and ignored: only Cloudflare API tokens the broker minted can be revoked. */
  token_type_hint?: "access_token";
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
   * `https://api.cloudflare.com` for Cloudflare credentials, or the URL of a service
   * the policy issues the broker's own tokens for. Empty is `invalid_request`.
   */
  @maxLength(200)
  audience?: string = "https://api.cloudflare.com";

  /**
   * Checked against the audience, not used to choose: what's issued is what the profile
   * has. For Cloudflare's audience, `access_token` or `r2_credentials`; for a
   * service's, `jwt` or `access_token`, two names for the same JWT. Any other is
   * `invalid_target`.
   */
  requested_token_type?: IssuedTokenType;

  /**
   * The profiles to get, as a space-delimited list (RFC 6749 §3.3, RFC 8693 §2.1). The
   * caller must be allowed every one, or the request is `invalid_scope` and nothing is
   * issued. Profiles for the Cloudflare audience are combined into one grant: their token
   * policies together, and at most one bucket. A profile for another service's audience
   * can't be combined. If omitted, exactly one profile must match.
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
 * alone (`r2_credentials`), or the broker's own JWT access token for a service
 * (`access_token`, or `jwt` if asked for by that name).
 */
union IssuedTokenType {
  "urn:ietf:params:oauth:token-type:access_token",
  "urn:cloudflare-sts:params:oauth:token-type:r2_credentials",
  "urn:ietf:params:oauth:token-type:jwt",
}

model TokenExchangeResponse {
  /**
   * The Cloudflare API token, absent for a profile with only a bucket; or, for a
   * service's audience, the JWT access token (RFC 9068, `typ` `at+jwt`) the broker
   * signed.
   */
  access_token?: string;

  /** `access_token` with an `access_token`, `r2_credentials` without one, or `jwt` as asked for. */
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

  /** The Cloudflare account, for the Cloudflare audience. */
  account_id?: string;

  /** The profiles that were granted, space-delimited (RFC 8693 §2.2.1). */
  scope: string;

  /** The R2 credentials, for a profile with a bucket. */
  bucket?: BucketCredentials;
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

  jwks_uri: url;
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

  /**
   * The broker's own extension: the providers people sign in with for a subject token,
   * those the policy gives a `client_id`. Left out when there are none. Not secret.
   */
  identity_providers?: IdentityProvider[];
}

/**
 * An OpenID Provider people sign in with as a public client, with PKCE, for an ID token
 * the broker takes.
 */
model IdentityProvider {
  /** The policy's name for it, which a client picks it by. */
  name: string;

  /** Its issuer. Its OpenID Connect Discovery document has the endpoints. */
  issuer: string;

  /** The client to sign in as: its ID tokens' `aud`. */
  client_id: string;
}

/** OpenID Provider Metadata (OpenID Connect Discovery 1.0 §3), without an authorization endpoint. */
model OpenIdProviderMetadata {
  /** Exactly the `iss` of the broker's tokens, so no trailing slash. */
  issuer: string;

  jwks_uri: url;

  /** `id_token`, as GitHub's and Kubernetes' issuers say, since Discovery requires one. */
  response_types_supported: string[];

  /** `public`: `sub` is the caller's `sub` from its issuer, the same for every service. */
  subject_types_supported: string[];

  /** `RS256`, what the broker signs its tokens with. */
  id_token_signing_alg_values_supported: string[];
}

/** A JWK Set (RFC 7517 §5): the broker's RSA public key, or none without a signing key. */
model Jwks {
  keys: {
    kty: "RSA";
    n: string;
    e: string;
    kid: string;
    alg: "RS256";
    use: "sig";
  }[];
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
   * is `invalid_request`, as RFC 8693 §2.2.2 has it; an `audience` the broker issues
   * nothing for is `invalid_target`, and a `scope` that names an unknown profile, or one
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
  @summary("The broker's Authorization Server Metadata (RFC 8414), with its keys and endpoints.")
  @operationId("metadata")
  @route("/.well-known/oauth-authorization-server")
  @get
  getMetadata():
    | Ok<AuthorizationServerMetadata, "The metadata. Cacheable for 5 minutes.">
    | InternalServerError;

  /**
   * For services that find an issuer's keys only through OpenID Connect Discovery, such
   * as AWS IAM, Google Cloud Workload Identity Federation and Vault. The broker isn't a
   * full OpenID Provider: tokens come from exchange only, so there's no authorization
   * endpoint. As GitHub's and Kubernetes' issuers do, it publishes what verifying its
   * tokens takes, and the members Discovery requires.
   */
  @summary("The broker's OpenID Provider Metadata (OpenID Connect Discovery 1.0), with its keys.")
  @operationId("openidConfiguration")
  @route("/.well-known/openid-configuration")
  @get
  openidConfiguration():
    | Ok<OpenIdProviderMetadata, "The metadata. Cacheable for 5 minutes.">
    | InternalServerError;

  @summary("The public key the broker signs its own tokens with.")
  @operationId("jwks")
  @route("/.well-known/jwks")
  @get
  jwks():
    | Ok<
        Jwks,
        "A JWK Set. Empty when no signing key is bound. Cacheable for 5 minutes."
      >
    | InternalServerError;
}
