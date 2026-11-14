// @ts-check
/** @typedef {import("./api.js").TokenRevocationRequest} TokenRevocationRequest */
// Revokes the token at job end. Never fails the job: the token expires on its own anyway.
import { brokerURL, input, state, warning } from "./runner.js";

const token = state("token");
const id = state("token_id");
const r2ExpiresOn = state("r2_expires_on");
const accessTokenId = state("access_token_id");

if (r2ExpiresOn) {
  console.log(`cloudflare-sts: R2 temporary credentials can't be revoked; they expire at ${r2ExpiresOn}`);
}

if (token) {
  try {
    const broker = brokerURL(input("url"));
    /** @satisfies {TokenRevocationRequest} */
    const body = { token, token_type_hint: "access_token" };
    // RFC 7009: form-encoded, and 200 whether revoked now or already gone.
    const response = await fetch(new URL("/oauth/revoke", broker), {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(body),
      signal: AbortSignal.timeout(30_000),
    });
    if (response.status === 200) {
      console.log(`cloudflare-sts: revoked token ${id}`);
    } else {
      warning(`cloudflare-sts: revoking token ${id} returned ${response.status}; it expires on its own`);
    }
  } catch (err) {
    warning(
      `cloudflare-sts: revoking token ${id} failed (${err instanceof Error ? err.message : err}); it expires on its own`,
    );
  }
}

if (accessTokenId) {
  try {
    const broker = brokerURL(input("url"));
    // By its ID, which only this job was given: Cloudflare can't say a service token's secret is right.
    const body = {
      token: accessTokenId,
      token_type_hint: "urn:cloudflare-sts:params:oauth:token-type:access_service_token",
    };
    const response = await fetch(new URL("/oauth/revoke", broker), {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(body),
      signal: AbortSignal.timeout(30_000),
    });
    if (response.status === 200) {
      console.log(`cloudflare-sts: revoked Access service token ${accessTokenId}`);
    } else {
      warning(
        `cloudflare-sts: revoking Access service token ${accessTokenId} returned ${response.status}; it expires on its own`,
      );
    }
  } catch (err) {
    warning(
      `cloudflare-sts: revoking Access service token ${accessTokenId} failed (${err instanceof Error ? err.message : err}); it expires on its own`,
    );
  }
}
