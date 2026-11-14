// @ts-check
// A stand-in for both the runner's OIDC endpoint and the broker.
// Used by the action tests, and run standalone by CI's clean-checkout smoke test:
//   node action/test/stub.js   (listens on $PORT, default 8787)
import { createServer } from "node:http";

export const REQUEST_TOKEN = "stub-request-token";
export const STUB_TOKEN = "stub-cloudflare-token";
export const STUB_TOKEN_ID = "stub-token-id";
export const STUB_ACCOUNT_ID = "0123456789abcdef0123456789abcdef";
export const STUB_BUCKET = {
  name: "org-terraform-state",
  access_key_id: "stub-r2-access-key-id",
  secret_access_key: "stub-r2-secret-access-key",
  session_token: "stub-r2-session-token",
  prefixes: ["github.com/example-org/app/"],
  endpoint: `https://${STUB_ACCOUNT_ID}.r2.cloudflarestorage.com`,
  expires_on: "2026-09-28T12:15:00Z",
};
export const STUB_ACCESS = {
  token_id: "stub-access-token-id",
  client_id: "stub-client-id.access",
  client_secret: "stub-client-secret",
  expires_on: "2026-09-28T12:15:00Z",
};
const ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token";
const ACCESS_SERVICE_TOKEN = "urn:cloudflare-sts:params:oauth:token-type:access_service_token";
const R2_CREDENTIALS = "urn:cloudflare-sts:params:oauth:token-type:r2_credentials";
/** A profile the stub answers as one with only a bucket: no token, just STUB_BUCKET. */
export const STUB_R2_PROFILE = "smoke-r2";
/** A profile the stub answers as one with only an Access service token, for the stub itself as the application. */
export const STUB_ACCESS_PROFILE = "smoke-access";

/**
 * @typedef {{ method: string, path: string, authorization?: string, body?: unknown }} Call
 * @param {{ port?: number, tokenStatus?: number, revokeStatus?: number, oidcStatuses?: number[], tokenFields?: Record<string, unknown>, accessRefusals?: number }} [options]
 *   `tokenFields` overrides fields of the 200 token response; `undefined` removes one.
 *   `accessRefusals` is how many requests with a service token the stub, as the application, turns away with a 403
 *   before it admits them: Cloudflare takes a moment to honor a new one.
 */
export function startStub({
  port = 0,
  tokenStatus = 200,
  revokeStatus = 200,
  oidcStatuses = [],
  tokenFields = {},
  accessRefusals = 0,
} = {}) {
  let refusals = accessRefusals;
  /** @type {Call[]} */
  const calls = [];
  const oidc = [...oidcStatuses];

  const server = createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", "http://stub");
    let raw = "";
    for await (const chunk of req) raw += chunk;
    const form = req.headers["content-type"] === "application/x-www-form-urlencoded";
    const body = !raw ? undefined : form ? Object.fromEntries(new URLSearchParams(raw)) : JSON.parse(raw);
    calls.push({ method: req.method ?? "", path: url.pathname, authorization: req.headers.authorization, body });

    /** @param {number} status @param {unknown} [json] */
    const send = (status, json) => {
      res.writeHead(status, json === undefined ? {} : { "content-type": "application/json" });
      res.end(json === undefined ? undefined : JSON.stringify(json));
    };

    if (req.method === "GET" && url.pathname === "/oidc") {
      const status = oidc.shift() ?? 200;
      if (status !== 200) return send(status, { message: "stub failure" });
      if (req.headers.authorization !== `bearer ${REQUEST_TOKEN}`) return send(401, { message: "bad request token" });
      return send(200, {
        value: `stub-jwt.${Buffer.from(url.searchParams.get("audience") ?? "").toString("base64url")}`,
      });
    }
    if (req.method === "POST" && url.pathname === "/oauth/token") {
      const exchange = body?.grant_type === "urn:ietf:params:oauth:grant-type:token-exchange";
      const idToken = body?.subject_token_type === "urn:ietf:params:oauth:token-type:id_token";
      if (!exchange) return send(400, { error: "unsupported_grant_type", error_description: "stub" });
      if (!idToken) return send(400, { error: "invalid_request", error_description: "stub" });
      if (!String(body?.subject_token).startsWith("stub-jwt."))
        return send(400, { error: "invalid_request", error_description: "invalid token: not a JWT" });
      // Not a broker that serves the route, so no OAuth error.
      if (tokenStatus === 404) return send(404);
      if (tokenStatus !== 200)
        return send(tokenStatus, { error: "invalid_request", error_description: "no profile matches the token" });
      // 2026-09-28T12:15:00Z, like the stub bucket's expires_on.
      const expires = { expires_in: 900, expires_at: 1790597700 };
      const r2 = { ...expires, issued_token_type: R2_CREDENTIALS, token_type: "N_A", account_id: STUB_ACCOUNT_ID };
      if (body?.scope === STUB_R2_PROFILE) {
        return send(200, { ...r2, scope: STUB_R2_PROFILE, bucket: STUB_BUCKET, ...tokenFields });
      }
      if (body?.scope === STUB_ACCESS_PROFILE) {
        return send(200, {
          ...expires,
          issued_token_type: ACCESS_SERVICE_TOKEN,
          token_type: "N_A",
          account_id: STUB_ACCOUNT_ID,
          scope: STUB_ACCESS_PROFILE,
          access: { ...STUB_ACCESS, audience: `http://${req.headers.host}` },
          ...tokenFields,
        });
      }
      return send(200, {
        access_token: STUB_TOKEN,
        issued_token_type: ACCESS_TOKEN,
        token_type: "Bearer",
        ...expires,
        token_id: STUB_TOKEN_ID,
        account_id: STUB_ACCOUNT_ID,
        scope: body?.scope ?? "default",
        ...tokenFields,
      });
    }
    if (req.method === "POST" && url.pathname === "/oauth/revoke") {
      if (!body?.token) return send(400, { error: "invalid_request", error_description: "stub" });
      return send(body.token === STUB_TOKEN || body.token === STUB_ACCESS.token_id ? revokeStatus : 200);
    }
    // The application the stub stands in for: Access turns a request away until it honors the token.
    if (req.method === "GET" && url.pathname === "/") {
      if (!req.headers["cf-access-client-id"] || refusals-- > 0) return send(403);
      return send(200, { ok: true });
    }
    send(404);
  });

  return new Promise(
    /** @param {(stub: { url: string, calls: Call[], close: () => Promise<void> }) => void} resolve */
    (resolve) => {
      server.listen(port, "127.0.0.1", () => {
        const address = /** @type {import("node:net").AddressInfo} */ (server.address());
        resolve({
          url: `http://127.0.0.1:${address.port}`,
          calls,
          close: () => new Promise((done) => server.close(() => done())),
        });
      });
    },
  );
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const stub = await startStub({ port: Number(process.env.PORT ?? 8787) });
  console.log(`stub listening on ${stub.url}`);
  process.on("SIGTERM", () => {
    for (const call of stub.calls) console.log(JSON.stringify({ ...call, authorization: undefined }));
    process.exit(0);
  });
}
