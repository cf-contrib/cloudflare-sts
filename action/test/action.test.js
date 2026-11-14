// @ts-check
// Runs main.js and post.js as the runner would: separate Node processes, with
// INPUT_*, GITHUB_ENV, GITHUB_STATE and the OIDC request variables set.
import { execFile } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { afterEach, describe, expect, it } from "vitest";
import {
  REQUEST_TOKEN,
  STUB_ACCOUNT_ID,
  STUB_BUCKET,
  STUB_R2_PROFILE,
  STUB_TOKEN,
  STUB_TOKEN_ID,
  startStub,
} from "./stub.js";

const run = promisify(execFile);
const SRC = new URL("../src/", import.meta.url);

/** @type {Awaited<ReturnType<typeof startStub>> | undefined} */
let stub;
afterEach(async () => {
  await stub?.close();
  stub = undefined;
});

/** Parses the `KEY<<DELIM\nvalue\nDELIM` format of GITHUB_ENV / GITHUB_STATE. @param {string} path */
function parseCommandFile(path) {
  /** @type {Record<string, string>} */
  const out = {};
  const lines = readFileSync(path, "utf8").split("\n");
  for (let i = 0; i < lines.length; i++) {
    const m = /^([^<]+)<<(.+)$/.exec(lines[i] ?? "");
    if (!m) continue;
    const [, key, eof] = m;
    const value = [];
    while (lines[++i] !== eof) value.push(lines[i]);
    out[/** @type {string} */ (key)] = value.join("\n");
  }
  return out;
}

/**
 * @param {"main.js" | "post.js"} script
 * @param {Record<string, string | undefined>} env
 */
async function action(script, env) {
  const dir = mkdtempSync(join(tmpdir(), "cloudflare-sts-"));
  const files = { GITHUB_ENV: join(dir, "env"), GITHUB_STATE: join(dir, "state") };
  writeFileSync(files.GITHUB_ENV, "");
  writeFileSync(files.GITHUB_STATE, "");
  /** @type {Record<string, string>} */
  const clean = {};
  for (const [k, v] of Object.entries({ PATH: process.env.PATH, ...files, ...env })) if (v !== undefined) clean[k] = v;

  let stdout = "";
  let code = 0;
  try {
    ({ stdout } = await run(process.execPath, [new URL(script, SRC).pathname], { env: clean }));
  } catch (err) {
    const e = /** @type {{ stdout: string, code: number }} */ (err);
    stdout = e.stdout;
    code = e.code;
  }
  return {
    code,
    stdout,
    env: parseCommandFile(files.GITHUB_ENV),
    state: parseCommandFile(files.GITHUB_STATE),
  };
}

/** @param {string} url */
const oidcEnv = (url) => ({
  ACTIONS_ID_TOKEN_REQUEST_URL: `${url}/oidc?api-version=2.0`,
  ACTIONS_ID_TOKEN_REQUEST_TOKEN: REQUEST_TOKEN,
});

describe("main", () => {
  it("mints a token, masks it and exports it", async () => {
    stub = await startStub();
    const r = await action("main.js", {
      ...oidcEnv(stub.url),
      INPUT_URL: `${stub.url}/`,
      INPUT_SCOPES: "workers-deploy",
      INPUT_TTL: " 10m ",
    });

    expect(r.code).toBe(0);
    expect(r.env).toEqual({ CLOUDFLARE_API_TOKEN: STUB_TOKEN, CLOUDFLARE_ACCOUNT_ID: STUB_ACCOUNT_ID });
    expect(r.state).toEqual({ token: STUB_TOKEN, token_id: STUB_TOKEN_ID });

    const out = r.stdout.split("\n");
    const maskAt = out.indexOf(`::add-mask::${STUB_TOKEN}`);
    expect(maskAt).toBeGreaterThanOrEqual(0);
    expect(out.some((l) => l.startsWith("::add-mask::stub-jwt."))).toBe(true);
    expect(r.stdout).toContain(
      `cloudflare-sts: minted token ${STUB_TOKEN_ID} (scope workers-deploy, expires 2026-09-28T12:15:00Z)`,
    );
    // The token value itself only ever appears in the mask command.
    expect(out.filter((l) => l.includes(STUB_TOKEN)).length).toBe(1);

    const oidc = stub.calls.find((c) => c.path === "/oidc");
    expect(oidc).toBeDefined();
    const token = stub.calls.find((c) => c.path === "/oauth/token");
    // The OIDC token goes in the body, as an RFC 8693 subject token, not in a header.
    expect(token?.authorization).toBeUndefined();
    expect(token?.body).toEqual({
      grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
      // The audience is the broker's origin, without the trailing slash.
      subject_token: `stub-jwt.${Buffer.from(stub.url).toString("base64url")}`,
      subject_token_type: "urn:ietf:params:oauth:token-type:id_token",
      scope: "workers-deploy",
      ttl: "10m",
    });
  });

  it("sends several scopes as one space-delimited scope", async () => {
    stub = await startStub();
    const r = await action("main.js", {
      ...oidcEnv(stub.url),
      INPUT_URL: stub.url,
      INPUT_SCOPES: "example-org/app:ci.dns\n  example-org/app:ci.deploy  ",
    });
    expect(r.code).toBe(0);
    const token = stub.calls.find((c) => c.path === "/oauth/token");
    expect(token?.body).toMatchObject({ scope: "example-org/app:ci.dns example-org/app:ci.deploy" });
  });

  it("omits scope and ttl when not given", async () => {
    stub = await startStub();
    const r = await action("main.js", {
      ...oidcEnv(stub.url),
      INPUT_URL: stub.url,
      INPUT_SCOPES: "",
      INPUT_TTL: "",
    });
    expect(r.code).toBe(0);
    expect(stub.calls.find((c) => c.path === "/oauth/token")?.body).toEqual({
      grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
      subject_token: expect.stringMatching(/^stub-jwt\./),
      subject_token_type: "urn:ietf:params:oauth:token-type:id_token",
    });
  });

  /** What a bucket exports. */
  const BUCKET_ENV = {
    CLOUDFLARE_R2_ACCESS_KEY_ID: STUB_BUCKET.access_key_id,
    CLOUDFLARE_R2_SECRET_ACCESS_KEY: STUB_BUCKET.secret_access_key,
    CLOUDFLARE_R2_SESSION_TOKEN: STUB_BUCKET.session_token,
    CLOUDFLARE_R2_ENDPOINT: `https://${STUB_ACCOUNT_ID}.r2.cloudflarestorage.com`,
    CLOUDFLARE_R2_BUCKET: STUB_BUCKET.name,
    CLOUDFLARE_R2_PREFIXES: JSON.stringify(["github.com/example-org/app/"]),
    CLOUDFLARE_R2_PREFIX: "github.com/example-org/app/",
  };

  it("exports R2 credentials, and no API token, for a profile with only a bucket", async () => {
    stub = await startStub();
    const r = await action("main.js", {
      ...oidcEnv(stub.url),
      INPUT_URL: stub.url,
      INPUT_SCOPES: STUB_R2_PROFILE,
    });

    expect(r.code).toBe(0);
    expect(r.env).toEqual({ CLOUDFLARE_ACCOUNT_ID: STUB_ACCOUNT_ID, ...BUCKET_ENV });
    expect(r.state).toEqual({ r2_expires_on: STUB_BUCKET.expires_on });
    expect(r.stdout).toContain(
      "cloudflare-sts: issued R2 credentials for bucket org-terraform-state under github.com/example-org/app/ (scope smoke-r2, expires 2026-09-28T12:15:00Z)",
    );
    expect(r.stdout).not.toContain("minted token");
    // The secrets only ever appear in the mask commands.
    const out = r.stdout.split("\n");
    for (const secret of [STUB_BUCKET.secret_access_key, STUB_BUCKET.session_token]) {
      expect(out.filter((l) => l.includes(secret))).toEqual([`::add-mask::${secret}`]);
    }
  });

  it("exports both for a profile with a token and a bucket", async () => {
    stub = await startStub({ tokenFields: { bucket: STUB_BUCKET } });
    const r = await action("main.js", { ...oidcEnv(stub.url), INPUT_URL: stub.url });
    expect(r.code).toBe(0);
    expect(r.env).toEqual({
      CLOUDFLARE_API_TOKEN: STUB_TOKEN,
      CLOUDFLARE_ACCOUNT_ID: STUB_ACCOUNT_ID,
      ...BUCKET_ENV,
    });
    expect(r.state).toEqual({
      token: STUB_TOKEN,
      token_id: STUB_TOKEN_ID,
      r2_expires_on: STUB_BUCKET.expires_on,
    });
  });

  it.each([[[]], [["a/", "b/"]]])("exports an empty CLOUDFLARE_R2_PREFIX for prefixes %j", async (prefixes) => {
    stub = await startStub({ tokenFields: { bucket: { ...STUB_BUCKET, prefixes } } });
    const r = await action("main.js", { ...oidcEnv(stub.url), INPUT_URL: stub.url });
    expect(r.code).toBe(0);
    expect(r.env).toMatchObject({
      CLOUDFLARE_R2_BUCKET: STUB_BUCKET.name,
      CLOUDFLARE_R2_PREFIXES: JSON.stringify(prefixes),
      CLOUDFLARE_R2_PREFIX: "",
    });
  });

  it("exports no AWS variables for a bucket", async () => {
    stub = await startStub({ tokenFields: { bucket: STUB_BUCKET } });
    const r = await action("main.js", { ...oidcEnv(stub.url), INPUT_URL: stub.url });
    expect(r.code).toBe(0);
    expect(Object.keys(r.env).filter((k) => k.startsWith("AWS_"))).toEqual([]);
  });

  it("exports no R2 variables when the profile has no bucket", async () => {
    stub = await startStub();
    const r = await action("main.js", { ...oidcEnv(stub.url), INPUT_URL: stub.url });
    expect(Object.keys(r.env).some((k) => k.startsWith("AWS_") || k.startsWith("CLOUDFLARE_R2_"))).toBe(false);
  });

  it.each([
    ["access_token", { access_token: undefined }],
    ["token_id", { token_id: undefined }],
    ["expires_at", { expires_at: undefined }],
    ["account_id", { account_id: undefined }],
    ["token and bucket", { access_token: undefined, token_id: undefined }],
    ["bucket.name", { bucket: { ...STUB_BUCKET, name: undefined } }],
    ["bucket.session_token", { bucket: { ...STUB_BUCKET, session_token: undefined } }],
    ["bucket.secret_access_key", { bucket: { ...STUB_BUCKET, secret_access_key: "" } }],
    ["bucket.prefixes", { bucket: { ...STUB_BUCKET, prefixes: undefined } }],
  ])("fails clearly when the broker response lacks %s", async (field, tokenFields) => {
    stub = await startStub({ tokenFields });
    const r = await action("main.js", { ...oidcEnv(stub.url), INPUT_URL: stub.url });
    expect(r.code).toBe(1);
    expect(r.stdout).toContain(`::error::cloudflare-sts broker returned an invalid response: missing ${field}`);
    expect(r.env).toEqual({});
    expect(r.state).toEqual({});
  });

  it("explains a missing id-token permission", async () => {
    const r = await action("main.js", { INPUT_URL: "https://cloudflare-sts-api.example.com" });
    expect(r.code).toBe(1);
    expect(r.stdout).toContain("::error::OIDC unavailable: add `permissions: id-token: write` to the job");
  });

  it("requires url", async () => {
    const r = await action("main.js", {});
    expect(r.code).toBe(1);
    expect(r.stdout).toContain("::error::Input required and not supplied: url");
  });

  it("refuses plain-http brokers that aren't loopback", async () => {
    const r = await action("main.js", { INPUT_URL: "http://cloudflare-sts-api.example.com" });
    expect(r.code).toBe(1);
    expect(r.stdout).toContain("url must use https");
  });

  it("fails with a hint when the broker denies the request", async () => {
    stub = await startStub({ tokenStatus: 400 });
    const r = await action("main.js", { ...oidcEnv(stub.url), INPUT_URL: stub.url });
    expect(r.code).toBe(1);
    expect(r.stdout).toContain(
      "::error::cloudflare-sts broker returned 400 (invalid_request: no profile matches the token): check that url matches",
    );
    expect(r.env).toEqual({});
    expect(r.state).toEqual({});
  });

  it("fails with a hint when the broker is older than the action", async () => {
    stub = await startStub({ tokenStatus: 404 });
    const r = await action("main.js", { ...oidcEnv(stub.url), INPUT_URL: stub.url });
    expect(r.code).toBe(1);
    expect(r.stdout).toContain("::error::cloudflare-sts broker returned 404: the broker doesn't serve /oauth/token");
  });

  it("retries a flaky OIDC endpoint", async () => {
    stub = await startStub({ oidcStatuses: [503] });
    const r = await action("main.js", { ...oidcEnv(stub.url), INPUT_URL: stub.url });
    expect(r.code).toBe(0);
    expect(stub.calls.filter((c) => c.path === "/oidc").length).toBe(2);
  });
});

describe("post", () => {
  it("revokes the minted token", async () => {
    stub = await startStub();
    const r = await action("post.js", {
      INPUT_URL: stub.url,
      STATE_token: STUB_TOKEN,
      STATE_token_id: STUB_TOKEN_ID,
    });
    expect(r.code).toBe(0);
    expect(r.stdout).toContain(`cloudflare-sts: revoked token ${STUB_TOKEN_ID}`);
    expect(stub.calls).toEqual([
      // RFC 7009: the token in a form body, not a header.
      {
        method: "POST",
        path: "/oauth/revoke",
        authorization: undefined,
        body: { token: STUB_TOKEN, token_type_hint: "access_token" },
      },
    ]);
  });

  it("only logs when the R2 credentials expire for a profile with only a bucket", async () => {
    stub = await startStub();
    const r = await action("post.js", { INPUT_URL: stub.url, STATE_r2_expires_on: STUB_BUCKET.expires_on });
    expect(r.code).toBe(0);
    expect(r.stdout).toContain(
      "cloudflare-sts: R2 temporary credentials can't be revoked; they expire at 2026-09-28T12:15:00Z",
    );
    expect(stub.calls).toEqual([]);
  });

  it("logs the R2 expiry and revokes the token for a profile with both", async () => {
    stub = await startStub();
    const r = await action("post.js", {
      INPUT_URL: stub.url,
      STATE_token: STUB_TOKEN,
      STATE_token_id: STUB_TOKEN_ID,
      STATE_r2_expires_on: STUB_BUCKET.expires_on,
    });
    expect(r.stdout).toContain("they expire at 2026-09-28T12:15:00Z");
    expect(r.stdout).toContain(`cloudflare-sts: revoked token ${STUB_TOKEN_ID}`);
  });

  it("does nothing when main didn't mint", async () => {
    stub = await startStub();
    const r = await action("post.js", { INPUT_URL: stub.url });
    expect(r.code).toBe(0);
    expect(stub.calls).toEqual([]);
  });

  it("warns instead of failing when revocation fails", async () => {
    stub = await startStub({ revokeStatus: 502 });
    const r = await action("post.js", {
      INPUT_URL: stub.url,
      STATE_token: STUB_TOKEN,
      STATE_token_id: STUB_TOKEN_ID,
    });
    expect(r.code).toBe(0);
    expect(r.stdout).toContain(
      "::warning::cloudflare-sts: revoking token stub-token-id returned 502; it expires on its own",
    );
  });

  it("warns instead of failing when the broker is unreachable", async () => {
    const r = await action("post.js", { INPUT_URL: "http://127.0.0.1:9", STATE_token: STUB_TOKEN });
    expect(r.code).toBe(0);
    expect(r.stdout).toContain("::warning::cloudflare-sts: revoking token");
  });
});
