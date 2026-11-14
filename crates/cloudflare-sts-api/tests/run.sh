#!/usr/bin/env bash
# Runs the integration tests: creates the test secrets in a local Secrets Store,
# and the policy in a local KV namespace,
# starts the Worker as wrangler.toml has it under `wrangler dev`, runs the tests
# against it, and stops it. All keys and tokens are made up and thrown away
# afterwards.
set -euo pipefail
cd "$(dirname "$0")/.."

STORE=00000000000000000000000000000000
PERSIST=.wrangler/integration
LOG=${CLOUDFLARE_STS_API_LOG:-$PWD/.wrangler/integration.log}
trap '[ -n "${DEV:-}" ] && kill "$DEV" 2>/dev/null; wait 2>/dev/null || true' EXIT

rm -rf "$PERSIST" && mkdir -p "$PERSIST"
secret() {
  # --value= keeps a value's leading dashes from being read as a flag.
  wrangler secrets-store secret create "$STORE" --name "$1" --scopes workers --value="$2" --persist-to "$PERSIST" >/dev/null
}
secret cloudflare-token test-cloudflare-token

# The policy: two KV keys, as in a deployment. The Worker holds it for a minute.
kv() {
  wrangler kv key put "$1" --path "$2" --binding CLOUDFLARE_STS_API_POLICY_KV --local --persist-to "$PERSIST" >/dev/null
}
kv config tests/config.toml
kv policy tests/policy.cedar

wrangler dev --persist-to "$PERSIST" --test-scheduled >"$LOG" 2>&1 &
DEV=$!
for _ in $(seq 120); do
  curl -s -o /dev/null http://127.0.0.1:8790/ && break
  kill -0 "$DEV" 2>/dev/null || { cat "$LOG"; exit 1; }
  sleep 1
done

CLOUDFLARE_STS_API_LOG="$LOG" cargo test --features integration --test integration -- --test-threads=1 "$@"
