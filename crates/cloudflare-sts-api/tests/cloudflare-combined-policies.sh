#!/usr/bin/env bash
# Checks, against the real Cloudflare API, what the broker relies on when a request names several
# scopes: that ONE account API token can be created with the token policies of several profiles
# put together, and that it works.
#
# It creates short-lived tokens, checks them, and deletes them again (also when it fails or is
# interrupted). It never prints a token value. Nothing here goes through the broker.
#
#   CLOUDFLARE_ACCOUNT_ID=<id> CLOUDFLARE_API_TOKEN=<token> \
#     crates/cloudflare-sts-api/tests/cloudflare-combined-policies.sh [--permissions "A,B,C"]
#
# CLOUDFLARE_API_TOKEN is an account-owned token with "Account API Tokens Write", the kind the
# broker holds. Use a throwaway account or a token you can revoke: it is only read from the
# environment. The default permissions are account-level ones; pass --permissions with names that
# exist on your account (a name shared by an account and a zone group uses the account one).
#
# Cases:
#   1. two different policies on one token          (what two scopes with a token each become)
#   2. the same policy twice                        (two profiles that grant the same thing)
#   3. one policy per permission given, at least 3  (a longer list, to see where a limit is)
# Case 1 must pass for combining scopes to be safe; 2 and 3 say what to expect at the edges.
set -euo pipefail

API=${CLOUDFLARE_API_BASE:-https://api.cloudflare.com/client/v4}
PERMISSIONS="Workers Scripts Write,Workers KV Storage Write,Workers R2 Storage Write"

while [ $# -gt 0 ]; do
  case $1 in
    --permissions) PERMISSIONS=${2:?--permissions needs a comma-separated list}; shift 2 ;;
    -h | --help) sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

for tool in curl jq; do
  command -v "$tool" >/dev/null || { echo "needs $tool" >&2; exit 2; }
done
: "${CLOUDFLARE_ACCOUNT_ID:?set CLOUDFLARE_ACCOUNT_ID}"
: "${CLOUDFLARE_API_TOKEN:?set CLOUDFLARE_API_TOKEN}"

ACCOUNT=$CLOUDFLARE_ACCOUNT_ID
RESOURCE="com.cloudflare.api.account.$ACCOUNT"
CREATED=() # ids of tokens to delete on the way out

# The token goes in a header file, not on a command line another process could read.
HEADERS=$(mktemp)
chmod 600 "$HEADERS"
printf 'Authorization: Bearer %s\nContent-Type: application/json\n' "$CLOUDFLARE_API_TOKEN" >"$HEADERS"

# call METHOD PATH [BODY]: prints the response body; never the request's secrets.
call() {
  local method=$1 path=$2 body=${3:-}
  if [ -n "$body" ]; then
    curl -sS -X "$method" -H @"$HEADERS" --data "$body" "$API$path"
  else
    curl -sS -X "$method" -H @"$HEADERS" "$API$path"
  fi
}

cleanup() {
  local id status=0
  for id in "${CREATED[@]:-}"; do
    [ -n "$id" ] || continue
    if call DELETE "/accounts/$ACCOUNT/tokens/$id" | jq -e '.success' >/dev/null 2>&1; then
      echo "  deleted token ${id:0:4}…"
    else
      echo "  COULD NOT DELETE token $id: delete it in the dashboard" >&2
      status=1
    fi
  done
  rm -f "$HEADERS"
  return "$status"
}
trap cleanup EXIT

echo "Reading the account's permission groups…"
GROUPS_JSON=$(call GET "/accounts/$ACCOUNT/tokens/permission_groups")
jq -e '.success == true' <<<"$GROUPS_JSON" >/dev/null || {
  echo "could not list permission groups: $(jq -c '.errors' <<<"$GROUPS_JSON")" >&2
  exit 1
}

# The id of the group named $1 whose scope is the account's.
group_id() {
  jq -r --arg name "$1" '
    [.result[] | select(.name == $name)
      | select((.scopes // []) | any(. == "com.cloudflare.api.account"))] | first | .id // empty
  ' <<<"$GROUPS_JSON"
}

IFS=',' read -r -a NAMES <<<"$PERMISSIONS"
IDS=()
for name in "${NAMES[@]}"; do
  id=$(group_id "$name")
  [ -n "$id" ] || { echo "no account-level permission group named \"$name\"; pass --permissions" >&2; exit 2; }
  IDS+=("$id")
done
[ "${#IDS[@]}" -ge 2 ] || { echo "give at least two permissions" >&2; exit 2; }

# policy ID…: one allow policy for the account with those permission groups.
policy() {
  jq -n --arg resource "$RESOURCE" '$ARGS.positional | {
    effect: "allow",
    permission_groups: map({id: .}),
    resources: {($resource): "*"}
  }' --args "$@"
}

EXPIRES=$(date -u -d '+10 minutes' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v+10M +%Y-%m-%dT%H:%M:%SZ)
FAILED_CASE_1=0

# try LABEL POLICY…: creates a token with these policies, checks it, records it for deletion.
try() {
  local label=$1 policies response id value verify
  shift
  policies=$(printf '%s\n' "$@" | jq -s '.')
  response=$(call POST "/accounts/$ACCOUNT/tokens" "$(jq -n \
    --arg name "cf-sts-smoke-$(date +%s)" --arg expires "$EXPIRES" --argjson policies "$policies" \
    '{name: $name, expires_on: $expires, policies: $policies}')")
  if ! jq -e '.success == true' <<<"$response" >/dev/null; then
    echo "  FAIL  $label: Cloudflare refused it: $(jq -c '.errors' <<<"$response")"
    return 1
  fi
  id=$(jq -r '.result.id' <<<"$response")
  value=$(jq -r '.result.value' <<<"$response")
  CREATED+=("$id")
  # The new token, used as itself, must be active.
  verify=$(curl -sS -H "Authorization: Bearer $value" "$API/accounts/$ACCOUNT/tokens/verify" || true)
  if jq -e '.success == true and .result.status == "active"' <<<"$verify" >/dev/null 2>&1; then
    echo "  PASS  $label: accepted ($(jq length <<<"$policies") policies), and the token is active"
  else
    echo "  FAIL  $label: created but not active: $(jq -c '.errors // .result' <<<"$verify" 2>/dev/null)"
    return 1
  fi
}

echo
echo "Case 1: two different policies on one token"
try "two policies" "$(policy "${IDS[0]}")" "$(policy "${IDS[1]}")" || FAILED_CASE_1=1

echo "Case 2: the same policy twice"
try "duplicate policy" "$(policy "${IDS[0]}")" "$(policy "${IDS[0]}")" || true

echo "Case 3: one policy per permission (${#IDS[@]})"
many=()
for id in "${IDS[@]}"; do many+=("$(policy "$id")"); done
try "${#IDS[@]} policies" "${many[@]}" || true

echo
echo "Cleaning up…"
if [ "$FAILED_CASE_1" -eq 1 ]; then
  echo "Case 1 failed: Cloudflare does not take one token with several policies as the broker builds"
  echo "it, so a request for several scopes would fail upstream. Do not rely on combining yet."
  exit 1
fi
echo "Case 1 passed: combining the token policies of several scopes works on this account."
