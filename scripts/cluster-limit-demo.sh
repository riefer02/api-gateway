#!/usr/bin/env bash
#
# Measures what a per-replica rate limit actually means behind a load
# balancer. Start with `just cluster-up`, then run this, then re-run the stack
# with STICKY=true to see the difference.
set -euo pipefail

cd "$(dirname "$0")/.."

# The one experiment that needs a small limit; the others disable it so their
# own measurements are not dominated by 429s.
export TENANT_LIMIT="${TENANT_LIMIT:-6}"

COMPOSE=(docker compose -f deploy/local/compose.yml)
BASE="http://127.0.0.1:${CLUSTER_PORT:-8000}"
TOKEN="dev-local.local-secret"
BODY='{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
JAR="$(mktemp)"
trap 'rm -f "$JAR"' EXIT

# Sticky routing is cookie-based, so a client has to keep the cookie to be
# stuck to a replica. Without a jar every request looks new, and the comparison
# would measure nothing.
COOKIE=()
if [[ "${STICKY:-false}" == "true" ]]; then
  COOKIE=(-c "$JAR" -b "$JAR")
fi

echo "waiting for the cluster"
"${COMPOSE[@]}" up -d --wait --wait-timeout 240 >/dev/null

echo "ensuring the upstream and route exist"
"${COMPOSE[@]}" exec -T gateway /usr/local/bin/api-gateway admin upstream put stub \
  --base-url http://stub:18100 --timeout-ms 30000 >/dev/null
"${COMPOSE[@]}" exec -T gateway /usr/local/bin/api-gateway admin route put demo \
  --prefix /mcp --upstream stub --method POST --rewrite /mcp \
  --tool-policy '{"mode":"off"}' >/dev/null

# A route compiled a moment ago needs one refresh interval to reach every
# replica; a request that lands early is a 404, not a failure.
for _ in $(seq 1 20); do
  if [[ "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/mcp" \
    "${COOKIE[@]}" -H "authorization: Bearer $TOKEN" \
    -H 'content-type: application/json' --data "$BODY")" == "200" ]]; then
    break
  fi
  sleep 0.5
done

sleep 2

echo
echo "sending 24 requests with one API key through the load balancer"
echo "tenant limit is 6/minute per replica, 3 replicas"

allowed=0
refused=0

for _ in $(seq 1 24); do
  status=$(curl -s -o /dev/null -w '%{http_code}' \
    -X POST "$BASE/mcp" "${COOKIE[@]}" \
    -H "authorization: Bearer $TOKEN" \
    -H 'content-type: application/json' \
    --data "$BODY")

  case "$status" in
    200) allowed=$((allowed + 1)) ;;
    429) refused=$((refused + 1)) ;;
    *) echo "unexpected status: $status"; exit 1 ;;
  esac
done

echo
printf 'allowed: %d\nrefused: %d\n' "$allowed" "$refused"
echo

if [[ "${STICKY:-false}" == "true" ]]; then
  echo "sticky routing is on: a client's requests stay on one replica,"
  echo "so the cluster-wide limit is the configured one."
else
  echo "This is the N x effect: each replica enforces its own bucket."
  echo "Re-run with STICKY=true to compare:"
  echo "  STICKY=true just cluster-up && STICKY=true just cluster-limit"
fi
