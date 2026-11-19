#!/usr/bin/env bash
#
# How fast a revocation reaches the other replicas. The credential cache TTL is
# 300s in this stack on purpose: a result in seconds can only come from the
# pg_notify broadcast, not from expiry.
set -euo pipefail

cd "$(dirname "$0")/.."

export TENANT_LIMIT=0

COMPOSE=(docker compose -f deploy/local/compose.yml)
BASE="http://127.0.0.1:${CLUSTER_PORT:-8000}"
BODY='{"jsonrpc":"2.0","id":1,"method":"tools/list"}'

"${COMPOSE[@]}" up -d --wait --wait-timeout 240 >/dev/null

"${COMPOSE[@]}" exec -T gateway /usr/local/bin/api-gateway admin upstream put stub \
  --base-url http://stub:18100 --timeout-ms 30000 >/dev/null
"${COMPOSE[@]}" exec -T gateway /usr/local/bin/api-gateway admin route put demo \
  --prefix /mcp --upstream stub --method POST --rewrite /mcp \
  --tool-policy '{"mode":"off"}' >/dev/null

created="$("${COMPOSE[@]}" exec -T gateway /usr/local/bin/api-gateway admin key create \
  --client client-local 2>/dev/null)"
TOKEN="$(printf '%s\n' "$created" | awk '/^token/{print $3}')"
KEY_ID="${TOKEN%%.*}"

if [[ -z "$TOKEN" ]]; then
  echo "could not create a key"; exit 1
fi

probe() {
  curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/mcp" \
    -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
    --data "$BODY"
}

# Let the route reach every replica.
for _ in $(seq 1 20); do
  [[ "$(probe)" == "200" ]] && break
  sleep 0.5
done
sleep 2

echo "key: ${KEY_ID:0:12}…   cache TTL: 300s"
echo "warming all replicas"
ok=0
for _ in $(seq 1 6); do
  [[ "$(probe)" == "200" ]] && ok=$((ok + 1))
done
echo "  $ok/6 authorized before revocation"

echo
echo "revoking through one replica"
"${COMPOSE[@]}" exec -T gateway /usr/local/bin/api-gateway admin key revoke "$KEY_ID" >/dev/null

start=$(date +%s%N)
for _ in $(seq 1 100); do
  if [[ "$(probe)" == "401" ]]; then break; fi
  sleep 0.1
done
elapsed=$(( ( $(date +%s%N) - start ) / 1000000 ))
status="$(probe)"

echo "  first 401 after ${elapsed}ms   (status now: $status)"
echo
if [[ "$status" == "401" && "$elapsed" -lt 5000 ]]; then
  echo "revocation propagated in ${elapsed}ms, far below the 300s TTL:"
  echo "the pg_notify path did the work."
else
  echo "revocation did not propagate quickly; expected 401 within 5s."
  exit 1
fi
