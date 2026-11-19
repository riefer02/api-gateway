#!/usr/bin/env bash
#
# What happens to traffic when a replica leaves mid-flight. Graceful (SIGTERM)
# is the default; HARD=true uses SIGKILL for contrast.
set -euo pipefail

cd "$(dirname "$0")/.."

# Measure failover, not the rate limiter.
export TENANT_LIMIT=0

COMPOSE=(docker compose -f deploy/local/compose.yml)
BASE="http://127.0.0.1:${CLUSTER_PORT:-8000}"
TOKEN="dev-local.local-secret"
BODY='{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
OUT="$(mktemp)"
trap 'rm -f "$OUT" "$OUT".*' EXIT

"${COMPOSE[@]}" up -d --wait --wait-timeout 240 >/dev/null

"${COMPOSE[@]}" exec -T gateway /usr/local/bin/api-gateway admin upstream put stub \
  --base-url http://stub:18100 --timeout-ms 30000 >/dev/null
"${COMPOSE[@]}" exec -T gateway /usr/local/bin/api-gateway admin route put demo \
  --prefix /mcp --upstream stub --method POST --rewrite /mcp \
  --tool-policy '{"mode":"off"}' >/dev/null

# Let every replica compile the route before measuring.
for _ in $(seq 1 20); do
  [[ "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/mcp" \
    -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
    --data "$BODY")" == "200" ]] && break
  sleep 0.5
done
sleep 2

victim="$("${COMPOSE[@]}" ps -q gateway | head -1)"
mode="SIGTERM"
if [[ "${HARD:-false}" == "true" ]]; then
  mode="SIGKILL"
fi
workers="${WORKERS:-8}"

echo "replicas: 3   workers: $workers   replica leaving: ${victim:0:12}   mode: $mode"
echo

for worker in $(seq 1 "$workers"); do
  (
    end=$((SECONDS + 6))
    while (( SECONDS < end )); do
      curl -s -o /dev/null -w '%{http_code}\n' -X POST "$BASE/mcp" \
        -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
        --data "$BODY" >> "$OUT.$worker" || echo "000" >> "$OUT.$worker"
      sleep 0.02
    done
  ) &
done

sleep 2

if [[ "$mode" == "SIGKILL" ]]; then
  docker kill "$victim" >/dev/null
else
  docker kill -s TERM "$victim" >/dev/null
fi

wait

echo "statuses during the window:"
cat "$OUT".* | sort | uniq -c | sed 's/^/  /'

echo
echo "recovery probe (10 requests after the window):"
ok=0
for _ in $(seq 1 10); do
  [[ "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/mcp" \
    -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
    --data "$BODY")" == "200" ]] && ok=$((ok + 1))
done
echo "  $ok/10 served"

echo
"${COMPOSE[@]}" up -d --wait --wait-timeout 120 >/dev/null
echo "replica brought back"
