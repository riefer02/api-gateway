#!/usr/bin/env bash
#
# A slow upstream, then a dead one. Uses Toxiproxy because tc netem is not
# available in the macOS Docker kernel, so the fault is TCP-level and portable.
set -euo pipefail

cd "$(dirname "$0")/.."

export TENANT_LIMIT=0

COMPOSE=(docker compose -f deploy/local/compose.yml)
BASE="http://127.0.0.1:${CLUSTER_PORT:-8000}"
TOX="http://127.0.0.1:${TOXIPROXY_PORT:-8474}"
TOKEN="dev-local.local-secret"
BODY='{"jsonrpc":"2.0","id":1,"method":"tools/list"}'

cleanup() {
  curl -s -X DELETE "$TOX/proxies/stub" >/dev/null 2>&1 || true
}
trap cleanup EXIT

"${COMPOSE[@]}" up -d --wait --wait-timeout 240 >/dev/null

# A dedicated upstream and route, so the healthy demo route is untouched.
"${COMPOSE[@]}" exec -T gateway /usr/local/bin/api-gateway admin upstream put flaky \
  --base-url http://toxiproxy:18101 --timeout-ms 30000 >/dev/null
"${COMPOSE[@]}" exec -T gateway /usr/local/bin/api-gateway admin route put flaky \
  --prefix /flaky --upstream flaky --method POST --rewrite /mcp \
  --request-timeout-ms 1000 --tool-policy '{"mode":"off"}' >/dev/null

cleanup
curl -s -X POST "$TOX/proxies" -H 'content-type: application/json' \
  --data '{"name":"stub","listen":"0.0.0.0:18101","upstream":"stub:18100"}' >/dev/null

call() {
  curl -s -o /tmp/fault-body -w '%{http_code}' -X POST "$BASE/flaky" \
    -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
    --data "$BODY"
}

for _ in $(seq 1 20); do
  [[ "$(call)" == "200" ]] && break
  sleep 0.5
done
sleep 2

echo "baseline:                 $(call)"

curl -s -X POST "$TOX/proxies/stub/toxics" -H 'content-type: application/json' \
  --data '{"name":"latency","type":"latency","attributes":{"latency":3000}}' >/dev/null

echo "slow upstream (3s > 1s deadline): $(call)   (deadline exceeded)"

# The breaker is per replica, so the cluster needs threshold x replicas
# failures before every replica has opened. That multiplication is the point.
replicas="$("${COMPOSE[@]}" ps -q gateway | wc -l | tr -d ' ')"
needed=$((6 * replicas))

# Concurrent, so every replica accumulates its threshold before the first
# cooldown expires and starts letting half-open probes through.
for _ in $(seq 1 "$needed"); do
  curl -s -o /dev/null -X POST "$BASE/flaky" \
    -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
    --data "$BODY" &
done
wait

echo "sent $needed failures ($replicas replicas x threshold 3); sampling 6:"
open=0
body=""
for _ in $(seq 1 6); do
  status="$(call)"
  printf '%s ' "$status"
  if [[ "$status" == "503" ]]; then
    open=$((open + 1))
    body="$(head -c 120 /tmp/fault-body)"
  fi
done
echo
echo "  $open/6 refused by an open circuit"
if [[ -n "$body" ]]; then
  echo "  body: $body"
fi

curl -s -X DELETE "$TOX/proxies/stub/toxics/latency" >/dev/null
echo
echo "toxic removed, waiting out the 2s cooldown"

consecutive=0
for _ in $(seq 1 80); do
  if [[ "$(call)" == "200" ]]; then
    consecutive=$((consecutive + 1))
    [[ "$consecutive" -ge 3 ]] && break
  else
    consecutive=0
  fi
  sleep 0.25
done

if [[ "$consecutive" -ge 3 ]]; then
  echo "recovered:                3 consecutive 200s"
else
  echo "did not recover within 20s"
  exit 1
fi
