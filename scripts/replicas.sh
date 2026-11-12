#!/usr/bin/env bash
#
# Proves the properties that only appear with more than one replica, using two
# local containers against one database. No cluster required.
#
#   ./scripts/replicas.sh          start, test, then stop
#   KEEP=1 ./scripts/replicas.sh   leave the stack running to poke at it

set -euo pipefail

cd "$(dirname "$0")/.."

# Distinct host ports by default so the harness coexists with anything already
# listening on 8080/9090.
export GATEWAY_PORT="${GATEWAY_PORT:-18080}"
export GATEWAY_ADMIN_PORT="${GATEWAY_ADMIN_PORT:-19090}"
export GATEWAY_B_PORT="${GATEWAY_B_PORT:-18081}"

A="http://127.0.0.1:${GATEWAY_PORT}"
B="http://127.0.0.1:${GATEWAY_B_PORT}"
ADMIN_A="http://127.0.0.1:${GATEWAY_ADMIN_PORT}"
ADMIN_TOKEN="replicas-token-0123456789"
AUTH="Authorization: Bearer ${ADMIN_TOKEN}"

cleanup() {
  if [[ "${KEEP:-0}" != "1" ]]; then
    docker compose --profile replicas down >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

pass() { printf '  PASS  %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; exit 1; }

wait_ready() {
  local url=$1 name=$2
  for _ in $(seq 1 60); do
    if curl -sf -o /dev/null "${url}/ready"; then
      pass "${name} is ready"
      return
    fi
    sleep 0.5
  done
  fail "${name} never became ready"
}

echo "starting two replicas…"
ADMIN_TOKENS="ops:${ADMIN_TOKEN}" \
  docker compose --profile replicas up -d --build >/dev/null

wait_ready "$A" "replica a"
wait_ready "$B" "replica b"

echo
echo "1. an issued key works on both replicas"
KEY=$(docker compose exec -T gateway /usr/local/bin/api-gateway \
  admin key create --client demo-client --scope read 2>/dev/null \
  | awk '/^token/{print $3}')

[[ -n "$KEY" ]] || fail "could not mint a key"

for name in a b; do
  base=$A; [[ $name == b ]] && base=$B
  code=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $KEY" "${base}/swapi/people/1")
  [[ "$code" == "200" ]] || fail "replica ${name} returned ${code}"
  pass "replica ${name} accepted the key"
done

echo
echo "2. a revocation reaches both replicas immediately (LISTEN/NOTIFY)"
KEY_ID=${KEY%%.*}
docker compose exec -T gateway /usr/local/bin/api-gateway \
  admin key revoke "$KEY_ID" >/dev/null 2>&1 || true

for name in a b; do
  base=$A; [[ $name == b ]] && base=$B
  code=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $KEY" "${base}/swapi/people/1")
  [[ "$code" == "401" ]] || fail "replica ${name} still accepts the revoked key (${code})"
  pass "replica ${name} rejected the revoked key"
done

echo
echo "3. a route added on replica a appears on replica b without a restart"

put() {
  local url=$1 body=$2 code
  code=$(curl -s -o /dev/null -w '%{http_code}' -X PUT "$url" \
    -H "$AUTH" -H 'content-type: application/json' -d "$body")
  [[ "$code" == "204" ]] || fail "PUT ${url} returned ${code}"
}

put "${ADMIN_A}/v1/upstreams/replicas-demo" '{"base_url":"https://swapi.dev/api"}'
put "${ADMIN_A}/v1/routes/replicas-demo" \
  '{"path_prefix":"/replicas-demo","methods":["GET"],"upstream_id":"replicas-demo","scopes":["read"]}'

NEW_KEY=$(docker compose exec -T gateway /usr/local/bin/api-gateway \
  admin key create --client demo-client --scope read 2>/dev/null \
  | awk '/^token/{print $3}')

for attempt in $(seq 1 20); do
  code=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer ${NEW_KEY}" \
    "${B}/replicas-demo/people/1")
  [[ "$code" == "200" ]] && break
  sleep 0.5
done

[[ "$code" == "200" ]] || fail "replica b never picked up the new route (${code})"
pass "replica b serves the new route"

echo
echo "all multi-replica properties hold"
echo
echo "note: rate limits and retry budgets are per replica by design. Two replicas"
echo "enforce twice the configured rate; divide your target by the replica count."
