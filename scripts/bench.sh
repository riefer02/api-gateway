#!/usr/bin/env bash
#
# Measures gateway overhead against the stub upstream.
#
# Prerequisites: Postgres is up (`just db-up`) and .env has DATABASE_URL and
# DEV_API_KEY_SECRET. Everything else is built and run by this script.

set -euo pipefail

cd "$(dirname "$0")/.."

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  . ./.env
  set +a
fi

: "${DEV_API_KEY_SECRET:?DEV_API_KEY_SECRET must be set (see .env.example)}"
: "${DATABASE_URL:?DATABASE_URL must be set (see .env.example)}"

PORT="${PORT:-8080}"
STUB_PORT="${STUB_PORT:-18080}"
DURATION="${DURATION:-10}"
CONCURRENCY="${CONCURRENCY:-50}"
TOKEN="dev-local.${DEV_API_KEY_SECRET}"

BIN="./target/release/api-gateway"
STUB="./target/release/examples/stub_upstream"
LOADGEN="./target/release/examples/loadgen"

echo "building release binaries…"
cargo build --release --quiet --bin api-gateway --example stub_upstream --example loadgen

cleanup() {
  [[ -n "${GATEWAY_PID:-}" ]] && kill "$GATEWAY_PID" 2>/dev/null || true
  [[ -n "${STUB_PID:-}" ]] && kill "$STUB_PID" 2>/dev/null || true
}
trap cleanup EXIT

STUB_PORT="$STUB_PORT" "$STUB" >/dev/null 2>&1 &
STUB_PID=$!

# High limits so the run measures proxy overhead rather than intended shedding.
LOG_LEVEL="${BENCH_LOG_LEVEL:-warn}" \
RATE_LIMIT_IP_PER_MINUTE=10000000 \
RATE_LIMIT_TENANT_PER_MINUTE=10000000 \
  "$BIN" serve >/tmp/api-gateway-bench.log 2>&1 &
GATEWAY_PID=$!

echo "waiting for the gateway…"
for _ in $(seq 1 60); do
  if curl -sf -o /dev/null "http://127.0.0.1:${PORT}/health"; then break; fi
  sleep 0.25
done

"$BIN" admin upstream put benchmark \
  --base-url "http://127.0.0.1:${STUB_PORT}" --timeout-ms 5000 >/dev/null
"$BIN" admin route put benchmark \
  --prefix /bench --upstream benchmark --scope read >/dev/null

sleep 3  # let the route table poll pick it up

echo
echo "baseline (direct to stub, concurrency=${CONCURRENCY}, ${DURATION}s)"
"$LOADGEN" "http://127.0.0.1:${STUB_PORT}/api/echo" "$DURATION" "$CONCURRENCY"

echo
echo "through the gateway (same load, with authentication)"
"$LOADGEN" "http://127.0.0.1:${PORT}/bench/api/echo" "$DURATION" "$CONCURRENCY" "$TOKEN"

echo
echo "gateway log: /tmp/api-gateway-bench.log"
