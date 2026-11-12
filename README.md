# api-gateway

An HTTP API gateway in Rust: authenticates API keys, resolves a Postgres-backed route
table, enforces per-route scopes, and proxies to allowlisted upstreams with streaming
bodies, strict header hygiene, and OpenTelemetry tracing.

Built on axum 0.8, sqlx 0.9, reqwest 0.13, and OpenTelemetry 0.33.

## Status

Working data plane and control plane: API-key auth with peppered verifiers, a
Postgres-backed route table with live reload, streaming proxy with strict header hygiene,
per-IP and per-tenant rate limits, per-upstream circuit breakers, Prometheus metrics,
OpenTelemetry traces, and graceful shutdown. Ships as a distroless container with a
compose stack.

Not yet built: the HTTP admin adapter, distributed rate limiting, credential caching,
and Kubernetes manifests. Strong pre-production baseline, not a finished product.

## Requirements

- Rust 1.99 (pinned in `rust-toolchain.toml`)
- Docker (local Postgres)
- [`just`](https://github.com/casey/just)

## Quick start

```bash
cp .env.example .env          # edit the local password
just db-up                    # Postgres 18 on 127.0.0.1:5432
just run                      # applies migrations, seeds the dev key
```

In a second shell, register the demo upstream and route:

```bash
just demo-route
```

```bash
curl -s localhost:8080/health          # liveness
curl -s localhost:8080/ready           # readiness (checks Postgres)
curl -s -H "Authorization: Bearer dev-local.$DEV_API_KEY_SECRET" \
     localhost:8080/swapi/people/1
```

```json
// 401 example
{"error":{"code":"invalid_credentials","message":"invalid or missing bearer credentials","request_id":"..."}}
```

## Routing model

Routes live in Postgres and are compiled into an immutable in-memory snapshot.

- **Matching**: longest path prefix that lands on a segment boundary (`/api` matches
  `/api/people`, never `/apix`), then highest priority. One route may claim a given
  prefix+method pair; overlaps are rejected at load, not resolved silently.
- **Path translation**: the matched prefix is **stripped** by default. Use `--rewrite`
  to put a path back. `/swapi/people/1` with prefix `/swapi` and no rewrite becomes
  `/people/1` on the upstream.
- **Authorization**: a route lists scopes; a caller must hold **all** of them.
- **Reload**: any write bumps `route_table_state.version`; replicas poll and swap the
  snapshot atomically. A bad table never replaces a good one — it is validated first.
  No restart, no dropped requests.
- **SSRF guard**: upstream hosts must be in `UPSTREAM_ALLOW_HOSTS` (required in
  production). This is checked when the table compiles, so a bad row cannot go live.

## Control plane

Everything is administered through the CLI; the HTTP adapter will share the same
service layer.

```bash
api-gateway admin tenant create acme
api-gateway admin client create acme-app --tenant acme
api-gateway admin key create --client acme-app --scope read --expires-in-days 90
api-gateway admin key rotate <key-id>
api-gateway admin key revoke <key-id>
api-gateway admin key list --client acme-app

api-gateway admin upstream put billing --base-url https://billing.internal --timeout-ms 5000
api-gateway admin route put billing-v1 --prefix /v1/billing --upstream billing --scope billing:read
api-gateway admin route list
```

The issued token is shown exactly once. Keys are stored as HMAC verifiers, never as
plaintext.

## Protection

- **Rate limits**: token buckets per client IP (before authentication) and per tenant
  (after). `429` responses carry `Retry-After` plus `RateLimit-*` headers. Limits are
  in-process and per replica: two replicas enforce twice the configured rate.
- **Circuit breaker**: per upstream, consecutive failures open the circuit for a
  cooldown, then a single half-open probe decides whether to close it. Open circuits
  answer `503` with `Retry-After` instead of piling onto a failing upstream.
- **Timeouts**: connect and header waits are bounded per upstream; response bodies then
  stream under the whole-request deadline.
- **Header hygiene**: hop-by-hop headers (including those named by `Connection`),
  `Forwarded`/`X-Forwarded-*`, and the gateway's own credentials are stripped in both
  directions. Upstream redirects are never followed.

## Metrics

`GET /metrics` renders Prometheus text from an in-process recorder:

| Metric | Labels |
|---|---|
| `gateway_requests_total` | `method`, `status` |
| `gateway_request_duration_seconds` | — |
| `gateway_upstream_requests_total` | `upstream`, `status` |
| `gateway_auth_failures_total` | `reason` |
| `gateway_circuit_open_total` | `upstream` |

The endpoint is on the main listener; keep it off the public edge with network policy
and scrape it from your monitoring network.

## Docker

```bash
docker compose up -d --build     # gateway + Postgres
curl -s localhost:8080/health
```

The image is a distroless, non-root, read-only-friendly multi-stage build. Liveness is
checked in-container by `api-gateway healthcheck`, so no shell or curl is required.

## Tasks

| Command | What it does |
|---|---|
| `just` | List recipes |
| `just check` | fmt + clippy + tests + dependency policy (mirrors CI) |
| `just clippy` | Clippy with `-D warnings` |
| `just test` | All tests (Postgres tests need `DATABASE_URL`) |
| `just deny` | Licenses, advisories, duplicates, wildcards |
| `just demo-route` | Registers the SWAPI demo upstream and route |
| `just docker` | Builds the runtime image |
| `just up` / `just down` | Full stack in Docker (gateway + Postgres) |
| `just db-up` / `just db-down` / `just db-logs` | Local Postgres |

## Configuration

Environment variables, loaded from `.env` in development. Production refuses
development defaults; `cargo run -- serve --check-config` prints the resolved values
with secrets redacted.

| Variable | Default | Notes |
|---|---|---|
| `APP_ENV` | — (required) | `development` or `production` |
| `HOST` / `PORT` | `127.0.0.1` / `8080` | Bind address |
| `LOG_LEVEL` | `info` | `tracing` env filter |
| `DATABASE_URL` | — (required) | Postgres connection string |
| `AUTH_PEPPER` | dev value | Required in production; see key rotation note |
| `DEV_API_KEY_SECRET` | — | Seeded key; **rejected** in production |
| `DEV_API_KEY_SCOPES` | `read` | Scopes granted to the seeded key |
| `UPSTREAM_ALLOW_HOSTS` | — | Comma-separated allowlist; required in production |
| `ROUTE_REFRESH_INTERVAL_MS` | `2000` | Route table poll interval |
| `REQUEST_TIMEOUT_SECS` | `15` | Whole-request deadline |
| `MAX_REQUEST_BODY_BYTES` | `1048576` | Inbound body limit |
| `SHUTDOWN_DRAIN_SECS` | `25` | Graceful drain budget |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | unset | OTLP/gRPC endpoint; logs only when unset |

## Layout

```
src/main.rs           CLI entry point
src/serve.rs          data plane: bootstrap, route refresh, drain
src/app.rs            layer composition (order is a contract)
src/routing.rs        route table: compile, match, validate, refresh
src/proxy.rs          forwarding, header policy, error mapping
src/auth/             tokens, verifiers, credential store
src/admin/            control plane service + CLI
src/config.rs         typed configuration + validation
src/error.rs          AppError + JSON envelope
migrations/           sqlx migrations (forward-only)
```

## Development rules

- `main` is protected; land changes through a pull request with CI green.
- No `unwrap`/`expect` on request paths.
- Secrets never appear in logs, traces, error bodies, or metric labels.
- New dependencies go through `cargo add` and must pass `just deny`.
