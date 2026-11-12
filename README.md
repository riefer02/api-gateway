# api-gateway

A production-shaped HTTP API gateway in Rust: authenticates API keys, resolves routes from
Postgres, enforces per-route scopes and per-tenant limits, and proxies to allowlisted
upstreams with streaming bodies, strict header hygiene, tracing, and metrics.

Built on axum 0.8, sqlx 0.9, reqwest 0.13, and OpenTelemetry 0.33. Designed to be cloned
and adapted — see [Using this as a template](#using-this-as-a-template).

## Status

Working data plane and control plane. Authentication with a bounded-staleness credential
cache, a Postgres-backed route table with live reload, streaming proxy with strict header
hygiene, per-IP and per-tenant rate limits, per-upstream circuit breakers, Prometheus
metrics, OpenTelemetry traces, and graceful shutdown. The control plane is available as
both a CLI and an HTTP API. Ships as a distroless container with a compose stack.

Not built yet: distributed rate limiting, Kubernetes manifests. Strong pre-production
baseline, not a finished product.

## Quick start

The fastest path is the container stack:

```bash
cp .env.example .env          # set a local Postgres password
docker compose up -d --build  # gateway + Postgres
```

Or run the binary against a local database:

```bash
cp .env.example .env
just db-up                    # Postgres 18 on 127.0.0.1:5432
just run                      # applies migrations, seeds the dev key
just demo-route               # in a second shell: registers /swapi -> swapi.dev
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

## Architecture

```
client
  │
  ▼
request id → metrics → trace → panic guard → deadline → body limit
  │
  ▼
route pipeline: reject malformed paths → IP limit → authenticate → tenant limit
                → resolve route → authorize scopes → breakers → proxy
  │
  ▼
allowlisted upstream
```

| Module | Responsibility |
|---|---|
| `src/app.rs` | Layer composition; the order is a contract. |
| `src/routes/upstream.rs` | The request pipeline, in one readable function. |
| `src/routing.rs` | Route table: compile, validate, match, atomically reload. |
| `src/proxy.rs` | Forwarding, header policy, body streaming, error mapping. |
| `src/auth/` | Tokens, peppered verifiers, credential cache, store. |
| `src/admin/` | Control-plane service with CLI and HTTP adapters. |
| `src/limits.rs` | Rate limiters and circuit breaker registry. |
| `src/config.rs` | Typed configuration with validation and redaction. |
| `src/error.rs` | `AppError` and the JSON error envelope. |
| `examples/` | Stub upstream and load generator for `just bench`. |
| `docs/` | Threat model, runbook, and control-plane OpenAPI. |
| `deploy/` | Prometheus alert rules. |

Requests never touch Postgres to resolve a route or render a policy: the table is compiled
to memory at boot and swapped atomically when the version counter changes.

## Routing model

- **Matching**: longest path prefix on a segment boundary (`/api` matches `/api/people`,
  never `/apix`), then priority. `GET` implies `HEAD`.
- **Path translation**: the matched prefix is **stripped** by default; `--rewrite` puts a
  path back. `/swapi/people/1` with prefix `/swapi` becomes `/people/1` upstream.
- **Methods**: a path that exists but does not accept the method returns `405` with `Allow`,
  not `404`.
- **Authorization**: routes declare scopes; callers must hold **all** of them.
- **Reload**: any write bumps `route_table_state.version`; replicas poll and swap. Invalid
  tables never replace a good one.
- **SSRF**: upstream hosts must be in `UPSTREAM_ALLOW_HOSTS` (required in production).
  Checked when the table compiles and again when an upstream is written.

## Control plane

Two adapters over one `AdminService`. The CLI is best for a shell or a deploy script:

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

The HTTP API serves the same operations on a separate listener. Set `ADMIN_TOKEN` to
enable it; it is off by default.

```bash
TOKEN=... ADMIN=http://127.0.0.1:9090

curl -s -X PUT "$ADMIN/v1/upstreams/billing" \
  -H "Authorization: Bearer $TOKEN" \
  -H "content-type: application/json" \
  -d '{"base_url":"https://billing.internal","timeout_ms":5000}'

curl -s -X PUT "$ADMIN/v1/routes/billing-v1" \
  -H "Authorization: Bearer $TOKEN" \
  -H "content-type: application/json" \
  -d '{"path_prefix":"/v1/billing","methods":["GET","POST"],"upstream_id":"billing","scopes":["billing:read"]}'

curl -s -X POST "$ADMIN/v1/keys" \
  -H "Authorization: Bearer $TOKEN" \
  -H "content-type: application/json" \
  -d '{"client_id":"acme-app","scopes":["read"],"expires_in_days":90}'
```

Full surface in [`docs/openapi.yaml`](docs/openapi.yaml). Tokens are shown exactly once and
stored only as HMAC verifiers. Rotation copies the remaining lifetime, refuses revoked keys,
and rolls back the replacement if the old revoke fails.

Because the admin listener shares the process, a revoke invalidates the credential cache
immediately. A revoke issued from the CLI in another process is bounded by
`AUTH_CACHE_TTL_SECS`.

## Protection

- **Rate limits**: token buckets per client IP (before authentication) and per tenant
  (after). `429` carries `Retry-After` and `RateLimit-*`. In-process and per replica, so
  N replicas enforce N times the configured rate.
- **Circuit breaker**: per upstream, consecutive-failure trigger, cooldown, single
  half-open probe. Open circuits answer `503` with `Retry-After`.
- **Deadlines**: connect and header waits are bounded per upstream; the whole request has
  its own deadline; bodies stream rather than buffer.
- **Header hygiene**: hop-by-hop headers — including those named by `Connection` — plus
  `Forwarded`/`X-Forwarded-*`, `Host`, `Authorization`, and `Cookie` are stripped before
  forwarding. `Server` and `Set-Cookie` are stripped on the way back. Redirects are never
  followed.

## Edge cases handled

This table is the specification.

| Case | Behaviour |
|---|---|
| `/a/../b`, `/a/%2e%2e/b`, `/a%2f..%2fb` | `400` before matching, so policy and forwarded path cannot diverge |
| Unknown path | `404` envelope; authentication runs first, so prefixes cannot be probed |
| Path exists, method does not | `405` plus `Allow` |
| `HEAD` on a `GET` route | Forwarded as `HEAD`, no body |
| Oversized declared `Content-Length` | `413` envelope |
| Oversized chunked body | Rejected mid-read by the streaming limit (plain `413`, see gaps) |
| Slow upstream headers | `504 upstream_timeout` |
| Slow whole request | `408 request_timeout` |
| Client-supplied request id | Accepted only if ≤128 printable ASCII, else replaced with a UUID |
| Upstream redirect | Passed through, never followed (SSRF) |
| Multi-valued headers | Preserved with `append`, not collapsed |
| Percent-encoded paths | Preserved; no double encoding |
| Duplicate query parameters | Forwarded verbatim |
| Revoked or expired key | `401`; suspended tenant/client `403` |
| Postgres unavailable | `503 service_unavailable`, not `500` |
| Duplicate route prefix+method | Rejected at write and at compile |
| Rotating a revoked key | Refused (`409`) |
| Unknown verifier version | Rejected without comparison |
| Circuit half-open | Exactly one probe request, the rest shed with `503` |

## Observability

`GET /metrics` renders Prometheus text:

| Metric | Labels |
|---|---|
| `gateway_requests_total` | `method`, `status` |
| `gateway_request_duration_seconds` | — |
| `gateway_upstream_requests_total` | `upstream`, `status` |
| `gateway_auth_failures_total` | `reason` |
| `gateway_circuit_open_total` | `upstream` |

Spans carry `route`, `upstream`, `tenant_id`, `client_id`, and `key_id` (identifiers only,
never secrets). Set `OTEL_EXPORTER_OTLP_ENDPOINT` to export; otherwise logs only.

The metrics endpoint shares the public listener — keep it off the edge with network policy.

## Performance

Measured with `just bench` on the development machine over loopback: release build, 50
concurrent connections, 10 s, warm credential cache, rate limits disabled, `LOG_LEVEL=warn`.

| Path | Throughput | p50 | p99 |
|---|---:|---:|---:|
| Direct to the stub upstream | 160k req/s | 0.31 ms | 0.51 ms |
| Through the gateway (authenticated) | 77k req/s | 0.64 ms | 0.96 ms |
| **Added by the gateway** | — | **+0.33 ms** | **+0.45 ms** |

Two things the same harness taught us:

- **Logging is the first cost.** The identical run at `LOG_LEVEL=debug` fell to 28k req/s
  and 1.58 ms p50, because every request formatted a span and a debug event. Run
  production at `info`.
- **Limits shed instead of collapsing.** With the default 600/min IP bucket the same load
  produced `429`s at the configured rate rather than timeouts.

These are loopback numbers: they measure gateway overhead, not your network or upstreams.
Reproduce with `just bench`.

## Configuration

Environment variables, loaded from `.env` in development. Production refuses development
defaults; `cargo run -- serve --check-config` prints resolved values with secrets redacted.

| Variable | Default | Notes |
|---|---|---|
| `APP_ENV` | — (required) | `development` or `production` |
| `HOST` / `PORT` | `127.0.0.1` / `8080` | Bind address |
| `LOG_LEVEL` | `info` | `tracing` filter |
| `DATABASE_URL` | — (required) | Postgres connection string |
| `AUTH_PEPPER` | dev value | Required in production; rotating it invalidates keys |
| `AUTH_CACHE_TTL_SECS` | `30` | Credential cache lifetime; `0` disables |
| `ADMIN_TOKEN` | unset | Enables the HTTP control plane when set |
| `ADMIN_BIND` | `127.0.0.1:9090` | Control-plane listener |
| `DEV_API_KEY_SECRET` | — | Seeded key; rejected in production |
| `DEV_API_KEY_SCOPES` | `read` | Scopes for the seeded key |
| `UPSTREAM_ALLOW_HOSTS` | — | Comma-separated allowlist; required in production |
| `ROUTE_REFRESH_INTERVAL_MS` | `2000` | Route table poll interval |
| `RATE_LIMIT_BACKEND` | `local` | `redis` is rejected until implemented |
| `RATE_LIMIT_IP_PER_MINUTE` | `600` | `0` disables |
| `RATE_LIMIT_TENANT_PER_MINUTE` | `6000` | `0` disables |
| `CIRCUIT_FAILURE_THRESHOLD` | `5` | Consecutive failures to open |
| `CIRCUIT_COOLDOWN_SECS` | `30` | Open duration |
| `REQUEST_TIMEOUT_SECS` | `15` | Whole-request deadline |
| `MAX_REQUEST_BODY_BYTES` | `1048576` | Inbound body limit |
| `SHUTDOWN_DRAIN_SECS` | `25` | Graceful drain budget |
| `DB_MAX_CONNECTIONS` / `DB_MIN_CONNECTIONS` / `DB_ACQUIRE_TIMEOUT_SECS` | `10` / `1` / `5` | Pool sizing |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | unset | OTLP/gRPC; logs only when unset |

## Deployment

The image is a multi-stage distroless build running as non-root:

```bash
just docker          # build
just up              # compose stack (gateway + Postgres)
```

`stop_grace_period` is 30 s against a 25 s drain budget. The container healthcheck is
`api-gateway healthcheck`, so no shell or curl is required in the image.

## Using this as a template

1. **Rename**: `Cargo.toml` package name, the `name` in `src/admin/cli.rs`, and the
   `ENTRYPOINT` path if you change the binary.
2. **License**: MIT is set in `LICENSE` and `Cargo.toml`; change it if that is wrong for you.
3. **Set the pepper story**: `AUTH_PEPPER` must come from your secret manager in production.
   Rotating it invalidates every key, so plan the re-issue.
4. **Replace the demo upstream**: `just demo-route` points at swapi.dev. Delete it and
   register your own through the admin API or CLI.
5. **Tune the limits** against a load test; the defaults are guesses for a small deployment.
6. **Set `ADMIN_TOKEN`** if you want the HTTP control plane, and keep its listener private.
7. **Decide on revocation staleness**: `AUTH_CACHE_TTL_SECS` is the window in which a
   cross-process revocation is not yet visible.

Deliberately generic: no cloud provider, no vendor SDK, no auth provider. The `AuthError`
and rate-limiter seams are where those integrations belong.

Known gaps, stated plainly: chunked bodies over the limit get a plain `413` rather than the
envelope, rate limits and breakers are per replica, and `/metrics` is unauthenticated.

## Further reading

- [`docs/threat-model.md`](docs/threat-model.md) — trust boundaries, threats, residual risk
- [`docs/runbook.md`](docs/runbook.md) — rotation, revocation, outages, deploy checklist
- [`docs/openapi.yaml`](docs/openapi.yaml) — control-plane API
- [`deploy/alerts.yml`](deploy/alerts.yml) — Prometheus rules

## Development

| Command | What it does |
|---|---|
| `just check` | fmt + clippy + tests + dependency policy (mirrors CI) |
| `just test` | Tests; Postgres tests run only when `DATABASE_URL` is set |
| `just deny` | Licenses, advisories, duplicates, wildcards |
| `just bench` | Measures gateway overhead against a local stub upstream |
| `just demo-route` | Registers the demo upstream and route |
| `just db-up` / `just db-down` / `just db-logs` | Local Postgres |

Rules: `main` is protected, no `unwrap` on request paths, secrets never reach logs or error
bodies, and new dependencies go through `cargo add` and must pass `just deny`.
