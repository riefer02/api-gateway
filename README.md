# api-gateway

[![ci](https://github.com/riefer02/api-gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/riefer02/api-gateway/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![rust](https://img.shields.io/badge/rust-1.99-orange.svg)](rust-toolchain.toml)

A production-shaped HTTP API gateway in Rust: authenticates API keys, resolves routes from
Postgres, enforces per-route scopes and per-tenant limits, and proxies to allowlisted
upstreams with streaming bodies, strict header hygiene, tracing, and metrics.

**At a glance:** ~9k lines of Rust, 104 tests, one binary, a distroless image with no
shell, and a measured +0.32 ms p50 over a direct call at 78k req/s.

Built on axum 0.8, sqlx 0.9, reqwest 0.13, and OpenTelemetry 0.33. Designed to be cloned
and adapted — see [Using this as a template](#using-this-as-a-template).

## Status

Working data plane and control plane. Authentication with a bounded-staleness credential
cache, a Postgres-backed route table with live reload, streaming proxy with strict header
hygiene, per-IP and per-tenant rate limits, per-upstream circuit breakers, Prometheus
metrics, OpenTelemetry traces, and graceful shutdown. The control plane is available as
both a CLI and an HTTP API. Ships as a distroless container with a compose stack.

Ships with a distroless image, a compose stack, Kubernetes manifests, and a Caddy
edge-TLS example. Not built: distributed rate limiting (needs more than one replica for
it to mean anything).

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
| `deploy/` | Prometheus alerts, Kubernetes manifests, Caddy edge config. |

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
api-gateway admin route put billing-v1 --prefix /v1/billing --upstream billing --disabled
api-gateway admin route list

api-gateway admin route rm billing-v1
api-gateway admin upstream rm billing
api-gateway admin client rm acme-app
api-gateway admin tenant rm acme
```

The HTTP API serves the same operations on a separate listener. Configure named tokens
to enable it; each name becomes the audit identity for everything that token does.

```bash
# no scope list = full admin
ADMIN_TOKENS="alice:$ALICE_TOKEN,bob:$BOB_TOKEN"
# scoped: readable config, but no writes and no key access
ADMIN_TOKENS="auditor:$AUDITOR_TOKEN:config:read+audit:read"
```

Scopes: `tenants:write`, `keys:read`, `keys:write`, `config:read`, `config:write`,
`audit:read`. A token with no scope list gets `*`. A request outside its scopes returns
`403` before touching the database.

`ADMIN_TOKEN=...` still works for a single shared credential and maps to the actor
`admin`. Tokens must be at least 16 characters; the listener stays off when neither is set.

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

### Audit trail

Every mutation is recorded with the actor bound to the token, the action, the subject, the
source IP, and the request id:

```bash
curl -s "$ADMIN/v1/audit?limit=20" -H "Authorization: Bearer $BOB_TOKEN"
api-gateway admin audit list --limit 20
```

```
2026-11-12 18:31:07.21 +00:00  alice  upstream.put  billing   127.0.0.1
2026-11-12 18:31:09.04 +00:00  bob    route.put     billing-v1  127.0.0.1
```

SQL-only mutations commit their audit row in the same transaction. Key issuance and
rotation go through the credential store, so their audit write follows the mutation and a
failure is logged rather than reported as a failed operation.

Because the admin listener shares the process, a revoke invalidates the credential cache
immediately. Revocations are also broadcast on a Postgres channel, so every replica drops
the entry at the same moment; `AUTH_CACHE_TTL_SECS` is only the fallback for a replica
whose listener is disconnected.

## Protection

- **Rate limits**: token buckets per client IP (before authentication) and per tenant
  (after). `429` carries `Retry-After` and `RateLimit-*`. In-process and per replica, so
  N replicas enforce N times the configured rate.
- **Circuit breaker**: per upstream, consecutive-failure trigger, cooldown, single
  half-open probe. Open circuits answer `503` with `Retry-After`.
- **Retries**: idempotent, body-less requests are retried on `502`/`503`/`504`,
  connection failure, or header timeout — at most `RETRY_MAX_ATTEMPTS` times, with
  exponential backoff and full jitter. A **retry budget** (`RETRY_BUDGET_RATIO`) caps
  retries at a fraction of normal traffic, so an outage cannot be amplified. Requests
  with bodies are never retried because the body streams and cannot be replayed;
  `Idempotency-Key` opts a bodiless `POST` in.
- **Deadlines**: connect and header waits are bounded per upstream; the whole request has
  its own deadline; request heads must arrive within `HEADER_READ_TIMEOUT_SECS`, and
  `MAX_CONNECTIONS` caps open sockets so a slowloris cannot exhaust file descriptors.
- **Bounded growth**: audit rows are pruned on a timer (`AUDIT_RETENTION_DAYS`); the rate
  limiter and credential cache sweep their shards on a timer, not on every insert.
- **Header hygiene**: hop-by-hop headers — including those named by `Connection` — plus
  `Forwarded`/`X-Forwarded-*`, `Host`, `Authorization`, and `Cookie` are stripped before
  forwarding. `Server` and `Set-Cookie` are stripped on the way back. Redirects are never
  followed.
- **Client identity**: the direct peer is the caller unless it appears in
  `TRUSTED_PROXIES`. Only then is `X-Forwarded-For`/`X-Real-IP` believed, walking the chain
  right to left and skipping trusted hops. The resolved address drives the per-IP limiter,
  the audit trail, and the `X-Forwarded-For` sent upstream — a spoofed header from an
  untrusted peer changes nothing.

## Edge cases handled

This table is the specification.

| Case | Behaviour |
|---|---|
| `/a/../b`, `/a/%2e%2e/b`, `/a%2f..%2fb` | `400` before matching, so policy and forwarded path cannot diverge |
| Unknown path | `404` envelope; authentication runs first, so prefixes cannot be probed |
| Path exists, method does not | `405` plus `Allow` |
| `HEAD` on a `GET` route | Forwarded as `HEAD`, no body |
| Oversized declared `Content-Length` | `413` envelope |
| Oversized chunked body | `413` envelope; unknown-length bodies are buffered up to the limit |
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
| Upstream `503` on a `GET` | Retried once, then served |
| Upstream `503` on a `POST` with a body | Never retried; the body cannot be replayed |
| Retry budget exhausted | The failing response is served instead of amplifying |
| Bodiless `POST` with `Idempotency-Key` | Retried |

## Observability

`GET /metrics` renders Prometheus text. Set `METRICS_TOKEN` to require a bearer token.

| Metric | Labels |
|---|---|
| `gateway_requests_total` | `method`, `status` |
| `gateway_request_duration_seconds` | — |
| `gateway_upstream_requests_total` | `upstream`, `status` |
| `gateway_auth_failures_total` | `reason` |
| `gateway_circuit_open_total` | `upstream` |
| `gateway_upstream_retries_total` | `upstream`, `reason` |
| `gateway_retry_budget_exhausted_total` | `upstream` |
| `gateway_auth_cache_total` | `result` |
| `gateway_admin_auth_failures_total` | — |
| `gateway_connections_rejected_total` | — |
| `gateway_ready` | — (0/1, set by `/ready`) |

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
| `METRICS_TOKEN` | unset | Requires a bearer token on `/metrics` when set |
| `ADMIN_TOKEN` | unset | Single shared token, actor `admin` |
| `ADMIN_TOKENS` | unset | `name:token[:scope+scope]`; enables the control plane and names the actor |
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
| `RETRY_MAX_ATTEMPTS` | `2` | Total attempts; `1` disables retries |
| `RETRY_BASE_DELAY_MS` | `50` | Backoff base, jittered, capped at 1 s |
| `RETRY_BUDGET_RATIO` | `0.2` | Retries per request as a fraction of traffic; `0` disables |
| `REQUEST_TIMEOUT_SECS` | `15` | Whole-request deadline |
| `HEADER_READ_TIMEOUT_SECS` | `10` | Bound on receiving a complete request head |
| `MAX_CONNECTIONS` | `1024` | Concurrent socket cap |
| `TRUSTED_PROXIES` | — | CIDRs allowed to set the client address; empty trusts nobody |
| `ADMIN_TIMEOUT_SECS` | `10` | Control-plane request deadline |
| `AUDIT_RETENTION_DAYS` | `90` | Audit pruning window; `0` keeps forever |
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

`stop_grace_period` is 30 s against a 25 s drain budget. The image ships a `HEALTHCHECK`
that runs `api-gateway healthcheck`, so no shell or curl is needed.

Kubernetes manifests live in [`deploy/k8s`](deploy/k8s): a non-root, read-only deployment
with probes, HPA, PDB, and a default-deny NetworkPolicy. [`deploy/Caddyfile`](deploy/Caddyfile)
is the reference edge that terminates TLS and keeps `/metrics` and `/ready` private. Set
`TRUSTED_PROXIES` to that proxy's address (the Caddy example runs on loopback) or every
caller shares the proxy's bucket.

## Scaling and replicas

The gateway keeps no request-affecting state that needs to be shared. Run as many replicas
as you like behind one load balancer, all pointing at the same Postgres.

| State | Scope | How it converges |
|---|---|---|
| Route table | per replica | each replica polls `route_table_state.version` and swaps its snapshot |
| Credential cache | per replica | revocations publish `pg_notify`; every replica invalidates on `LISTEN` |
| Rate limits | **per replica** | deliberately not shared — N replicas allow N × the configured rate |
| Retry budget | **per replica** | same arithmetic |
| Circuit breakers | per replica | each replica learns an upstream's health independently |
| Migrations | global | sqlx takes an advisory lock, so concurrent starters serialise |

Prove the interesting half locally, with no cluster:

```bash
just replicas        # two containers, one database
```

This is intentionally not part of CI — see
[ADR 0001](docs/adr/0001-replicas-and-ci.md) for the reasoning and the trigger to revisit.

It asserts three things that only exist with more than one replica: a key issued once works
on both, a revocation reaches both immediately, and a route added through one replica's
control plane is served by the other within one refresh interval.

For a real deployment, size the knobs against the replica count: if the product promise is
600 requests/minute per IP, set `RATE_LIMIT_IP_PER_MINUTE=600 / replicas`, or accept that
the cluster-wide limit is N × the configured value. That is the one number that silently
changes when you scale.

Note that publishing a port rewrites the peer address, so `TRUSTED_PROXIES` must name the
proxy's actual address on the network the gateway sees — the Docker bridge, an ingress pod
CIDR, or `127.0.0.1` when the proxy runs in the same network namespace.

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
7. **Decide on revocation staleness**: cross-replica revocation is immediate over Postgres
   `LISTEN/NOTIFY`; `AUTH_CACHE_TTL_SECS` is the fallback window if a listener drops.

Deliberately generic: no cloud provider, no vendor SDK, no auth provider. The `AuthError`
and rate-limiter seams are where those integrations belong.

Known gaps, stated plainly: rate limits, retry budgets, and breakers are per replica;
unknown-length request bodies are buffered up to the limit instead of streamed; TLS
terminates at the edge rather than in the gateway.

## Further reading

- [`docs/threat-model.md`](docs/threat-model.md) — trust boundaries, threats, residual risk
- [`docs/runbook.md`](docs/runbook.md) — rotation, revocation, outages, deploy checklist
- [`docs/openapi.yaml`](docs/openapi.yaml) — control-plane API
- [`deploy/alerts.yml`](deploy/alerts.yml) — Prometheus rules
- [`docs/adr/`](docs/adr) — decisions, including why the replica model is shaped this way
  and what runs in CI versus on demand

## Development

| Command | What it does |
|---|---|
| `just check` | fmt + clippy + tests + dependency policy (mirrors CI) |
| `just test` | Tests; Postgres tests run only when `DATABASE_URL` is set |
| `just deny` | Licenses, advisories, duplicates, wildcards |
| `just bench` | Measures gateway overhead against a local stub upstream |
| `just replicas` | Starts two replicas and proves revocation + route convergence |
| `just demo-route` | Registers the demo upstream and route |
| `just db-up` / `just db-down` / `just db-logs` | Local Postgres |

Rules: `main` is protected, no `unwrap` on request paths, secrets never reach logs or error
bodies, and new dependencies go through `cargo add` and must pass `just deny`.
