# api-gateway

[![ci](https://github.com/riefer02/api-gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/riefer02/api-gateway/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![rust](https://img.shields.io/badge/rust-1.99-orange.svg)](rust-toolchain.toml)

A production-shaped HTTP API gateway in Rust: authenticates API keys, resolves routes from
Postgres, enforces per-route scopes and per-tenant limits, and proxies to allowlisted
upstreams with streaming bodies, strict header hygiene, tracing, and metrics.

**At a glance:** ~17k lines of Rust, 262 tests, one binary, a distroless image with no
shell, and a measured +0.33 ms p50 over a direct call at 77k req/s.

Built on axum 0.8, sqlx 0.9, reqwest 0.13, and OpenTelemetry 0.33. Designed to be cloned
and adapted — see [Using this as a template](#using-this-as-a-template).

## Status

Deployed and operating as a reference implementation. Data plane and control plane are
complete: API-key and OAuth 2.1 resource-server authentication with a bounded-staleness
credential cache, a Postgres-backed route table with live reload, a streaming proxy with
strict header hygiene, MCP tool policy with argument validation, per-call audit, per-IP,
per-tenant, per-user and per-tool limits, per-upstream circuit breakers, Prometheus
metrics, OpenTelemetry traces that continue into upstreams, and graceful shutdown. The
control plane is both a CLI and an HTTP API.

The guarantees are structural where they can be:

- **Configuration fails closed.** A production deployment cannot start with a development
  secret, an empty upstream allowlist, or a missing pepper.
- **Postgres is never on the request path.** Policy is compiled to memory and swapped
  atomically, so a database outage cannot stop traffic the credential cache can still
  serve — and readiness reflects that, rather than draining every replica on a blip.
- **Every failure carries the request id**, and every tool call is attributable to a tenant
  and a subject whether it was allowed or denied.
- **Header hygiene in both directions.** Hop-by-hop, `Connection`-named, forwarded,
  credential, trace and gateway-owned headers are stripped; redirects are never followed.
- **Egress is resolved, not just parsed.** An allowlisted hostname is filtered by address
  when it resolves, and the client connects to exactly what survived, so the metadata
  service and the gateway's own loopback are unreachable by default.
- **The control-plane audit is chained.** An edit, insertion or reordering breaks it at
  a named row, and `admin audit verify` proves it rather than asserting it.
- **An overloaded upstream sheds load.** With `UPSTREAM_MAX_CONCURRENCY` set, a permit is
  held for the life of the response body — so a long stream counts as the concurrency it
  is — and saturation answers `503` with `Retry-After` rather than queueing without bound.

Known limits, stated rather than discovered:

- Rate limits, retry budgets and circuit breakers are per replica: N replicas enforce
  N × the configured rate.
- Not independently audited. The threat model, the controls it claims, and the tests that
  enforce them live in [`docs/threat-model.md`](docs/threat-model.md) and
  [`SECURITY.md`](SECURITY.md).

Ships with a distroless non-root image, a compose stack, Kubernetes manifests with
readiness/liveness probes, a PodDisruptionBudget and an HPA, Prometheus alert rules, and a
Caddy edge-TLS example.

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

If port 5432 is already taken, set `DB_HOST_PORT` and the matching port in
`DATABASE_URL` for the host-binary path — the container always listens on 5432
internally, so the compose stack needs no other change.

The shell does not read `.env`; load it first (or copy the token printed by
`admin key create`):

```bash
set -a; . ./.env; set +a

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
request id → CORS/Origin → metrics → trace → panic guard → deadline → body limit
  │
  ▼
route pipeline: reject malformed paths → IP limit → authenticate → tenant limit
                → user limit → resolve route → authorize scopes → MCP policy
                → upstream auth → breakers → proxy → audit
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
| `src/auth/` | Tokens, peppered verifiers, credential cache, OAuth/JWKS, store. |
| `src/mcp/` | Tool policy and the small JSON-RPC surface the gateway enforces. |
| `src/audit.rs` | Bounded, batched per-call audit off the request path. |
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

A route `PUT`/`route put` is **partial for security fields**: omitting `tenant_id`,
`scopes`, `tool_policy`, or the enable flags preserves what is stored. An explicit
empty value clears it (for example `--scope` with `--replace-scopes` and no values, or
`--tenant ""`). Omitted non-security fields (`rewrite`, timeout, cap) also preserve; an empty
`rewrite` clears it, timeout `0` restores the default, and cap `0` means unlimited. This is deliberate: a routine timeout edit must not
widen tenancy or disable tool policy.

The HTTP API serves the same operations on a separate listener. Configure named tokens
to enable it; each name becomes the audit identity for everything that token does.

```bash
# no scope list = full admin
ADMIN_TOKENS="alice:replace-with-a-long-random-token,bob:another-long-random-token"
# scoped: readable config, but no writes and no key access
ADMIN_TOKENS="auditor:replace-with-a-long-random-token:config:read+audit:read"
```

Scopes: `tenants:write`, `keys:read`, `keys:write`, `config:read`, `config:write`,
`audit:read`. A token with no scope list gets `*`. A request outside its scopes returns
`403` before touching the database.

`ADMIN_TOKEN=...` still works for a single shared credential and maps to the actor
`admin`. Tokens must be at least 16 characters; the listener stays off when neither is set.

```bash
# Set these to the tokens you configured in ADMIN_TOKENS.
ADMIN=http://127.0.0.1:9090
TOKEN=...   # the token you gave `alice` in ADMIN_TOKENS
# BOB_TOKEN and AUDITOR_TOKEN are used in the audit examples below.

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

### Per-call data audit

The data plane records every authenticated call separately from the control plane:

```bash
curl -s "$ADMIN/v1/data-audit?limit=20" -H "Authorization: Bearer $AUDITOR_TOKEN"
api-gateway admin audit data --limit 20
```

Each row carries the tenant, OIDC subject, assistant client, MCP method, tool, decision,
status, latency, request id, and token id. Payloads, tokens, and verifier material never
appear. Writes go through a bounded queue and a batched insert; a full queue increments
`gateway_data_audit_dropped_total` rather than slowing the request.

## Protection

- **Rate limits**: token buckets per client IP (before authentication), per tenant,
  per user, and per tool per tenant. `429` carries `Retry-After` and `RateLimit-*`.
  In-process and per replica, so N replicas enforce N times the configured rate.
- **MCP policy**: routes may enforce a role-based tool allow-list; denied calls are
  JSON-RPC errors, `tools/list` is filtered, and every authenticated call is audited
  with the user, assistant, tool, and decision. Tool arguments are checked against
  the schema the upstream advertised in `tools/list`.
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
  `Forwarded`/`X-Forwarded-*`, `Host`, the caller's `Authorization`, and `Cookie` are
  stripped before forwarding. A route with an upstream audience gets a freshly
  exchanged token; the caller's token is never reused. `Server` and `Set-Cookie` are stripped on the way back. Redirects are never
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
| OAuth token for another audience/issuer | `401` with `invalid_token` and the metadata pointer |
| JWKS unreachable and no cached key | `503`, never `401` |
| Valid token, missing route scope | `403 insufficient_scope` with the required scopes |
| Tool outside the route's allow-list | `200` with a JSON-RPC error; audited as `deny` |
| `tools/list` outside policy | Denied tools removed; unparseable/non-JSON fails closed; batches filter every list |
| `server/discover` on an allow-list route | Passed through; it carries no tool catalogue |
| `Mcp-Method` / `Mcp-Name` disagrees with body | `400` with JSON-RPC `HeaderMismatch` (`-32020`) |
| Route bound to another tenant | `404`, no fallback to a shorter prefix |
| Upstream with an audience | RFC 8693 exchanged token; inbound token never forwarded |
| Response over the route cap | `502 response_too_large` (declared) or truncated stream (chunked); `0` means unlimited |
| Browser request from an unlisted origin | `403` when `CORS_ALLOWED_ORIGINS` is configured |

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
| `gateway_oauth_jwks_ready` | — (0/1; key set loaded) |
| `gateway_mcp_denied_total` | `route` |
| `gateway_upstream_auth_failures_total` | `reason` |
| `gateway_data_audit_dropped_total` | — |
| `gateway_data_audit_write_failures_total` | — |

Spans carry `route`, `upstream`, `tenant_id`, `client_id`, `key_id`, `subject`, and
`auth_method` (identifiers only, never secrets). Set `OTEL_EXPORTER_OTLP_ENDPOINT` to export; otherwise logs only.

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
| `AUTH_CACHE_TTL_SECS` | `30` | Credential cache lifetime (max 3600); `0` disables |
| `METRICS_TOKEN` | unset | Requires a bearer token on `/metrics` when set |
| `ADMIN_TOKEN` | unset | Single shared token, actor `admin` |
| `ADMIN_TOKENS` | unset | `name:token[:scope+scope]`; enables the control plane and names the actor |
| `ADMIN_BIND` | `127.0.0.1:9090` | Control-plane listener |
| `DEV_API_KEY_SECRET` | — | Seeded key; rejected in production |
| `DEV_API_KEY_SCOPES` | `read` | Scopes for the seeded key |
| `UPSTREAM_ALLOW_HOSTS` | — | Comma-separated allowlist; required in production |
| `UPSTREAM_EGRESS` | `deny-link-local` | What an allowed host may resolve to: `deny-link-local`, `deny-private`, `allow-all` |
| `UPSTREAM_MAX_CONCURRENCY` | `0` | In-flight requests per upstream, per replica; `0` disables the bulkhead |
| `UPSTREAM_QUEUE_TIMEOUT_MS` | `0` | How long to wait for a bulkhead permit; `0` sheds immediately |
| `ROUTE_REFRESH_INTERVAL_MS` | `2000` | Route table poll interval |
| `UPSTREAM_POOL_MAX_IDLE_PER_HOST` | `64` | Idle sockets kept per upstream client, per replica; bounds idle accumulation, not peak concurrency |
| `MCP_TOOL_SCHEMA_TTL_SECS` | `300` | How long a learned tool schema is trusted; `0` disables argument validation |
| `RATE_LIMIT_BACKEND` | `local` | `redis` is rejected until implemented |
| `RATE_LIMIT_IP_PER_MINUTE` | `600` | Pre-auth abuse control; `0` disables |
| `RATE_LIMIT_TENANT_PER_MINUTE` | `6000` | Per-tenant fairness; `0` disables |
| `RATE_LIMIT_USER_PER_MINUTE` | `600` | Per-user fairness for OAuth callers; `0` disables |
| `RATE_LIMIT_TOOL_PER_MINUTE` | `0` | Per-tool calls per tenant, on tool-policy routes; `0` disables |
| `CIRCUIT_FAILURE_THRESHOLD` | `5` | Consecutive failures to open |
| `CIRCUIT_COOLDOWN_SECS` | `30` | Open duration |
| `RETRY_MAX_ATTEMPTS` | `2` | Total attempts; `1` disables retries |
| `RETRY_BASE_DELAY_MS` | `50` | Backoff base, jittered, capped at 1 s |
| `RETRY_BUDGET_RATIO` | `0.2` | Retries per request as a fraction of traffic; `0` disables |
| `REQUEST_TIMEOUT_SECS` | `15` | Default route deadline |
| `MAX_REQUEST_TIMEOUT_SECS` | `300` | Absolute cap a route may request |
| `MAX_RESPONSE_BYTES` | `10485760` | Default response cap; a route may set `0` for unlimited |
| `STREAM_IDLE_TIMEOUT_SECS` | `60` | Cut a response stream that produces no bytes for this long |
| `CORS_ALLOWED_ORIGINS` | — | Exact browser origins; empty disables CORS and `Origin` validation |
| `HEADER_READ_TIMEOUT_SECS` | `10` | Bound on receiving a complete request head |
| `MAX_CONNECTIONS` | `1024` | Concurrent socket cap |
| `TRUSTED_PROXIES` | — | CIDRs allowed to set the client address; empty trusts nobody |
| `ADMIN_TIMEOUT_SECS` | `10` | Control-plane request deadline |
| `AUDIT_RETENTION_DAYS` | `90` | Control-plane audit window; `0` keeps forever |
| `DATA_AUDIT_ENABLED` | `true` | Per-call data-plane audit |
| `DATA_AUDIT_QUEUE_CAPACITY` / `DATA_AUDIT_BATCH_SIZE` | `1024` / `100` | Bounded queue and batch size |
| `DATA_AUDIT_RETENTION_DAYS` | `90` | Data audit window; `0` keeps forever |
| `AUDIT_CLAIMS` | — | Token claims recorded in the data-plane audit, e.g. `project_id,agent_id`; max 8 |
| `MAX_REQUEST_BODY_BYTES` | `1048576` | Inbound body limit |
| `SHUTDOWN_DRAIN_SECS` | `25` | Graceful drain budget |
| `OAUTH_ISSUER` | unset | Enables OAuth when set; the IdP issuer |
| `OAUTH_AUDIENCE` / `OAUTH_JWKS_URI` / `OAUTH_RESOURCE` / `OAUTH_AUTHORIZATION_SERVERS` | — | Required with `OAUTH_ISSUER`; a partial block is a boot error |
| `OAUTH_SCOPES_SUPPORTED` | — | advertised scopes |
| `OAUTH_ALGORITHMS` | `RS256` | RS256/384/512 or ES256/384 |
| `OAUTH_TOKEN_FORMAT` | `jwt` | Only JWT is implemented; introspection is a deliberate seam |
| `OAUTH_CLOCK_SKEW_SECS` / `OAUTH_JWKS_TTL_SECS` | `30` / `300` | Validation and cache windows |
| `OAUTH_DEFAULT_TENANT` | `oauth` | Tenant for tokens without a tenant claim |
| `OAUTH_TOKEN_ENDPOINT` / `OAUTH_CLIENT_ID` / `OAUTH_CLIENT_SECRET` | unset | RFC 8693 exchange; required for an upstream audience |
| `OAUTH_CLIENT_AUTH` | `basic` | `basic` or `post` for the token endpoint |
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
`TRUSTED_PROXIES` to the address the gateway actually sees for that proxy: `127.0.0.1`
only when Caddy shares the gateway's network namespace, otherwise the Docker bridge
gateway or the ingress pod CIDR. If it is wrong, every caller shares one bucket — verify
with the runbook's client-address check.

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
| JWKS cache | per replica | each replica fetches and refreshes the issuer's keys independently |
| Token-exchange cache | per replica | short-lived tokens; a miss exchanges again |
| Data audit | per replica queue, shared table | batched inserts; a full queue drops with a metric |
| Upstream connections | per replica | one pooled client per upstream config; idle sockets bounded by `UPSTREAM_POOL_MAX_IDLE_PER_HOST` |
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
6. **Set `ADMIN_TOKENS`** if you want the HTTP control plane, and keep its listener private (`ADMIN_TOKEN` is the legacy single-token form).
7. **Decide on revocation staleness**: cross-replica revocation is immediate over Postgres
   `LISTEN/NOTIFY`; `AUTH_CACHE_TTL_SECS` is the fallback window if a listener drops.
8. **Wire an identity provider for MCP**: set the `OAUTH_*` block, publish
   `/.well-known/oauth-protected-resource`, and verify the issuer advertises PKCE
   `S256`. If upstreams need per-user tokens, configure `OAUTH_TOKEN_ENDPOINT` and
   give each upstream an `audience`. Do not build an authorization server into the
   gateway.
9. **Decide tool policy per route**: `off` is a deliberate transparent proxy; an
   allow-list is the governed mode. Record-level authorization stays in the MCP
   server.

Deliberately generic: no cloud provider, no vendor SDK, no auth provider. The `AuthError`
and rate-limiter seams are where those integrations belong.

Known gaps, stated plainly: rate limits, retry budgets, and breakers are per replica;
unknown-length request bodies are buffered up to the limit instead of streamed; TLS
terminates at the edge rather than in the gateway.

## Enterprise AI connectors (MCP)

The same data plane can front organization-installed AI connectors: ChatGPT apps
and Claude connectors, both of which speak the Model Context Protocol over
Streamable HTTP.

**Protocol era:** design for both. The `2026-07-28` revision is stateless and is
the target, but current Claude connectors still use the `2025-11-25` initialization
era and OpenAI has not published `2026-07-28` support. The gateway forwards
`initialize`, `Mcp-Session-Id`, and legacy `Last-Event-ID` rather than holding
session state; `2026-07-28` clients simply ignore them. Do not assume the pilot is
stateless-only.

**Implemented in this template**

- **OAuth 2.1 resource server.** Validates JWTs from the configured issuer against
  a cached JWKS, checks `iss`/`aud`/`exp`/`nbf`, and rejects ID tokens by audience
  (and `typ: id+jwt` early). Publishes RFC 9728 protected-resource metadata.
  OAuth `401`s carry `error` + `resource_metadata` + `scope`; OAuth `403`s carry
  `insufficient_scope`; API-key failures carry `Bearer` only. The gateway never
  issues tokens.
- **Per-user principal.** One identity type for API keys and OAuth, with subject,
  assistant client, scopes, roles/groups, and token id. Per-user rate limits and
  per-call audit use it.
- **Tool-level policy.** A route can carry an allow-list keyed by role. Every
  `tools/call` is checked before forwarding, including each call in a batch, and
  denied calls return a JSON-RPC error the model can render. `tools/list` responses
  are filtered so the model never sees a tool the caller cannot use; a
  wrong-content-type or unparseable list fails closed. `server/discover` and
  JSON-RPC error envelopes pass through. `Mcp-Method`, `Mcp-Name`, and
  `MCP-Protocol-Version` must agree with the body when present. Filtered lists are
  rewritten `cacheScope: private` and lose their shared-cache `ttlMs`. Setting
  `RATE_LIMIT_TOOL_PER_MINUTE` adds a per-tenant bucket per tool, so one tenant
  cannot monopolise an expensive one; `gateway_mcp_tool_calls_total` counts calls
  by tenant, tool and decision, with denied names collapsed to `unlisted` so a
  caller cannot create metric series by inventing tool names.
- **Argument validation.** `tools/list` responses teach the gateway each tool's
  `inputSchema`, cached for `MCP_TOOL_SCHEMA_TTL_SECS`. A `tools/call` whose
  arguments are not an object, or that omits a field the schema marks `required`,
  is refused locally with JSON-RPC `-32602` and never reaches the upstream. This is
  deliberately not a JSON Schema engine: unsupported keywords mean "no opinion", and
  a tool the gateway has not seen listed fails open. The tool still validates;
  the schema is one the upstream chose to publish.
- **Upstream identity.** Routes can declare an audience. The gateway exchanges the
  caller's token with RFC 8693 and sends a short-lived token minted for that
  upstream. The inbound token is never forwarded to another audience.
- **Per-call audit.** Tenant, subject, assistant, tool, decision, status, latency,
  request id, and token id go to a bounded queue and a batched insert. A full queue
  drops and increments a metric rather than adding latency.
- **Attribution beyond the subject.** `AUDIT_CLAIMS` names token claims — `project_id`,
  `agent_id`, anything signed by the IdP — and their values are recorded in the
  per-call audit's `detail`. A caller may also send `X-Run-Id`; it is validated,
  recorded, and echoed on the response, including on errors, so a client can join its
  own logs to the audit row. Neither is ever read for authorization.
- **Tamper-evident control-plane audit.** Every mutation row carries the hash of its
  predecessor and a hash of its own contents, appended one writer at a time under an
  advisory lock. `admin audit verify` walks the chain and exits non-zero at the first
  row that does not verify. The high-volume data-plane audit stays batched and
  unchained on purpose: it is not the log an auditor reads.
- **MCP timing.** Per-route deadline and response cap; `max_response_bytes: 0`
  disables the cap for long-lived streams, and every streamed body has an idle
  timeout (`STREAM_IDLE_TIMEOUT_SECS`). Tool calls carry bodies and are never
  retried. The global deadline is a hard backstop, not the route budget.
- **Edge behaviour.** Exact-origin CORS and `Origin` validation when
  `CORS_ALLOWED_ORIGINS` is set; `Mcp-*` headers pass through; upstream
  `Access-Control-*` headers are stripped so the gateway owns CORS; hop-by-hop and
  credential headers are still stripped. Browser clients using `x-mcp-header` tools
  must add those `Mcp-Param-*` names to the CORS allow-list; server-side connectors
  do not.

Example control-plane calls:

For a local end-to-end demo, run `just mcp-stub` and `just mcp-route` (with the
host binary, not the compose gateway), then after sourcing `.env`:

```bash
curl -s -X POST localhost:8080/mcp \
  -H "Authorization: Bearer dev-local.$DEV_API_KEY_SECRET" \
  -H "content-type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search_tickets","arguments":{"query":"open"}}}'
```

The same request for `delete_ticket` returns a JSON-RPC denial and an audit row.

Production-shaped example (requires the `OAUTH_TOKEN_ENDPOINT`/client block for the
`--audience`):

```bash
api-gateway admin upstream put corp-mcp \
  --base-url https://mcp.internal \
  --timeout-ms 30000 \
  --audience https://mcp.internal

api-gateway admin route put mcp \
  --prefix /mcp \
  --upstream corp-mcp \
  --method POST \
  --rewrite /mcp \
  --request-timeout-ms 120000 \
  --tool-policy '{"mode":"allow_list","roles":{"support":["search_tickets"]}}'
```

**Still out of scope, deliberately**

- Record-level authorization. The MCP server or data API decides which records a
  user may read; the gateway decides which tools they may call.
- Prompt-injection and tool-poisoning defence beyond tool allow-lists, output caps,
  and the planned schema pinning. Do not claim the gateway makes an unsafe tool
  safe.
- Full JSON Schema validation. The gateway checks that arguments are an object and
  that advertised `required` fields are present; types, formats, `oneOf` and the
  rest are the tool's business. Schema *pinning* — refusing a tool whose definition
  changed after approval — is not built either, so a poisoned `tools/list` is
  filtered for authorization but not for intent.
- Opaque-token introspection. JWT access tokens are supported; introspection is a
  deliberate seam, not a silent fallback.
- A static upstream credential store. Token exchange is the supported path; a
  service credential is a documented residual risk, not a default.
- Tool-schema pinning/drift alerts and a human approval workflow for write tools.
- DLP/PII inspection of tool output.
- Virtual MCP aggregation across multiple upstream servers.
- Multi-tenant admin and shared deployments. v1 is one organization per deployment.

See [`docs/mcp-gateway.md`](docs/mcp-gateway.md) for the protocol details and the
phased backlog, and [ADR 0002](docs/adr/0002-mcp-resource-server.md) for the
direction.

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
| `just mutants` | Mutation testing (needs `cargo install cargo-mutants`; slow, on demand) |
| `just demo-route` | Registers the demo upstream and route |
| `just mcp-stub` | Runs a local MCP upstream on `127.0.0.1:18100` |
| `just mcp-route` | Registers `/mcp` with a `search_tickets` allow-list |
| `just db-up` / `just db-down` / `just db-logs` | Local Postgres |

Rules: CI must be green before a change lands; no `unwrap` on request paths; secrets never
reach logs or error bodies; new dependencies go through `cargo add` and must pass `just deny`.

The suite runs in about two seconds. Database tests run only when `DATABASE_URL` is set and
fail loudly, with a hint, when it is unreachable — they never skip silently. Property tests
cover the path, header, and client-identity invariants. `just mutants` runs mutation testing
on demand; the retry, error, client-identity, and routing modules currently report no
surviving mutants.
