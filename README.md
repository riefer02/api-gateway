# api-gateway

An HTTP API gateway in Rust: terminates client requests, authenticates API keys,
enforces policy, and proxies to allowlisted upstreams with tracing and strict header
hygiene.

Built on axum 0.8, sqlx 0.9 (Postgres), reqwest 0.13, and OpenTelemetry 0.33.

## Status

Pre-alpha, but the spine is real: typed configuration, Postgres-backed credentials,
streaming proxy, JSON error envelope, graceful shutdown, and request-id correlation.
Missing: the route table, rate limits, admin plane, circuit breakers. Not yet safe for
production traffic.

## Requirements

- Rust 1.99 (pinned in `rust-toolchain.toml`)
- Docker (local Postgres)
- [`just`](https://github.com/casey/just)

## Quick start

```bash
cp .env.example .env          # edit the local password and secret
just db-up                    # Postgres 18 on 127.0.0.1:5432
just run
```

Migrations run on boot. In development a key is seeded from `DEV_API_KEY_SECRET`.

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

`/swapi/{*path}` currently proxies to the single configured upstream. It is a stand-in
for the Postgres-backed route table (workstream W5).

## Tasks

| Command | What it does |
|---|---|
| `just` | List recipes |
| `just check` | fmt + clippy + tests + dependency policy (mirrors CI) |
| `just clippy` | Clippy with `-D warnings` |
| `just test` | All tests (Postgres tests need `DATABASE_URL`) |
| `just deny` | Licenses, advisories, duplicates, wildcards |
| `just db-up` / `just db-down` / `just db-logs` | Local Postgres |

## Configuration

Environment variables, loaded from `.env` in development. Production refuses
development defaults; `just run -- --check-config` prints the resolved values with
secrets redacted.

| Variable | Default | Notes |
|---|---|---|
| `APP_ENV` | — (required) | `development` or `production` |
| `HOST` / `PORT` | `127.0.0.1` / `8080` | Bind address |
| `LOG_LEVEL` | `info` | `tracing` env filter |
| `DATABASE_URL` | — (required) | Postgres connection string |
| `DB_MAX_CONNECTIONS` / `DB_MIN_CONNECTIONS` / `DB_ACQUIRE_TIMEOUT_SECS` | `10` / `1` / `5` | Pool sizing |
| `DEV_API_KEY_SECRET` | — | Seeded key; **rejected** in production |
| `UPSTREAM_BASE_URL` | `https://swapi.dev/api` | Test upstream |
| `UPSTREAM_ALLOW_HOSTS` | — | Comma-separated allowlist; required in production |
| `UPSTREAM_TIMEOUT_SECS` | `10` | Upstream request timeout |
| `REQUEST_TIMEOUT_SECS` | `15` | Whole-request deadline |
| `MAX_REQUEST_BODY_BYTES` | `1048576` | Inbound body limit |
| `SHUTDOWN_DRAIN_SECS` | `25` | Graceful drain budget |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | unset | OTLP/gRPC endpoint; logs only when unset |

## Layout

```
src/main.rs           bootstrap, signals, drain
src/app.rs            layer composition (order is a contract)
src/config.rs         typed env configuration + validation
src/error.rs          AppError + JSON envelope
src/proxy.rs          forwarding, header policy, error mapping
src/routes/           HTTP adapters (health, readiness, upstream)
src/auth/             API keys, scopes, in-memory + Postgres stores
migrations/           sqlx migrations (forward-only)
```

## Development rules

- `main` is protected; land changes through a pull request with CI green.
- No `unwrap`/`expect` on request paths.
- Secrets never appear in logs, traces, error bodies, or metric labels.
- New dependencies go through `cargo add` and must pass `just deny`.
