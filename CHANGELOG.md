# Changelog

Notable changes, newest first. Format loosely follows [Keep a Changelog](https://keepachangelog.com);
versions follow [Semantic Versioning](https://semver.org).

## [0.1.0] — 2026-11-12

First tagged build: a working data plane and an audited control plane.

### Data plane

- API-key authentication with HMAC-SHA256 verifiers, a server pepper, constant-time
  comparison, expiry, revocation, and tenant/client suspension.
- Postgres-backed route table compiled into an immutable in-memory snapshot; longest-prefix
  matching on segment boundaries, explicit rewrite, per-route scopes, `405` with `Allow`,
  `HEAD` implied by `GET`.
- Streaming reverse proxy: request and response bodies stream, hop-by-hop and
  `Connection`-named headers are stripped, upstream redirects are never followed, and the
  path that is authorized is the path that is forwarded.
- Per-IP and per-tenant token-bucket rate limits with `RateLimit-*` and `Retry-After`.
- Per-upstream circuit breakers and budgeted, idempotent-only retries with jittered backoff.
- Whole-request deadline, header-read timeout, connection cap, and body limits.

### Control plane

- One `AdminService` with a CLI and an HTTP adapter on a separate, bearer-token listener.
- Named admin tokens with scopes (`tenants`, `keys`, `config`, `audit`).
- Tenant, client, key, upstream, and route lifecycle including deletion, rotation, and
  enable/disable.
- Append-only audit log with actor, action, subject, source IP, and request id; retention
  is configurable.

### Operations

- Prometheus metrics, OpenTelemetry traces, structured logs, and a boot summary with
  advisories for risky configuration.
- Split liveness/readiness with a cached database probe and route-table staleness detection.
- Graceful drain on `SIGTERM`, per connection, with a configurable budget.
- Distroless image, compose stack, Kubernetes manifests, and a Caddy edge-TLS example.
- Cross-replica revocation over Postgres `LISTEN/NOTIFY`.

### Known limitations

- Rate limits, retry budgets, and breakers are per replica; the cluster limit is N ×.
- TLS terminates at the edge rather than in the gateway.
- Unknown-length request bodies are buffered up to the limit.
- Not security-audited. Review `docs/threat-model.md` before production traffic.
