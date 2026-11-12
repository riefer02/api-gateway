# ADR 0001 — Replica model and CI scope

Status: accepted · 2026-11-12

## Context

The gateway can run as one process or many. Before deciding what to test on every push, we
need to be explicit about which state is shared and which is not, because that determines
both the deployment shape and the value of a multi-replica test.

## Decision — replica model

The gateway holds no request-affecting state that must be shared between replicas. The only
shared dependency is Postgres.

| State | Scope | Convergence |
|---|---|---|
| Route table | per replica | poll `route_table_state.version`, swap the snapshot atomically |
| Credential cache | per replica | `pg_notify` on revoke, `LISTEN` on each replica, TTL as fallback |
| Rate limits | **per replica** | deliberately not shared: N replicas allow N × the configured rate |
| Retry budget | **per replica** | same arithmetic |
| Circuit breakers | per replica | each replica learns upstream health independently |
| Schema migrations | global | sqlx advisory lock serialises concurrent starters |

Consequences we accept:

- No sticky sessions, no leader election, no shared cache to operate. Scaling is a replica
  count, not an architecture change.
- Rate limits and retry budgets are sized **per replica**. The operator divides the
  product target by the replica count, or documents that the cluster limit is N ×.
- A revocation is visible on every replica within the NOTIFY round trip; the cache TTL
  (`AUTH_CACHE_TTL_SECS`) is only the fallback when a replica's listener is disconnected.

## Decision — CI scope

Per push (the contract: fast, hermetic, no internet):

- `cargo fmt --check`, `clippy -D warnings`
- unit + Postgres-backed integration tests
- `cargo deny` (advisories, licenses, bans, sources)
- container build + `--version` smoke test

Not per push:

- the two-replica convergence harness (`just replicas`). It builds images twice and reaches
  a public upstream, so it is slow and flaky by nature. Keeping it manual means the
  property is demonstrable without making every push wait on Docker and the internet.
- load benchmarks (`just bench`). Numbers belong in a report, not a pass/fail gate.

## Consequences

- The multi-replica property is proven by `scripts/replicas.sh`, run on demand and before a
  release that changes routing, auth, or the cache.
- CI stays under a few minutes, which keeps the feedback loop useful.
- Nothing in the deployment depends on the replica count except the arithmetic above.

## Deliberately not done yet

- Redis-backed rate limiting. It buys cluster-wide accuracy that only matters once the
  per-replica multiplication is unacceptable, which needs a real second replica and real
  traffic. `RATE_LIMIT_BACKEND=redis` fails fast at boot rather than pretending.
- Multi-replica or benchmark jobs in CI. Revisit when either (a) a deployment actually runs
  more than one replica, or (b) the harness is rewired to the local stub upstream so it has
  no internet dependency.
- In-gateway TLS. Terminated at the edge today, with a reference Caddy config.

## Revisit when

- a production deployment runs ≥ 2 replicas, or the per-IP multiplication shows up in
  incident reports — then build the Redis limiter behind the existing config seam;
- the multi-replica harness is switched to the stub upstream — then move it to a nightly
  job without touching the per-push budget;
- a second maintainer joins — then the manual harness moves into a release checklist.
