# ADR 0005 — Replica-local limits and breakers, measured

Status: accepted · 2026-11-19 · extends [ADR 0001](0001-replicas-and-ci.md)

## Context

ADR 0001 decided that rate limits, retry budgets and circuit breakers are per replica, with
no shared state, and that `RATE_LIMIT_BACKEND=redis` fails fast rather than pretending. That
was a design argument. Six months later there is a local cluster that can measure it, and the
measurement changes what the documentation should say.

The question an operator actually asks is "if I set 600/minute, what do I get?". The answer
depends on replica count and on how the load balancer distributes clients.

## Decision

Keep the model. Do not add a shared store.

- **Limits and breakers stay in-process and per replica.** The gateway's value is that it
  has no request-path dependency beyond the upstream; putting Redis there would trade an
  outage mode for precision the template does not need.
- **Document the multiplication, do not hide it.** N replicas allow N × the configured rate.
  An operator who needs a cluster-wide ceiling divides the target by the replica count or
  uses sticky routing.
- **Sticky routing is the mitigation, and it is a proxy setting.** Consistent hashing or a
  cookie pins a client to one replica, so that replica's bucket sees the whole client. It
  costs hotspots: one heavy tenant can saturate one replica while others idle.
- **Breakers multiply too.** A threshold of 3 needs 3 × replicas failures before every
  replica has opened. A client sees a mix of rejections and fresh probes until then.

## Measurements

Local cluster, three replicas, tenant limit 6/minute, 24 requests with one key:

| Routing | Allowed | Refused |
|---|---:|---:|
| Round-robin | 15 | 9 |
| Sticky | 5 | 19 |

The two other numbers that belong to this decision:

- **Revocation is not a cache concern.** With a 300 s cache TTL, a revoke reached the other
  replicas in **12 ms** via `pg_notify`. The TTL is the fallback, not the mechanism.
- **A replica leaving under load** lost about 10 of ~490 requests with 8 concurrent clients,
  with SIGTERM and SIGKILL alike — the missing phase was endpoint removal, not drain. That
  is why `deploy/k8s` runs `api-gateway prestop --seconds 5` before the drain.

## Consequences

- Scaling is a replica count, not an architecture change; no shared cache to operate.
- The effective limit is a function of the deployment. Documentation says so rather than
  implying a single configured number.
- Sticky routing introduces hotspots and a load-balancer dependency. It is a deployment
  choice, not a property of the gateway.
- A hard contractual limit cannot be enforced precisely without a shared store.

## Alternatives

| Alternative | Why not |
|---|---|
| **Redis counters** | Exact, and puts a network hop and a new outage mode on every request. Also invites a fail-open/fail-closed decision under pressure, which is worse than a documented approximation |
| **Partition the budget (1/N each)** | No hot-path hop, but it drifts whenever replicas are uneven and behaves badly during rollouts |
| **Sticky routing by default** | Fixes the arithmetic and introduces hotspots and proxy coupling for every deployment, including single-replica ones |
| **Global limit at the edge only** | Coarse and useful as a backstop, but it cannot see tenants or tools |

## Revisit when

- a contract or a regulator requires a hard cluster-wide limit — then build the Redis backend
  behind the existing `RateLimitBackend` seam, with an explicit decision about what happens
  when the store is unavailable;
- a single tenant dominates a replica under sticky routing — then reconsider partitioning or
  per-tenant sharding;
- breaker flapping under a slow upstream becomes operational noise — then lengthen the
  cooldown rather than sharing state.
