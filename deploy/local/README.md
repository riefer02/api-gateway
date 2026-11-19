# Local cluster

Three gateway replicas behind Traefik, one Postgres, one MCP stub. It exists to
make replicated behaviour observable on a laptop, not to be a production
network.

```sh
just cluster-up          # build and start; waits for health
just cluster-limit       # the per-replica rate-limit measurement
just cluster-down        # stop and delete the volume

STICKY=true just cluster-up && STICKY=true just cluster-limit   # the comparison
```

Everything is on `127.0.0.1:8000`. The development API key is
`dev-local.local-secret`; the admin CLI runs inside a replica with
`docker compose -f deploy/local/compose.yml exec gateway api-gateway admin …`.

## One measured run

Three replicas, tenant limit 6/minute, 24 requests with one key, same stack
both times. The warm-up request consumes one token, hence 5 rather than 6.

| Routing | Allowed | Refused |
|---|---:|---:|
| Round-robin (default) | 15 | 9 |
| `STICKY=true` | 5 | 19 |

The first row is the documented N × behaviour, observed rather than assumed.
The second is the same limit behaving cluster-wide, with a cookie doing the
partitioning.

## Experiments

Each one asserts a behaviour and prints the numbers it measured.

| Command | What it does |
|---|---|
| `just cluster-limit` | 24 requests, one key, 6/minute per tenant, three replicas |
| `just cluster-failover` | 8 concurrent clients for 6s; one replica leaves at t+2s |
| `HARD=true just cluster-failover` | the same with SIGKILL instead of SIGTERM |
| `just cluster-revocation` | a fresh key is revoked on one replica; the others must refuse it |
| `just cluster-fault` | Toxiproxy adds 3s latency to a 1s-deadline route; the breaker opens, then recovers |

## What it proves

- **The N × rate limit is real.** `just cluster-limit` sends one tenant's
  requests through the balancer with a 6/minute limit and three replicas, and
  shows more than 6 accepted. With `STICKY=true` the same run shows 6. That is
  the whole argument for sticky routing, measured rather than asserted.
- **Failover.** `docker compose … kill gateway` removes a replica; Traefik
  stops routing to it and the remaining ones serve. Nothing in the gateway
  needs to know.
- **Revocation convergence.** Revoke a key through one replica and the others
  drop it via `pg_notify`, not by waiting out the cache TTL.
- **Breaker and bulkhead.** Point a route at a stubbed 500 or a slow upstream
  and watch `gateway_upstream_saturated_total` and the circuit state.
- **Rolling restart.** `docker compose … up -d --scale gateway=3 --no-deps`
  after a config change; readiness keeps Traefik from sending traffic to a
  replica that has not loaded routes.

## What the experiments found

These are measurements from one laptop run, not claims about a production
network.

**Per-replica limits multiply.** 6/minute with three replicas allowed 15 of 24
requests round-robin, and 5 with sticky routing. The mitigation is partitioning,
not a bigger number.

**Per-replica breakers multiply too.** A threshold of 3 needs 3 × replicas
failures before every replica has opened; the first experiment showed 408s from
still-closed replicas until the burst was sent concurrently.

**Drain is necessary but not sufficient.** With 8 concurrent clients, SIGTERM
and SIGKILL both lost about 10 of ~490 requests. The reason is not the drain
budget: the load balancer keeps sending to the terminating replica until it
notices the container is gone, and the listener has already stopped accepting.
Kubernetes has the missing phase — endpoint removal plus a `preStop` delay — so
`deploy/k8s` now runs `api-gateway prestop --seconds 5` before the drain.

**A deadline did not trip the breaker.** The timeout wraps the proxied call, so
the call never returns and the breaker's own accounting never runs. Fixed:
a deadline now records a failure. Without it the breaker protected against fast
failures but not the slow ones it exists for.

**Revocation is not a cache concern.** With a 300s cache TTL, revocation reached
the other replicas in 12ms via `pg_notify`. The TTL is a fallback, not the
mechanism.

**A slow upstream makes the breaker flap** between open and half-open, letting
one probe through per cooldown. That is the design: an open circuit that never
probes cannot recover.

## What it cannot prove

- **Absolute throughput.** Docker Desktop runs a VM on macOS, so requests per
  second here are not comparable to Linux, and the load generator competes for
  the same cores. Ratios (overhead versus a direct call) survive; absolutes do
  not.
- **Network conditions.** `tc netem` is not available in the macOS Docker
  kernel. Fault injection should go through Toxiproxy, which proxies TCP and
  can add latency, bandwidth limits and resets portably.
- **A long soak.** Hours of traffic on a laptop say more about thermal
  throttling than about the gateway.

## Deliberate omissions

No Kubernetes here: the manifests in `deploy/k8s` are the deployment story, and
`kind` on a laptop adds a control plane without adding a behaviour these three
containers cannot show. No Chaos Monkey yet: the first useful experiments are
the ones above, and Toxiproxy is the portable way to run them.
