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
