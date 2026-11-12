# Runbook

Operational procedures for the gateway. Every command assumes `DATABASE_URL` and
`ADMIN_TOKEN` are exported.

## Health

```bash
curl -sf localhost:8080/health   # process alive
curl -sf localhost:8080/ready    # database reachable
curl -s  localhost:8080/metrics | grep -E 'gateway_(requests|circuit|upstream)'
```

`/ready` failing means the gateway cannot authenticate anyone. It does **not** mean the
process is unhealthy: keep it running so it can recover, but take it out of rotation.

## Rotate a customer's key

```bash
api-gateway admin key rotate <key-id>
```

Issues a replacement with the same client, scopes, and remaining lifetime, then revokes the
old key. The token is printed once. If the revoke fails, the replacement is revoked again
automatically, so you never leave an unprinted active key behind.

## Revoke access

```bash
api-gateway admin key revoke <key-id>
```

Effective immediately in this process. Other processes (and the CLI) are bounded by
`AUTH_CACHE_TTL_SECS`; to make a revocation global instantly, restart the data plane or
lower the TTL.

Suspending a whole client or tenant is a database operation today:

```sql
UPDATE clients SET status = 'suspended' WHERE id = 'acme-app';
UPDATE tenants SET status = 'suspended' WHERE id = 'acme';
```

## Roll back a route change

Route versions are not kept as rows yet, so rollback means re-running the previous
definition. Keep route definitions in version control next to your deploy config:

```bash
api-gateway admin route put billing-v1 \
  --prefix /v1/billing --upstream billing --scope billing:read
```

A replica that fails to load a new table keeps serving the last good snapshot and logs
`route table refresh failed`.

## Circuit breaker stuck open

```bash
curl -s localhost:8080/metrics | grep gateway_circuit_open_total
```

The breaker re-probes after `CIRCUIT_COOLDOWN_SECS`. If it keeps reopening, the upstream is
still failing; fix the upstream or raise `CIRCUIT_FAILURE_THRESHOLD` temporarily. Restarting
the gateway also resets breakers, because they are in-process.

## Database outage

Symptoms: `/ready` returns 503, authenticated requests return `503 service_unavailable`,
logs show `credential store query failed`.

The route table keeps serving from memory, and the credential cache keeps working for its
TTL. Neither is a substitute for the database. Restore Postgres; the pool reconnects on its
own.

## Overload

Symptoms: `429` and `503` rates rising, `gateway_request_duration_seconds` climbing.

Shedding is the intended behaviour. Check whether the cause is traffic (raise
`RATE_LIMIT_*`) or a slow upstream (breaker opens, `gateway_upstream_requests_total` shows
5xx). Do not disable limits to "fix" an upstream problem.

## Graceful restart

`SIGTERM` stops accepting connections and drains for `SHUTDOWN_DRAIN_SECS` (25 s default).
Orchestrators must allow a matching grace period; the compose file uses 30 s. A drain
timeout logs `drain timed out; exiting with requests in flight` and exits successfully.

## Deploy checklist

1. `just check` is green.
2. Migrations run on boot; a failed migration aborts startup.
3. `AUTH_PEPPER` and `ADMIN_TOKEN` come from the secret store, never from the image.
4. `UPSTREAM_ALLOW_HOSTS` is non-empty in production.
5. `/ready` is in the load balancer; `/health` is the liveness probe.
6. Scrape `/metrics` from the monitoring network only.
