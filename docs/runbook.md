# Runbook

Operational procedures for the gateway. Every command assumes `DATABASE_URL` is exported;
the CLI talks to Postgres directly and does not read admin tokens.

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

Immediate in this process and broadcast to every replica over Postgres `LISTEN/NOTIFY`.
The cache TTL (`AUTH_CACHE_TTL_SECS`) is only the fallback if a replica's listener drops.

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

## Who changed what

```bash
api-gateway admin audit list --limit 50
curl -s "$ADMIN/v1/audit?limit=50" -H "Authorization: Bearer $TOKEN"
```

Rows carry the actor bound to the admin token, the action, the subject, the source IP, and
the request id from the response. Tokens can be scoped (`config:read`, `keys:write`, …), so
`actor` answers *who* and the token's scopes bound *what they could do*.

## Decommission

Delete from the leaves up; foreign keys refuse to orphan rows, so a wrong order returns
`409` rather than losing data.

```bash
api-gateway admin route rm billing-v1
api-gateway admin upstream rm billing     # 409 while routes still reference it
api-gateway admin key revoke <key-id>
api-gateway admin client rm acme-app      # 409 while keys still exist
api-gateway admin tenant rm acme          # 409 while clients still exist
```

To take a route out of service without deleting it, re-register it disabled:

```bash
api-gateway admin route put billing-v1 --prefix /v1/billing --upstream billing --disabled
```

## Audit retention

`AUDIT_RETENTION_DAYS` (default 90) prunes `audit_events` at boot and every six hours. Set
it to `0` to keep everything forever, and make sure the table is backed up if you do.

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
