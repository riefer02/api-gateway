# Runbook

Operational procedures for the gateway. Every command assumes the same environment as the
server: at minimum `APP_ENV` and `DATABASE_URL`; production also needs `AUTH_PEPPER` and
`UPSTREAM_ALLOW_HOSTS`, and audience management needs the `OAUTH_*` block. The CLI talks to
Postgres directly and does not read admin tokens. It does **not** migrate automatically;
run `api-gateway admin migrate` explicitly (or let `serve` apply migrations on boot).
The shell examples use `$ADMIN`, `$TOKEN`, `$AUDITOR_TOKEN`, and `$METRICS_TOKEN`
from your environment; define them from `ADMIN_TOKENS`/`METRICS_TOKEN` first.

## Health

```bash
curl -sf localhost:8080/health   # process alive
curl -sf localhost:8080/ready    # route table fresh; database reachable (or cached)
curl -s -H "Authorization: Bearer $METRICS_TOKEN" localhost:8080/metrics \
  | grep -E 'gateway_(requests|circuit|upstream)'
```

`/ready` fails when the route table has not refreshed within its staleness window, when the
compiler rejected the current configuration, or when Postgres has been unreachable for
longer than the credential cache can cover. A short database blip is tolerated on purpose:
the process can still serve from cache, and draining the fleet would turn the blip into an
outage. It does **not** mean the process is unhealthy: keep it running so it can recover.

## Rotate a customer's key

```bash
api-gateway admin key rotate <key-id>
```

Issues a replacement with the same client, scopes, and remaining lifetime, then revokes the
old key. An already-expired key is refused (`409`); issue a new key instead. The token is printed once. If the revoke fails, the replacement is revoked again
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

## Revoke an OAuth user

The gateway does not hold a user directory. Disable the person in the identity
provider, and their access token stops working when it expires. Access-token
lifetime is the revocation SLA for JWT credentials; if the customer requires
immediate revocation, lower the token lifetime or add an introspection/revocation
check in front of sensitive routes, and accept the availability cost.

## JWKS outage or key rotation

Symptoms: OAuth requests return `503 service_unavailable`, logs mention
`JWKS unavailable`, or every token returns `401 invalid_token` after a rotation.

- A `503` means the gateway cannot fetch the issuer's key set and has no cached key
  for the token. Check `OAUTH_JWKS_URI` and the issuer's availability. Do not change
  the gateway's issuer/audience to "fix" an outage.
- An unknown `kid` triggers one refresh per cooldown (`10 s`). A rotation inside that
  window is delayed, not rejected forever.
- A valid token is never downgraded to `401` because the key set is unreachable when
  a matching cached key exists.
- Alert on `gateway_auth_failures_total{reason="oauth_unavailable"}`.

## Token exchange failure

Symptoms: a route with an audience returns `502 upstream_auth_failed`, or `503` on
the authorization server.

Check `OAUTH_TOKEN_ENDPOINT`, the client credentials, and whether the IdP permits
the `audience` and scope. The gateway never falls back to forwarding the inbound
token: that would be token passthrough. Failures are not retried as a tool call.

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

## Audit integrity

```bash
api-gateway admin audit verify
```

Walks the control-plane chain from the oldest retained row and exits non-zero at the first
row that does not verify. Rows written before the chain (or by a replica that had not been
upgraded) are counted as outside the chain, not trusted. A mixed-version rollout can
therefore look like a break until every replica runs the current version: verify after the
upgrade, not during it. The chain is unkeyed and anchored at the oldest retained row, so it
detects edits and reordering, not a writer who recomputes the suffix or prunes the head.

## Decommission

Delete from the leaves up; foreign keys refuse to orphan rows, so a wrong order returns
`409` rather than losing data.

```bash
api-gateway admin route rm billing-v1
api-gateway admin upstream rm billing     # 409 while routes still reference it
api-gateway admin key revoke <key-id>
api-gateway admin client rm acme-app      # 409 while keys still exist
api-gateway admin tenant rm acme          # 409 while clients OR routes still exist
```

To take a route out of service without deleting it, re-register it disabled:

```bash
api-gateway admin route put billing-v1 --prefix /v1/billing --upstream billing --disabled
```

## Audit retention

`AUDIT_RETENTION_DAYS` (default 90) prunes `audit_events` at boot and every six hours. Set
it to `0` to keep everything forever, and make sure the table is backed up if you do.

Per-call data-plane audit is pruned separately by `DATA_AUDIT_RETENTION_DAYS`
(default 90). Watch `gateway_data_audit_dropped_total` and
`gateway_data_audit_write_failures_total`: a non-zero rate means the queue or the
database cannot keep up, and the audit trail has gaps.

## Roll back a tool policy

Tool policy is part of the route row. A route PUT that omits `--tool-policy`, `--tenant`,
`--scope`, or the enable flags preserves the stored value; only an explicit value changes
it. To turn policy off:

```bash
api-gateway admin route put mcp \
  --prefix /mcp --upstream corp-mcp --method POST \
  --tool-policy '{"mode":"off","roles":{}}'
```

`off` stops inspecting MCP bodies; it does not widen route scopes. Prefer narrowing
the allow-list over turning policy off.

## Inspect data-plane audit

```bash
api-gateway admin audit data --limit 20
api-gateway admin audit data --limit 20 --tenant acme \
  --since 2026-11-01T00:00:00Z
curl -s "$ADMIN/v1/data-audit?limit=20&tenant=acme" -H "Authorization: Bearer $AUDITOR_TOKEN"
```

To keep reading older rows, pass the previous page's `next_cursor` back as `--cursor`
(HTTP: `cursor`). The listing is newest-first and keyset-paged, so rows written while you
page do not shift the boundary.

Rows carry identifiers and decisions, never payloads or tokens. `subject` is the
OIDC `sub`, not an email; resolve it through the IdP if a human-readable identity is
needed. Export rows to the customer's SIEM if the contract requires it.

## Roll back below this release

`routes.tenant_id` and `tool_policy` are security attributes that older binaries do not
understand. A mixed-version rollout or a rollback below this release can serve a
tenant-bound MCP route to every tenant and ignore tool policy. Treat this release as
**forward-only** unless this query returns zero:

```sql
SELECT count(*) FROM routes
WHERE tenant_id IS NOT NULL OR tool_policy->>'mode' <> 'off';
```

If it is non-zero, drain the old version, remove or re-scope those routes deliberately,
and only then roll back. The schema down migration drops `data_audit_events`; export it
first.

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
timeout logs `drain timed out; exiting with connections still open` and exits 0.

## Deploy checklist

1. `just check` is green.
2. Migrations run on `serve` boot, or explicitly with `api-gateway admin migrate`;
   a failed migration aborts startup. Other admin commands do not migrate.
3. `AUTH_PEPPER` and `ADMIN_TOKENS` come from the secret store, never from the image.
4. `UPSTREAM_ALLOW_HOSTS` is non-empty in production.
5. `/ready` is in the load balancer; `/health` is the liveness probe.
6. Scrape `/metrics` from the monitoring network only.
7. `TRUSTED_PROXIES` names the edge proxy's actual address on the network the
   gateway sees. Verify it end to end: send a request through the edge and confirm
   the audit row (or the upstream's `X-Forwarded-For`) shows the caller, not the
   proxy. If it shows the proxy, every caller shares one per-IP bucket and the audit
   address is wrong.
8. If OAuth is enabled, `OAUTH_AUDIENCE` is this endpoint's unique audience, the
   issuer metadata advertises PKCE `S256`, and `/.well-known/oauth-protected-resource`
   is reachable without a token.
9. `CORS_ALLOWED_ORIGINS` lists exact browser origins (if any); server-to-server
   connectors do not need it. A wildcard is rejected at boot. If OAuth is enabled,
   allow egress from the gateway to the IdP's `OAUTH_JWKS_URI` and
   `OAUTH_TOKEN_ENDPOINT` on 443; a default-deny NetworkPolicy will otherwise block
   every OAuth request.
10. `DATA_AUDIT_ENABLED` is true and the data-audit tables are in the backup set.
11. Tool policies are `off` or an explicit allow-list; a route left in `off` mode
    is a deliberate decision, not an oversight.
