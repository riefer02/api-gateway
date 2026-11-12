# Threat model

Scope: the gateway process, its Postgres database, and the trust boundary between callers
and upstreams. Out of scope: the upstream services themselves, the host OS, and the
identity provider (there is none yet).

## Trust boundaries

```
 untrusted caller ──▶ [ edge TLS terminator ] ──▶ [ gateway ] ──▶ [ upstream ]
                                                    │
                                                    └──▶ [ Postgres ]
 operator ──▶ [ admin CLI / admin listener ] ───────┘
```

- The **caller** controls the request line, headers, and body. Nothing it sends is trusted.
- The **upstream** controls the response, including headers and status.
- The **operator** is trusted, but the admin token is still treated as a secret.
- **Postgres** is trusted; its contents are not exposed to callers.

## Threats and mitigations

| Threat | Mitigation | Residual risk |
|---|---|---|
| Credential theft from a database dump | Verifiers only, HMAC-SHA256 with a server pepper; the secret is never stored | A leaked pepper plus a leaked dump is offline-crackable only if the secret is weak; secrets are 256-bit |
| Key guessing | 256-bit secrets, constant-time comparison, rate limits on the auth path | None practical |
| Key id enumeration | Lookup by id then constant-time verify; auth failures are indistinguishable | Timing on the id lookup remains theoretically observable |
| Stolen admin token | Separate listener, named tokens with scopes, not exposed by default | No mTLS/OIDC yet; rotate the token |
| SSRF through route config | Upstream allowlist enforced at write and compile; redirects disabled; credentials in URLs rejected | DNS rebinding between validation and use is not defended against; pin hosts at the network layer |
| Path confusion (authorize one path, forward another) | Dot segments, including percent-encoded forms, rejected before matching | Upstreams that decode other encodings (e.g. `%252e`) are out of our control |
| Request smuggling | Hyper rejects ambiguous `Content-Length`/`Transfer-Encoding`; hop-by-hop and `Connection`-named headers stripped | Depends on hyper's parser |
| Credential leakage to upstreams | `Authorization`, `Cookie`, `Host`, and forwarded headers stripped before forwarding | Upstreams that need caller identity must be given an explicit design decision |
| Secret leakage to logs | No secret is logged; upstream errors logged by kind, not `Display`; request ids sanitized | URL paths may still contain caller-chosen secrets if callers put them there |
| Resource exhaustion | Body limits, whole-request deadline, header-read timeout, connection cap, per-IP and per-tenant rate limits, cached readiness probe | In-process limits are per replica |
| Amplification via retries | Idempotent, body-less retries only, gated by a token-bucket retry budget | Retried requests still reach the upstream twice |
| Spoofed client identity | Forwarding headers are believed only from `TRUSTED_PROXIES`; the chain is walked right to left, skipping trusted hops | A misconfigured trusted CIDR lets a caller spoof its address |
| Tenant isolation failure | Tenant/client status checked per request; scopes per route | A single cache entry serves one key; no cross-tenant sharing |
| Revocation lag | In-process revoke invalidates immediately; cross-process bounded by `AUTH_CACHE_TTL_SECS` | Set the TTL to your revocation SLA |
| Metrics endpoint disclosure | `METRICS_TOKEN` gates `/metrics`; unset is documented and surfaced at boot | An unset token leaves it open to anyone who can reach the port |
| Container breakout | Distroless, non-root, no shell, no package manager | Standard container hardening still applies |

## Assumptions

- TLS terminates at a trusted edge (Caddy, nginx, a load balancer). The gateway surfaces
  `X-Forwarded-*` advisories by stripping client-supplied values.
- The database is on a private network and its credentials are injected from a secret store.
- Operators are identified by named admin tokens; scopes bound what each may do, but all
  scopes are still coarse (`config:write` covers every route and upstream).

## Open work

- mTLS or OIDC for the admin listener, replacing static tokens.
- Distributed rate limiting so limits hold across replicas.
- Audit rows are append-only but not tamper-evident: someone with database write access
  can delete or rewrite them. Hash-chaining or shipping to an append-only sink is the
  next step if that matters to you.
