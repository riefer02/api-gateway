# Threat model

Scope: the gateway process, its Postgres database, the identity provider it trusts, and
the trust boundary between callers and upstreams. Out of scope: the upstream services
themselves and the host OS.

## Trust boundaries

```
 untrusted caller ──▶ [ edge TLS terminator ] ──▶ [ gateway ] ──▶ [ upstream ]
                                                    │
                                                    ├──▶ [ Postgres ]
                                                    └──▶ [ IdP / JWKS ]
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
| SSRF through route config | Upstream allowlist enforced at write and compile; redirects disabled; credentials in URLs rejected; resolved addresses filtered by `UPSTREAM_EGRESS` at connect time, IP literals at compile time | The default policy blocks loopback, link-local and the two common metadata endpoints, not every provider's; `allow-all` removes the filter |
| Path confusion (authorize one path, forward another) | Dot segments, backslashes, and matrix-parameter `;`/`%3b` rejected before matching | Upstreams that double-decode other encodings (e.g. `%252e`) remain out of our control |
| Request smuggling | Hyper rejects ambiguous `Content-Length`/`Transfer-Encoding`; hop-by-hop and `Connection`-named headers stripped | Depends on hyper's parser |
| Credential leakage to upstreams | `Authorization`, `Cookie`, `Host`, and forwarded headers stripped before forwarding | Upstreams that need caller identity get an exchanged token, never the inbound one |
| Token accepted for another service | JWT validation checks signature, issuer, audience, expiry, and algorithm; ID tokens are rejected | An issuer that mints a shared audience defeats this; configure a unique audience per gateway |
| Token passthrough / confused deputy | The inbound token is never forwarded; RFC 8693 exchange mints a token for the upstream audience; the gateway never issues tokens | Depends on the IdP binding `audience` correctly and on the upstream validating it |
| Tool-policy bypass | `tools/call` is parsed on enforcing routes; `tools/list` is filtered; malformed bodies are refused rather than passed | An upstream that accepts non-JSON-RPC shapes or a route left in `off` mode bypasses tool policy by design |
| Prompt injection through tool output | Tool allow-lists, write-tool approval (roadmap), response caps, and audit | The gateway cannot make an unsafe or over-broad tool safe; record-level authz belongs in the data layer |
| Cross-tenant route access | Optional `routes.tenant_id`; a tenant route is invisible to other tenants and never falls through to a shorter prefix | A shared route with broad scopes is reachable by every tenant by design |
| Browser origin abuse / DNS rebinding | `Origin` is validated against an exact allow-list when CORS is configured; preflight is answered before auth; upstream CORS headers are stripped | With CORS unset, browser clients are not origin-checked; an MCP deployment should configure the allow-list |
| Audit tampering or gaps | Control-plane rows are hash-chained and `admin audit verify` walks the chain; per-call audit is route-gated with status-derived decisions, a bounded queue and explicit drop/write-failure metrics; identifiers only | The chain is unkeyed and starts at the oldest retained row, so a writer who can recompute the suffix, or remove the oldest rows, is not detected; export to an append-only sink for that threat |
| Secret leakage to logs | No secret is logged; upstream errors logged by kind, not `Display`; request ids sanitized; tool arguments are not audited | URL paths and tool arguments may still contain caller-chosen secrets if callers put them there |
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
- OAuth is delegated to the customer's identity provider. The gateway validates
  tokens and never issues them.
- The database is on a private network and its credentials are injected from a secret store.
- Operators are identified by named admin tokens; scopes bound what each may do, but all
  scopes are still coarse (`config:write` covers every route and upstream).
- One organization per deployment for v1. Shared deployments need tenant-scoped
  admin roles and audit partitioning before they are supported.

## Open work

- mTLS or OIDC for the admin listener, replacing static tokens.
- Distributed rate limiting so limits hold across replicas.
- Tool-schema pinning and drift alerts; approval workflow for write tools.
- Opaque-token introspection, with an explicit outage policy.
- Static upstream credentials, if a customer cannot use token exchange: envelope
  encryption/KMS, rotation, and a documented residual risk.
- Record-level authorization remains in the MCP server or data API; the gateway must
  not become the only authorization layer.
- Audit integrity has a known ceiling: the control-plane chain is unkeyed and anchored at
  the oldest retained row, so it detects edits and reordering but not a writer who
  recomputes the suffix or prunes the head. The data-plane audit is unhashed by design.
  Ship both to an append-only sink if the threat includes database write access.
