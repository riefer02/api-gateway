# Organization AI connectors through this gateway

This document explains how the gateway fronts organization-installed AI
connectors: ChatGPT apps and Claude connectors, both of which speak the Model
Context Protocol (MCP) over Streamable HTTP.

**Status:** the identity, policy, audit, and upstream-auth seams described here are
implemented and tested; the remaining gaps are listed in §7. **Protocol era (as of November 2026):** treat
`2026-07-28` as the target, not the traffic you receive today. Current Claude
connectors still use the `2025-11-25` initialization era, and OpenAI has not
published `2026-07-28` support. The gateway forwards both; it does not hold session
state.

Read [`docs/threat-model.md`](threat-model.md) first. This document assumes it.

---

## 1. What the product is

| Surface | What the organization installs | What the connector speaks |
|---|---|---|
| ChatGPT Business / Enterprise / Edu | An admin creates and publishes a **custom app / connector**, then grants access with RBAC. Employees connect it. | Remote **MCP** over HTTPS, usually OAuth 2.1 on the user's behalf. |
| Claude Team / Enterprise | An Owner adds a **custom connector**; per-tool states can be Always allow / Needs approval / Blocked. | Remote **MCP** over HTTPS; OAuth (DCR or CIMD), Anthropic-held credentials, static headers, or no auth. |
| OpenAI API | A remote MCP `server_url` (or a Secure MCP Tunnel for private servers). | MCP. |
| Legacy ChatGPT custom GPT | A GPT with an OpenAPI Action. | REST + OpenAPI. Being retired. |

Two planning facts:

1. **MCP is the convergence point.** Custom GPTs are scheduled to become
   inaccessible on 11 December 2026 (11 February 2027 for approved Enterprise /
   FedRAMP deferrals), and custom Actions do not migrate. New work should target a
   remote MCP endpoint.
2. **The gateway is not the install surface.** OpenAI and Anthropic own the
   directory and the org admin console. This gateway is the HTTPS endpoint they
   point at, plus the control plane that decides which tools each role gets.

### The endpoint assistants expect

For MCP `2026-07-28` (the target; current clients may still be `2025-11-25`):

- One HTTPS endpoint, typically `POST /mcp`, JSON-RPC 2.0. A reply is a JSON object
  or a request-scoped SSE stream. This revision is **stateless**: no handshake, no
  session, and `Mcp-Session-Id` must be ignored.
- A protected server is an **OAuth 2.1 resource server**. It publishes
  `/.well-known/oauth-protected-resource[/path]` (RFC 9728) and answers missing or
  invalid credentials with `401` + `WWW-Authenticate: Bearer resource_metadata="…"`.
- Tokens are audience-bound with RFC 8707 `resource`; the server validates `iss`,
  `aud`, `exp`, and scope. ID tokens are never accepted.
- Client registration is moving from DCR (deprecated in this revision) to **Client
  ID Metadata Documents**. That is the authorization server's job, not the
  gateway's.
- The server validates `Origin` (DNS-rebinding defence); browser clients need CORS.
  The gateway installs that check only when `CORS_ALLOWED_ORIGINS` is non-empty, so
  an MCP deployment should set it.
- `Last-Event-ID` was removed in this revision; the gateway forwards it only for
  legacy compatibility. The GET event stream is legacy too.

Claude has no private-network tunnel: its connectors reach a public HTTPS endpoint
on port 443 from Anthropic cloud ranges. OpenAI offers a Secure MCP Tunnel for
private servers. If the client requires private networking on Claude, that is an
architecture decision, not a gateway setting.

The previous revision (`2025-11-25`) is session-based. If it must be supported,
terminate sessions at the upstream MCP server, never in the gateway.

---

## 2. Architecture

```
 ChatGPT / Claude (vendor cloud)
        │  HTTPS + OAuth 2.1 bearer (aud = this gateway)
        ▼
 [ edge TLS: Caddy / ALB / ingress ]      HSTS, hides /metrics and /ready
        │
        ▼
 [ api-gateway ]
   request id → CORS/Origin → metrics → trace → panic → hard deadline
   → path safety → IP limit
   → authenticate: API key OR OAuth JWT (iss/aud/exp/scopes) → Principal
   → tenant limit → user limit
   → resolve route (+ tenant binding)
   → authorize route scopes (403 insufficient_scope)
   → MCP policy: tools/call allow-list; tools/list filtering
   → upstream auth: RFC 8693 exchange (preferred)
   → proxy: no redirects, no retries for tool calls, response cap
   → async per-call audit (bounded queue, batched insert)
        │
        ├──▶ MCP server A (per-user token from exchange)
        ├──▶ MCP server B
        └──▶ plain REST upstreams (existing routes)
        │
        ▼
   Postgres: routes, keys, tool policies, control audit, data audit
   IdP / authorization server: Entra, Okta, Auth0, WorkOS, Keycloak
```

The important boundary: **the authorization server is the IdP, not this process.**
The gateway validates tokens and enforces policy; it never issues tokens.

---

## 3. What is implemented

| Capability | Where | Notes |
|---|---|---|
| OAuth 2.1 resource server | `src/auth/oauth.rs` | Cached JWKS, `iss`/`aud`/`exp`/`nbf`, algorithm allow-list, ID-token rejection, claim bounds, `503` on key-set outage. |
| Protected-resource metadata | `src/routes/metadata.rs` | RFC 9728 document, public, path-suffixed form supported. |
| MCP challenges | `src/error.rs` | `401` with `resource_metadata`; `403 insufficient_scope` for route scopes. |
| Per-user principal | `src/auth.rs` | One type for API keys and OAuth: tenant, subject, assistant client, scopes, roles/groups, token id, inbound token for exchange. OAuth tokens without a `tenant` claim use `OAUTH_DEFAULT_TENANT`. |
| Per-user limits | `src/limits.rs`, `src/routes/upstream.rs` | `RATE_LIMIT_USER_PER_MINUTE`, keyed `tenant:subject`. |
| Tenant-bound routes | `src/routing.rs`, migration | `routes.tenant_id`; a tenant route is invisible to other tenants and no shorter prefix is used as a fallback. |
| Tool policy | `src/mcp/`, `routes.tool_policy` | Role → tools; `*` role/tool supported. `tools/call` denied as a JSON-RPC error; `tools/list`/`server/discover` responses are filtered; policy mode requests JSON and an unparseable or non-JSON response fails closed rather than streaming unfiltered. API keys act as the `service` role. Batch requests are enforced on every call; the audit row records the first method/tool. |
| Upstream token exchange | `src/auth/exchange.rs` | RFC 8693, per-`(subject, audience, scope)` cache, short TTL, `basic` or `client_secret_post`, no inbound-token passthrough. |
| Per-call audit | `src/audit.rs`, `data_audit_events` | Tenant, subject, assistant, method, tool, decision, status, latency, request id, token id, and a bounded `detail` holding configured token claims and the caller's run id. Bounded queue, drop metric, batched insert, retention. |
| Per-route timing | `routing.rs`, migration | `request_timeout_ms`, `max_response_bytes` (`0` = unlimited); streamed bodies have an idle timeout; global values are defaults and `MAX_REQUEST_TIMEOUT_SECS` is the hard cap. |
| CORS and Origin validation | `src/app.rs` | Exact origins only, when configured; preflight before auth; a present unlisted `Origin` is refused; upstream `Access-Control-*` headers are stripped. Add vendor origins if the assistant sends one. Browser clients that use tools annotated with `x-mcp-header` also need those specific `Mcp-Param-*` names in the CORS allow-list; ChatGPT/Claude server-side calls do not. |
| Protocol headers | `src/proxy.rs` | `Mcp-Method`, `Mcp-Name`, `MCP-Protocol-Version`, and `Mcp-Param-*` pass through; `Mcp-Session-Id` and `Last-Event-ID` are legacy passthroughs. Hop-by-hop and credentials are stripped. |
| Control-plane access | `src/admin/` | Route/upstream fields, tool-policy JSON, data-audit reader. |

Measured guarantees worth keeping in tests:

- A token for another audience, issuer, or an expired token is rejected.
- A JWKS outage is `503`, never `401`.
- An unknown `kid` refreshes at most once per cooldown, so random kids cannot become
  a JWKS amplifier.
- A caller cannot spoof the injected upstream `Authorization` header.
- A denied tool never reaches the upstream, and the denial is audited.
- A tenant route is invisible to another tenant, and its prefix does not fall
  through to a shared route.
- A tool call is never retried (it carries a body).
- A response over the route cap is refused or truncated explicitly.

---

## 4. Data model

```sql
-- upstreams
audience TEXT,                 -- RFC 8693 audience
exchange_scope TEXT,

-- routes
tenant_id TEXT REFERENCES tenants(id) ON DELETE CASCADE,
request_timeout_ms INTEGER,
max_response_bytes BIGINT,
tool_policy JSONB NOT NULL DEFAULT '{"mode":"off","roles":{}}',

-- append-only data-plane audit
CREATE TABLE data_audit_events (
    id BIGSERIAL PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    tenant_id TEXT NOT NULL,
    subject TEXT,
    assistant TEXT,
    auth_method TEXT NOT NULL,
    mcp_method TEXT,
    route_id TEXT,
    tool_name TEXT,
    decision TEXT NOT NULL CHECK (decision IN ('allow','deny')),
    status SMALLINT,
    latency_ms INTEGER,
    request_id TEXT,
    token_id TEXT,
    detail JSONB NOT NULL DEFAULT '{}' -- reserved; the writer currently leaves it empty
);
```

`detail` holds identifiers or hashes only. No payloads, tokens, or verifier
material. The table has no foreign keys: an audit row must outlive the route it
describes.

---

## 5. Where authorization belongs

Three layers, each doing one job:

1. **Identity** — the gateway validates the token: tenant, person, assistant.
2. **Tool policy** — the gateway answers "may this person use this tool at all".
3. **Resource policy** — the MCP server or data API answers "may this person read
   *this* record", using the user's identity.

A gateway that tries to do (3) by parsing tool outputs will be wrong and slow. A
gateway that only does (1) is an expensive TLS terminator. The middle is the
product.

---

## 6. Deployment and scale

### Sizing

200 employees × 100 tool calls/day = 20,000/day, about **0.23 req/s average**. The
gateway does 77k req/s on loopback. Capacity is not the reason to cluster.

**Run two replicas for availability, not throughput.** One is a single point of
failure during deploys and node loss. Keep `minReplicas: 2`, `maxReplicas: 3–5`, a
PodDisruptionBudget, and anti-affinity.

### What breaks first

| Component | Failure mode | Mitigation |
|---|---|---|
| Postgres | The real SPOF: auth resolution, route reload, both audit tables, admin. | Managed HA, PITR, connection budget (replicas × 10), restore drill. Requests use cached credentials and the in-memory route table, so a short outage is `503` on misses. |
| Edge TLS | Routing outage | Two Caddy instances or a managed LB; health-check `/ready`. |
| Long SSE | Deploy drain cuts the stream. | Raise `SHUTDOWN_DRAIN_SECS` or accept reconnects; clients reconnect. |
| Per-replica limits | N replicas allow N × configured. | Divide by replica count or document it. Per-user limits are the real protection. |
| JWKS cache | IdP rotation or outage. | Cache, refresh on unknown `kid`, serve `503` on outage, alert. |
| Audit queue | Spikes drop events. | Bounded queue, `gateway_data_audit_dropped_total`, batch inserts, alert. |

### Stateless MCP and replicas

MCP `2026-07-28` is stateless per request, so any replica can serve any request.
Today's clients are mostly `2025-11-25` and send `initialize`; the gateway forwards
that without holding state. If the upstream is itself session-based and replicated,
the load balancer must pin the session to one upstream replica; the gateway cannot
make a stateful upstream stateless. Document the availability cost of that pinning.

---

## 7. Remaining work

Deliberately out of scope for a single-organization pilot, in rough priority:

1. **Record-level authorization.** Stays in the MCP server/data API. Do not
   duplicate it in the gateway.
2. **Opaque-token introspection.** JWT access tokens are supported; `OAUTH_TOKEN_FORMAT`
   rejects anything else at boot rather than accepting tokens it cannot validate.
   Introspection needs its own client credentials, caching, and outage policy; a 401 on
   an introspection outage is the wrong answer, so this is a deliberate seam.
3. **Static upstream credentials.** Token exchange is the supported path. A
   service credential is a residual risk and needs envelope encryption/KMS, not a
   new column with plaintext.
4. **Tool-schema pinning.** Hash the advertised schema at approval time and alert on
   drift; this blunts tool poisoning.
5. **DLP and response inspection.** Size caps exist; PII/secret classifiers and
   redaction are a separate product.
6. **Virtual MCP aggregation.** One endpoint fronting many MCP servers with a
   namespaced tool catalog. Only if aggregation is the value.
7. **Human approval for high-risk tools.** The policy model can grow an `approval`
   decision; the workflow is a product feature.
8. **Shared multi-tenant deployment.** Requires tenant-scoped admin roles,
   per-tenant upstream allowlists, and partitioned audit access.
9. **Distributed limits and quotas.** Not worth Redis until a second replica is
   required for availability.
10. **Enterprise-managed auth (ID-JAG).** Depends on the customer's IdP; the
    gateway's token validation already fits once the AS issues the token.

---

## 8. Threat model additions

Add these to [`docs/threat-model.md`](threat-model.md):

| Threat | Why it is new | Mitigation |
|---|---|---|
| Confused deputy | The gateway acts for many users. | Bound tokens, per-route audience, user identity carried through exchange. |
| Token passthrough | Forwarding the inbound token to another service. | Audience checks; exchange mints a new token; the inbound token is never attached to an upstream. |
| Shared super-credential | One upstream key reaches everything. | Per-user exchange; narrow service accounts only for uniformly visible data. |
| Prompt injection | Tool output is untrusted input. | Tool allow-lists, approvals for writes, output caps, DLP. The gateway cannot solve this; say so. |
| Tool poisoning | A compromised upstream changes tool descriptions. | Schema pinning, review, allow-lists. |
| Cross-tenant route access | Global route table. | Tenant-bound routes; no fallback to a shorter prefix. |
| Audit tampering | Append-only by convention. | Export to an append-only sink; hash-chain if required. |
| Credential leakage in logs | Tool arguments and query strings can hold secrets. | No payload audit by default; redaction; identifiers only. |
| Malicious MCP server | Third-party code with data access. | Allowlist images/versions, least privilege, egress policy. |

---

## 9. Non-goals

- Building an OAuth authorization server or identity provider.
- Solving prompt injection or making an unsafe tool safe.
- Being the retrieval/indexing layer or the vector database.
- A public marketplace listing; enterprise custom apps are admin-installed.
- Multi-region active-active for a 200-person deployment.
- Response caching, transformation DSLs, GraphQL, service-mesh sidecar.

---

## 10. IdP go-live checklist

These are the integration failures that actually block a connector:

- **Claude uses only the first `authorization_servers` entry.** Put the real issuer
  first; there is no fallback.
- **Claude needs both `client_id_metadata_document_supported: true` and `none` in
  `token_endpoint_auth_methods_supported`**, or it silently falls back to DCR.
- **ChatGPT may need RFC 9207 `iss` support.** If the AS does not advertise
  `authorization_response_iss_parameter_supported`, ChatGPT uses a per-callback
  client ID that must be allowlisted.
- **DCR is incompatible with enterprise-managed auth** because the IdP stamps a
  fixed client ID. Choose one model before the pilot.
- **Entra needs the MCP URL as an Application ID URI**, or token acquisition fails
  with `AADSTS9010010`.
- **Claude redirect URI** appears as both `https://claude.ai/api/mcp/auth_callback`
  and `https://claude.com/api/mcp/auth_callback`; allowlist both.
- **PKCE S256 metadata is mandatory**; a missing
  `code_challenge_methods_supported: ["S256"]` is a hard connector failure.
- **Keycloak realm imports skip the standard client scopes.** `--import-realm`
  creates only what the JSON lists, so a hand-written realm has no `profile`,
  `email`, `roles`, `web-origins`, `acr`, or `basic` scope. Tokens then carry no
  `realm_access`/`resource_access`, and the built-in account console returns
  `403` after login. Create the realm through the admin API, or import the
  standard scopes and assign them to the `account` and `account-console`
  clients (Keycloak 26 ignores `defaultClientScopes` in a client update; use the
  `clients/{id}/default-client-scopes/{scopeId}` endpoint).
- **ChatGPT connectors call `server/discover` before anything else.** The
  upstream must return the `2026-07-28` result shape (`resultType`,
  `supportedVersions`, `serverInfo` under `_meta`, `ttlMs`, `cacheScope`). A
  server that answers with the legacy `initialize` shape produces
  "Authentication succeeded, action discovery failed" after a successful OAuth
  flow, which looks like an auth bug but is a payload-shape bug.
- **ChatGPT's automatic client registration usually does not work against a
  hardened IdP.** Anonymous DCR is blocked by default (trusted-host policy) and
  CIMD is not advertised by Keycloak. Use "User-Defined OAuth Client" with a
  pre-registered public client and the callback
  `https://chatgpt.com/connector_platform_oauth_redirect`, and grant `email`
  and `offline_access` or the token request fails with `invalid_scope`.

## 11. Questions to settle with the client

1. Which assistants and plan tiers? Is a legacy custom GPT still in use before the
   December 2026 retirement?
2. Which IdP, and does it support PKCE metadata, CIMD/DCR, resource indicators, and
   token exchange?
3. Which data sources, and do they offer per-user OAuth or only a service account?
4. Read-only or write tools? Which actions need approval?
5. Compliance: SOC 2, HIPAA, GDPR, residency, retention, SIEM export.
6. How many users, peak concurrency, tool calls per day, largest expected response?
7. Who administers tools, and what does "install" mean to them?
8. Existing gateway, zero-trust proxy, or egress controls to fit behind.
9. Is the MCP server ours, theirs, or a vendor's? Who owns row-level authz?
10. Success criteria and pilot group; what would make them turn it off?

---

## 12. References

- MCP specification, transports and authorization (revision 2026-07-28):
  <https://modelcontextprotocol.io/specification/2026-07-28/>
- MCP authorization tutorial:
  <https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/authorization>
- RFC 9728 (Protected Resource Metadata), RFC 8414 (AS Metadata), RFC 8707
  (Resource Indicators), RFC 9207 (`iss`), RFC 8693 (Token Exchange).
- OpenAI, connecting custom MCP servers in ChatGPT:
  <https://help.openai.com/en/articles/12584461-connecting-custom-mcp-servers-in-chatgpt>
- Claude, custom connectors using remote MCP:
  <https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp>
