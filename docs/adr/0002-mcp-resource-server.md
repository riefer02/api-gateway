# ADR 0002 — MCP-aware resource server for organization-installed AI connectors

- **Status:** Accepted
- **Date:** 2026-11-18
- **Deciders:** maintainer, client platform/security
- **Related:** [MCP gateway analysis](../mcp-gateway.md), [threat model](../threat-model.md), [ADR 0001](0001-replicas-and-ci.md)

> Implementation note (2026-11-18): the resource server, protected-resource
> metadata, per-user principal, tool policy, RFC 8693 exchange, per-call audit,
> tenant-bound routes, and per-route timing are implemented and covered by tests.
> The alternatives and consequences below remain the reasoning of record.

## Context

The repository is a production-shaped API gateway: static API-key auth, a
Postgres-backed route table, a streaming proxy, per-tenant limits, breakers,
metrics/traces, and an audited control plane. It was built for service-to-service
traffic.

The next workload is different. An organization installs an AI connector in
ChatGPT (custom app) or Claude (custom connector), employees use it, and the vendor
calls a remote MCP server over HTTPS. Those calls act for an individual employee,
carry OAuth access tokens, and invoke named tools inside a JSON-RPC envelope. The
buyer expects per-user audit, per-tool authorization, least-privilege access to the
underlying systems, and a credible story for revocation and outages.

Three candidate shapes were considered:

1. Keep the gateway transparent; require every upstream MCP server to implement
   OAuth, policy, and audit itself.
2. Make the gateway an MCP-aware policy enforcement point and OAuth resource server,
   delegating token issuance to the customer's identity provider.
3. Make the gateway a virtual MCP server that terminates the protocol and executes
   tools.

## Decision

Adopt **(2)**, in phases, with (1) available as a per-route mode.

The gateway will:

- Act as an **OAuth 2.1 resource server**, not an authorization server. It
  validates JWTs from the configured issuer against a cached JWKS, checks `iss`,
  `aud`, `exp`, `nbf`, and scope, and publishes RFC 9728 protected-resource
  metadata. It never mints tokens.
- Produce a **per-user principal** (tenant, OIDC subject, assistant client, scopes,
  roles, token id) alongside the existing service API-key identity. Email is not
  retained; resolve the subject through the IdP if a human-readable identity is needed.
- Enforce **tool allowlists** by parsing `tools/call` on MCP routes and filtering
  `tools/list`. Row- and record-level authorization stays in the MCP server or data
  API, using the user's own identity.
- Obtain upstream access through **token exchange** (RFC 8693) where the IdP
  supports it. Reversible, encrypted credentials are a documented fallback only for
  APIs that cannot accept per-user tokens. Inbound tokens are never forwarded to a
  different audience.
- Emit **asynchronous, per-call audit** events with identifiers and decisions, not
  payloads.
- Default to **one organization per deployment** for v1. Multi-tenant deployments
  require tenant-bound routes (`routes.tenant_id`), tenant-scoped admin roles, and
  tenant-partitioned audit before they are supported.

The gateway will not become an authorization server, an identity provider, a
retrieval/indexing layer, or a virtual MCP aggregator in v1.

## Consequences

**Positive**

- The vendor admin consoles keep owning installation; the gateway owns runtime
  governance. That is the boundary customers already understand.
- Delegating token issuance avoids the consent, registration, refresh-rotation, and
  key-management surface of an authorization server.
- The existing proxy, SSRF allowlist, header hygiene, route reload, audit control
  plane, and replica model carry over unchanged in shape.
- The target MCP revision (`2026-07-28`) is stateless, so the existing replica model is
  sufficient for availability. Current clients may still use `2025-11-25` sessions; the
  gateway forwards them without holding state, and a stateful upstream needs load-balancer
  pinning.
- Per-user identity makes the audit trail, per-user limits, and least privilege
  possible at all.

**Negative / accepted**

- A new authentication path (JWT/JWKS), two new external dependencies in practice
  (the IdP and its metadata), and more failure modes (JWKS outage, key rotation,
  clock skew).
- Tool-level filtering requires buffering MCP responses; the hot path stops being a
  pure byte proxy on those routes. Bound the bodies and keep it per-route.
- Token exchange depends on IdP support; the fallback reintroduces shared-credential
  risk and must be documented per upstream.
- The route table remains global in v1. That is only safe because of the one-org
  deployment decision; revisiting multi-tenancy is a schema and policy change, not a
  configuration flag.
- JWT revocation is bounded by token lifetime. Short-lived tokens plus refresh are
  the mechanism; an introspection or revocation-list call per request is rejected as
  a latency and availability cost unless a customer requires it.

## Alternatives considered

- **Transparent proxy only.** Cheapest, but pushes identity, policy, audit, and
  credential custody into every MCP server. That multiplies the security review and
  makes central governance impossible, which is the reason to buy a gateway.
- **Virtual MCP server.** Best aggregation story, worst schedule. It makes the
  gateway responsible for protocol semantics, tool namespaces, cancellation, and
  streaming assembly. Defer until a customer pays for aggregation.
- **Build the authorization server.** Rejected. It is a separate product with a
  much larger security surface. Use the IdP or a managed AS.
- **Shared multi-tenant deployment first.** Rejected for v1. Blast radius, data
  residency, and policy isolation are easier to get right per organization, and the
  vendor install model is per organization anyway.

## Validation

The decision is revisited when any of these is true:

- A customer requires cross-organization tool sharing or a single shared endpoint.
- The chosen IdP cannot mint audience-scoped tokens or perform token exchange.
- Response buffering for `tools/list` filtering breaches the latency budget at
  pilot load.
- Legacy session-based MCP clients or a stateful upstream force session affinity at the load
  balancer; the gateway itself remains stateless.
