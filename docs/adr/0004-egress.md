# ADR 0004 — Egress is a resolution-time capability

Status: accepted · 2026-11-19

## Context

The gateway's job includes deciding which upstreams it may call. The first implementation
checked the URL: scheme, embedded credentials, and the hostname against an allowlist. That
is a check on a *name*.

The name is not what the gateway connects to. A hostname that resolved to the instance
metadata service, to the gateway's own admin listener, or to a private network it had no
business reaching passed the check and was dialled. DNS could also change its answer between
validation and connection.

## Decision

Two layers, because they answer different questions:

1. **The allowlist decides what the gateway may talk to.** Enforced when an upstream is
   written by the admin API and when a route is compiled, so a stored row cannot fail every
   subsequent reload.
2. **`UPSTREAM_EGRESS` decides what that name may become.** A custom `reqwest` DNS resolver
   filters resolved addresses and the client connects to exactly what survived, so a second
   lookup cannot answer differently and multi-address failover still works.

The default policy, `deny-link-local`, blocks loopback, link-local, multicast, unspecified,
documentation ranges and the common cloud metadata endpoints (`169.254.169.254`,
`fd00:ec2::254`, `100.100.100.200`, `192.0.0.192`), while still allowing VPC and
unique-local upstreams — because internal upstreams are the normal case, not the exception.

Two details are load-bearing:

- **IP literals are checked at compile time.** A literal never reaches the resolver, so the
  filter alone would leave `http://169.254.169.254/` reachable.
- **IPv4-mapped and IPv4-compatible forms are unmapped before judging.** `::1` is checked as
  IPv6 first, because it unmaps to `0.0.0.1` and would otherwise stop counting as loopback.

`allow-all` exists for development against a loopback stub and produces a startup advisory.

## Consequences

- The metadata service and the gateway's own loopback are unreachable under the default
  policy, including through DNS.
- The policy cannot enumerate every provider's metadata address, and NAT64
  (`64:ff9b::/96`) is not unmapped. The README says "the common cloud metadata endpoints"
  rather than claiming universality.
- The filter applies to upstream calls. The JWKS and token-exchange clients are configured
  from the environment and do not use it; their URLs are operator-controlled, which lowers
  the risk without removing it.
- This is not a firewall. It constrains what *this process* dials; a compromised process or
  a different client in the same network is out of scope.

## Alternatives

| Alternative | Why not |
|---|---|
| **Hostname allowlist only** | The original design: validates a string, not a socket |
| **Resolve once at compile and pin one IP** | Kills multi-address failover, and goes stale as soon as DNS changes |
| **Network policy only** | The real boundary, and it belongs in the deployment guide. A binary cannot firewall the host it runs on |
| **An egress proxy for all upstream traffic** | Strongest, and another hop to operate. Worth it when the network policy is centralised anyway |

## Revisit when

- a deployment wants a hard guarantee — then pair this with a VPC egress firewall or a
  Kubernetes `NetworkPolicy` deny by default, and document both together;
- the JWKS or exchange clients need the same guarantee — then give them the resolver too;
- an upstream legitimately needs loopback in production (a sidecar) — then prefer an explicit
  per-upstream allowance over `allow-all`.
