# Changelog

Notable changes, newest first. Format loosely follows [Keep a Changelog](https://keepachangelog.com);
versions follow [Semantic Versioning](https://semver.org).

## [Unreleased]

### Fixed

- **Clearing a row's chain marker is detected.** An unchained row after the chain has
  started is a break, not a gap: otherwise clearing `chained` on a suffix would present an
  edited log as intact. The cost is stated: a mixed-version rollout produces a break until
  every replica runs this version, so verify after the upgrade rather than during it.
- **A rejected route table is not hidden by the staleness window.** Compile failures now
  set a separate readiness signal, so a bad configuration is reported immediately instead
  of waiting out `AUTH_CACHE_TTL_SECS`; only an unreachable database is tolerated.
- **An oversized schema is skipped, not truncated.** A tool with more than 64 required
  fields, or a field name over 128 bytes, gets no gateway-side validation at all rather
  than partial validation that would accept calls missing a required field.
- **Pruning is a prefix under the chain lock.** Retention now deletes a contiguous id
  prefix while holding the same advisory lock as inserts, so a clock jump cannot remove a
  middle row and turn retention into an apparent break.
- **Readiness pings are bounded.** A hung database reports an unready probe instead of
  holding the check open past the probe timeout.
- **CORS allows and exposes `X-Run-Id`**, so a browser client can send it and read the echo.
- **The local MCP recipes relax egress explicitly.** `just mcp-stub`, `just mcp-route` and
  `scripts/bench.sh` set `UPSTREAM_EGRESS=allow-all` for their loopback upstreams, which
  the new default would otherwise refuse.
- **The audit chain no longer trusts a missing hash.** A row is chained because
  `audit_events.chained` says so, not because its hash happens to be present. Blanking
  `row_hash` on a chained row is a break; a row written before the chain, or by a replica
  that had not been upgraded, is a counted gap and does not invalidate the rows around it.
  New rows link to the last chained row, so an un-upgraded writer cannot restart the chain
  at genesis.
- **Verification starts where the chain starts.** Retention deletes the oldest rows, so the
  walk begins at the oldest surviving chained row instead of requiring genesis; `admin
  audit verify` names that row, and exits non-zero when there are unhashed rows but nothing
  chained to prove.
- **Readiness no longer drains the fleet before the cache does.** The route-table staleness
  window is now at least the credential-cache lifetime; previously it was 11 s against a
  30 s cache, so a database outage took every replica out of rotation long before the
  mechanism built to survive one was exhausted.
- **The admin write path applies the egress policy.** An upstream literal the compiler
  would reject is refused when it is stored, instead of being accepted and then failing
  every route reload. Upgrade note: a literal loopback upstream now fails to compile under
  the default `deny-link-local`; set `UPSTREAM_EGRESS=allow-all` for sidecar or local-stub
  deployments.
- **A wildcard tool grant no longer mints metric series.** When a role grants `"*"` every
  tool name is caller-chosen, so `gateway_mcp_tool_calls_total` labels it `unlisted` and the
  per-tool quota shares one bucket instead of one per invented name.
- **An upstream cannot choose the `X-Run-Id` echo.** It is a gateway-owned response header,
  and a duplicate request header is refused rather than first-wins.
- **Egress covers more than the two obvious metadata addresses.** Alibaba Cloud
  (`100.100.100.200`) and Oracle Cloud (`192.0.0.192`) metadata endpoints are blocked under
  the default policy, and IPv4-compatible IPv6 (`::a.b.c.d`) is judged as the address it
  embeds without mistaking `::1` for `0.0.0.1`.
- **A learned schema cannot retain unbounded memory.** `required` is capped at 64 fields of
  128 bytes, because the shape lives for the cache TTL and an upstream chooses its size.
- **`AUDIT_CLAIMS` accepts namespaced names.** Up to 64 characters of letters, digits and
  `_ - . : /`, so a URL-shaped Keycloak claim can be recorded; whitespace and control
  characters remain refused.
- **The example environment ships the safe egress default.** `.env.example` now sets
  `deny-link-local`; running the MCP stub on host loopback needs an explicit local
  override, and `allow-all` produces a startup advisory in any environment.
- **`tools/list` buffering is bounded and configurable.** Filtering parses the whole
  catalogue into a `serde_json::Value`, which costs several times the raw bytes; the
  hard-coded 4 MiB ceiling could turn one legitimate large catalogue into an
  out-of-memory kill. `MCP_FILTER_MAX_BYTES` (default 1 MiB, 64 KiB–8 MiB) now bounds
  it, and a catalogue over the ceiling is refused with `502` instead of buffered.

### Added

- **Claim attribution and caller correlation.** `AUDIT_CLAIMS` copies named token claims
  (`project_id`, `agent_id`, …) into the data-plane audit's `detail`; only scalars pass,
  control characters and values over 128 bytes are refused rather than truncated, and a
  refused claim increments `gateway_claim_rejected_total`. `GET /v1/data-audit` and
  `admin audit data` return the `detail`, so the attribution is readable. `X-Run-Id` is validated
  (`[A-Za-z0-9._:-]{1,128}`), audited and echoed on the response including errors, so a
  client can join its logs to ours. Neither is used for authorization.
- **Tamper-evident control-plane audit chain.** `audit_events` gains `prev_hash` and
  `row_hash`; appends are serialised by an advisory lock inside the writing transaction,
  so two rows cannot claim the same predecessor. `admin audit verify` walks the chain in
  pages and exits non-zero at the first row that fails, naming it. Rows written before
  the migration are reported as unchained rather than silently rehashed. The data-plane
  audit stays batched and unchained: it is high volume, and it is not the log auditors
  read.
- **Per-upstream bulkhead.** `UPSTREAM_MAX_CONCURRENCY` bounds in-flight requests to one
  upstream per replica, with `UPSTREAM_QUEUE_TIMEOUT_MS` deciding whether to queue or shed.
  The permit is held until the response body finishes, so a long stream counts as the
  concurrency it is, and saturation returns `503` with `Retry-After` plus
  `gateway_upstream_saturated_total`. Off by default: bounds that reject traffic are
  opt-in, unlike the pool bound which only decides what is kept.
- **Egress policy.** `UPSTREAM_EGRESS` decides what an allowlisted upstream hostname may
  resolve to, applied by a filtering DNS resolver so the client connects to exactly the
  addresses that passed: `deny-link-local` (default; blocks loopback, link-local, the IPv4
  and IPv6 metadata endpoints, multicast and unspecified, while allowing VPC addresses),
  `deny-private` (public unicast only), or `allow-all`. Previously the allowlist validated
  a string at compile time and any address the name resolved to was reachable.
- **MCP argument validation.** On a tool-policy route the gateway learns each
  tool's `inputSchema` from `tools/list` and refuses a `tools/call` whose arguments
  are not an object, or that omits an advertised `required` field, with JSON-RPC
  `-32602`. Deliberately not a JSON-Schema engine: unsupported keywords mean "no
  opinion" and an unlearned tool fails open. `MCP_TOOL_SCHEMA_TTL_SECS` (default
  `300`, `0` disables).
- **Per-tool quota and counters.** `RATE_LIMIT_TOOL_PER_MINUTE` adds a bucket keyed
  by tenant and tool; `gateway_mcp_tool_calls_total` counts by tenant, tool and
  decision. Denied tool names collapse to `unlisted` so a caller cannot create
  metric series by inventing names.
- **Bound on idle upstream connections.** `UPSTREAM_POOL_MAX_IDLE_PER_HOST`
  (default `64`, valid `1..=1024`). Previously unbounded, so each replica could
  retain as many idle sockets per upstream as its peak concurrency produced.
- **Trace context reaches upstreams.** The gateway injects `traceparent` on
  proxied requests, and drops caller-supplied `traceparent`, `tracestate` and
  `baggage` so a client cannot claim parentage for spans it did not create.
- **OAuth 2.1 resource server.** JWKS cache with cooldown and outage handling, JWT
  validation (issuer, audience, expiry, `nbf`, algorithm allow-list, ID-token
  rejection), RFC 9728 protected-resource metadata, and MCP-shaped `401`/`403`
  challenges. Delegates token issuance to the customer's IdP.
- **Per-user principal.** One identity type for API keys and OAuth, with subject,
  assistant client, scopes, roles/groups, token id, and the inbound token for
  exchange. Per-user rate limits are keyed `tenant:subject`.
- **MCP tool policy.** Role-based `tools/call` allow-lists, JSON-RPC denials,
  filtered `tools/list`/`server/discover` responses, and a typed `tool_policy` on
  each route.
- **RFC 8693 token exchange.** Routes can declare an upstream audience; the gateway
  mints a short-lived upstream token and never forwards the inbound token to another
  audience. Exchanged tokens are cached per `(subject, audience, scope)`. Supports
  HTTP Basic and `client_secret_post`; opaque-token introspection is rejected at
  boot rather than silently accepted.
- **Per-call data audit.** Bounded queue, batched inserts, explicit drop and write
  failure metrics, separate retention, and a control-plane reader
  (`GET /v1/data-audit`, `admin audit data`).
- **Tenant-bound routes.** Optional `routes.tenant_id`; a tenant route is invisible
  to other tenants and does not fall through to a shorter prefix.
- **Per-route timing.** `request_timeout_ms` and `max_response_bytes` with
  `MAX_REQUEST_TIMEOUT_SECS` as the hard cap.
- **CORS and `Origin` validation.** Exact origins only, preflight before auth,
  unlisted origins refused.
- **Control-plane fields.** Upstream `audience`/`exchange_scope`; route
  `tenant_id`/`tool_policy`/`request_timeout_ms`/`max_response_bytes`; CLI and
  OpenAPI updated.

### Fixed

- **Readiness no longer drains every replica on a database blip.** The probe now answers
  "can this process still serve?" — a failed ping is tolerated for the credential cache TTL,
  because cached credentials and the in-memory route table keep working while Postgres is
  unreachable. Before, one failed ping removed every replica from rotation at once.
- **`jsonwebtoken` 9 → 12 (CVE-2026-25537).** A malformed `exp` or `nbf` was
  treated as absent, so the check could be skipped. Expiry was a required claim
  here, which closed the dangerous half, but the fix is the upgrade. Enables the
  `rust_crypto` provider; the pure-Rust crypto stack is 30 additional crates and
  replaces the ring-backed path. All OAuth tests, including expired-token,
  wrong-audience and algorithm-confusion cases, pass unchanged.
- **MCP policy bypasses found in review.** A batch `tools/list` is now filtered even
  when the first message is a notification; `server/discover` and JSON-RPC error
  envelopes pass through instead of returning 502; `Mcp-Name` and
  `MCP-Protocol-Version` must agree with the body; duplicate JSON keys and a JSON-RPC
  body on a non-POST method are refused. Filtered lists are `cacheScope: private`
  and lose `ttlMs`.
- **JWKS resilience.** One unsupported key in the issuer's set no longer takes OAuth
  offline; an empty-cache outage respects the refresh cooldown; unknown `kid`s are
  still bounded.
- **Token exchange binding.** The cache key includes tenant and a hash of the inbound
  token, the lifetime is capped, and `issued_token_type` must be an access token.
- **Route writes are partial for security fields.** Omitting `tenant_id`, `scopes`,
  `tool_policy`, or enable flags preserves the stored value; `route list` returns
  scopes.
- **Tenant deletion is `RESTRICT`**, matching clients: a tenant with routes returns
  409 rather than silently deleting them. The runbook documents the forward-only
  rollback check for tenant/tool-policy routes.
- **Audit truthfulness.** Per-call rows are written only after a route resolves;
  status >= 400 defaults to `deny`; `occurred_at` is the call time, not the batch
  insert time; pruning is advisory-locked and batched; shutdown drain uses the
  process budget and reports a timeout.
- **Streaming.** Response bodies have an idle timeout; `max_response_bytes: 0` means
  unlimited; filtered policy responses are capped at 4 MiB.
- **Demo stub binding.** `examples/mcp_stub.rs` now honors `MCP_STUB_HOST` (default
  loopback). It previously bound `127.0.0.1` unconditionally, so the gateway container
  could not reach it in the compose demo.
- **CORS.** `Mcp-Name` is allowed on preflight; upstream `Access-Control-*` headers
  are stripped so the gateway owns the policy.
- **Token and cache hardening.** Bearer/key-id length caps, local-only revocation
  tombstones with a generation check, OAuth/JWKS/cache TTL bounds, and a boot error
  when OAuth companions are set without `OAUTH_ISSUER`.
- `TRUSTED_PROXIES` was parsed and then discarded for the data plane: `serve.rs`
  installed an empty trust list into `AppState`, so behind an edge proxy every caller
  was resolved as the proxy's address. That collapsed per-IP rate limiting into one
  shared bucket and made the audit source address useless. The parsed list is now
  shared by both listeners, and a regression test asserts the forwarded client
  address reaches the upstream.

### Changed

- The 15 s request timeout is now the default route deadline, not an absolute
  whole-process deadline; a route may request up to `MAX_REQUEST_TIMEOUT_SECS`
  (300 s). The previous 408 behaviour remains the default for routes that do not
  override it.
- `AdminService` takes the maximum request deadline and whether token exchange is
  configured, so an upstream audience cannot be stored without a way to exchange.

### Documentation

- [`docs/mcp-gateway.md`](docs/mcp-gateway.md): protocol details, implemented
  capabilities, remaining work, deployment, and threat-model additions for
  organization-installed AI connectors.
- [`docs/adr/0002-mcp-resource-server.md`](docs/adr/0002-mcp-resource-server.md):
  the gateway is an MCP-aware OAuth resource server, not an authorization server;
  one organization per deployment for v1.
- Runbook: OAuth revocation, JWKS outage, token-exchange failure, data audit, and
  tool-policy rollback.

## [0.1.0] — 2026-11-12

First tagged build: a working data plane and an audited control plane.

### Data plane

- API-key authentication with HMAC-SHA256 verifiers, a server pepper, constant-time
  comparison, expiry, revocation, and tenant/client suspension.
- Postgres-backed route table compiled into an immutable in-memory snapshot; longest-prefix
  matching on segment boundaries, explicit rewrite, per-route scopes, `405` with `Allow`,
  `HEAD` implied by `GET`.
- Streaming reverse proxy: request and response bodies stream, hop-by-hop and
  `Connection`-named headers are stripped, upstream redirects are never followed, and the
  path that is authorized is the path that is forwarded.
- Per-IP and per-tenant token-bucket rate limits with `RateLimit-*` and `Retry-After`.
- Per-upstream circuit breakers and budgeted, idempotent-only retries with jittered backoff.
- Whole-request deadline, header-read timeout, connection cap, and body limits.

### Control plane

- One `AdminService` with a CLI and an HTTP adapter on a separate, bearer-token listener.
- Named admin tokens with scopes (`tenants`, `keys`, `config`, `audit`).
- Tenant, client, key, upstream, and route lifecycle including deletion, rotation, and
  enable/disable.
- Append-only audit log with actor, action, subject, source IP, and request id; retention
  is configurable.

### Operations

- Prometheus metrics, OpenTelemetry traces, structured logs, and a boot summary with
  advisories for risky configuration.
- Split liveness/readiness with a cached database probe and route-table staleness detection.
- Graceful drain on `SIGTERM`, per connection, with a configurable budget.
- Distroless image, compose stack, Kubernetes manifests, and a Caddy edge-TLS example.
- Cross-replica revocation over Postgres `LISTEN/NOTIFY`.

### Known limitations

- Rate limits, retry budgets, and breakers are per replica; the cluster limit is N ×.
- TLS terminates at the edge rather than in the gateway.
- Unknown-length request bodies are buffered up to the limit.
- Not security-audited. Review `docs/threat-model.md` before production traffic.
