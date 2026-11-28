# Architecture

This is the map an owner needs before changing something. It states the boundaries the
code relies on, who owns each piece of mutable state, and the checks that keep both true.
It is not a tour: each section ends in a rule you can be held to.

`AGENTS.md` holds the short list of invariants; this file explains them.

## The request path is a contract

```
client
  │
  ▼
request id → CORS/Origin → metrics → trace → panic guard → deadline → body limit
  │
  ▼
reject unsafe path → IP limit → authenticate → tenant limit → user limit
  → resolve route → authorize scopes → MCP policy → upstream auth
  → breakers → bulkhead → proxy → audit
  │
  ▼
allowlisted upstream
```

Layer order in `src/app.rs` is not a style choice. The request id exists before anything
logs, the deadline covers body reads, and a panic becomes an envelope instead of a dropped
socket. Moving a layer silently changes one of those properties.

The pipeline order in `src/routes/upstream.rs` is equally deliberate: authentication runs
before route resolution so an unauthenticated caller cannot probe which prefixes exist,
and the IP limiter runs before the correlation-id parse so a malformed header cannot skip
the only control that applies pre-auth.

## Module map and dependency direction

Solid arrows are compile-time dependencies; there are no cycles in production code.
Tests may import anything.

```
                    ┌──────────────┐
                    │    config    │  (fan-in 9: read-only types)
                    └──────────────┘
                           ▲
   ┌───────────┬───────────┼────────────┬──────────────┐
 state       routing     limits        net           retry
   ▲           ▲
 serve ────────┘
   │
   ▼
 app ──► routes ──► upstream.rs ──► auth, proxy, mcp, audit, limits, routing
                       │
                       └──────────► error (every failure crosses here)

 admin ──► accounts, keys, routes, audit_read  (one aggregate each)
   │            │
   │            └──► auth::store  (credentials)
   └──► routing  (route compilation rules)
```

Rules that are checked by `scripts/check-architecture.sh`:

- **`state` is the composition root, and nothing it composes imports it.** `auth`,
  `proxy`, `routing`, `limits`, `retry`, `net`, `mcp` and `error` must not name
  `crate::state`. They take the handles they need (`AuthContext` is the example).
- **SQL belongs to the storage modules.** The data-plane modules never query. The
  control plane owns its own tables; credentials have exactly one owner (ADR 0006).
- **Metric names live in `src/metric_names.rs`.** A literal elsewhere is an unowned
  series that no alert watches.

`config` is a leaf and a hub at once: it may only depend on `net` (for egress parsing),
and everyone may depend on it. That is what lets a new setting be added in one file.

## One owner per aggregate

| Aggregate | Module | Sole writer | Notes |
|---|---|---|---|
| Credentials | `src/auth/store/` | `ApiKeyStore` impls | Rotation is one transaction; see ADR 0006 |
| Routes, upstreams | `src/admin/routes.rs` → `src/routing.rs` | admin (write), compiler (read) | The compiler re-validates every row at boot; the write path applies the same validators |
| Tenants, clients | `src/admin/accounts.rs` | `AdminService` | Deletes are `RESTRICT`ed and reported as 409 |
| Control-plane audit | `src/admin/audit.rs` | append-only hash chain | Never edited; verified by a command (ADR 0003) |
| Data-plane audit | `src/audit.rs` | bounded queue, batch writer | Off the request path; may drop (ADR 0003) |
| Configuration | `src/config.rs` | env at boot | Validated once; no module reads the environment |
| Errors | `src/error.rs` | `AppError` | The only way to produce an HTTP failure |
| Metrics | `src/metric_names.rs` | constants | `deploy/alerts.yml` is checked against them |

If a change needs to write a table from a module that is not listed, the answer is a
method on the owner, not a new query. That is how rotation became atomic.

## State ownership

All mutable state is in-process, per replica, and bounded. There is no shared mutable
state across a module boundary.

| State | Owner | Bound |
|---|---|---|
| Route table snapshot | `routing::RouteTableHandle` (arc-swap) | replaced wholesale on version change |
| Compiled upstream clients | `routing::Upstream` (Arc) | one per (upstream, timeout, audience, scope) |
| Credential cache | `auth::cache::CachedApiKeyStore` | TTL + entry cap, sharded; tombstoned locally |
| Breakers | `limits::BreakerRegistry` | `MAX_TRACKED_UPSTREAMS`, cleared at the cap |
| Bulkheads | `limits::BulkheadRegistry` | same cap; permits per upstream |
| Retry budget | `retry::RetryPolicy` | token bucket |
| JWKS | `auth::oauth::JwksCache` | TTL + single-flight refresh |
| Exchange tokens | `auth::exchange::TokenExchange` | TTL + (tenant, user, audience) key |
| MCP tool schemas | `mcp::schema::SchemaCache` | TTL + fields per tool |
| Audit queue | `audit::ChannelAudit` | mpsc capacity; drops and counts |
| Readiness | `state::Readiness` | TTL + grace |

Per-replica enforcement is deliberate and measured; see ADR 0005 before making a limit
shared.

## How to change things

**A setting.** Add the field to the relevant `*Config` in `config.rs`, parse it in
`from_source`, validate the relations in `validate`, add an advisory if a safe-looking
value is operationally loud, and update `.env.example` + the README table. One test per
rule. No module reads the environment.

**A route field.** Add it to `RouteRow` and `RouteSpec`, validate it in `routing.rs`
(a public `validate_*` used by both the compiler and `admin/routes.rs`), thread it
through `CompiledRoute` and the OpenAPI document, then add a write-path test and a
compile-path test. Two copies of the rule is how they drift.

**A metric.** Add the constant to `src/metric_names.rs` and use it. If an alert should
fire, add it to `deploy/alerts.yml`; the test fails if the rule names a metric the
process does not emit.

**A control-plane mutation.** Add the method to the aggregate module under `src/admin/`,
take `&Actor`, validate before the transaction, write the audit row in the same
transaction (`admin/audit.rs`), expose it in `admin/http.rs` and `admin/cli.rs`, and
document it in `docs/openapi.yaml`. The actor's scope check belongs in the HTTP adapter,
where the credential is known.

**A new module.** It must be reachable without a cycle and must not import `state` unless
it is a composition root. If it owns mutable state, say what bounds it. Add it to this
document's map in the same commit.

## Known limits at organization scale

These are deliberate and documented rather than hidden. Capacity planning should start
here.

- **Control-plane listings are keyset-paginated** for keys (per client), upstreams, and
  routes: `limit` (default 100, max 1000) plus an opaque `cursor`, with the next cursor in
  the response body. Pagination is stable under concurrent inserts and deletes. Audit
  listings clamp to 1000 rows and page by `before_id`.
- **Rate limits and breakers are per replica** (ADR 0005). N replicas allow up to N × the
  configured rate, and a breaker needs N × its threshold before every replica opens.
- **Control-plane writes serialise** on one advisory lock so the audit chain has a single
  writer (ADR 0003). Fine at operator speed; it is not a bulk-import path.
- **Audit verification is O(rows) and manual.** It pages, so memory is bounded, but a
  multi-million-row chain is a scheduled maintenance job, not a request-time check.
- **The JWKS and exchange caches are per replica.** An IdP outage is absorbed per replica
  and a cold replica re-fetches on first use.

## Enforcement

`just check` runs everything CI runs:

| Check | Catches |
|---|---|
| `cargo fmt --check` | formatting drift |
| `scripts/check-architecture.sh` | dependency direction, table ownership, inline metric names |
| `cargo clippy -D warnings` | everything the compiler tolerates |
| `cargo test` | behaviour; Postgres tests run when `DATABASE_URL` is set |
| `cargo deny check` | licences, advisories, wildcards, unknown registries |

The architecture script is a set of greps on purpose: a violation is a line in the diff,
not a judgement call. If a rule cannot be expressed as a grep, it belongs in a test or in
`AGENTS.md`.

## Decisions

`docs/adr/` records why the non-obvious ones are the way they are, including what would
make them wrong:

- 0001 replicas and CI
- 0002 MCP resource server
- 0003 audit chain (control plane vs data plane)
- 0004 egress policy
- 0005 replica-local enforcement
- 0006 credential store ownership and atomic rotation
