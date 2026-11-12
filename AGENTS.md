# AGENTS.md

Keep this file short. Empirically, repository context files do not improve task
success and add ~20% inference cost (Gloaguen et al., 2026); they earn their
tokens only for non-obvious constraints that neither the code nor CI states.
Delete anything a linter, test, or type already enforces. No repo tours.

## Commands

- `just check` — fmt, clippy (`-D warnings`), tests, dependency policy. Run before handing work back.
- `just test` — tests. Postgres tests run only when `DATABASE_URL` is set; start it with `just db-up`.
- `just deny` — licenses, advisories, wildcards, unknown registries.
- `cargo add <crate>` — dependencies are added by CLI, never by hand-editing versions.
- `cargo run -- serve --check-config` — print resolved config with secrets redacted, then exit.

## Invariants

- `src/app.rs` layer order is a contract: set request id, sanitise it, propagate, metrics,
  tracing, panic catch, deadline, body limit. Reordering silently breaks correlation.
- Every HTTP failure goes through `AppError` (`src/error.rs`). Do not invent ad-hoc
  status codes or response bodies; the envelope carries the request id.
- Secrets never appear in logs, traces, error bodies, metric labels, or `Debug` output.
  Key material is stored as verifiers only. Never log a `reqwest::Error` with `Display`:
  it embeds the request URL and its query string.
- `src/proxy.rs` owns header hygiene: hop-by-hop, `Connection`-named, forwarded, and
  gateway-owned headers are stripped in both directions. Redirects are never followed.
- `src/routes/upstream.rs` is the whole request pipeline: reject malformed paths, limits,
  authenticate, resolve, authorize, proxy. Keep it readable; hidden layers are how policy
  gets skipped.
- `unwrap`/`expect` are allowed only in bootstrap and tests.
- All environment access lives in `src/config.rs`. A new setting needs a validation
  rule and a test in the same change.
- Caller identity comes from `ConnectInfo` inserted in `run_server`; never infer a client
  address from a header until a trusted-proxy model exists.
- Reject paths with `routing::is_unsafe_path` before matching. Anything that normalizes
  differently in `url` than in our matcher is an authorization bypass.
- Postgres is the source of truth for credentials and routes, but never on the request
  path: compile to memory at boot, swap atomically on version bump.
- Admin mutations go through `src/admin`; the CLI is one adapter over that service.
  Every mutation records an audit row with the actor bound to the admin token, and the
  `detail` payload holds identifiers only — never tokens or verifier material.
- Limits and breakers are in-process state (`src/limits.rs`). They are per replica and
  deliberately not shared; do not add cross-request locks outside those structures.
- Anything personal — local deploy config, credentials, scratch notes — lives in
  `.local/`, which is gitignored. Never reference a personal path from tracked files.

## Working style

- Behaviour change = tests in the same commit. New tests must fail before the fix.
- Keep diffs scoped to one workstream; shared files (`main.rs`, `app.rs`, `state.rs`,
  `error.rs`, `Cargo.toml`) change once, deliberately, not from several directions.
- Report what is stubbed. A green build with a silent stub is worse than a red one.
