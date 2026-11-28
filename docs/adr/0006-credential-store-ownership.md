# ADR 0006 — One owner for `api_keys`, and rotation is one transaction

Status: accepted · 2026-11-27

## Context

The credential table had two owners. `ApiKeyStore` owned authentication reads and the
insert/revoke writes, but `AdminService` also read `api_keys` directly to list a client's
keys and to load a key before rotating it, and the development seed deleted and inserted
rows itself. For an organization that means a security reviewer must find every SQL site
rather than open one file, and an in-memory double cannot answer a control-plane listing.

Rotation also assumed two writes could be made consistent by hand: issue the replacement,
then revoke the old key, and revoke the replacement if the revoke failed. Between the two
writes both credentials are valid. A process death in that window leaves an active key
whose token was never shown, or an old key that outlives its replacement.

## Decision

`ApiKeyStore` is the only interface to `api_keys`, for the data plane and the control
plane alike.

- **Reads and writes both live behind the trait.** `list_for_client` returns a
  `KeySummary` defined beside the store, so the projection cannot drift from the rows.
  `find_by_key_id` already returns everything rotation needs; the admin path no longer
  issues its own `SELECT`.
- **`rotate_key(old, new)` is one transaction.** It revokes the old key and inserts the
  replacement together, and returns `false` without inserting anything when the old key
  is missing or already revoked. There is no compensating write and no window in which
  both credentials are active.
- **The notification is transactional too.** `pg_notify` for both ids commits with the
  write, so no replica can observe one without the other.
- **The cache treats both ids.** The old id gets a local tombstone; the replacement clears
  a negative entry but must not be tombstoned, or a replica would deny the key it just
  issued.
- **`replace_key` is the one destructive operation**, used only by the development seed,
  which needs a fixed id (`dev-local`) and a fresh verifier on every boot. It is named for
  what it does rather than hidden behind `insert`.

The control-plane admin module keeps the SQL for its own entities — tenants, clients,
routes, upstreams — and the audit chain keeps its own. The rule is one owner per table,
not "no SQL outside a repository layer".

## Consequences

- The trait grows by three methods (list, rotate, replace). That is the price of the
  boundary; every method is used by the control plane, and none is a pass-through.
- Rotation is atomic, and a failed rotation leaves the old key exactly as it was.
- The test double implements the same operations, so control-plane listing is testable
  without Postgres.
- The development seed is no longer atomic with tenant/client creation. It is
  development-only and both halves are idempotent, so the next boot repairs it.
- `created_at` stays out of the authentication record. The in-memory double stores it
  beside the credential; production reads it from the row it is already listing.

## Alternatives

| Alternative | Why not |
|---|---|
| **Expose the pool or a transaction to `AdminService`** | Makes the table public again, one query at a time; the next feature adds the fourth |
| **A separate read trait for listings** | Keeps authentication from seeing summaries, but gives the table two interfaces to keep in step for no caller that needs the split |
| **Insert-then-revoke with a compensating revoke** | The current behaviour: valid in the happy path, and a window the code cannot close |
| **Delete-then-insert for rotation** | Loses the revocation timestamp and can leave no credential at all if the insert fails |
| **A lint that only forbids SQL in `admin`** | Enforces the letter of the rule while leaving the reason unstated; the trait is the mechanism, the check is the backstop |

## Revisit when

- a second consumer needs credential listings with filtering or pagination — then the read
  model grows a cursor in one place instead of in every caller;
- rotation must also change scopes or tenancy rather than only the secret — then the
  operation is a replacement, not a rotation, and deserves its own method and ADR.
