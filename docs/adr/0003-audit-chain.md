# ADR 0003 — Control-plane audit is an unkeyed, prefix-anchored hash chain

Status: accepted · 2026-11-19

## Context

Control-plane mutations — tenants, clients, keys, upstreams, routes — are the record an
auditor or an incident review will read. They were append-only by convention: nothing
stopped an edit, and nothing proved one had not happened.

Two constraints shaped the decision. The first is the threat model: the gateway's concern
is a mistaken or careless operator, a bad migration, or an application bug corrupting the
record — not a database administrator deliberately forging evidence. The second is
operational: the record must be verifiable with nothing but the database and the binary,
because a template cannot assume a signing service, a bucket, or a compliance budget.

## Decision

Each control-plane row carries the hash of its predecessor and a hash of its own contents,
over a canonical JSON encoding (keys sorted at every depth). Appends are serialised by an
advisory lock inside the writing transaction, so two rows cannot claim one predecessor.

Three details make verification meaningful rather than decorative:

- **Membership is recorded, not inferred.** A `chained` column says which rows belong to the
  chain. An empty hash on a chained row is a break; a row without the marker is a gap. If
  membership were inferred from "hash is empty", blanking the column would hide any suffix.
- **The walk starts at the oldest retained row.** Retention deletes the head, so requiring
  genesis would report a break on a healthy deployment. The cost is explicit: removing the
  oldest rows is indistinguishable from retention.
- **A row outside the chain after the chain has started is a break.** This is what makes
  clearing the marker on a suffix visible. It also means a mixed-version rollout reads as a
  break until every replica runs the current binary — verify after the upgrade, not during.

The per-call data-plane audit is **not** chained. It is high volume, batched, and not the
log an auditor reads; chaining it would put a serialised write on the request path to prove
something nobody asks it to prove.

## Consequences

- An edit, an insertion, a reordering, or a cleared marker is detected and named by
  `admin audit verify`, which exits non-zero.
- The chain is **unkeyed**. Someone who can write the table can recompute the suffix, and
  someone who can delete rows can remove the head. The chain detects quiet edits; it does
  not prove integrity to an adversary with write access.
- `audit verify` is a manual command. There is no background verification and no alert on a
  broken chain.
- One writer at a time serialises control-plane mutations. At this volume that is free; it
  would not be for the data plane.

## Alternatives

| Alternative | Why not |
|---|---|
| **HMAC each row with a key** | Moves the trust boundary to key custody. Meaningful only if the key is held by someone who cannot write the table, which a template cannot arrange |
| **Periodic signed checkpoint** | Closes the recompute-suffix gap, but needs a destination and a signer. The right upgrade when compliance asks |
| **Ship every row to an append-only sink** | Strongest, and the only option that survives a compromised database. Infrastructure this project does not have |
| **Nothing** | The record is what an incident review reads; "append-only by convention" is not a property |

## Revisit when

- someone asks for evidence an external auditor will accept, or the threat model adds a
  database-writer adversary — then add an anchor: a checkpoint hash written somewhere the
  database writer cannot reach;
- verification needs to be continuous — then run `admin audit verify` on a schedule and
  alert on failure;
- the mixed-version break becomes an operational problem — then add a grace window keyed on
  the binary version rather than the marker.
