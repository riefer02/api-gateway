-- Append-only record of control-plane mutations.
--
-- `actor` is the name bound to the admin token that made the change; it is an
-- identity, not a role. `detail` must never contain secrets: record identifiers
-- and scope names, never tokens or verifier material.

CREATE TABLE audit_events (
    id          BIGSERIAL PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor       TEXT NOT NULL CHECK (length(btrim(actor)) > 0),
    action      TEXT NOT NULL CHECK (length(btrim(action)) > 0),
    subject     TEXT NOT NULL DEFAULT '',
    source_ip   TEXT,
    request_id  TEXT,
    detail      JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX audit_events_occurred_at_idx ON audit_events (occurred_at DESC, id DESC);
CREATE INDEX audit_events_actor_idx ON audit_events (actor);
