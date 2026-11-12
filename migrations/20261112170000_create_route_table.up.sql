-- Routes and upstreams are data, not code: the admin plane owns them, and the
-- gateway compiles them into an in-memory snapshot at boot and on version bump.

CREATE TABLE upstreams (
    id          TEXT PRIMARY KEY,
    base_url    TEXT NOT NULL,
    timeout_ms  INTEGER NOT NULL CHECK (timeout_ms BETWEEN 1 AND 300000),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE routes (
    id             TEXT PRIMARY KEY,
    upstream_id    TEXT NOT NULL REFERENCES upstreams(id) ON DELETE RESTRICT,
    path_prefix    TEXT NOT NULL CHECK (path_prefix LIKE '/%'),
    methods        TEXT[] NOT NULL CHECK (cardinality(methods) > 0),
    rewrite_prefix TEXT,
    scopes         TEXT[] NOT NULL DEFAULT '{}',
    priority       INTEGER NOT NULL DEFAULT 0,
    enabled        BOOLEAN NOT NULL DEFAULT true,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX routes_enabled_prefix_idx ON routes (path_prefix) WHERE enabled;

-- Single-row version counter. Replicas poll it; a change swaps the snapshot.
CREATE TABLE route_table_state (
    only_one   BOOLEAN PRIMARY KEY DEFAULT true CHECK (only_one),
    version    BIGINT NOT NULL DEFAULT 1,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO route_table_state (only_one, version) VALUES (true, 1);

-- Any writer (admin CLI, psql, migration) bumps the version; the gateway never
-- has to remember to do it.
CREATE FUNCTION bump_route_table_version() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    UPDATE route_table_state
       SET version = version + 1, updated_at = now()
     WHERE only_one;
    RETURN NULL;
END;
$$;

CREATE TRIGGER routes_bump_version
AFTER INSERT OR UPDATE OR DELETE ON routes
FOR EACH STATEMENT EXECUTE FUNCTION bump_route_table_version();

CREATE TRIGGER upstreams_bump_version
AFTER INSERT OR UPDATE OR DELETE ON upstreams
FOR EACH STATEMENT EXECUTE FUNCTION bump_route_table_version();
