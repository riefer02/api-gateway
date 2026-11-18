-- MCP-aware routing and per-call audit.
--
-- Routes gain an optional tenant binding, a per-route deadline, a response
-- cap, and a tool policy. Upstreams gain an audience for RFC 8693 token
-- exchange. The audit table is deliberately separate from control-plane
-- audit_events: different retention, different readers, different rules.

ALTER TABLE upstreams
    ADD COLUMN audience TEXT,
    ADD COLUMN exchange_scope TEXT;

ALTER TABLE upstreams
    ADD CONSTRAINT upstreams_audience_shape
    CHECK (audience IS NULL OR length(btrim(audience)) BETWEEN 1 AND 512);

ALTER TABLE routes
    ADD COLUMN tenant_id TEXT REFERENCES tenants(id) ON DELETE RESTRICT,
    ADD COLUMN request_timeout_ms INTEGER,
    ADD COLUMN max_response_bytes BIGINT,
    ADD COLUMN tool_policy JSONB NOT NULL DEFAULT '{"mode":"off","roles":{}}'::jsonb;

ALTER TABLE routes
    ADD CONSTRAINT routes_request_timeout_range
    CHECK (request_timeout_ms IS NULL OR request_timeout_ms BETWEEN 1 AND 3600000);

ALTER TABLE routes
    ADD CONSTRAINT routes_max_response_bytes_range
    CHECK (max_response_bytes IS NULL OR max_response_bytes BETWEEN 1024 AND 1073741824);

ALTER TABLE routes
    ADD CONSTRAINT routes_tool_policy_is_object
    CHECK (jsonb_typeof(tool_policy) = 'object');

CREATE INDEX routes_tenant_prefix_idx ON routes (tenant_id, path_prefix) WHERE enabled;

-- Append-only record of data-plane calls. No foreign keys: an audit row must
-- outlive the route it describes, and `detail` holds identifiers or hashes,
-- never payloads, tokens, or verifier material.
CREATE TABLE data_audit_events (
    id          BIGSERIAL PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    tenant_id   TEXT NOT NULL,
    subject     TEXT,
    assistant   TEXT,
    auth_method TEXT NOT NULL,
    mcp_method  TEXT,
    route_id    TEXT,
    tool_name   TEXT,
    decision    TEXT NOT NULL CHECK (decision IN ('allow', 'deny')),
    status      SMALLINT,
    latency_ms  INTEGER,
    request_id  TEXT,
    token_id    TEXT,
    detail      JSONB NOT NULL DEFAULT '{}'::jsonb,
    CHECK (length(tenant_id) BETWEEN 1 AND 128),
    CHECK (subject IS NULL OR length(subject) <= 512),
    CHECK (assistant IS NULL OR length(assistant) <= 256),
    CHECK (route_id IS NULL OR length(route_id) <= 256),
    CHECK (tool_name IS NULL OR length(tool_name) <= 256),
    CHECK (request_id IS NULL OR length(request_id) <= 256),
    CHECK (token_id IS NULL OR length(token_id) <= 256)
);

CREATE INDEX data_audit_events_occurred_at_idx
    ON data_audit_events (occurred_at DESC, id DESC);

CREATE INDEX data_audit_events_tenant_time_idx
    ON data_audit_events (tenant_id, occurred_at DESC, id DESC);

CREATE INDEX data_audit_events_subject_idx
    ON data_audit_events (subject, occurred_at DESC);
