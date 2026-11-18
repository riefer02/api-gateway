-- WARNING: this destroys the data-plane audit history. Export it first.
DROP TABLE IF EXISTS data_audit_events;

ALTER TABLE routes
    DROP CONSTRAINT IF EXISTS routes_tool_policy_is_object,
    DROP CONSTRAINT IF EXISTS routes_max_response_bytes_range,
    DROP CONSTRAINT IF EXISTS routes_request_timeout_range;

DROP INDEX IF EXISTS routes_tenant_prefix_idx;

ALTER TABLE routes
    DROP COLUMN IF EXISTS tool_policy,
    DROP COLUMN IF EXISTS max_response_bytes,
    DROP COLUMN IF EXISTS request_timeout_ms,
    DROP COLUMN IF EXISTS tenant_id;

ALTER TABLE upstreams
    DROP CONSTRAINT IF EXISTS upstreams_audience_shape;

ALTER TABLE upstreams
    DROP COLUMN IF EXISTS exchange_scope,
    DROP COLUMN IF EXISTS audience;
