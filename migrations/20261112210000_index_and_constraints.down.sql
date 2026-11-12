ALTER TABLE routes DROP CONSTRAINT IF EXISTS routes_priority_range;
DROP INDEX IF EXISTS audit_events_action_idx;
DROP INDEX IF EXISTS api_keys_client_created_idx;
DROP INDEX IF EXISTS routes_upstream_id_idx;
