-- Indexes for the queries the gateway actually issues.

-- Deleting an upstream checks routes that reference it.
CREATE INDEX routes_upstream_id_idx ON routes (upstream_id);

-- Listing a client's keys is ordered newest first.
CREATE INDEX api_keys_client_created_idx ON api_keys (client_id, created_at DESC);

-- Audit search by action (e.g. every key.revoke).
CREATE INDEX audit_events_action_idx ON audit_events (action);

-- Route priority is a small tie-breaker, not an arbitrary number.
ALTER TABLE routes
    ADD CONSTRAINT routes_priority_range CHECK (priority BETWEEN -1000 AND 1000);
