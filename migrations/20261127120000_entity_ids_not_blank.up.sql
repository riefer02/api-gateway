-- An entity id is a key: it addresses a row in a URL, names it in the audit
-- log, and becomes a keyset boundary. The admin service refuses a blank one
-- before it reaches Postgres; this is the same rule at the storage boundary,
-- for writers outside the service.
--
-- NOT VALID: rows stored before the check may still carry an empty or
-- whitespace-only id. Failing the migration on them would block the deploy,
-- and rewriting their ids would orphan the audit rows that name them. Writes
-- and updates are checked now; once the stored rows are cleaned up,
-- `VALIDATE CONSTRAINT` turns the scan into a planner-visible guarantee.
ALTER TABLE routes
    ADD CONSTRAINT routes_id_not_blank CHECK (length(btrim(id)) > 0) NOT VALID;

ALTER TABLE upstreams
    ADD CONSTRAINT upstreams_id_not_blank CHECK (length(btrim(id)) > 0) NOT VALID;

ALTER TABLE tenants
    ADD CONSTRAINT tenants_id_not_blank CHECK (length(btrim(id)) > 0) NOT VALID;

ALTER TABLE clients
    ADD CONSTRAINT clients_id_not_blank CHECK (length(btrim(id)) > 0) NOT VALID;
