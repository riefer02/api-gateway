ALTER TABLE routes DROP CONSTRAINT IF EXISTS routes_id_not_blank;
ALTER TABLE upstreams DROP CONSTRAINT IF EXISTS upstreams_id_not_blank;
ALTER TABLE tenants DROP CONSTRAINT IF EXISTS tenants_id_not_blank;
ALTER TABLE clients DROP CONSTRAINT IF EXISTS clients_id_not_blank;
