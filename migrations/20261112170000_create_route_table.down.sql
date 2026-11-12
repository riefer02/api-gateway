DROP TRIGGER IF EXISTS upstreams_bump_version ON upstreams;
DROP TRIGGER IF EXISTS routes_bump_version ON routes;
DROP FUNCTION IF EXISTS bump_route_table_version();
DROP TABLE IF EXISTS route_table_state;
DROP TABLE IF EXISTS routes;
DROP TABLE IF EXISTS upstreams;
