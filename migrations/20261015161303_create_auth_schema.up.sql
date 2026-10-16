-- Add up migration script here
CREATE TABLE tenants (
    id TEXT PRIMARY KEY,
    status TEXT NOT NULL CHECK (status IN ('active', 'suspended'))
);

CREATE TABLE clients (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    status TEXT NOT NULL CHECK (status IN ('active', 'suspended'))
);

CREATE INDEX clients_tenant_id_idx ON clients (tenant_id);

CREATE TABLE api_keys (
    key_id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE RESTRICT,
    verifier BYTEA NOT NULL CHECK (octet_length(verifier) = 32),
    verifier_version SMALLINT NOT NULL CHECK (verifier_version BETWEEN 1 AND 255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    CONSTRAINT api_keys_expiry_after_creation
    CHECK (expires_at IS NULL OR expires_at > created_at)
);

CREATE INDEX api_keys_client_id_idx ON api_keys (client_id);

CREATE TABLE api_key_scopes (
    key_id TEXT NOT NULL REFERENCES api_keys(key_id) ON DELETE CASCADE,
    scope TEXT NOT NULL CHECK (length(btrim(scope)) > 0),
    PRIMARY KEY (key_id, scope)
);

