CREATE TABLE nodes (
    node_id TEXT PRIMARY KEY,
    node_name TEXT,
    public_key BYTEA NOT NULL UNIQUE,
    private_key_encrypted BYTEA NOT NULL,
    virtual_ip TEXT NOT NULL UNIQUE,
    auth_token TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'registered'
        CHECK(status IN ('registered','active','stale','deregistered')),
    endpoint TEXT,
    listen_port INTEGER NOT NULL DEFAULT 51820,
    last_heartbeat TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE invites (
    code TEXT PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    used_by_node_id TEXT REFERENCES nodes(node_id)
);
