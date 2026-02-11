CREATE TABLE services (
    id TEXT PRIMARY KEY,
    peer_id TEXT NOT NULL REFERENCES nodes(node_id),
    name TEXT NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL DEFAULT 'tcp' CHECK(protocol IN ('tcp','udp','both')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(peer_id, port, protocol)
);

CREATE TABLE access_rules (
    id TEXT PRIMARY KEY,
    service_id TEXT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
    target_peer_id TEXT NOT NULL REFERENCES nodes(node_id),
    granted_by TEXT NOT NULL CHECK(granted_by IN ('owner','admin')),
    rule_type TEXT NOT NULL CHECK(rule_type IN ('allow','deny')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(service_id, target_peer_id, granted_by)
);
