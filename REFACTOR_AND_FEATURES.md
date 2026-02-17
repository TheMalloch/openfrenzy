# Refactor & Features: Server-Orchestrated Mesh

## Overview

MeshLink has been refactored from a two-crate model (`coord-server` + `meshlink`) to a single unified `meshlink` binary that serves as both a peer node and (via `meshlink cs` subcommands) the coordination server. The server orchestrates node lifecycle, key generation, IP allocation, configuration delivery, and now pushes peer list updates to all connected nodes.

---

## Completed Features

### Single Binary Architecture
- `coord-server/` deleted, all functionality merged into `meshlink/src/coord/`
- One workspace member: `meshlink`
- Coordination server runs via `meshlink cs start`

### Server-Side Key Generation & IP Allocation
- `coord/key_manager.rs` — X25519 keypair generation
- `coord/ip_allocator.rs` — CIDR pool allocation with `override_ip` option for admin overrides
- `coord/config_generator.rs` — TOML config generation including IPv6 endpoints

### Node Registration & Authentication
- `POST /api/v1/register` — invite code + optional name -> keypair + IP + config
- Credentials saved to `/etc/meshlink/credentials.json`
- Config written to `/etc/meshlink/config.toml`

### Configurable Invite System
- Single-use (default) or multi-use invites
- `max_uses` (0 = unlimited) and `use_count` tracking
- Configurable expiration (`--expires-hours`)
- CLI: `meshlink cs create-invite --multi-use --max-uses 5 --expires-hours 48`
- HTTP API: `POST /api/v1/admin/invite` with JSON body

### Server-Push Peer List Updates
- Coordination server broadcasts `PEER_LIST_RESP (0x32)` to all connected peers when:
  - A new peer registers via UDP
  - Stale nodes are removed by the background checker
- Shared `Arc<UdpSocket>` and `Arc<Mutex<HashMap>>` peer map used across UDP server and stale checker
- Client discovery task handles unsolicited pushes in `tokio::select!`

### Config Rewrite on Peer Changes
- `rewrite_config_peers()` in discovery — rewrites `[[peers]]` section from SharedState
- Handles both peer additions and removals
- `remove_peer()` added to SharedState for clean peer removal with route cleanup

### IPv6 Endpoint Storage
- `ipv6_endpoint` column in nodes table
- UDP handler stores IPv6 source addresses
- Config generator emits `ipv6_endpoint` in peer blocks

### ACL Removal
- `AclRule` struct removed
- ACL fields removed from `Config`, `PeerInfo`, `SharedState`
- ACL check methods and helpers removed from router
- `server_heartbeat_task` removed (replaced by push mechanism)
- `ApiClient` stripped to `register()` only

---

## Database Schema

### nodes table
```sql
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
    ipv6_endpoint TEXT,
    listen_port INTEGER NOT NULL DEFAULT 51820,
    last_heartbeat TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

### invites table
```sql
CREATE TABLE invites (
    code TEXT PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    used_by_node_id TEXT REFERENCES nodes(node_id),
    max_uses INTEGER NOT NULL DEFAULT 1,
    use_count INTEGER NOT NULL DEFAULT 0
);
```

---

## User Workflow

### Register and Start
```bash
sudo meshlink up \
  --server http://your-server:4001 \
  --invite <invite-code> \
  --name my-laptop
```

### Subsequent Runs
```bash
sudo meshlink up
```

### Automatic Peer Discovery
- Server pushes updated peer lists when topology changes
- Config file is rewritten automatically
- No manual peer configuration needed

---

## Remaining TODO

### Encryption
- Wire encryption not yet implemented (packets use `0x04` type byte prefix only)
- Plan: ChaCha20-Poly1305 per-packet encryption after X25519 handshake

### Operational
- End-to-end ping between peers not yet verified in production
- HTTPS/TLS for the HTTP API
- Config signing to prevent tampering

### Future Features
- Web dashboard for mesh topology visualization
- Multi-tenant support (isolated meshes on one server)
- High availability (multiple coord servers)
- Relay fallback when hole punching fails
