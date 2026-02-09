# Refactor & Features: Server-Orchestrated Mesh

## Overview

Refactor MeshLink from a peer-driven model (where nodes manually configure each other) to a server-orchestrated model (where the coordination server acts as a full orchestrator managing node lifecycle, key generation, IP allocation, and configuration).

**New Entry Point:** Users only need the server domain to join the mesh.

---

## Architecture Changes

### Current Model
```
User manually:
1. Generates keypair locally
2. Creates TOML with hardcoded server address + peer list
3. Exchanges public keys out-of-band
4. Manually assigns virtual IPs
5. Runs meshlink up
```

### New Model
```
User provides:
1. Server domain (e.g., mesh.example.com)
2. (Optional) Node name/identifier
3. Authentication token (invite code or signup)

Server orchestrator:
1. Generates keypair pair for the node
2. Allocates unique virtual IP from pool
3. Generates TOML file with correct configuration
4. Returns credentials to user
5. Dynamically updates all connected nodes when topology changes
```

---

## Core Features to Implement

### 1. Server-Side Key Generation & Storage
**File:** `coord-server/src/key_manager.rs` (new)

- Generate Ed25519 keypair for each node (or use existing X25519)
- Store encrypted private keys in coordserver database
- Return public key + encrypted private key to node during registration
- Implement secure key delivery (HTTPS, short-lived tokens)

```rust
pub struct KeyManager {
    // Maps node_id -> (public_key, encrypted_private_key)
}

impl KeyManager {
    pub fn generate_node_keypair(&mut self, node_id: &str) -> (String, String) {
        // Generate keypair, encrypt private key with node-specific secret
        // Return (public_key_b64, encrypted_private_key_b64)
    }
}
```

### 2. Automatic IP Address Management
**File:** `coord-server/src/ip_allocator.rs` (new)

- Track allocated virtual IPs
- Implement CIDR pool (e.g., 10.0.0.0/24)
- Auto-assign next available IP on node registration
- Reclaim IP when node deregisters

```rust
pub struct IpAllocator {
    network: Ipv4Net,  // e.g., 10.0.0.0/24
    allocated: HashSet<Ipv4Addr>,
}

impl IpAllocator {
    pub fn allocate(&mut self) -> Option<Ipv4Addr> {
        // Find next available IP in range
    }
    
    pub fn release(&mut self, ip: Ipv4Addr) {
        // Mark IP as available
    }
}
```

### 3. Dynamic TOML Generation & Delivery
**File:** `coord-server/src/config_generator.rs` (new)

- Generate complete TOML based on current mesh topology
- Endpoint for nodes to fetch their config: `GET /api/v1/node/{node_id}/config`
- Include all current peers from server registry
- Sign config to prevent tampering

```rust
pub struct ConfigGenerator {
    key_manager: Arc<KeyManager>,
    ip_allocator: Arc<IpAllocator>,
}

impl ConfigGenerator {
    pub fn generate_for_node(&self, node_id: &str) -> String {
        // Generate TOML with:
        // - Node's private_key (from key_manager)
        // - Node's virtual_ip (from ip_allocator)
        // - All peers from registry with endpoints
    }
}
```

### 4. Node Registration & Authentication
**File:** `coord-server/src/registration.rs` (new)

- Issue invite codes/signup tokens
- Register new nodes with optional name/metadata
- Return:
  - Generated keypair
  - Allocated virtual IP
  - TOML configuration
  - Node credentials for future auth

**Endpoint:** `POST /api/v1/register`
```json
Request: {
  "invite_code": "abc123xyz",
  "node_name": "laptop-main"
}

Response: {
  "node_id": "node_abc123",
  "private_key": "base64...",
  "public_key": "base64...",
  "virtual_ip": "10.0.0.5/24",
  "config": "TOML content...",
  "auth_token": "token_xyz789"
}
```

### 5. Config Sync Mechanism
**File:** `coord-server/src/config_sync.rs` (new)

When topology changes (new node joins, node leaves):
- Update all connected nodes' peer lists
- Send new TOML configurations via:
  - Polling: nodes periodically fetch `/api/v1/node/{id}/config`
  - Pushing: server sends config updates via WebSocket or gRPC
  - File watch: nodes watch `/etc/meshlink/config.toml` for changes

```rust
pub async fn sync_config_to_all_nodes(
    &self,
    registry: &PeerRegistry,
) {
    // For each active node:
    // 1. Generate new config
    // 2. Write to /etc/meshlink/config.toml (or signal via API)
    // 3. Trigger node reload
}
```

### 6. Simplified Node Startup
**File:** `meshlink/src/main.rs` (refactored)

Instead of reading from static TOML, node fetches config on startup:

```bash
./meshlink up --server mesh.example.com --node-id node_abc123 --auth-token token_xyz789
```

Or from env:
```bash
MESHLINK_SERVER=mesh.example.com \
MESHLINK_NODE_ID=node_abc123 \
MESHLINK_AUTH_TOKEN=token_xyz789 \
./meshlink up
```

Node behavior:
1. Connect to server, authenticate with token
2. Fetch initial config (IP, peers, keys)
3. Start TUN/UDP with fetched config
4. Watch for config updates from server
5. Reload configuration when peers join/leave

### 7. Node Lifecycle Management
**File:** `coord-server/src/node_registry.rs` (new)

Track node state:
- `Registered` — node created, awaiting first connection
- `Active` — node connected, heartbeat OK
- `Stale` — no heartbeat (>2 min), but not yet removed
- `Deregistered` — explicitly removed

```rust
pub struct NodeRegistry {
    nodes: HashMap<String, NodeEntry>,
}

pub struct NodeEntry {
    pub node_id: String,
    pub public_key: [u8; 32],
    pub virtual_ip: Ipv4Addr,
    pub status: NodeStatus,
    pub last_heartbeat: Instant,
    pub endpoint: Option<SocketAddr>,
}
```

---

## Implementation Plan

### Phase 1: Server Enhancement (coord-server)
- [ ] Add HTTPS/TLS support (for secure config delivery)
- [ ] Implement database (SQLite for simplicity, or PostgreSQL for production)
  - Store node records: node_id, public_key, virtual_ip, auth_token
- [ ] Build key manager (generate + store keypairs)
- [ ] Build IP allocator (track CIDR pool)
- [ ] Build config generator (TOML generation)
- [ ] Add REST API endpoints:
  - `POST /api/v1/register` — new node registration
  - `GET /api/v1/node/{id}/config` — fetch config
  - `POST /api/v1/node/{id}/heartbeat` — node keepalive
  - `DELETE /api/v1/node/{id}` — explicit deregistration
- [ ] Implement config sync (notify nodes on topology changes)

### Phase 2: Node Client Refactor (meshlink)
- [ ] Add `--server`, `--node-id`, `--auth-token` CLI flags
- [ ] Replace static TOML loader with dynamic config fetcher
- [ ] Implement config polling/watching (reload on server updates)
- [ ] Add graceful reload when peers change
- [ ] Remove manual `genkey` command (now server-side)
- [ ] Update GUIDE.md with new workflow

### Phase 3: Onboarding UI (Optional)
- [ ] Web dashboard on coord server (or separate service)
- [ ] Generate invite codes
- [ ] Display mesh topology
- [ ] Show node status
- [ ] Manage peer connectivity

---

## New User Workflow

### For Users

**1. Get Invite Code**
```
Admin generates: https://mesh.example.com/invite?code=abc123xyz
```

**2. Register Node**
```bash
# Pull config from server (first time)
./meshlink register --server mesh.example.com --invite abc123xyz

# Output:
# ✓ Registration successful
# ✓ Node ID: node_5f7a8c
# ✓ Virtual IP: 10.0.0.5/24
# ✓ Config saved to: /etc/meshlink/config.toml
# ✓ Auth token: token_xyz789 (save for future logins)
```

**3. Start Node**
```bash
sudo ./meshlink up --server mesh.example.com --node-id node_5f7a8c
```

Or persist credentials:
```bash
# One-time: save to /etc/meshlink/.noderc
./meshlink login --server mesh.example.com --node-id node_5f7a8c --token token_xyz789

# Future startups:
sudo ./meshlink up
```

**4. Automatic Peer Discovery**
- Server automatically notifies node when new peers join
- Node updates routing table, no manual config needed

**5. Leave Mesh**
```bash
./meshlink unregister --server mesh.example.com --node-id node_5f7a8c
```

---

## Data Structures

### Server Database Schema (SQLite)
```sql
-- Nodes
CREATE TABLE nodes (
    node_id TEXT PRIMARY KEY,
    public_key BLOB NOT NULL,
    virtual_ip TEXT NOT NULL,
    auth_token TEXT NOT NULL UNIQUE,
    status TEXT CHECK(status IN ('registered', 'active', 'stale', 'deregistered')),
    last_heartbeat INTEGER,
    endpoint TEXT,
    created_at INTEGER,
    updated_at INTEGER
);

-- Invite Codes
CREATE TABLE invites (
    code TEXT PRIMARY KEY,
    created_at INTEGER,
    used_at INTEGER,
    used_by_node_id TEXT REFERENCES nodes(node_id)
);

-- Config History (for auditing)
CREATE TABLE config_snapshots (
    snapshot_id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER,
    config_json TEXT
);
```

---

## Security Considerations

1. **HTTPS/TLS Only**
   - All client-server communication over TLS
   - Verify server certificate (or pin)

2. **Authentication**
   - Auth tokens are short-lived (e.g., 24h, refreshed on heartbeat)
   - Tokens stored securely (hashed in DB)

3. **Key Material**
   - Private keys generated server-side and encrypted at rest
   - Never logged or exposed in transit
   - Consider hardware key storage (HSM) for production

4. **Invite Codes**
   - Single-use, time-limited (e.g., 24h expiry)
   - Admin generates and distributes securely

5. **Config Integrity**
   - Sign generated configs (HMAC or Ed25519)
   - Verify signature before applying

---

## Migration Path

For existing MeshLink users:
1. Keep old static config mode operational
2. Add new orchestrator mode alongside
3. Provide migration script: `./meshlink migrate --server mesh.example.com`
4. Eventually deprecate static mode

---

## Testing

### Unit Tests
- KeyManager: keypair generation, encryption
- IpAllocator: allocation, release, collision detection
- ConfigGenerator: TOML generation correctness

### Integration Tests
- Node registration → IP allocation → config delivery
- Multiple nodes: topology changes trigger config updates
- Node failure/recovery: stale peer cleanup
- Config reload: new peers appear without restart

### Load/Scale Tests
- 100+ nodes in one mesh
- Topology changes rate
- Concurrent registrations

---

## Files to Create/Modify

### New Files (coord-server)
- `coord-server/src/db.rs` — database abstraction
- `coord-server/src/key_manager.rs` — keypair generation
- `coord-server/src/ip_allocator.rs` — IP management
- `coord-server/src/config_generator.rs` — TOML generation
- `coord-server/src/registration.rs` — registration endpoint
- `coord-server/src/config_sync.rs` — topology sync
- `coord-server/src/node_registry.rs` — node tracking
- `coord-server/src/api.rs` — REST endpoints (refactor from main.rs)

### Modified Files (meshlink)
- `meshlink/src/main.rs` — CLI flags, config fetching
- `meshlink/src/config.rs` — support dynamic config reload
- `meshlink/src/discovery/mod.rs` — heartbeat, config polling
- `GUIDE.md` — new user workflow

### Documentation
- `REFACTOR_AND_FEATURES.md` — this file
- `ARCHITECTURE_ORCHESTRATOR.md` — design details

---

## Benefits

✅ **Easier Onboarding** — Users only need server domain + invite code  
✅ **Zero Manual Config** — Server generates everything  
✅ **Automatic Scaling** — New nodes integrate instantly  
✅ **Centralized Control** — Admins manage mesh from one place  
✅ **Dynamic Mesh** — Nodes can join/leave without restart  
✅ **Better Security** — Keys generated and managed server-side  
✅ **Audit Trail** — Config snapshots for compliance  

---

## Open Questions

1. **Database?** SQLite (dev), PostgreSQL (prod), or in-memory?
2. **Config Distribution?** Polling, WebSocket push, or file sync?
3. **High Availability?** Multiple coord servers with replication?
4. **Key Escrow?** Should admin have access to node private keys?
5. **Multi-Tenant?** Support multiple isolated meshes on one server?

