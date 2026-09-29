# MeshLink Setup Guide

## Build

```bash
cargo build --release
```

The single binary is at `target/release/meshlink`.

---

## 1. Coordination Server Setup

The coordination server is built into the `meshlink` binary. It handles UDP peer discovery, an HTTP REST API for node registration, and server-push peer list updates. It requires a PostgreSQL database.

### Prerequisites

- A publicly reachable VPS
- PostgreSQL database

### Database Setup

```bash
# Create the database and user
createdb meshlink
createuser meshlink

# Initialize tables
export DATABASE_URL="postgres:///meshlink?user=meshlink"
meshlink cs db-setup
```

### Generate a Server Keypair

```bash
meshlink cs key-gen
```

### Create Invite Codes

```bash
# Single-use invite (default, expires in 24 hours)
meshlink cs create-invite

# Multi-use invite (up to 10 uses, expires in 48 hours)
meshlink cs create-invite --multi-use --max-uses 10 --expires-hours 48

# Unlimited multi-use invite (expires in 72 hours)
meshlink cs create-invite --multi-use --expires-hours 72
```

Or via the admin HTTP API:
```bash
# Requires ADMIN_TOKEN environment variable to be set on the server
curl -X POST http://your-server:4001/api/v1/admin/invite \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"max_uses": 5, "expires_in_hours": 48}'
```

### Start the Server

```bash
export DATABASE_URL="postgres:///meshlink?user=meshlink"

# Optional configuration (shown with defaults)
export MESH_NETWORK="10.0.0.0/24"
export HTTP_PORT=4001
export UDP_PORT=4000
export ADMIN_TOKEN="your-secret-admin-token"  # enables admin API

meshlink cs start
```

The server listens on:
- **UDP 4000** — peer discovery, NAT detection, and peer list push
- **HTTP 4001** — REST API for registration and invite management

Open both ports in your firewall:
```bash
sudo ufw allow 4000/udp
sudo ufw allow 4001/tcp
```

---

## 2. Node Setup (Server-Orchestrated)

This is the recommended workflow. Nodes register with a single command and receive their configuration automatically. When peers join or leave, the server pushes updated peer lists to all connected nodes.

### Register and Start

```bash
sudo meshlink up \
  --server http://your-server:4001 \
  --invite <invite-code> \
  --name my-laptop
```

This will:
1. Register the node with the coordination server
2. Receive a generated keypair and virtual IP
3. Save credentials to `/etc/meshlink/credentials.json`
4. Write config to `/etc/meshlink/config.toml`
5. Start the daemon

On subsequent runs, just:
```bash
sudo meshlink up
```

The daemon loads the saved config and connects to the coordination server automatically.

### Override Coordination Server

If the coordination server address changes or you want to use a different one:
```bash
sudo meshlink up --coord-server new-server.example.com:4000
```

### Check Status

```bash
sudo meshlink status
sudo meshlink peers
```

---

## 3. Quick Example

### On the coordination server

```bash
export DATABASE_URL="postgres:///meshlink?user=meshlink"
meshlink cs db-setup
meshlink cs start
```

Create a multi-use invite:
```bash
meshlink cs create-invite --multi-use --max-uses 5
# -> Invite code: 550e8400-e29b-41d4-a716-446655440000
```

### On Node A

```bash
sudo meshlink up \
  --server http://your-server:4001 \
  --invite 550e8400-e29b-41d4-a716-446655440000 \
  --name node-a
```

### On Node B

```bash
sudo meshlink up \
  --server http://your-server:4001 \
  --invite 550e8400-e29b-41d4-a716-446655440000 \
  --name node-b
```

### Test connectivity

When Node B joins, the server pushes an updated peer list to Node A automatically. Both nodes' config files are rewritten with the new peer.

From Node A:
```bash
ping 10.0.0.2
```

From Node B:
```bash
ping 10.0.0.1
```

---

## 4. Advanced: Static Configuration (Manual)

For environments without a coordination server HTTP API, you can configure nodes manually.

### Generate a keypair

```bash
meshlink genkey
```

Output:
```
Private key: <base64 string>
Public key:  <base64 string>
```

### Create a config file

```bash
sudo meshlink setup
sudo nano /etc/meshlink/config.toml
```

```toml
[node]
private_key = "<your-private-key>"
listen_port = 51820
virtual_ip = "10.0.0.1/24"
tun_name = "meshlink0"

[coordination]
server = "<coord-server-ip>:4000"

[[peers]]
public_key = "<peer-public-key>"
allowed_ips = ["10.0.0.2/32"]
# endpoint is optional — the coord server handles discovery
# endpoint = "1.2.3.4:51820"
```

Each node must have a unique `virtual_ip` on the same subnet:

| Node   | virtual_ip   |
|--------|------------- |
| Node A | 10.0.0.1/24  |
| Node B | 10.0.0.2/24  |
| Node C | 10.0.0.3/24  |

### Start the daemon

```bash
sudo meshlink up

# Or with a custom config path
sudo meshlink -c /path/to/config.toml up
```

---

## 5. Coordination Server Commands

All coordination server management is via `meshlink cs <subcommand>`:

| Command | Description |
|---------|-------------|
| `meshlink cs start` | Start the coordination server (UDP + HTTP) |
| `meshlink cs db-setup` | Create database tables |
| `meshlink cs db-wipe` | Drop all tables (destructive!) |
| `meshlink cs key-gen` | Generate and print an X25519 keypair |
| `meshlink cs create-invite` | Create a new invite code |

### Invite flags

| Flag | Default | Description |
|------|---------|-------------|
| `--multi-use` | `false` | Allow the invite to be used multiple times |
| `--max-uses <n>` | `0` | Max uses when multi-use (0 = unlimited) |
| `--expires-hours <n>` | `24` | Hours until the invite expires |

---

## 6. Server-Push Peer Updates

When a new peer registers or an existing peer goes stale, the coordination server automatically broadcasts an updated peer list to all connected peers via UDP. Nodes that advertise support receive it as `0x34` chunks that each fit in one unfragmented datagram; older nodes get a single `0x32` message.

On the client side:
- The discovery task handles these unsolicited pushes (only from the coordination server's address)
- Chunked lists are reassembled before anything is applied
- New peers are added to the routing table
- Stale peers are removed, except peers marked `static = true` in the config
- The config file's `[[peers]]` entries are rewritten to match; other sections and comments are kept

To pin a peer that the coordination server does not know about:

```toml
[[peers]]
public_key = "base64_encoded_key"
allowed_ips = ["10.0.0.50/32"]
endpoint = "203.0.113.7:51820"
static = true
```

This means nodes stay in sync without polling — topology changes propagate immediately.

---

## 7. Logging

Set the `RUST_LOG` environment variable for more detail:

```bash
# Info level (default)
sudo RUST_LOG=meshlink=info meshlink up

# Debug level (shows peer list updates, keepalives)
sudo RUST_LOG=meshlink=debug meshlink up

# Trace level (very verbose, shows every packet)
sudo RUST_LOG=meshlink=trace meshlink up
```

---

## 8. Firewall

Each node needs its `listen_port` (default 51820) open for UDP:

```bash
sudo ufw allow 51820/udp
```

The coordination server needs both ports open:

```bash
sudo ufw allow 4000/udp   # peer discovery + push
sudo ufw allow 4001/tcp   # REST API
```

---

## Notes

- The coordination server never sees your traffic. It only stores public keys and endpoint addresses.
- In server-orchestrated mode, the server generates keypairs and allocates IPs automatically.
- TUN device creation requires root or `CAP_NET_ADMIN`. To run without root:
  ```bash
  sudo setcap cap_net_admin+ep ./meshlink
  ```
- The daemon creates a unix socket at `/var/run/meshlink.sock` for runtime control. The `status` and `peers` commands communicate through it.
- Credentials are stored at `/etc/meshlink/credentials.json` after registration.
- IPv6 endpoints are stored in the database when peers connect over IPv6.
