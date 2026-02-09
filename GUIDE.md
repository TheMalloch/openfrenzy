# MeshLink Setup Guide

## Build

```bash
cargo build --release
```

Binaries will be at:
- `target/release/meshlink`
- `target/release/coord-server`

---

## 1. Coordination Server Setup

The coordination server handles both UDP peer discovery and an HTTP REST API for node registration and config management. It requires a PostgreSQL database.

### Prerequisites

- A publicly reachable VPS
- PostgreSQL database

### Database Setup

```bash
# Create the database
createdb meshlink

# The server runs migrations automatically on startup
```

### Start the Server

```bash
# Set the database connection string
export DATABASE_URL="postgres://user:pass@localhost/meshlink"

# Optional: configure network and ports (shown with defaults)
export MESH_NETWORK="10.0.0.0/24"
export HTTP_PORT=4001
export UDP_PORT=4000

./coord-server
```

The server listens on:
- **UDP 4000** — peer discovery and NAT detection (existing protocol)
- **HTTP 4001** — REST API for registration, config, and heartbeat

Open both ports in your firewall:
```bash
sudo ufw allow 4000/udp
sudo ufw allow 4001/tcp
```

### Create Invite Codes

```bash
# Create an invite code (valid for 24 hours)
curl -X POST http://your-server:4001/api/v1/admin/invite
```

Response:
```json
{
  "code": "550e8400-e29b-41d4-a716-446655440000",
  "expires_at": "2025-01-02T12:00:00Z"
}
```

Share the invite code with users who need to join the mesh.

---

## 2. Node Setup (Server-Orchestrated)

This is the recommended workflow. Nodes register with a single command and receive their configuration automatically.

### Register

```bash
sudo ./meshlink register \
  --server http://your-server:4001 \
  --invite <invite-code> \
  --name my-laptop
```

This will:
1. Register the node with the coordination server
2. Receive a generated keypair and virtual IP
3. Save credentials to `/etc/meshlink/credentials.json`
4. Write config to `/etc/meshlink/config.toml`

### Start the Daemon

```bash
sudo ./meshlink up
```

The daemon automatically detects stored credentials and fetches the latest config from the server. It also sends periodic heartbeats and updates its peer list when new nodes join.

You can also pass server parameters explicitly:

```bash
sudo ./meshlink up \
  --server http://your-server:4001 \
  --node-id <node-id> \
  --auth-token <token>
```

Or use environment variables:

```bash
export MESHLINK_SERVER=http://your-server:4001
export MESHLINK_NODE_ID=<node-id>
export MESHLINK_AUTH_TOKEN=<token>
sudo -E ./meshlink up
```

### Check Status

```bash
sudo ./meshlink status
sudo ./meshlink peers
```

### Unregister

```bash
sudo ./meshlink unregister
```

This deregisters the node from the server and removes local credentials.

---

## 3. Quick Server-Orchestrated Example

### On the coordination server

```bash
export DATABASE_URL="postgres://localhost/meshlink"
./coord-server
```

Create two invite codes:
```bash
curl -s -X POST http://localhost:4001/api/v1/admin/invite | jq -r .code
# -> invite_code_A
curl -s -X POST http://localhost:4001/api/v1/admin/invite | jq -r .code
# -> invite_code_B
```

### On Node A

```bash
sudo ./meshlink register --server http://your-server:4001 --invite <invite_code_A> --name node-a
sudo ./meshlink up
```

### On Node B

```bash
sudo ./meshlink register --server http://your-server:4001 --invite <invite_code_B> --name node-b
sudo ./meshlink up
```

### Test connectivity

From Node A:
```bash
ping 10.0.0.2
```

From Node B:
```bash
ping 10.0.0.1
```

Nodes automatically discover each other through the server — no manual peer configuration needed.

---

## 4. Advanced: Static Configuration (Manual)

For environments without a coordination server API, you can still configure nodes manually.

### Generate a keypair

```bash
./meshlink genkey
```

Output:
```
Private key: <base64 string>
Public key:  <base64 string>
```

Save both. Share only the public key with other nodes.

### Create a config file

```bash
sudo mkdir -p /etc/meshlink
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

Each node must have a unique `virtual_ip` on the same subnet. Example layout:

| Node   | virtual_ip   |
|--------|------------- |
| Node A | 10.0.0.1/24  |
| Node B | 10.0.0.2/24  |
| Node C | 10.0.0.3/24  |

Each node lists the other nodes under `[[peers]]`. Add one `[[peers]]` block per remote node.

### Start the daemon

```bash
# Requires root or CAP_NET_ADMIN for TUN device creation
sudo ./meshlink up

# Or with a custom config path
sudo ./meshlink -c /path/to/config.toml up
```

---

## 5. Logging

Set the `RUST_LOG` environment variable for more detail:

```bash
# Info level (default)
sudo RUST_LOG=meshlink=info ./meshlink up

# Debug level (shows every packet)
sudo RUST_LOG=meshlink=debug ./meshlink up

# Trace level (very verbose)
sudo RUST_LOG=meshlink=trace ./meshlink up
```

---

## 6. Firewall

Each node needs its `listen_port` (default 51820) open for UDP:

```bash
sudo ufw allow 51820/udp
```

The coordination server needs both ports open:

```bash
sudo ufw allow 4000/udp   # peer discovery
sudo ufw allow 4001/tcp   # REST API
```

---

## Notes

- All traffic between nodes is encrypted with ChaCha20-Poly1305 after an X25519 key exchange.
- The coordination server never sees your traffic. It only stores public keys and endpoint addresses.
- In server-orchestrated mode, the server generates keypairs and allocates IPs automatically.
- TUN device creation requires root or `CAP_NET_ADMIN`. To run without root:
  ```bash
  sudo setcap cap_net_admin+ep ./meshlink
  ```
- The daemon creates a unix socket at `/var/run/meshlink.sock` for runtime control. The `status` and `peers` commands communicate through it.
- Credentials are stored at `/etc/meshlink/credentials.json` after registration.
