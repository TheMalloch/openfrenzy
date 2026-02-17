# OpenFrenzy

A peer-to-peer LAN mesh networking tool written in Rust. Creates UDP tunnels between machines, making them appear on the same virtual LAN (e.g. `10.0.0.0/24`) regardless of their physical network location.

## Architecture

- **Topology:** Full mesh — every node connects directly to every other node
- **NAT traversal:** UDP hole punching via a coordination server
- **Discovery:** Centralized coordination server where peers register and discover each other
- **Transport:** UDP with type-byte framing (encryption planned)
- **Server push:** The coordination server broadcasts peer list updates to all connected nodes when peers join or leave

## Project Structure

Single binary (`meshlink`) that runs as both a peer node and (optionally) the coordination server:

```
meshlink/
  src/
    main.rs           — entry point, tokio runtime, spawns async tasks
    config.rs          — TOML config parsing
    state.rs           — shared runtime state: peer table, route table, stats
    tun/mod.rs         — TUN virtual interface creation, async read/write
    net/udp.rs         — UDP socket async reader/writer tasks
    net/hole_punch.rs  — NAT traversal: endpoint discovery + simultaneous open
    crypto/handshake.rs — X25519 key generation
    crypto/transport.rs — packet wrap/unwrap (type-byte framing)
    router/mod.rs      — route table + packet forwarding
    discovery/mod.rs   — coord server client: registration, peer list, keepalive, push handling
    cli/mod.rs         — clap CLI + unix socket for runtime control
    api_client.rs      — HTTP client for registration
    coord/             — embedded coordination server
      mod.rs           — server entry point (UDP + HTTP + stale checker)
      db.rs            — PostgreSQL database layer
      api.rs           — HTTP API (registration, invite management)
      udp_handler.rs   — UDP protocol handler + broadcast
      config_generator.rs — TOML config generation for nodes
      ip_allocator.rs  — virtual IP allocation from CIDR pool
      key_manager.rs   — X25519 keypair generation
```

## Quick Start

See [GUIDE.md](GUIDE.md) for full setup instructions.

```bash
# Build
cargo build --release

# --- Coordination server (on a public VPS) ---
export DATABASE_URL="postgres:///meshlink?user=meshlink"
meshlink cs db-setup
meshlink cs create-invite --multi-use --max-uses 10
meshlink cs start

# --- Node (on each machine) ---
sudo meshlink up \
  --server http://your-server:4001 \
  --invite <invite-code> \
  --name my-laptop
```

## Async Task Model

Six concurrent tokio tasks communicating via `mpsc` channels:

1. `tun_reader` — reads packets from TUN device, feeds outbound pipeline
2. `tun_writer` — receives inbound packets, writes to TUN
3. `udp_reader` — reads from UDP socket, feeds inbound pipeline
4. `udp_writer` — receives outbound packets, sends to wire
5. `discovery` — peer discovery, keepalive, and push handling with coord server
6. `cli_listener` — unix socket accepting runtime commands

## Packet Pipeline

```
Outbound: TUN read → route lookup → wrap → UDP send
Inbound:  UDP recv → unwrap → route verify → TUN write
```

## Config Format

```toml
[node]
private_key = "base64_encoded_key"
listen_port = 51820
virtual_ip = "10.0.0.1/24"
tun_name = "meshlink0"

[coordination]
server = "coord.example.com:4000"

[[peers]]
public_key = "base64_encoded_key"
allowed_ips = ["10.0.0.2/32"]
endpoint = "1.2.3.4:51820"
```

## UDP Coordination Protocol

| Type | Name | Payload |
|------|------|---------|
| `0x10` | NAT_DETECT_REQ | (empty) |
| `0x11` | NAT_DETECT_RESP | `[addr_type:1][ip:4\|16][port:2]` |
| `0x30` | REGISTER | `[pub_key:32][listen_port:2]` |
| `0x31` | PEER_LIST_REQ | `[pub_key:32]` |
| `0x32` | PEER_LIST_RESP | `[count:2]([pub_key:32][vip:4][addr_type:1][ip:4\|16][port:2])*` |
| `0x33` | KEEPALIVE | `[pub_key:32]` |

The server also sends unsolicited `0x32` broadcasts when peers join or go stale.

## Requirements

- Linux (TUN device requires `CAP_NET_ADMIN` or root)
- PostgreSQL (for the coordination server)
- Rust toolchain for building

## License

See LICENSE file.
