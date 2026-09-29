# OpenFrenzy / MeshLink

A peer-to-peer LAN mesh for Linux, written in Rust. Machines join a virtual
LAN (e.g. `10.0.0.0/24`) over direct UDP tunnels, wherever they physically are.
A coordination server hands out addresses and tells nodes how to reach each other.

## Security status — read this first

MeshLink is **not yet safe for untrusted networks**. As of today:

- **Tunnel traffic is not encrypted.** Packets travel as plaintext UDP.
- **Peers are identified by UDP source address**, which can be spoofed.
- **The coordination server generates and stores node private keys** unless the
  node registers with `--public-key`.
- **UDP registration/keepalive is not cryptographically authenticated.**

The fix is planned in [`roadmap/`](roadmap/README.md): Noise_IK sessions
(Phase 1), then authenticated coordination with node-generated keys (Phase 2).
Hardening already in place is listed in
[`roadmap/backlog.md`](roadmap/backlog.md) under "Residual risks".

## Architecture

- **Topology:** full mesh — every node talks directly to every other node
- **NAT traversal:** UDP hole punching, coordinated by the server
- **Discovery:** central coordination server (PostgreSQL-backed); nodes register,
  send keepalives, and receive peer lists pushed on every membership change
- **Fallback:** if UDP to the coordinator is blocked, nodes keep in sync over its
  HTTPS API
- **Transport:** UDP with a one-byte type prefix (no encryption yet — see above)

## Binaries

| Binary | Purpose |
|---|---|
| `meshlink` | Peer daemon **and** coordination server (`meshlink cs …`) |
| `mldeploy` | Operator tool: push files / run commands on peers over SSH, publish signed updates, auto-update daemon |

## Project structure

```
meshlink/src/
  main.rs            entry point: CLI dispatch, registration, daemon runtime
  cli/mod.rs         clap CLI + unix control socket (status, peers)
  config.rs          node config.toml parsing
  credentials.rs     credentials.json (server, node_id, auth token)
  setup.rs           `meshlink setup`: system dirs, group, permissions
  state.rs           shared peer table, route table, endpoint index, counters
  util.rs            atomic file writes, constant-time token compare
  tun/mod.rs         TUN device
  net/udp.rs         UDP socket reader/writer tasks, packet dispatch
  net/hole_punch.rs  NAT detection + hole-punch probes
  crypto/            X25519 identity (handshake.rs), packet framing (transport.rs)
  router/mod.rs      outbound (TUN→UDP) and inbound (UDP→TUN) pipelines
  discovery/mod.rs   coordinator client: register, keepalive, peer lists, HTTP fallback
  api_client.rs      HTTP registration client
  peer_api/          optional per-node HTTP(S) API + web page (status, peers, token rotation)
  coord/             embedded coordination server
    mod.rs             entry point, coord.toml / env config
    udp_handler.rs     UDP protocol, peer map, broadcasts
    api.rs             HTTP API (registration, admin, node fallback, updates)
    db.rs              PostgreSQL layer (schema created by setup_tables)
    config_generator.rs  node config.toml generation
    ip_allocator.rs, port_allocator.rs, key_manager.rs
    caddy.rs           Caddy reverse-proxy config for per-node port ranges
    scanner.rs         periodic TCP port scan of nodes (admin UI)
    admin_html.rs      admin web UI (/admin)
    update_store.rs    update binaries on disk
mldeploy/src/main.rs
systemd/             unit files (see GUIDE.md)
install.sh           installer for peer or coordination server
roadmap/             phased plan: security rewrite, scope split, usability
```

## Quick start

See [GUIDE.md](GUIDE.md) for full instructions.

```bash
cargo build --release

# Coordination server (public VPS, PostgreSQL running)
sudo ./install.sh coord
#   then write /etc/meshlink/coord.toml (GUIDE.md §1) — external_address is required
meshlink cs --config /etc/meshlink/coord.toml db-setup
sudo systemctl start meshlink-coord
meshlink cs --config /etc/meshlink/coord.toml create-invite --multi-use --max-uses 10

# Each node
sudo ./install.sh peer
sudo meshlink up --server https://coord.example.com --invite <code> --name my-laptop
```

## Tasks inside the node daemon

Channels connect the packet pipeline; state is shared through `SharedState`.

1. `tun_reader` — TUN → outbound router
2. `outbound_router` — route lookup, wrap, → UDP writer
3. `udp_writer` — sends datagrams
4. `udp_reader` — receives datagrams; data → inbound router, coordinator replies → discovery
5. `inbound_router` — attribute to a peer, check `allowed_ips`, → TUN writer
6. `tun_writer` — writes to TUN
7. `discovery` — registration, keepalive, peer lists, hole punching, HTTP fallback
8. `cli_listener` — unix socket for `meshlink status` / `peers`
9. `peer_api` — optional HTTP(S) API

```
Outbound: TUN read → route lookup → wrap → UDP send
Inbound:  UDP recv → unwrap → attribute + allowed_ips check → TUN write
```

## Node config format

Written by `meshlink up --invite …`; editable by hand.

```toml
[node]
private_key = "base64_encoded_key"   # absent if registered with --public-key; add your own
listen_port = 51820
virtual_ip = "10.0.0.1/24"
tun_name = "meshlink0"

[coordination]
server = "coord.example.com:4000"     # UDP address
api_url = "https://coord.example.com" # HTTPS fallback (optional)
auth_token = "..."                    # credentials.json takes precedence

[[peers]]                             # rewritten automatically by discovery
public_key = "base64_encoded_key"
allowed_ips = ["10.0.0.2/32"]
endpoint = "1.2.3.4:51820"

[[peers]]                             # kept across rewrites
public_key = "base64_encoded_key"
allowed_ips = ["10.0.0.50/32"]
endpoint = "203.0.113.7:51820"
static = true
```

## Wire protocol

Node ↔ node:

| Type | Name | Payload |
|------|------|---------|
| `0x04` | DATA | raw IPv4 packet (plaintext) |
| `0x20` | HOLE_PUNCH | `[pub_key:32]` |

Node ↔ coordination server (UDP):

| Type | Name | Payload |
|------|------|---------|
| `0x10` | NAT_DETECT_REQ | (empty) |
| `0x11` | NAT_DETECT_RESP | `[addr_type:1][ip:4\|16][port:2]` |
| `0x30` | REGISTER | `[pub_key:32][listen_port:2][lan_count:1][lan_ip:4]*[caps:1]` |
| `0x31` | PEER_LIST_REQ | `[pub_key:32]` |
| `0x32` | PEER_LIST_RESP | `[count:2](entry)*` |
| `0x33` | KEEPALIVE | `[pub_key:32][lan_count:1][lan_ip:4]*[caps:1]` |
| `0x34` | PEER_LIST_CHUNK | `[list_id:2][idx:1][total:1][count:2](entry)*` |

`entry` = `[pub_key:32][vip:4][addr_type:1][ip:4|16][port:2][lan_ip:4][lan_port:2]`.

The LAN list and `caps` byte are optional trailing fields. `caps & 0x01`
means the node understands `0x34`; such nodes get peer lists split into
chunks of at most 1400 bytes, others get a single `0x32`. The server also
sends unsolicited peer lists when nodes join, go stale, or are disabled.
Nodes accept `0x11`/`0x32`/`0x34` only from the coordinator's address, and the
server answers `0x31` only for a key registered from the requesting address.

## Requirements

- Linux (TUN needs `CAP_NET_ADMIN` or root)
- PostgreSQL for the coordination server
- Rust toolchain to build

## License

No license file has been added yet.
