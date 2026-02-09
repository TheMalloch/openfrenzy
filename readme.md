# OpenFrenzy Project Context

## What is OpenFrenzy?
A peer-to-peer LAN mesh networking tool written in Rust. It creates encrypted UDP tunnels between machines, making them appear on the same virtual LAN (e.g. `10.0.0.0/24`) regardless of their physical network location.

## Architecture
- **Topology:** Full mesh — every node connects directly to every other node
- **NAT traversal:** UDP hole punching via a coordination server, relay planned for later
- **Discovery:** Centralized coordination server where peers register and discover each other
- **Transport:** UDP with ChaCha20-Poly1305 encryption, X25519 key exchange

## Project Structure
Two binaries in a workspace:

### `OpenFrenzy/` — Node daemon (runs on each machine)
- `src/main.rs` — entry point, tokio runtime, spawns async tasks
- `src/config.rs` — TOML config parsing into typed structs
- `src/state.rs` — shared runtime state: peer table, route table, stats (no mutex on hot path, use channels)
- `src/tun/mod.rs` — TUN virtual interface creation, async read/write
- `src/net/udp.rs` — UDP socket async reader/writer tasks
- `src/net/hole_punch.rs` — NAT traversal: STUN-like endpoint discovery + simultaneous open
- `src/crypto/handshake.rs` — X25519 Diffie-Hellman key exchange per peer session
- `src/crypto/transport.rs` — ChaCha20-Poly1305 per-packet encrypt/decrypt with nonce counter
- `src/router/mod.rs` — route table mapping virtual IPs to peer endpoints, packet forwarding
- `src/discovery/mod.rs` — coordination server client: registration, peer list fetch, keepalive
- `src/cli/mod.rs` — clap CLI commands + unix socket for runtime control

### `coord-server/` — Coordination server (single public VPS)
- `src/main.rs` — lightweight UDP/TCP server holding `{public_key → endpoint}` mappings, STUN-like NAT detection

## Async Task Model (tokio)
Six concurrent tasks communicating via `tokio::mpsc` channels:
1. `tun_reader` — reads packets from TUN device, feeds outbound pipeline
2. `tun_writer` — receives decrypted inbound packets, writes to TUN
3. `udp_reader` — reads from UDP socket, feeds inbound pipeline
4. `udp_writer` — receives encrypted packets, sends to wire
5. `discovery` — periodic peer discovery and keepalive with coord server
6. `cli_listener` — unix socket accepting runtime commands

## Packet Pipeline
```
Outbound: TUN read → router lookup → crypto encrypt → UDP send
Inbound:  UDP recv → crypto decrypt → router lookup → TUN write
```

## Key Crates
- `tokio` — async runtime
- `tun-tap` or `tokio-tun` — TUN device
- `x25519-dalek` — key exchange
- `chacha20poly1305` — symmetric encryption
- `serde` + `toml` — config
- `clap` — CLI
- `tracing` — structured logging

## Config Format (TOML)
```toml
[node]
private_key = "base64_encoded_key"
listen_port = 51820
virtual_ip = "10.0.0.1/24"
tun_name = "OpenFrenzy0"

[coordination]
server = "coord.example.com:4000"

[[peers]]
public_key = "base64_encoded_key"
allowed_ips = ["10.0.0.2/32"]
endpoint = "optional_static_ip:port"
```

## Design Constraints
- Zero-copy where possible on the hot path
- No shared mutex on packet pipeline — use mpsc channels between tasks
- All crypto is per-packet stateless after handshake
- NAT type detection at startup before attempting hole punch
- Graceful degradation: direct → hole punch → (future) relay

## Target Platform
- Linux (Debian 13) — TUN device requires `CAP_NET_ADMIN` or root
- Async I/O via tokio, single-threaded runtime acceptable for initial version
