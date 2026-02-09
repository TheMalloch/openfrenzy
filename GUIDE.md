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

Run this on a publicly reachable VPS. It holds no keys and stores no traffic -- it only helps peers find each other.

```bash
# Default port 4000
./coord-server

# Or specify a different bind address
./coord-server 0.0.0.0:5000
```

Open the chosen UDP port in your firewall.

---

## 2. Node Setup

Repeat these steps on every machine that will join the mesh.

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
# endpoint is optional -- the coord server handles discovery
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

### Check status

From another terminal on the same machine:

```bash
sudo ./meshlink status
sudo ./meshlink peers
```

### Stop

Press Ctrl+C in the terminal running the daemon.

---

## 3. Quick Two-Node Example

### On the coordination server (public VPS)

```bash
./coord-server
```

### On Node A

```bash
# Generate keys
./meshlink genkey
# Note: Private key = AAA_PRIV, Public key = AAA_PUB
```

`/etc/meshlink/config.toml`:
```toml
[node]
private_key = "AAA_PRIV"
listen_port = 51820
virtual_ip = "10.0.0.1/24"
tun_name = "meshlink0"

[coordination]
server = "your-vps-ip:4000"

[[peers]]
public_key = "BBB_PUB"
allowed_ips = ["10.0.0.2/32"]
```

```bash
sudo ./meshlink up
```

### On Node B

```bash
./meshlink genkey
# Note: Private key = BBB_PRIV, Public key = BBB_PUB
```

`/etc/meshlink/config.toml`:
```toml
[node]
private_key = "BBB_PRIV"
listen_port = 51820
virtual_ip = "10.0.0.2/24"
tun_name = "meshlink0"

[coordination]
server = "your-vps-ip:4000"

[[peers]]
public_key = "AAA_PUB"
allowed_ips = ["10.0.0.1/32"]
```

```bash
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

---

## 4. Logging

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

## 5. Firewall

Each node needs its `listen_port` (default 51820) open for UDP:

```bash
sudo ufw allow 51820/udp
```

The coordination server needs its port (default 4000) open for UDP:

```bash
sudo ufw allow 4000/udp
```

---

## Notes

- All traffic between nodes is encrypted with ChaCha20-Poly1305 after an X25519 key exchange.
- The coordination server never sees your traffic. It only stores public keys and endpoint addresses.
- TUN device creation requires root or `CAP_NET_ADMIN`. To avoid running as root:
  ```bash
  sudo setcap cap_net_admin+ep ./meshlink
  ```
- The daemon creates a unix socket at `/var/run/meshlink.sock` for runtime control. The `status` and `peers` commands communicate through it.
