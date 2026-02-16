#!/usr/bin/env bash
#
# test-mesh-ping.sh — Spin up 3 meshlink nodes on localhost and ping between them.
#
# Usage:
#   ./test-mesh-ping.sh          # builds as current user, re-execs itself as root
#   sudo ./test-mesh-ping.sh     # if already root, builds + runs directly
#
# What it does:
#   1. Builds meshlink (as the invoking user, so cargo is in PATH)
#   2. Re-execs as root if needed (for TUN devices)
#   3. Generates 3 keypairs
#   4. Creates config files with pre-set endpoints (no coord server needed)
#   5. Starts 3 meshlink daemons
#   6. Pings between all pairs
#   7. Cleans up on exit
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BINARY="$SCRIPT_DIR/target/release/meshlink"

# ── Step 1: Build as regular user, then re-exec as root ───────────────
if [[ $EUID -ne 0 ]]; then
    echo "[mesh-test] building meshlink (as $(whoami))..."
    cargo build --manifest-path "$SCRIPT_DIR/meshlink/Cargo.toml" --release 2>&1 | tail -3

    if [[ ! -x "$BINARY" ]]; then
        echo "[FAIL] binary not found at $BINARY"
        exit 1
    fi
    echo "[mesh-test] build done, re-running as root..."
    exec sudo -E -- "$0" "$@"
fi

# ── From here on we are root ─────────────────────────────────────────

# ── Settings ──────────────────────────────────────────────────────────
NUM_NODES=3
MESH_SUBNET="10.99.0"        # nodes get .1, .2, .3 etc.
BASE_PORT=41820               # UDP listen ports: 41820, 41821, 41822
PING_COUNT=3
PING_TIMEOUT=5
WORK_DIR=$(mktemp -d /tmp/meshlink-test.XXXXXX)
PIDS=()

# ── Colors ────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${CYAN}[mesh-test]${NC} $*"; }
ok()   { echo -e "${GREEN}[  OK  ]${NC} $*"; }
fail() { echo -e "${RED}[ FAIL ]${NC} $*"; }
warn() { echo -e "${YELLOW}[ WARN ]${NC} $*"; }

# ── Cleanup ───────────────────────────────────────────────────────────
cleanup() {
    log "cleaning up..."

    # Kill all meshlink daemons
    for pid in "${PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done

    # Remove socket file
    rm -f /var/run/meshlink.sock

    # Remove work dir
    rm -rf "$WORK_DIR"

    log "done."
}
trap cleanup EXIT

# ── Verify binary ────────────────────────────────────────────────────
if [[ ! -x "$BINARY" ]]; then
    fail "binary not found at $BINARY — was the build skipped?"
    exit 1
fi
ok "using $BINARY"

# ── Generate keypairs ─────────────────────────────────────────────────
log "generating $NUM_NODES keypairs..."

declare -a PRIV_KEYS
declare -a PUB_KEYS

for i in $(seq 1 "$NUM_NODES"); do
    output=$("$BINARY" genkey)
    priv=$(echo "$output" | grep "Private" | awk '{print $3}')
    pub=$(echo "$output"  | grep "Public"  | awk '{print $3}')
    PRIV_KEYS[$i]="$priv"
    PUB_KEYS[$i]="$pub"
    log "  node $i: vip=${MESH_SUBNET}.${i}  port=$((BASE_PORT + i - 1))  pub=${pub:0:12}..."
done

# ── Write config files ────────────────────────────────────────────────
log "writing configs to $WORK_DIR ..."

for i in $(seq 1 "$NUM_NODES"); do
    conf="$WORK_DIR/node${i}.toml"
    port=$((BASE_PORT + i - 1))

    cat > "$conf" <<TOML
[node]
private_key = "${PRIV_KEYS[$i]}"
listen_port = ${port}
virtual_ip = "${MESH_SUBNET}.${i}/24"
tun_name = "mlt${i}"

[coordination]
server = "127.0.0.1:19999"
TOML

    # Add every other node as a peer with a localhost endpoint
    for j in $(seq 1 "$NUM_NODES"); do
        if [[ $j -eq $i ]]; then
            continue
        fi
        peer_port=$((BASE_PORT + j - 1))
        cat >> "$conf" <<TOML

[[peers]]
public_key = "${PUB_KEYS[$j]}"
allowed_ips = ["${MESH_SUBNET}.${j}/32"]
endpoint = "127.0.0.1:${peer_port}"
TOML
    done

    ok "  $conf"
done

# ── Start nodes ───────────────────────────────────────────────────────
log "starting $NUM_NODES meshlink daemons..."

for i in $(seq 1 "$NUM_NODES"); do
    conf="$WORK_DIR/node${i}.toml"
    logfile="$WORK_DIR/node${i}.log"

    "$BINARY" -c "$conf" 2>"$logfile" &
    pid=$!
    PIDS+=("$pid")
    ok "  node $i  pid=$pid  log=$logfile"
done

# Wait for TUN devices to come up
log "waiting for TUN devices..."
for attempt in $(seq 1 20); do
    all_up=true
    for i in $(seq 1 "$NUM_NODES"); do
        if ! ip link show "mlt${i}" &>/dev/null; then
            all_up=false
            break
        fi
    done
    if $all_up; then
        break
    fi
    sleep 0.5
done

# Verify TUN devices
for i in $(seq 1 "$NUM_NODES"); do
    if ip link show "mlt${i}" &>/dev/null; then
        ok "  mlt${i} is up"
    else
        fail "  mlt${i} did not come up"
        warn "  node $i log:"
        head -20 "$WORK_DIR/node${i}.log"
        exit 1
    fi
done

# Small extra delay for routing to settle
sleep 1

# ── Ping tests ────────────────────────────────────────────────────────
log "running ping tests ($PING_COUNT pings each, ${PING_TIMEOUT}s timeout)..."
echo ""

total=0
passed=0

for src in $(seq 1 "$NUM_NODES"); do
    for dst in $(seq 1 "$NUM_NODES"); do
        if [[ $src -eq $dst ]]; then
            continue
        fi

        total=$((total + 1))
        src_ip="${MESH_SUBNET}.${src}"
        dst_ip="${MESH_SUBNET}.${dst}"
        label="node${src} (${src_ip}) -> node${dst} (${dst_ip})"

        if ping -c "$PING_COUNT" -W "$PING_TIMEOUT" -I "${MESH_SUBNET}.${src}" "$dst_ip" &>/dev/null; then
            ok "$label"
            passed=$((passed + 1))
        else
            fail "$label"
        fi
    done
done

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if [[ $passed -eq $total ]]; then
    ok "All $total ping tests passed!"
else
    fail "$passed / $total ping tests passed"
fi
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# ── Dump stats ────────────────────────────────────────────────────────
log "node logs are in $WORK_DIR/node*.log"

for i in $(seq 1 "$NUM_NODES"); do
    echo ""
    log "--- node $i (mlt${i}) ---"
    ip -br addr show dev "mlt${i}" 2>/dev/null || true
done

echo ""

if [[ $passed -eq $total ]]; then
    exit 0
else
    exit 1
fi
