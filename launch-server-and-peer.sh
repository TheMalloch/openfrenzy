#!/usr/bin/env bash
#
# launch-server-and-peer.sh — Start a coord server AND a peer on the same machine.
#
# Usage:
#   ./launch-server-and-peer.sh --invite <code>
#   ./launch-server-and-peer.sh --invite <code> --name mynode \
#       --database-url "postgres:///meshlink?user=meshlink" \
#       --http-port 4001 --udp-port 4000 --bind-address "[::]" \
#       --stale-timeout-secs 120 --log-level debug
#
# All flags are optional — defaults come from config files or built-in defaults.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BINARY="$SCRIPT_DIR/target/release/meshlink"

# ── Defaults ────────────────────────────────────────────────────────
PEER_CONFIG="/etc/meshlink/config.toml"
CS_CONFIG="/etc/meshlink/coord.toml"
FOREGROUND=false

# Peer flags
SERVER=""
INVITE=""
NAME=""
COORD_SERVER=""

# Coord server override flags
DATABASE_URL=""
MESH_CIDR=""
HTTP_PORT=""
UDP_PORT=""
BIND_ADDRESS=""
EXTERNAL_ADDRESS=""
TLS_CERT=""
TLS_KEY=""
ADMIN_TOKEN=""
STALE_TIMEOUT_SECS=""
CLEANUP_INTERVAL_SECS=""
MAX_PEERS=""
DEFAULT_LISTEN_PORT=""
DEFAULT_EXPIRY_HOURS=""
DEFAULT_MAX_USES=""
LOG_LEVEL=""

# ── Parse args ──────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        # Config file paths
        --peer-config)            PEER_CONFIG="$2";          shift 2 ;;
        --cs-config)              CS_CONFIG="$2";            shift 2 ;;
        --foreground|-f)          FOREGROUND=true;           shift ;;

        # Peer flags
        --server)                 SERVER="$2";               shift 2 ;;
        --invite)                 INVITE="$2";               shift 2 ;;
        --name)                   NAME="$2";                 shift 2 ;;
        --coord-server)           COORD_SERVER="$2";         shift 2 ;;

        # Coord server override flags
        --database-url)           DATABASE_URL="$2";         shift 2 ;;
        --mesh-cidr)              MESH_CIDR="$2";            shift 2 ;;
        --http-port)              HTTP_PORT="$2";            shift 2 ;;
        --udp-port)               UDP_PORT="$2";             shift 2 ;;
        --bind-address)           BIND_ADDRESS="$2";         shift 2 ;;
        --external-address)       EXTERNAL_ADDRESS="$2";     shift 2 ;;
        --tls-cert)               TLS_CERT="$2";             shift 2 ;;
        --tls-key)                TLS_KEY="$2";              shift 2 ;;
        --admin-token)            ADMIN_TOKEN="$2";          shift 2 ;;
        --stale-timeout-secs)     STALE_TIMEOUT_SECS="$2";  shift 2 ;;
        --cleanup-interval-secs)  CLEANUP_INTERVAL_SECS="$2"; shift 2 ;;
        --max-peers)              MAX_PEERS="$2";            shift 2 ;;
        --default-listen-port)    DEFAULT_LISTEN_PORT="$2";  shift 2 ;;
        --default-expiry-hours)   DEFAULT_EXPIRY_HOURS="$2"; shift 2 ;;
        --default-max-uses)       DEFAULT_MAX_USES="$2";     shift 2 ;;
        --log-level)              LOG_LEVEL="$2";            shift 2 ;;

        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Config paths:"
            echo "  --peer-config <path>              Peer config [default: /etc/meshlink/config.toml]"
            echo "  --cs-config <path>                Coord server config [default: /etc/meshlink/coord.toml]"
            echo "  --foreground, -f                  Run peer in foreground"
            echo ""
            echo "Peer options:"
            echo "  --server <url>                    Coord HTTP URL for registration"
            echo "  --invite <code>                   Invite code"
            echo "  --name <name>                     Node name"
            echo "  --coord-server <addr>             Override coord UDP address"
            echo ""
            echo "Coord server overrides (all optional, override config file):"
            echo "  --database-url <url>              PostgreSQL connection URL"
            echo "  --mesh-cidr <cidr>                Mesh network CIDR"
            echo "  --http-port <port>                HTTP API port"
            echo "  --udp-port <port>                 UDP coordination port"
            echo "  --bind-address <addr>             Bind address"
            echo "  --external-address <addr>         Public address for peers"
            echo "  --tls-cert <path>                 TLS certificate path"
            echo "  --tls-key <path>                  TLS key path"
            echo "  --admin-token <token>             Admin bearer token"
            echo "  --stale-timeout-secs <secs>       Stale peer timeout"
            echo "  --cleanup-interval-secs <secs>    Cleanup interval"
            echo "  --max-peers <n>                   Max peers (0=unlimited)"
            echo "  --default-listen-port <port>      Default listen port for nodes"
            echo "  --default-expiry-hours <hours>    Default invite expiry"
            echo "  --default-max-uses <n>            Default invite max uses"
            echo "  --log-level <level>               Log level"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# ── Build if needed ─────────────────────────────────────────────────
if [[ ! -x "$BINARY" ]]; then
    echo "[setup] building meshlink..."
    cargo build --manifest-path "$SCRIPT_DIR/meshlink/Cargo.toml" --release 2>&1 | tail -3
fi

# ── Need root for TUN ──────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    echo "[setup] need root for TUN device, re-running with sudo..."
    exec sudo -E -- "$0" "$@"
fi

# ── Cleanup on exit ─────────────────────────────────────────────────
CS_PID=""
cleanup() {
    echo "[setup] shutting down..."
    if [[ -n "$CS_PID" ]] && kill -0 "$CS_PID" 2>/dev/null; then
        kill "$CS_PID" 2>/dev/null || true
        wait "$CS_PID" 2>/dev/null || true
    fi
    # Peer cleans itself up via PID file / signal
}
trap cleanup EXIT

# ── 1. Start coord server ──────────────────────────────────────────
CS_CMD=("$BINARY" cs -c "$CS_CONFIG" start)

[[ -n "$DATABASE_URL" ]]         && CS_CMD+=(--database-url "$DATABASE_URL")
[[ -n "$MESH_CIDR" ]]           && CS_CMD+=(--mesh-cidr "$MESH_CIDR")
[[ -n "$HTTP_PORT" ]]           && CS_CMD+=(--http-port "$HTTP_PORT")
[[ -n "$UDP_PORT" ]]            && CS_CMD+=(--udp-port "$UDP_PORT")
[[ -n "$BIND_ADDRESS" ]]        && CS_CMD+=(--bind-address "$BIND_ADDRESS")
[[ -n "$EXTERNAL_ADDRESS" ]]    && CS_CMD+=(--external-address "$EXTERNAL_ADDRESS")
[[ -n "$TLS_CERT" ]]            && CS_CMD+=(--tls-cert "$TLS_CERT")
[[ -n "$TLS_KEY" ]]             && CS_CMD+=(--tls-key "$TLS_KEY")
[[ -n "$ADMIN_TOKEN" ]]         && CS_CMD+=(--admin-token "$ADMIN_TOKEN")
[[ -n "$STALE_TIMEOUT_SECS" ]]  && CS_CMD+=(--stale-timeout-secs "$STALE_TIMEOUT_SECS")
[[ -n "$CLEANUP_INTERVAL_SECS" ]] && CS_CMD+=(--cleanup-interval-secs "$CLEANUP_INTERVAL_SECS")
[[ -n "$MAX_PEERS" ]]           && CS_CMD+=(--max-peers "$MAX_PEERS")
[[ -n "$DEFAULT_LISTEN_PORT" ]] && CS_CMD+=(--default-listen-port "$DEFAULT_LISTEN_PORT")
[[ -n "$DEFAULT_EXPIRY_HOURS" ]] && CS_CMD+=(--default-expiry-hours "$DEFAULT_EXPIRY_HOURS")
[[ -n "$DEFAULT_MAX_USES" ]]    && CS_CMD+=(--default-max-uses "$DEFAULT_MAX_USES")
[[ -n "$LOG_LEVEL" ]]           && CS_CMD+=(--log-level "$LOG_LEVEL")

echo "[setup] starting coord server: ${CS_CMD[*]}"
"${CS_CMD[@]}" &
CS_PID=$!

# Give the server a moment to bind ports
sleep 2

if ! kill -0 "$CS_PID" 2>/dev/null; then
    echo "[FAIL] coord server died on startup"
    exit 1
fi
echo "[setup] coord server running (PID $CS_PID)"

# ── 2. Start peer ──────────────────────────────────────────────────
PEER_CMD=("$BINARY" -c "$PEER_CONFIG" up)

[[ -n "$SERVER" ]]       && PEER_CMD+=(--server "$SERVER")
[[ -n "$INVITE" ]]       && PEER_CMD+=(--invite "$INVITE")
[[ -n "$NAME" ]]         && PEER_CMD+=(--name "$NAME")
[[ -n "$COORD_SERVER" ]] && PEER_CMD+=(--coord-server "$COORD_SERVER")
$FOREGROUND              && PEER_CMD+=(--foreground)

echo "[setup] starting peer: ${PEER_CMD[*]}"
"${PEER_CMD[@]}" &
PEER_PID=$!

echo "[setup] peer running (PID $PEER_PID)"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Coord server PID: $CS_PID"
echo "  Peer daemon PID:  $PEER_PID"
echo "  Press Ctrl+C to stop both"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Wait for either process to exit
wait -n "$CS_PID" "$PEER_PID" 2>/dev/null || true
