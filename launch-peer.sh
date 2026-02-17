#!/usr/bin/env bash
#
# launch-peer.sh — Register with a coord server and start a meshlink peer.
#
# Usage:
#   ./launch-peer.sh --server http://coord.example.com:4001 --invite <code>
#   ./launch-peer.sh --server http://coord.example.com:4001 --invite <code> --name mypeer
#   ./launch-peer.sh  # (after initial registration, just starts the daemon)
#
# All flags are optional overrides — defaults come from config file.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BINARY="$SCRIPT_DIR/target/release/meshlink"

# ── Defaults (override with flags) ─────────────────────────────────
CONFIG="/etc/meshlink/config.toml"
SERVER=""
INVITE=""
NAME=""
COORD_SERVER=""
FOREGROUND=false

# ── Parse args ──────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --config)         CONFIG="$2";       shift 2 ;;
        --server)         SERVER="$2";       shift 2 ;;
        --invite)         INVITE="$2";       shift 2 ;;
        --name)           NAME="$2";         shift 2 ;;
        --coord-server)   COORD_SERVER="$2"; shift 2 ;;
        --foreground|-f)  FOREGROUND=true;   shift ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --config <path>         Config file path [default: /etc/meshlink/config.toml]"
            echo "  --server <url>          Coord server HTTP URL (for --invite registration)"
            echo "  --invite <code>         Invite code for first-time registration"
            echo "  --name <name>           Node name (used with --invite)"
            echo "  --coord-server <addr>   Override coord server UDP address (e.g. coord.example.com:4000)"
            echo "  --foreground, -f        Run in foreground instead of daemonizing"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# ── Build if needed ─────────────────────────────────────────────────
if [[ ! -x "$BINARY" ]]; then
    echo "[peer] building meshlink..."
    cargo build --manifest-path "$SCRIPT_DIR/meshlink/Cargo.toml" --release 2>&1 | tail -3
fi

# ── Build the command ───────────────────────────────────────────────
CMD=("$BINARY" -c "$CONFIG" up)

[[ -n "$SERVER" ]]       && CMD+=(--server "$SERVER")
[[ -n "$INVITE" ]]       && CMD+=(--invite "$INVITE")
[[ -n "$NAME" ]]         && CMD+=(--name "$NAME")
[[ -n "$COORD_SERVER" ]] && CMD+=(--coord-server "$COORD_SERVER")
$FOREGROUND              && CMD+=(--foreground)

# ── Need root for TUN device ───────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    echo "[peer] need root for TUN device, re-running with sudo..."
    exec sudo -E -- "${CMD[@]}"
fi

echo "[peer] starting: ${CMD[*]}"
exec "${CMD[@]}"
