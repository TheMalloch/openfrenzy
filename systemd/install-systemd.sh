#!/usr/bin/env bash
# install-systemd.sh — Install all meshlink systemd units and configuration.
#
# Run as root after install.sh has already been executed:
#   sudo ./systemd/install-systemd.sh
#
# What it installs:
#   /etc/systemd/system/meshlink-coord.service
#   /etc/systemd/system/meshlink-peer.service
#   /etc/systemd/system/mldeploy-autoupdate.service
#   /etc/tmpfiles.d/meshlink.conf
#   /etc/modules-load.d/tun.conf
#   /etc/meshlink/coord.env          (template, only if missing)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${CYAN}[systemd]${NC} $*"; }
ok()   { echo -e "${GREEN}  ok${NC}  $*"; }
warn() { echo -e "${YELLOW}  warn${NC} $*"; }
fail() { echo -e "${RED}  fail${NC} $*"; exit 1; }

[[ $EUID -ne 0 ]] && fail "must be run as root (sudo $0)"

# ── Service units ────────────────────────────────────────────────────────────

for unit in meshlink-coord.service meshlink-peer.service mldeploy-autoupdate.service; do
    src="$SCRIPT_DIR/$unit"
    dest="/etc/systemd/system/$unit"
    log "installing $unit"
    install -m 644 "$src" "$dest"
    ok "$dest"
done

# ── tmpfiles.d ───────────────────────────────────────────────────────────────

log "installing tmpfiles.d/meshlink.conf"
install -m 644 "$SCRIPT_DIR/tmpfiles.d/meshlink.conf" /etc/tmpfiles.d/meshlink.conf
ok "/etc/tmpfiles.d/meshlink.conf"

# Apply immediately (creates /var/lib/meshlink, /run/meshlink, etc.)
systemd-tmpfiles --create /etc/tmpfiles.d/meshlink.conf
ok "runtime directories created"

# ── modules-load.d ───────────────────────────────────────────────────────────

log "installing modules-load.d/tun.conf"
install -m 644 "$SCRIPT_DIR/modules-load.d/tun.conf" /etc/modules-load.d/tun.conf
ok "/etc/modules-load.d/tun.conf"

# Load tun immediately if not already present
if ! lsmod | grep -q '^tun '; then
    modprobe tun && ok "tun module loaded" || warn "modprobe tun failed — may already be built-in"
else
    ok "tun module already loaded"
fi

# ── coord.env template ───────────────────────────────────────────────────────

ENV_FILE="/etc/meshlink/coord.env"
if [[ ! -f "$ENV_FILE" ]]; then
    log "creating coord.env template at $ENV_FILE"
    mkdir -p /etc/meshlink
    cat > "$ENV_FILE" <<'EOF'
# MeshLink coordination server environment — fill in before starting the service.
DATABASE_URL=postgres:///meshlink?user=meshlink
ADMIN_TOKEN=change-me
MESH_NETWORK=10.0.0.0/24
HTTP_PORT=4001
UDP_PORT=4000
EXTERNAL_ADDRESS=your.server.com
UPDATES_DIR=/var/lib/meshlink/updates
# CADDY_EXTERNAL_DOMAIN=your.server.com
EOF
    chown root:meshlink "$ENV_FILE"
    chmod 640 "$ENV_FILE"
    ok "$ENV_FILE (template written — edit before starting meshlink-coord)"
else
    ok "$ENV_FILE already exists, skipping"
fi

# ── Reload systemd ───────────────────────────────────────────────────────────

log "reloading systemd daemon"
systemctl daemon-reload
ok "daemon reloaded"

# ── Summary ──────────────────────────────────────────────────────────────────

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${GREEN}systemd units installed${NC}"
echo ""
echo "  On the coordination server:"
echo "    1. Edit /etc/meshlink/coord.env"
echo "    2. systemctl enable --now meshlink-coord"
echo ""
echo "  On each peer (after meshlink up --invite <code>):"
echo "    systemctl enable --now meshlink-peer"
echo "    systemctl enable --now mldeploy-autoupdate   # optional"
echo ""
echo "  Logs:"
echo "    journalctl -u meshlink-coord -f"
echo "    journalctl -u meshlink-peer -f"
echo "    journalctl -u mldeploy-autoupdate -f"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
