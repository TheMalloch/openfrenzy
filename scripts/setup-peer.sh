#!/usr/bin/env bash
# setup-peer.sh — Clean install / reset for the meshlink peer node.
#
# Wipes all previous state (config, credentials, service) and prepares
# the system.  After this runs, register the node with:
#   sudo meshlink up --server https://<coord-domain> --invite <TOKEN>
#
# Usage:  sudo ./scripts/setup-peer.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ── Colors ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()  { echo -e "${CYAN}[peer-setup]${NC} $*"; }
ok()   { echo -e "${GREEN}  ok${NC}  $*"; }
warn() { echo -e "${YELLOW}  warn${NC} $*"; }
fail() { echo -e "${RED}  fail${NC} $*"; exit 1; }

# ── Root check ────────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && fail "must be run as root (sudo $0)"

REAL_USER="${SUDO_USER:-}"

# ── Constants ─────────────────────────────────────────────────────────────────
GROUP_NAME="meshlink"
INSTALL_PATH="/usr/local/bin/meshlink"
CONFIG_DIR="/etc/meshlink"
CONFIG_FILE="$CONFIG_DIR/config.toml"
CREDS_FILE="$CONFIG_DIR/credentials.json"
RUNTIME_DIR="/run/meshlink"
LOG_FILE="/var/log/meshlink.log"
TUN_DEVICE="meshlink0"
SERVICE_NAME="meshlink-peer"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
TMPFILES_FILE="/etc/tmpfiles.d/meshlink.conf"
MODULES_FILE="/etc/modules-load.d/tun.conf"

# ── 1. Stop existing service ──────────────────────────────────────────────────
log "stopping $SERVICE_NAME (if running)..."
if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
    systemctl stop "$SERVICE_NAME"
    ok "service stopped"
else
    ok "service was not running"
fi
if systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
    systemctl disable "$SERVICE_NAME"
    ok "service disabled"
fi

# ── 2. Purge previous state ───────────────────────────────────────────────────
log "purging previous configuration..."
rm -f "$CONFIG_FILE"                 && ok "removed $CONFIG_FILE"
rm -f "$CREDS_FILE"                  && ok "removed $CREDS_FILE"
rm -f "$LOG_FILE"                    2>/dev/null; true
rm -f "$RUNTIME_DIR/meshlink.pid"    2>/dev/null; true
rm -f "$RUNTIME_DIR/meshlink.sock"   2>/dev/null; true

# Tear down TUN device if it exists
if ip link show "$TUN_DEVICE" &>/dev/null; then
    log "removing TUN device $TUN_DEVICE..."
    ip link set "$TUN_DEVICE" down 2>/dev/null || true
    ip link delete "$TUN_DEVICE"   2>/dev/null || true
    ok "TUN device $TUN_DEVICE removed"
fi

# ── 3. Build binary ───────────────────────────────────────────────────────────
MESHLINK_SRC="$REPO_ROOT/meshlink"
SRC_BINARY="$REPO_ROOT/target/release/meshlink"

if [[ -d "$MESHLINK_SRC" ]]; then
    log "building meshlink (release)..."
    if [[ -n "$REAL_USER" ]]; then
        sudo -u "$REAL_USER" cargo build \
            --manifest-path "$MESHLINK_SRC/Cargo.toml" \
            --release 2>&1 | tail -5
    else
        cargo build \
            --manifest-path "$MESHLINK_SRC/Cargo.toml" \
            --release 2>&1 | tail -5
    fi
    ok "build complete"
else
    warn "source not found at $MESHLINK_SRC — skipping build"
fi

if [[ ! -f "$SRC_BINARY" ]]; then
    fail "binary not found at $SRC_BINARY — build failed or no source available"
fi

# ── 4. Install binary ─────────────────────────────────────────────────────────
log "installing binary to $INSTALL_PATH..."
cp "$SRC_BINARY" "$INSTALL_PATH"
chmod 755 "$INSTALL_PATH"
ok "installed to $INSTALL_PATH"

# ── 5. Set capabilities ───────────────────────────────────────────────────────
# CAP_NET_ADMIN  — create/configure TUN devices
# CAP_NET_RAW    — raw socket access
log "setting Linux capabilities on $INSTALL_PATH..."
if ! command -v setcap &>/dev/null; then
    fail "setcap not found — install libcap2-bin:  apt install libcap2-bin"
fi
setcap 'cap_net_admin,cap_net_raw,cap_net_bind_service=eip' "$INSTALL_PATH"
if getcap "$INSTALL_PATH" | grep -q cap_net_admin; then
    ok "capabilities set"
else
    fail "capability verification failed"
fi

# ── 6. Create system group ────────────────────────────────────────────────────
log "ensuring system group '$GROUP_NAME'..."
if ! getent group "$GROUP_NAME" &>/dev/null; then
    groupadd --system "$GROUP_NAME"
    ok "created group $GROUP_NAME"
else
    ok "group $GROUP_NAME exists"
fi

# ── 7. Create directories ─────────────────────────────────────────────────────
log "creating directories..."
install -d -m 2775 -o root -g "$GROUP_NAME" "$CONFIG_DIR"
install -d -m 0755 -o root -g "$GROUP_NAME" "$RUNTIME_DIR"
touch "$LOG_FILE"
chown "root:$GROUP_NAME" "$LOG_FILE"
chmod 0664 "$LOG_FILE"
ok "directories ready"

# ── 8. Write tmpfiles.d ───────────────────────────────────────────────────────
log "writing $TMPFILES_FILE..."
cat > "$TMPFILES_FILE" <<'EOF'
# meshlink — runtime and state paths
d  /var/lib/meshlink          0750  root  meshlink  -
d  /var/lib/meshlink/updates  0750  root  meshlink  -
d  /run/meshlink              0755  root  meshlink  -
f  /run/meshlink/meshlink.pid 0660  root  meshlink  -
EOF
systemd-tmpfiles --create "$TMPFILES_FILE"
ok "tmpfiles applied"

# ── 9. Ensure TUN module loads at boot ────────────────────────────────────────
log "writing $MODULES_FILE..."
echo "tun" > "$MODULES_FILE"
if ! lsmod | grep -q '^tun '; then
    modprobe tun && ok "tun module loaded" || warn "modprobe tun failed — may be built-in"
else
    ok "tun module already loaded"
fi

# ── 10. Write systemd service unit ───────────────────────────────────────────
log "writing $SERVICE_FILE..."
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=MeshLink Peer Node
After=network-online.target systemd-modules-load.service
Wants=network-online.target
StartLimitIntervalSec=120s
StartLimitBurst=5

[Service]
Type=simple
User=$GROUP_NAME
Group=$GROUP_NAME

ExecStart=$INSTALL_PATH up --foreground

KillSignal=SIGTERM
TimeoutStopSec=15s

Restart=on-failure
RestartSec=10s

RuntimeDirectory=meshlink
RuntimeDirectoryMode=0750

StandardOutput=journal
StandardError=journal
SyslogIdentifier=meshlink-peer

AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW

NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=$CONFIG_DIR /var/run

DeviceAllow=/dev/net/tun rw
DevicePolicy=closed

PrivateNetwork=no

[Install]
WantedBy=multi-user.target
EOF
ok "$SERVICE_FILE written"

# ── 11. Add user to group ─────────────────────────────────────────────────────
if [[ -n "$REAL_USER" ]]; then
    log "adding '$REAL_USER' to group '$GROUP_NAME'..."
    usermod -aG "$GROUP_NAME" "$REAL_USER"
    ok "$REAL_USER added to $GROUP_NAME"
fi

# ── 12. Reload systemd (enable but do NOT start — needs registration first) ──
log "reloading systemd daemon..."
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
ok "service enabled (not started — register first)"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${GREEN}peer node ready for registration${NC}"
echo ""
echo "  Binary:  $INSTALL_PATH"
echo "  Config:  $CONFIG_DIR/"
if [[ -n "$REAL_USER" ]]; then
    echo "  User:    $REAL_USER -> group $GROUP_NAME"
    echo "           (log out and back in for group change to take effect)"
fi
echo ""
echo "  Register and connect:"
echo "    sudo meshlink up \\"
echo "      --server https://<coord-domain> \\"
echo "      --invite <token>"
echo ""
echo "  Then start the background service:"
echo "    sudo systemctl start $SERVICE_NAME"
echo ""
echo "  Logs:  journalctl -u $SERVICE_NAME -f"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
