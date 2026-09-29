#!/usr/bin/env bash
#
# install.sh — Install meshlink (peer node or coordination server).
#
# Builds the binary, sets capabilities, creates system user/group/dirs,
# installs the systemd service, and enables it.  Does NOT start the service
# or prompt for configuration values — follow the printed next-steps after
# the script completes.
#
# Usage:
#   sudo ./install.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_BINARY="$SCRIPT_DIR/target/release/meshlink"
INSTALL_PATH="/usr/local/bin/meshlink"
GROUP_NAME="meshlink"
CONFIG_DIR="/etc/meshlink"
STATE_DIR="/var/lib/meshlink"
RUNTIME_DIR="/run/meshlink"
LOG_FILE="/var/log/meshlink.log"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()  { echo -e "${CYAN}[install]${NC} $*"; }
ok()   { echo -e "${GREEN}  ok${NC}  $*"; }
warn() { echo -e "${YELLOW}  warn${NC} $*"; }
fail() { echo -e "${RED}  fail${NC} $*"; exit 1; }

# ── Root check ────────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && fail "must be run as root:  sudo $0"

REAL_USER="${SUDO_USER:-}"

# ── Mode selection ────────────────────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  MeshLink installer"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  1) peer  — node that joins the mesh"
echo "  2) coord — coordination server"
echo ""
MODE_INPUT="${1:-${INSTALL_MODE:-}}"
if [[ -z "$MODE_INPUT" ]]; then
    read -rp "  Install as [peer/coord]: " MODE_INPUT
fi
echo ""

case "${MODE_INPUT,,}" in
    1|p|peer)   MODE=peer  ;;
    2|c|coord)  MODE=coord ;;
    *) fail "invalid choice: '$MODE_INPUT' — enter peer or coord" ;;
esac

log "installing meshlink as: $MODE"

# ── 1. Build binary ───────────────────────────────────────────────────────────
if [[ ! -f "$SRC_BINARY" ]]; then
    log "building meshlink (release)..."
    if [[ -n "$REAL_USER" ]]; then
        sudo -u "$REAL_USER" cargo build \
            --manifest-path "$SCRIPT_DIR/meshlink/Cargo.toml" \
            --release 2>&1 | tail -5
    else
        cargo build \
            --manifest-path "$SCRIPT_DIR/meshlink/Cargo.toml" \
            --release 2>&1 | tail -5
    fi
fi
[[ -f "$SRC_BINARY" ]] || fail "binary not found at $SRC_BINARY — build failed"

# ── 2. Install binary ─────────────────────────────────────────────────────────
log "installing binary..."
cp "$SRC_BINARY" "$INSTALL_PATH"
chmod 755 "$INSTALL_PATH"
ok "$INSTALL_PATH"

# ── 3. Set capabilities ───────────────────────────────────────────────────────
log "setting capabilities..."
command -v setcap &>/dev/null || fail "setcap not found — apt install libcap2-bin"
setcap 'cap_net_admin,cap_net_raw,cap_net_bind_service=eip' "$INSTALL_PATH"
getcap "$INSTALL_PATH" | grep -q cap_net_admin || fail "capability verification failed"
ok "cap_net_admin cap_net_raw cap_net_bind_service"

# ── 4. System group ───────────────────────────────────────────────────────────
log "ensuring system group '$GROUP_NAME'..."
if ! getent group "$GROUP_NAME" &>/dev/null; then
    groupadd --system "$GROUP_NAME"
    ok "created group $GROUP_NAME"
else
    ok "group $GROUP_NAME exists"
fi

# ── 5. Directories ────────────────────────────────────────────────────────────
log "creating directories..."
install -d -m 2775 -o root -g "$GROUP_NAME" "$CONFIG_DIR"
install -d -m 0750 -o root -g "$GROUP_NAME" "$STATE_DIR"
install -d -m 0750 -o root -g "$GROUP_NAME" "$STATE_DIR/updates"
install -d -m 0755 -o root -g "$GROUP_NAME" "$RUNTIME_DIR"
touch "$LOG_FILE"
chown "root:$GROUP_NAME" "$LOG_FILE"
chmod 0664 "$LOG_FILE"
ok "directories ready"

# ── 6. tmpfiles.d ─────────────────────────────────────────────────────────────
log "writing /etc/tmpfiles.d/meshlink.conf..."
cat > /etc/tmpfiles.d/meshlink.conf <<'EOF'
# meshlink runtime paths — recreated each boot
d  /var/lib/meshlink          0750  root  meshlink  -
d  /var/lib/meshlink/updates  0750  root  meshlink  -
d  /run/meshlink              0755  root  meshlink  -
f  /run/meshlink/meshlink.pid 0660  root  meshlink  -
EOF
systemd-tmpfiles --create /etc/tmpfiles.d/meshlink.conf
ok "/etc/tmpfiles.d/meshlink.conf"

# ── 7. TUN module ─────────────────────────────────────────────────────────────
log "ensuring tun kernel module..."
echo "tun" > /etc/modules-load.d/tun.conf
if ! lsmod | grep -q '^tun '; then
    modprobe tun && ok "tun module loaded" || warn "modprobe tun failed (may be built-in)"
else
    ok "tun module already loaded"
fi

# ═════════════════════════════════════════════════════════════════════════════
# COORD branch
# ═════════════════════════════════════════════════════════════════════════════
if [[ "$MODE" == coord ]]; then

    # System user (coord server runs as meshlink:meshlink)
    log "ensuring system user 'meshlink'..."
    if ! id meshlink &>/dev/null; then
        useradd --system --no-create-home --shell /usr/sbin/nologin \
                --gid "$GROUP_NAME" meshlink
        ok "created user meshlink"
    else
        ok "user meshlink exists"
    fi

    # Service unit
    log "writing meshlink-coord.service..."
    cat > /etc/systemd/system/meshlink-coord.service <<EOF
[Unit]
Description=MeshLink Coordination Server
After=network-online.target postgresql.service
Wants=network-online.target
StartLimitIntervalSec=60s
StartLimitBurst=3

[Service]
Type=simple
User=meshlink
Group=meshlink

ExecStart=$INSTALL_PATH cs --config $CONFIG_DIR/coord.toml start

KillSignal=SIGTERM
TimeoutStopSec=15s
Restart=on-failure
RestartSec=5s

StandardOutput=journal
StandardError=journal
SyslogIdentifier=meshlink-coord

NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=$CONFIG_DIR $STATE_DIR /etc/caddy

PrivateNetwork=no

[Install]
WantedBy=multi-user.target
EOF
    ok "/etc/systemd/system/meshlink-coord.service"

    systemctl daemon-reload
    systemctl enable meshlink-coord
    ok "meshlink-coord enabled (not started)"

    # ── Summary ───────────────────────────────────────────────────────────────
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "${GREEN}coord installation complete${NC}"
    echo ""
    echo "  Next steps:"
    echo ""
    echo "  1. Write $CONFIG_DIR/coord.toml"
    echo "     (see docs — set [server] external_address, [database] url, [admin] token, etc.)"
    echo ""
    echo "  2. Set up the database:"
    echo "       $INSTALL_PATH cs --config $CONFIG_DIR/coord.toml db-setup"
    echo ""
    echo "  3. Start the service:"
    echo "       systemctl start meshlink-coord"
    echo ""
    echo "  4. Create an invite for peers:"
    echo "       $INSTALL_PATH cs --config $CONFIG_DIR/coord.toml create-invite"
    echo ""
    echo "  Logs:  journalctl -u meshlink-coord -f"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# ═════════════════════════════════════════════════════════════════════════════
# PEER branch
# ═════════════════════════════════════════════════════════════════════════════
else

    # Add calling user to meshlink group
    if [[ -n "$REAL_USER" ]]; then
        log "adding '$REAL_USER' to group '$GROUP_NAME'..."
        usermod -aG "$GROUP_NAME" "$REAL_USER"
        ok "$REAL_USER -> $GROUP_NAME"
    fi

    # Service unit
    log "writing meshlink-peer.service..."
    cat > /etc/systemd/system/meshlink-peer.service <<EOF
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

ExecStartPre=-/sbin/ip link delete meshlink0
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
    ok "/etc/systemd/system/meshlink-peer.service"

    systemctl daemon-reload
    systemctl enable meshlink-peer
    ok "meshlink-peer enabled (not started)"

    # ── Summary ───────────────────────────────────────────────────────────────
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "${GREEN}peer installation complete${NC}"
    echo ""
    echo "  Next steps:"
    echo ""
    echo "  1. Register with the coordination server:"
    echo "       sudo $INSTALL_PATH up \\"
    echo "         --server https://<coord-domain> \\"
    echo "         --invite <token>"
    echo ""
    echo "  2. Start the service:"
    echo "       systemctl start meshlink-peer"
    echo ""
    if [[ -n "$REAL_USER" ]]; then
        echo "  Note: log out and back in for the group change to take effect,"
        echo "        then you can run meshlink without sudo."
        echo ""
    fi
    echo "  Logs:  journalctl -u meshlink-peer -f"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

fi
