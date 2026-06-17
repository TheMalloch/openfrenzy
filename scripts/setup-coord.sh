#!/usr/bin/env bash
# setup-coord.sh — Clean install / reset for the meshlink coordination server.
#
# Wipes all previous state (config, database, runtime dirs) and configures fresh.
# Requires the meshlink binary already present at /usr/local/bin/meshlink.
#
# Usage:  sudo ./scripts/setup-coord.sh
#
set -euo pipefail

# ── Colors ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()  { echo -e "${CYAN}[coord-setup]${NC} $*"; }
ok()   { echo -e "${GREEN}  ok${NC}  $*"; }
warn() { echo -e "${YELLOW}  warn${NC} $*"; }
fail() { echo -e "${RED}  fail${NC} $*"; exit 1; }

# ── Root check ────────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && fail "must be run as root (sudo $0)"

COORD_BIN="/usr/local/bin/meshlink"
[[ -x "$COORD_BIN" ]] || fail "meshlink binary not found at $COORD_BIN — build and install it first"

# ── Constants ─────────────────────────────────────────────────────────────────
GROUP_NAME="meshlink"
USER_NAME="meshlink"
CONFIG_DIR="/etc/meshlink"
COORD_CONF="$CONFIG_DIR/coord.toml"
STATE_DIR="/var/lib/meshlink"
UPDATES_DIR="$STATE_DIR/updates"
RUNTIME_DIR="/run/meshlink"
SERVICE_NAME="meshlink-coord"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
TMPFILES_FILE="/etc/tmpfiles.d/meshlink.conf"

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
log "purging previous configuration and state..."
rm -f  "$COORD_CONF"             && ok "removed $COORD_CONF"
rm -rf "$UPDATES_DIR"            && ok "removed $UPDATES_DIR"
rm -f  "$RUNTIME_DIR/coord.sock" 2>/dev/null; true

# ── 3. Create system user and group ──────────────────────────────────────────
log "ensuring system user/group '$USER_NAME'..."
if ! getent group "$GROUP_NAME" &>/dev/null; then
    groupadd --system "$GROUP_NAME"
    ok "created group $GROUP_NAME"
else
    ok "group $GROUP_NAME exists"
fi
if ! id "$USER_NAME" &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin \
            --gid "$GROUP_NAME" "$USER_NAME"
    ok "created user $USER_NAME"
else
    ok "user $USER_NAME exists"
fi

# ── 4. Create directories ─────────────────────────────────────────────────────
log "creating directories..."
install -d -m 0750 -o root -g "$GROUP_NAME" "$CONFIG_DIR"
install -d -m 0750 -o root -g "$GROUP_NAME" "$STATE_DIR"
install -d -m 0750 -o root -g "$GROUP_NAME" "$UPDATES_DIR"
install -d -m 0755 -o root -g "$GROUP_NAME" "$RUNTIME_DIR"
ok "directories ready"

# ── 5. Prompt for configuration ───────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Coordination server configuration"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# External address (bare VPS IP for UDP — Cloudflare/CDN blocks UDP)
read -rp "  External address (bare VPS IP for UDP, e.g. 1.2.3.4): " EXTERNAL_ADDRESS
[[ -z "$EXTERNAL_ADDRESS" ]] && fail "external_address cannot be empty"

# Caddy external domain (HTTPS subdomain for registration + HTTP fallback)
read -rp "  Caddy external domain for HTTPS (e.g. mesh.example.com, leave blank to skip): " CADDY_DOMAIN
CADDY_DOMAIN="${CADDY_DOMAIN:-}"

# PostgreSQL database URL
DEFAULT_DB="postgres:///meshlink?user=meshlink"
read -rp "  PostgreSQL database URL [$DEFAULT_DB]: " DATABASE_URL
DATABASE_URL="${DATABASE_URL:-$DEFAULT_DB}"

# Mesh CIDR
read -rp "  Mesh CIDR [10.0.0.0/24]: " MESH_CIDR
MESH_CIDR="${MESH_CIDR:-10.0.0.0/24}"

# HTTP port
read -rp "  HTTP port [443]: " HTTP_PORT
HTTP_PORT="${HTTP_PORT:-443}"

# UDP port
read -rp "  UDP port [4000]: " UDP_PORT
UDP_PORT="${UDP_PORT:-4000}"

# Admin token
echo ""
GEN_ADMIN=$(openssl rand -hex 32)
read -rp "  Admin token (leave blank to generate): " ADMIN_TOKEN
ADMIN_TOKEN="${ADMIN_TOKEN:-$GEN_ADMIN}"
if [[ "$ADMIN_TOKEN" == "$GEN_ADMIN" ]]; then
    echo -e "  ${YELLOW}Generated admin token:${NC} $ADMIN_TOKEN"
    echo "  (save this — you will need it for admin API calls)"
fi

echo ""

# ── 6. Write coord.toml ───────────────────────────────────────────────────────
log "writing $COORD_CONF..."

CADDY_SECTION=""
if [[ -n "$CADDY_DOMAIN" ]]; then
    CADDY_SECTION="
[caddy]
config_path = \"/etc/caddy/meshlink.conf\"
admin_api   = \"http://localhost:2019\"
external_domain = \"$CADDY_DOMAIN\""
fi

cat > "$COORD_CONF" <<EOF
[database]
url = "$DATABASE_URL"

[network]
mesh_cidr = "$MESH_CIDR"

[server]
http_port        = $HTTP_PORT
udp_port         = $UDP_PORT
bind_address     = "[::]"
external_address = "$EXTERNAL_ADDRESS"

[admin]
token = "$ADMIN_TOKEN"

[peers]
stale_timeout_secs    = 120
cleanup_interval_secs = 60
default_listen_port   = 51820

[logging]
level = "info"

[updates]
dir = "$UPDATES_DIR"
$CADDY_SECTION
EOF

chown "root:$GROUP_NAME" "$COORD_CONF"
chmod 640 "$COORD_CONF"
ok "$COORD_CONF written (root:$GROUP_NAME 640)"

# ── 7. Write tmpfiles.d ───────────────────────────────────────────────────────
log "writing $TMPFILES_FILE..."
cat > "$TMPFILES_FILE" <<'EOF'
# meshlink — runtime and state paths (meshlink-coord + meshlink-peer)
d  /var/lib/meshlink          0750  root  meshlink  -
d  /var/lib/meshlink/updates  0750  root  meshlink  -
d  /run/meshlink              0755  root  meshlink  -
EOF
systemd-tmpfiles --create "$TMPFILES_FILE"
ok "tmpfiles applied"

# ── 8. Write systemd service unit ─────────────────────────────────────────────
log "writing $SERVICE_FILE..."
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=MeshLink Coordination Server
After=network-online.target postgresql.service
Wants=network-online.target
StartLimitIntervalSec=60s
StartLimitBurst=3

[Service]
Type=simple
User=$USER_NAME
Group=$GROUP_NAME

ExecStart=$COORD_BIN cs --config $COORD_CONF start

KillSignal=SIGTERM
TimeoutStopSec=15s

Restart=on-failure
RestartSec=5s

StandardOutput=journal
StandardError=journal
SyslogIdentifier=meshlink-coord

RuntimeDirectory=meshlink
RuntimeDirectoryMode=0755

NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=$CONFIG_DIR $STATE_DIR

PrivateNetwork=no

[Install]
WantedBy=multi-user.target
EOF
ok "$SERVICE_FILE written"

# ── 9. Enable and start ───────────────────────────────────────────────────────
log "reloading systemd and starting service..."
systemctl daemon-reload
systemctl enable --now "$SERVICE_NAME"
ok "service enabled and started"

sleep 1
if systemctl is-active --quiet "$SERVICE_NAME"; then
    ok "meshlink-coord is running"
else
    warn "service did not start cleanly — check: journalctl -u $SERVICE_NAME -n 30"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
HTTPS_URL=""
if [[ -n "$CADDY_DOMAIN" ]]; then
    HTTPS_URL="https://$CADDY_DOMAIN"
else
    HTTPS_URL="http://$EXTERNAL_ADDRESS:$HTTP_PORT"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${GREEN}coord server ready${NC}"
echo ""
echo "  Config:    $COORD_CONF"
echo "  HTTP API:  $HTTPS_URL"
echo "  UDP:       $EXTERNAL_ADDRESS:$UDP_PORT"
echo ""
echo "  Create an invite token:"
echo "    $COORD_BIN cs --config $COORD_CONF create-invite"
echo ""
echo "  Peer registration (on each peer machine):"
echo "    sudo meshlink up \\"
echo "      --server $HTTPS_URL \\"
echo "      --invite <token>"
echo ""
echo "  Logs:  journalctl -u $SERVICE_NAME -f"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
