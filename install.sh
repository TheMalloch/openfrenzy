#!/usr/bin/env bash
#
# install.sh — Install meshlink binary with permissions so it runs without sudo.
#
# What it does:
#   1. Builds the release binary (if needed)
#   2. Copies binary to /usr/local/bin/meshlink
#   3. Sets Linux capabilities (TUN creation, low-port binding)
#   4. Creates meshlink system group
#   5. Creates /etc/meshlink (config dir), /var/run, /var/log paths with group perms
#   6. Adds calling user to meshlink group
#
# After running this, the user can do:
#   meshlink cs db-setup
#   meshlink cs create-invite
#   meshlink cs start
#   meshlink up --server ... --invite ...
#
# All without sudo.
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
PID_DIR="/var/run"
LOG_FILE="/var/log/meshlink.log"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${CYAN}[install]${NC} $*"; }
ok()   { echo -e "${GREEN}  [done]${NC} $*"; }
fail() { echo -e "${RED}  [fail]${NC} $*"; exit 1; }

# ── Must be root ────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root."
    echo "  sudo $0"
    exit 1
fi

REAL_USER="${SUDO_USER:-}"
if [[ -z "$REAL_USER" ]]; then
    echo "Warning: \$SUDO_USER not set, cannot add user to group automatically."
fi

# ── 1. Build ────────────────────────────────────────────────────────
if [[ ! -f "$SRC_BINARY" ]]; then
    log "building meshlink (release)..."
    if [[ -n "$REAL_USER" ]]; then
        sudo -u "$REAL_USER" cargo build --manifest-path "$SCRIPT_DIR/meshlink/Cargo.toml" --release 2>&1 | tail -3
    else
        cargo build --manifest-path "$SCRIPT_DIR/meshlink/Cargo.toml" --release 2>&1 | tail -3
    fi
fi

if [[ ! -f "$SRC_BINARY" ]]; then
    fail "binary not found at $SRC_BINARY"
fi

# ── 2. Install binary ──────────────────────────────────────────────
log "installing binary to $INSTALL_PATH"
cp "$SRC_BINARY" "$INSTALL_PATH"
chmod 755 "$INSTALL_PATH"
ok "copied to $INSTALL_PATH"

# ── 3. Set capabilities ────────────────────────────────────────────
# CAP_NET_ADMIN  — create/configure TUN devices
# CAP_NET_RAW    — raw socket access (for TUN)
# CAP_NET_BIND_SERVICE — bind to ports < 1024 (if needed)
log "setting Linux capabilities"

if ! command -v setcap &>/dev/null; then
    fail "setcap not found — install libcap2-bin (apt install libcap2-bin)"
fi

setcap 'cap_net_admin,cap_net_raw,cap_net_bind_service=eip' "$INSTALL_PATH"
ok "cap_net_admin,cap_net_raw,cap_net_bind_service on $INSTALL_PATH"

# Verify
if getcap "$INSTALL_PATH" | grep -q cap_net_admin; then
    ok "capabilities verified"
else
    fail "capability verification failed"
fi

# ── 4. Create system group ─────────────────────────────────────────
log "setting up group '$GROUP_NAME'"
if getent group "$GROUP_NAME" &>/dev/null; then
    ok "group '$GROUP_NAME' already exists"
else
    groupadd --system "$GROUP_NAME"
    ok "created system group '$GROUP_NAME'"
fi

# ── 5. Create directories and set permissions ──────────────────────
log "setting up directories"

# /etc/meshlink — config dir (group writable so meshlink can write config on register)
mkdir -p "$CONFIG_DIR"
chown "root:$GROUP_NAME" "$CONFIG_DIR"
chmod 2775 "$CONFIG_DIR"
ok "$CONFIG_DIR (root:$GROUP_NAME 2775)"

# Fix existing files in config dir
for f in "$CONFIG_DIR"/*.toml "$CONFIG_DIR"/credentials.json; do
    if [[ -f "$f" ]]; then
        chown "root:$GROUP_NAME" "$f"
        chmod 0664 "$f"
    fi
done

# /var/run — PID file and socket (needs to be writable)
# Create meshlink-specific runtime dir
mkdir -p "$PID_DIR"
# We can't change /var/run ownership, but we can make the specific files group-writable
# by pre-creating them
for runtime_file in "$PID_DIR/meshlink.pid" "$PID_DIR/meshlink.sock"; do
    touch "$runtime_file"
    chown "root:$GROUP_NAME" "$runtime_file"
    chmod 0664 "$runtime_file"
done
ok "$PID_DIR/meshlink.{pid,sock} (root:$GROUP_NAME 0664)"

# /var/log/meshlink.log
touch "$LOG_FILE"
chown "root:$GROUP_NAME" "$LOG_FILE"
chmod 0664 "$LOG_FILE"
ok "$LOG_FILE (root:$GROUP_NAME 0664)"

# ── 6. Add user to group ───────────────────────────────────────────
if [[ -n "$REAL_USER" ]]; then
    log "adding '$REAL_USER' to group '$GROUP_NAME'"
    usermod -aG "$GROUP_NAME" "$REAL_USER"
    ok "user '$REAL_USER' added to '$GROUP_NAME'"
fi

# ── Summary ─────────────────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${GREEN}meshlink installed successfully${NC}"
echo ""
echo "  Binary:  $INSTALL_PATH"
echo "  Caps:    cap_net_admin,cap_net_raw,cap_net_bind_service"
echo "  Config:  $CONFIG_DIR/"
echo "  Log:     $LOG_FILE"
if [[ -n "$REAL_USER" ]]; then
    echo "  User:    $REAL_USER -> group $GROUP_NAME"
fi
echo ""
echo "You may need to log out and back in for the group change to take effect."
echo "Then you can run meshlink without sudo:"
echo ""
echo "  meshlink cs db-setup"
echo "  meshlink cs create-invite"
echo "  meshlink cs start"
echo "  meshlink up --server http://<host>:4001 --invite <code>"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
