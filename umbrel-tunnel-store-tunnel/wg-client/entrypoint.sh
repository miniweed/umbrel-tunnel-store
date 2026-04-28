#!/bin/bash
set -e

DATA_DIR="${DATA_DIR:-/data}"
WG_CONF_SRC="$DATA_DIR/wg0.conf"
WG_CONF="/etc/wireguard/wg0.conf"

echo "[wg] Umbrel Tunnel WireGuard client starting..."

# Start API server immediately so keygen works before any config exists
python3 /wg-api.py &
API_PID=$!

cleanup() {
    echo "[wg] Shutting down..."
    wg-quick down wg0 2>/dev/null || true
    kill "$API_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Wait for config to be written by the web container
until [ -f "$WG_CONF_SRC" ] && [ -s "$WG_CONF_SRC" ]; do
    echo "[wg] Waiting for WireGuard config..."
    sleep 3
done

cp "$WG_CONF_SRC" "$WG_CONF"

# Bring up WireGuard
until wg-quick up wg0; do
    echo "[wg] Failed to bring up wg0, retrying in 5s..."
    sleep 5
done
echo "[wg] Tunnel up"

# Watch config for changes and syncconf (no interface teardown)
PREV_HASH=$(md5sum "$WG_CONF_SRC" | cut -d' ' -f1)
while true; do
    sleep 3
    [ -f "$WG_CONF_SRC" ] || continue
    CURR_HASH=$(md5sum "$WG_CONF_SRC" | cut -d' ' -f1)
    if [ "$CURR_HASH" != "$PREV_HASH" ]; then
        echo "[wg] Config changed, syncing..."
        cp "$WG_CONF_SRC" "$WG_CONF"
        wg syncconf wg0 <(wg-quick strip "$WG_CONF") 2>&1 && echo "[wg] Sync OK" || echo "[wg] Sync failed"
        PREV_HASH="$CURR_HASH"
    fi
done
