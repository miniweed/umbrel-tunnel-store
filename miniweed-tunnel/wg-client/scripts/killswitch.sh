#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "[killswitch] must run as root"
  exit 1
fi

WG_PORT="${WG_PORT:-51820}"
STATUS_FILE="${STATUS_FILE:-/var/run/miniweed.status}"

echo "[killswitch] Stopping WireGuard tunnel"
systemctl stop wg-quick@wg0 || true

echo "[killswitch] Blocking UDP ${WG_PORT}"
iptables -w -C INPUT -p udp --dport "$WG_PORT" -j DROP 2>/dev/null || \
  iptables -w -A INPUT -p udp --dport "$WG_PORT" -j DROP

echo "killed at $(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$STATUS_FILE"
echo "[killswitch] done"
