#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "[vps-setup] must run as root"
  exit 1
fi

if [ ! -f /mnt/killswitch.sh ]; then
  echo "[vps-setup] missing /mnt/killswitch.sh"
  exit 1
fi

echo "[vps-setup] installing miniweed killswitch service"

install -d -m 755 /usr/local/bin
install -m 700 /mnt/killswitch.sh /usr/local/bin/miniweed-killswitch

cat > /etc/systemd/system/miniweed-killswitch.service <<'EOF'
[Unit]
Description=Miniweed killswitch service
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/miniweed-killswitch
Environment=WG_PORT=51820

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable miniweed-killswitch.service >/dev/null 2>&1 || true
echo "[vps-setup] done"
