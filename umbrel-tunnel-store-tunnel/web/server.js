const express = require('express');
const fs = require('fs');
const path = require('path');
const http = require('http');

const app = express();
const DATA_DIR = process.env.DATA_DIR || '/data';
const WG_API_HOST = process.env.WG_API_HOST || 'wg';
const WG_API_PORT = 8080;

const CONFIG_FILE = path.join(DATA_DIR, 'config.json');
const WG_CONF = path.join(DATA_DIR, 'wg0.conf');
const CADDYFILE = path.join(DATA_DIR, 'Caddyfile');

const DEFAULT_CONFIG = {
  privateKey: '',
  publicKey: '',
  vpsIp: '',
  vpsPort: 51820,
  vpsPubKey: '',
  tunnelClientIp: '10.8.0.2',
  tunnelServerIp: '10.8.0.1',
  domain: '',
  acmeEmail: '',
  services: []
};

const DEFAULT_CADDYFILE = ':80 {\n  respond "Umbrel Tunnel — not configured yet"\n}\n';

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── helpers ──────────────────────────────────────────────────────────────────

function ensureDataDir() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(CADDYFILE)) {
    fs.writeFileSync(CADDYFILE, DEFAULT_CADDYFILE);
  }
}

function loadConfig() {
  try {
    return { ...DEFAULT_CONFIG, ...JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8')) };
  } catch {
    return { ...DEFAULT_CONFIG };
  }
}

function saveConfig(cfg) {
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(cfg, null, 2));
}

function generateWgConf(cfg) {
  if (!cfg.privateKey || !cfg.vpsPubKey || !cfg.vpsIp) return null;
  return [
    '[Interface]',
    `Address = ${cfg.tunnelClientIp}/32`,
    `PrivateKey = ${cfg.privateKey}`,
    '',
    '[Peer]',
    `PublicKey = ${cfg.vpsPubKey}`,
    `Endpoint = ${cfg.vpsIp}:${cfg.vpsPort}`,
    `AllowedIPs = ${cfg.tunnelServerIp}/32`,
    'PersistentKeepalive = 25',
    ''
  ].join('\n');
}

function generateCaddyfile(cfg) {
  const enabled = (cfg.services || []).filter(s => s.enabled && s.target);
  if (!cfg.domain || !cfg.acmeEmail || !enabled.length) return DEFAULT_CADDYFILE;

  const blocks = [`{\n  email ${cfg.acmeEmail}\n  admin localhost:2019\n}\n`];
  for (const svc of enabled) {
    const host = svc.subdomain ? `${svc.subdomain}.${cfg.domain}` : cfg.domain;
    blocks.push(`${host} {\n  reverse_proxy ${svc.target}\n}\n`);
  }
  return blocks.join('\n');
}

function generateVpsScript(cfg) {
  return `#!/bin/bash
# Umbrel Tunnel — VPS Setup
# Ejecutar como root en un VPS Debian/Ubuntu

set -e
apt-get update -qq
apt-get install -y -qq wireguard iptables

VPS_PRIV=$(wg genkey)
VPS_PUB=$(echo "$VPS_PRIV" | wg pubkey)
ETH=$(ip route show default | awk '/default/{print $5}' | head -1)

cat > /etc/wireguard/wg0.conf <<WGEOF
[Interface]
Address = ${cfg.tunnelServerIp}/24
ListenPort = ${cfg.vpsPort}
PrivateKey = $VPS_PRIV
PostUp   = iptables -t nat -A PREROUTING -i $ETH -p tcp --dport 80  -j DNAT --to-destination ${cfg.tunnelClientIp}:80
PostUp   = iptables -t nat -A PREROUTING -i $ETH -p tcp --dport 443 -j DNAT --to-destination ${cfg.tunnelClientIp}:443
PostUp   = iptables -t nat -A POSTROUTING -j MASQUERADE
PostUp   = sysctl -w net.ipv4.ip_forward=1
PreDown  = iptables -t nat -D PREROUTING -i $ETH -p tcp --dport 80  -j DNAT --to-destination ${cfg.tunnelClientIp}:80
PreDown  = iptables -t nat -D PREROUTING -i $ETH -p tcp --dport 443 -j DNAT --to-destination ${cfg.tunnelClientIp}:443
PreDown  = iptables -t nat -D POSTROUTING -j MASQUERADE

[Peer]
PublicKey = ${cfg.publicKey}
AllowedIPs = ${cfg.tunnelClientIp}/32
WGEOF

systemctl enable wg-quick@wg0
systemctl start wg-quick@wg0

echo ""
echo "=============================================="
echo " VPS Public Key: $VPS_PUB"
echo "=============================================="
echo " Pega esta clave en Umbrel Tunnel y listo."
`;
}

function wgApi(urlPath) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { hostname: WG_API_HOST, port: WG_API_PORT, path: urlPath, method: 'GET' },
      res => {
        let data = '';
        res.on('data', c => (data += c));
        res.on('end', () => {
          try { resolve(JSON.parse(data)); } catch { resolve(data); }
        });
      }
    );
    req.setTimeout(5000, () => { req.destroy(); reject(new Error('timeout')); });
    req.on('error', reject);
    req.end();
  });
}

// ── routes ───────────────────────────────────────────────────────────────────

app.get('/api/config', (req, res) => {
  const cfg = loadConfig();
  // Never expose private key to the frontend
  res.json({ ...cfg, privateKey: cfg.privateKey ? '••••' : '' });
});

app.post('/api/config', (req, res) => {
  const existing = loadConfig();
  const update = req.body;
  if (update.privateKey === '••••') update.privateKey = existing.privateKey;

  const cfg = { ...existing, ...update };
  saveConfig(cfg);

  const wgConf = generateWgConf(cfg);
  if (wgConf) fs.writeFileSync(WG_CONF, wgConf);
  fs.writeFileSync(CADDYFILE, generateCaddyfile(cfg));

  res.json({ ok: true });
});

app.get('/api/keygen', async (req, res) => {
  try {
    const keys = await wgApi('/keygen');
    // Save private key immediately, return only public key
    const cfg = loadConfig();
    cfg.privateKey = keys.privateKey;
    cfg.publicKey = keys.publicKey;
    saveConfig(cfg);
    res.json({ publicKey: keys.publicKey });
  } catch (err) {
    res.status(503).json({ error: 'WireGuard no disponible: ' + err.message });
  }
});

app.get('/api/status', async (req, res) => {
  try {
    res.json(await wgApi('/status'));
  } catch {
    res.json({ connected: false, raw: 'WireGuard no disponible' });
  }
});

app.get('/api/vps-setup', (req, res) => {
  const cfg = loadConfig();
  if (!cfg.publicKey || !cfg.vpsIp) {
    return res.status(400).json({ error: 'Configura la IP del VPS y genera las claves primero' });
  }
  res.json({ script: generateVpsScript(cfg) });
});

// ── boot ─────────────────────────────────────────────────────────────────────

ensureDataDir();
const PORT = parseInt(process.env.PORT) || 3000;
app.listen(PORT, () => console.log(`[web] Umbrel Tunnel UI en :${PORT}`));
