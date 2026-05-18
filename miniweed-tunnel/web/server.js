const express = require('express');
const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');
const { Client } = require('ssh2');

const app = express();
const DATA_DIR = process.env.DATA_DIR || '/data';
const WG_API_HOST = process.env.WG_API_HOST || 'wg';
const WG_API_PORT = 8080;
const API_AUTH_TOKEN = process.env.TUNNEL_API_TOKEN || '';
const deployJobs = new Map();
let configLock = Promise.resolve();
const MAX_SERVICES = 64;

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
  services: [],
  serviceHealth: {}
};

const DEFAULT_CADDYFILE = ':80 {\n  respond "Umbrel Tunnel — not configured yet"\n}\n';

app.use(express.json({ limit: '32kb' }));
app.disable('x-powered-by');

const apiRateWindowMs = 60 * 1000;
const apiRateMax = 120;
const apiRateStore = new Map();
const deployJobTtlMs = 60 * 60 * 1000;
const deployJobMax = 200;
const SSH_COMMON_FALLBACK_USERS = ['debian', 'ubuntu'];
const SSH_MAX_USER_ATTEMPTS = 3;

app.set('trust proxy', 1);

function parseCookies(req) {
  const cookie = req.headers.cookie || '';
  const out = {};
  for (const part of cookie.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    const key = part.slice(0, idx).trim();
    const value = part.slice(idx + 1).trim();
    if (!key) continue;
    try {
      out[key] = decodeURIComponent(value);
    } catch {
      out[key] = value;
    }
  }
  return out;
}

function withConfigLock(fn) {
  const run = configLock.then(() => fn());
  configLock = run.catch(() => {});
  return run;
}

function cleanupApiRateStore() {
  const now = Date.now();
  for (const [ip, entry] of apiRateStore.entries()) {
    if (!entry || now > entry.resetAt) apiRateStore.delete(ip);
  }
}

function cleanupDeployJobs() {
  const now = Date.now();
  for (const [jobId, job] of deployJobs.entries()) {
    if (!job) {
      deployJobs.delete(jobId);
      continue;
    }
    const refTs = job.finishedAt || job.startedAt || now;
    if (now - refTs > deployJobTtlMs) deployJobs.delete(jobId);
  }

  if (deployJobs.size <= deployJobMax) return;
  const byOldest = [...deployJobs.entries()].sort((a, b) => {
    const aTs = a[1].finishedAt || a[1].startedAt || 0;
    const bTs = b[1].finishedAt || b[1].startedAt || 0;
    return aTs - bTs;
  });
  for (const [jobId] of byOldest.slice(0, deployJobs.size - deployJobMax)) {
    deployJobs.delete(jobId);
  }
}

const rateGc = setInterval(cleanupApiRateStore, 60 * 1000);
if (typeof rateGc.unref === 'function') rateGc.unref();
const jobsGc = setInterval(cleanupDeployJobs, 5 * 60 * 1000);
if (typeof jobsGc.unref === 'function') jobsGc.unref();

function apiRateLimit(req, res, next) {
  const now = Date.now();
  const ip = req.ip || req.socket?.remoteAddress || 'unknown';
  const entry = apiRateStore.get(ip);

  if (!entry || now > entry.resetAt) {
    apiRateStore.set(ip, { count: 1, resetAt: now + apiRateWindowMs });
    return next();
  }

  entry.count += 1;
  if (entry.count > apiRateMax) {
    return res.status(429).json({ error: 'Demasiadas peticiones, prueba de nuevo en un minuto' });
  }

  return next();
}

function requireApiAuth(req, res, next) {
  if (!API_AUTH_TOKEN) return next();
  const headerToken = req.get('x-tunnel-api-token');
  const cookieToken = parseCookies(req).tunnel_api_token;
  if (headerToken !== API_AUTH_TOKEN && cookieToken !== API_AUTH_TOKEN) {
    return res.status(401).json({ error: 'No autorizado' });
  }
  return next();
}

app.use('/api', apiRateLimit, requireApiAuth);
app.use(express.static(path.join(__dirname, 'public'), { index: false }));

app.get(['/', '/index.html'], (req, res) => {
  const indexPath = path.join(__dirname, 'public', 'index.html');
  let html = fs.readFileSync(indexPath, 'utf8');
  html = html.replace('__TUNNEL_API_TOKEN__', JSON.stringify(''));
  if (API_AUTH_TOKEN) {
    const secureAttr = req.secure || req.get('x-forwarded-proto') === 'https' ? '; Secure' : '';
    res.setHeader('Set-Cookie', `tunnel_api_token=${encodeURIComponent(API_AUTH_TOKEN)}; Path=/; HttpOnly; SameSite=Strict${secureAttr}`);
  }
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(html);
});

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

function isWireGuardKey(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9+/]{43}=$/.test(value)) return false;
  try {
    return Buffer.from(value, 'base64').length === 32;
  } catch {
    return false;
  }
}

function keyFingerprint(key) {
  if (!isWireGuardKey(key)) return '';
  return `${key.slice(0, 6)}...${key.slice(-6)}`;
}

function isHostname(value) {
  if (typeof value !== 'string' || value.length > 253) return false;
  const labels = value.split('.');
  if (labels.length < 2) return false;
  return labels.every(label => /^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/.test(label));
}

function isSubdomain(value) {
  if (!value) return true;
  return typeof value === 'string' && /^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/.test(value);
}

function isEmail(value) {
  return !value || (typeof value === 'string' && /^[^\s@{}]+@[^\s@{}]+\.[^\s@{}]+$/.test(value));
}

function isTargetUrl(value) {
  try {
    const url = new URL(value);
    const hasPath = url.pathname && url.pathname !== '/';
    const hasQuery = Boolean(url.search);
    const hasHash = Boolean(url.hash);
    return ['http:', 'https:'].includes(url.protocol)
      && !/[\r\n{}]/.test(value)
      && !hasPath
      && !hasQuery
      && !hasHash;
  } catch {
    return false;
  }
}

function normalizeTargetUrl(value) {
  if (typeof value !== 'string') return '';
  const trimmed = value.trim();
  if (!trimmed) return '';
  const candidate = /^https?:\/\//i.test(trimmed) ? trimmed : `http://${trimmed}`;
  try {
    const parsed = new URL(candidate);
    if (!['http:', 'https:'].includes(parsed.protocol)) return '';
    return `${parsed.protocol}//${parsed.host}`;
  } catch {
    return '';
  }
}

function serviceKey(svc) {
  const subdomain = (svc?.subdomain || '').trim().toLowerCase() || '@root';
  const target = (svc?.target || '').trim().toLowerCase();
  return `${subdomain}|${target}`;
}

function probeServiceTarget(target, timeoutMs = 4000) {
  return new Promise(resolve => {
    try {
      const parsed = new URL(target);
      const isHttps = parsed.protocol === 'https:';
      if (!isHttps && parsed.protocol !== 'http:') {
        return resolve({ ok: false, error: 'Protocolo no soportado' });
      }

      const transport = isHttps ? https : http;
      const req = transport.request(
        {
          protocol: parsed.protocol,
          hostname: parsed.hostname,
          port: parsed.port || (isHttps ? 443 : 80),
          path: '/',
          method: 'GET',
          timeout: timeoutMs,
          rejectUnauthorized: false
        },
        res => {
          res.resume();
          resolve({ ok: true, statusCode: res.statusCode || 0 });
        }
      );

      req.on('timeout', () => req.destroy(new Error('timeout')));
      req.on('error', err => resolve({ ok: false, error: err.message }));
      req.end();
    } catch (err) {
      resolve({ ok: false, error: err.message });
    }
  });
}

async function checkServicesHealth(services) {
  const health = {};
  await Promise.all((services || []).map(async svc => {
    const key = serviceKey(svc);
    if (!svc.enabled || !svc.target) {
      health[key] = { ok: false, checked: false, message: 'Desactivado o incompleto' };
      return;
    }

    const result = await probeServiceTarget(svc.target);
    if (result.ok) {
      health[key] = {
        ok: true,
        checked: true,
        statusCode: result.statusCode,
        message: `Conectado (${result.statusCode})`
      };
    } else {
      health[key] = {
        ok: false,
        checked: true,
        message: `Sin conexion (${result.error || 'error desconocido'})`
      };
    }
  }));
  return health;
}

function validateConfig(cfg) {
  const errors = [];

   if ((cfg.services || []).length > MAX_SERVICES) {
    errors.push(`Demasiados servicios: máximo ${MAX_SERVICES}`);
  }

  if (cfg.vpsPort < 1 || cfg.vpsPort > 65535) errors.push('El puerto WireGuard debe estar entre 1 y 65535');
  if (cfg.privateKey && !isWireGuardKey(cfg.privateKey)) errors.push('La clave privada de Umbrel no es válida');
  if (cfg.publicKey && !isWireGuardKey(cfg.publicKey)) errors.push('La clave pública de Umbrel no es válida');
  if (cfg.vpsPubKey && !isWireGuardKey(cfg.vpsPubKey)) errors.push('La clave pública del VPS no es válida');
  if (cfg.domain && !isHostname(cfg.domain)) errors.push('El dominio principal no es válido');
  if (!isEmail(cfg.acmeEmail)) errors.push('El email de Let\'s Encrypt no es válido');

  const seenHosts = new Set();
  for (const [index, svc] of (cfg.services || []).entries()) {
    if (!isSubdomain(svc.subdomain)) errors.push(`El subdominio del servicio ${index + 1} no es válido`);
    if (svc.target && !isTargetUrl(svc.target)) errors.push(`La URL interna del servicio ${index + 1} no es válida`);

    if (cfg.domain && svc.enabled && svc.target) {
      const host = svc.subdomain ? `${svc.subdomain}.${cfg.domain}`.toLowerCase() : cfg.domain.toLowerCase();
      if (seenHosts.has(host)) {
        errors.push(`Hay dos servicios usando el mismo host público (${host})`);
      }
      seenHosts.add(host);
    }
  }

  return errors;
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
# VPS dedicado exclusivamente a reverse proxy

set -euo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

if [ "$(id -u)" -ne 0 ]; then
  echo "Este script debe ejecutarse como root"
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

if command -v ufw >/dev/null 2>&1; then
  ufw disable >/dev/null 2>&1 || true
  systemctl disable ufw >/dev/null 2>&1 || true
  systemctl stop ufw >/dev/null 2>&1 || true
fi

apt-get -o DPkg::Lock::Timeout=300 update -qq
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean false | debconf-set-selections
apt-get -o DPkg::Lock::Timeout=300 install -y -qq wireguard iptables iptables-persistent fail2ban unattended-upgrades

PUBLIC_IF=$(ip route show default | awk '/default/{print $5; exit}')
if [ -z "$PUBLIC_IF" ]; then
  echo "No se pudo detectar la interfaz de red publica"
  exit 1
fi

SSH_PORT=$(/usr/sbin/sshd -T 2>/dev/null | awk '/^port /{print $2; exit}' || true)
if [ -z "$SSH_PORT" ]; then
  SSH_PORT=$(awk '/^[[:space:]]*Port[[:space:]]+[0-9]+/{print $2; exit}' /etc/ssh/sshd_config 2>/dev/null || true)
fi
[ -z "$SSH_PORT" ] && SSH_PORT=22

if ! ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)\${SSH_PORT}$"; then
  echo "No se detecta sshd escuchando en el puerto $SSH_PORT. Abortando para evitar lockout."
  exit 1
fi

WG_PORT=${cfg.vpsPort}
WG_CLIENT_IP=${cfg.tunnelClientIp}

mkdir -p /root/miniweed-backups
BACKUP_FILE="/root/miniweed-backups/iptables-before-$(date +%s).rules"
iptables-save > "$BACKUP_FILE"

cat > /root/miniweed-rollback-firewall.sh <<'ROLLBACKEOF'
#!/bin/bash
set -euo pipefail
LATEST=$(ls -1t /root/miniweed-backups/iptables-before-*.rules 2>/dev/null | head -1)
if [ -z "$LATEST" ]; then
  echo "No hay backup de firewall para restaurar"
  exit 1
fi
iptables-restore < "$LATEST"
echo "Restaurado firewall desde $LATEST"
ROLLBACKEOF
chmod 700 /root/miniweed-rollback-firewall.sh

ROLLBACK_FLAG=/root/miniweed-firewall-ok
rm -f "$ROLLBACK_FLAG"
( sleep 120; [ -f "$ROLLBACK_FLAG" ] || /root/miniweed-rollback-firewall.sh ) &
ROLLBACK_PID=$!

# Hardening de red del host
cat > /etc/sysctl.d/99-miniweed-tunnel-hardening.conf <<SYSCTLEOF
net.ipv4.ip_forward=1
net.ipv4.conf.all.rp_filter=2
net.ipv4.conf.default.rp_filter=2
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.tcp_syncookies=1
SYSCTLEOF
sysctl --system >/dev/null

# Firewall estricto para VPS dedicado (sin cortar la sesion SSH activa)
iptables -w -P INPUT ACCEPT
iptables -w -P FORWARD ACCEPT
iptables -w -P OUTPUT ACCEPT
iptables -w -t nat -F
iptables -w -F
iptables -w -X

iptables -w -A INPUT -i lo -j ACCEPT
iptables -w -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -w -A INPUT -p tcp --dport "$SSH_PORT" -j ACCEPT
iptables -w -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -w -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -w -A INPUT -p udp --dport "$WG_PORT" -j ACCEPT
iptables -w -A INPUT -p icmp --icmp-type echo-request -m limit --limit 10/second --limit-burst 20 -j ACCEPT

iptables -w -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination "$WG_CLIENT_IP:80"
iptables -w -t nat -A PREROUTING -p tcp --dport 443 -j DNAT --to-destination "$WG_CLIENT_IP:443"
# Evita retorno asimetrico: SNAT al lado WG para que Umbrel responda por el tunel
iptables -w -t nat -A POSTROUTING -o wg0 -p tcp -d "$WG_CLIENT_IP" --dport 80 -j MASQUERADE
iptables -w -t nat -A POSTROUTING -o wg0 -p tcp -d "$WG_CLIENT_IP" --dport 443 -j MASQUERADE
iptables -w -t nat -A POSTROUTING -o "$PUBLIC_IF" -j MASQUERADE

iptables -w -A FORWARD -p tcp -d "$WG_CLIENT_IP" --dport 80 -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
iptables -w -A FORWARD -p tcp -d "$WG_CLIENT_IP" --dport 443 -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
iptables -w -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

iptables -w -P INPUT DROP
iptables -w -P FORWARD DROP

iptables-save > /etc/iptables/rules.v4
systemctl enable netfilter-persistent >/dev/null 2>&1 || true
systemctl restart netfilter-persistent >/dev/null 2>&1 || true

# Fail2ban para SSH
mkdir -p /etc/fail2ban/jail.d
cat > /etc/fail2ban/jail.d/sshd.local <<FAIL2BANEOF
[sshd]
enabled = true
backend = systemd
maxretry = 5
findtime = 10m
bantime = 1h
FAIL2BANEOF
systemctl enable fail2ban >/dev/null 2>&1 || true
systemctl restart fail2ban >/dev/null 2>&1 || true

# Actualizaciones de seguridad automáticas
systemctl enable unattended-upgrades >/dev/null 2>&1 || true
systemctl restart unattended-upgrades >/dev/null 2>&1 || true

# Endurecer SSH a solo clave publica (sin romper acceso)
SSH_HARDENED="no"
if [ -s /root/.ssh/authorized_keys ]; then
  mkdir -p /etc/ssh/sshd_config.d
  cat > /etc/ssh/sshd_config.d/99-miniweed-tunnel.conf <<SSHEOF
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PubkeyAuthentication yes
PermitRootLogin prohibit-password
SSHEOF

  if /usr/sbin/sshd -t; then
    systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
    SSH_HARDENED="yes"
  else
    rm -f /etc/ssh/sshd_config.d/99-miniweed-tunnel.conf
    echo "Advertencia: configuracion SSH invalida, se omite endurecimiento SSH"
  fi
else
  echo "Advertencia: /root/.ssh/authorized_keys no existe o esta vacio; se mantiene acceso por password para evitar lockout"
fi

VPS_PRIV=$(wg genkey)
VPS_PUB=$(echo "$VPS_PRIV" | wg pubkey)

cat > /etc/wireguard/wg0.conf <<WGEOF
[Interface]
Address = ${cfg.tunnelServerIp}/24
ListenPort = ${cfg.vpsPort}
PrivateKey = $VPS_PRIV

[Peer]
PublicKey = ${cfg.publicKey}
AllowedIPs = ${cfg.tunnelClientIp}/32
WGEOF

chmod 600 /etc/wireguard/wg0.conf

systemctl enable wg-quick@wg0
systemctl start wg-quick@wg0

if ! systemctl is-active --quiet wg-quick@wg0; then
  /root/miniweed-rollback-firewall.sh || true
  echo "WireGuard no arrancó correctamente. Firewall restaurado."
  exit 1
fi

touch "$ROLLBACK_FLAG"
kill "$ROLLBACK_PID" 2>/dev/null || true

echo ""
echo "=============================================="
echo " VPS Public Key: $VPS_PUB"
echo "=============================================="
echo " SSH PORT permitido: $SSH_PORT"
if [ "$SSH_HARDENED" = "yes" ]; then
  echo " SSH hardening: PasswordAuthentication no (solo clave publica)"
else
  echo " SSH hardening: OMITIDO para evitar lockout"
fi
echo " IMPORTANTE: en el panel cloud del proveedor abre TCP 80/443 y UDP $WG_PORT"
echo " Backup firewall: $BACKUP_FILE"
echo " Rollback script: /root/miniweed-rollback-firewall.sh"
echo " Pega esta clave en Umbrel Tunnel y listo."
`;
}

function validateSshDeployInput(input) {
  const host = (input.sshHost || '').trim();
  const user = (input.sshUser || 'root').trim();
  const port = parseInt(input.sshPort, 10) || 22;
  const privateKey = input.privateKey || '';
  const password = (input.password || '').trim();
  const passphrase = (input.passphrase || '').trim();

  if (!host) return { error: 'SSH host requerido' };
  if (!user) return { error: 'SSH user requerido' };
  if (port < 1 || port > 65535) return { error: 'SSH port inválido' };
  if (password || passphrase) return { error: 'Este deploy solo acepta clave privada SSH' };
  if (!privateKey) return { error: 'Debes proporcionar clave privada SSH' };

  if (privateKey && (!privateKey.includes('BEGIN') || !privateKey.includes('PRIVATE KEY'))) {
    return { error: 'Clave privada SSH inválida' };
  }

  return {
    host,
    user,
    port,
    privateKey
  };
}

function extractSuggestedSshUser(text) {
  if (!text) return '';
  const match = String(text).match(/Please login as the user\s+["']?([a-z_][a-z0-9_-]*)["']?/i);
  return match ? match[1] : '';
}

function isSshAuthLikeFailure(text) {
  const value = String(text || '').toLowerCase();
  if (!value) return false;
  return [
    'please login as the user',
    'permission denied',
    'authentication methods failed',
    'all configured authentication methods failed',
    'publickey',
    'root login',
    'login as the user',
    'access denied',
    'code 142'
  ].some(snippet => value.includes(snippet));
}

function buildRetryUserCandidates(requestedUser, suggestedUser = '') {
  const first = (requestedUser || 'root').trim() || 'root';
  const base = [first];

  const suggested = (suggestedUser || '').trim();
  if (suggested && suggested !== first) base.push(suggested);

  if (first === 'root') {
    for (const fallbackUser of SSH_COMMON_FALLBACK_USERS) {
      if (!base.includes(fallbackUser)) base.push(fallbackUser);
    }
  }

  return base.slice(0, SSH_MAX_USER_ATTEMPTS);
}

function shellSingleQuote(value) {
  return `'${String(value).replace(/'/g, `'\\''`)}'`;
}

function asPrivilegedShellCommand(command) {
  const quoted = shellSingleQuote(command);
  return [
    'if [ "$(id -u)" -eq 0 ]; then',
    `  bash -lc ${quoted};`,
    'elif command -v sudo >/dev/null 2>&1; then',
    `  sudo -n bash -lc ${quoted};`,
    'elif command -v doas >/dev/null 2>&1; then',
    `  doas -n bash -lc ${quoted};`,
    'else',
    '  echo "__MINIWEED_NEED_ROOT_OR_SUDO__";',
    '  exit 97;',
    'fi'
  ].join(' ');
}

function normalizeDeployError(err) {
  const combined = `${err?.message || ''}\n${err?.stdout || ''}\n${err?.stderr || ''}`;
  if (/Cannot parse privateKey: Unsupported key format/i.test(combined)) {
    return 'La clave SSH no es compatible. Usa una clave privada OpenSSH/PEM sin passphrase (recomendado: ed25519 o ecdsa no-sk).';
  }
  if (/Encrypted private (OpenSSH )?key detected, but no passphrase given/i.test(combined)) {
    return 'La clave SSH está cifrada con passphrase y este deploy no la soporta. Usa una clave sin passphrase para el deploy automático.';
  }
  if (combined.includes('__MINIWEED_NEED_ROOT_OR_SUDO__')) {
    return 'El usuario SSH no tiene privilegios de administrador. Usa root o un usuario con sudo/doas sin password.';
  }
  if (/Timed out while waiting for handshake/i.test(combined)) {
    return 'Timeout de conexion SSH (handshake). Revisa IP/puerto SSH y firewall del proveedor.';
  }
  return `Fallo SSH: ${err?.message || 'error desconocido'}`;
}

function runRemoteCommand(ssh, command, timeoutMs = 20 * 60 * 1000) {
  return new Promise((resolve, reject) => {
    let stdout = '';
    let stderr = '';

    ssh.exec(command, (err, stream) => {
      if (err) return reject(err);

      const timer = setTimeout(() => {
        stream.close();
        reject(new Error('Timeout ejecutando comando remoto (20m)'));
      }, timeoutMs);

      stream.on('close', code => {
        clearTimeout(timer);
        resolve({ code, stdout, stderr });
      });

      stream.on('data', data => {
        stdout += data.toString();
      });

      stream.stderr.on('data', data => {
        stderr += data.toString();
      });
    });
  });
}

function deployScriptOverSsh(sshConfig, script) {
  return new Promise((resolve, reject) => {
    const ssh = new Client();
    ssh.on('ready', async () => {
      try {
        const encoded = Buffer.from(script, 'utf8').toString('base64');
        const remotePath = '/root/miniweed-tunnel-vps-setup.sh';
        const rawCmd = [
          `printf '%s' '${encoded}' | base64 -d > ${remotePath}`,
          `chmod 700 ${remotePath}`,
          `bash -n ${remotePath}`,
          `bash ${remotePath} > /root/miniweed-tunnel-vps-setup.last.log 2>&1 || (cat /root/miniweed-tunnel-vps-setup.last.log && exit 1)`,
          `cat /root/miniweed-tunnel-vps-setup.last.log`
        ].join(' && ');
        const cmd = asPrivilegedShellCommand(rawCmd);

        const result = await runRemoteCommand(ssh, cmd);
        ssh.end();
        if (result.code !== 0) {
          const err = new Error(`Comando remoto terminó con código ${result.code}`);
          err.stdout = result.stdout;
          err.stderr = result.stderr;
          return reject(err);
        }
        resolve(result);
      } catch (err) {
        ssh.end();
        reject(err);
      }
    });

    ssh.on('error', reject);
    ssh.connect({
      host: sshConfig.host,
      port: sshConfig.port,
      username: sshConfig.user,
      privateKey: sshConfig.privateKey || undefined,
      readyTimeout: 20000
    });
  });
}

async function deployWithSshUserFallback(sshConfig, script) {
  const firstUser = (sshConfig.user || 'root').trim() || 'root';
  let users = buildRetryUserCandidates(firstUser);
  let lastErr;
  let attemptedUsers = [];

  for (let i = 0; i < users.length; i += 1) {
    const username = users[i];
    const attemptConfig = { ...sshConfig, user: username };
    attemptedUsers = [...attemptedUsers, username];

    try {
      await deployScriptOverSsh(attemptConfig, '#!/bin/bash\nset -e\necho "SSH preflight OK"\n');
      const result = await deployScriptOverSsh(attemptConfig, script);
      return { result, sshConfig: attemptConfig, attemptedUsers };
    } catch (err) {
      lastErr = err;
      const combined = `${err?.message || ''}\n${err?.stdout || ''}\n${err?.stderr || ''}`;
      const suggestedUser = extractSuggestedSshUser(combined);
      const isAuthRelated = isSshAuthLikeFailure(combined);

      if (i === 0 && isAuthRelated && suggestedUser) {
        users = buildRetryUserCandidates(firstUser, suggestedUser);
      }

      const hasMoreCandidates = i < users.length - 1;
      if (!hasMoreCandidates) break;

      if (!isAuthRelated && !suggestedUser) break;
    }
  }

  throw lastErr || new Error('No se pudo conectar por SSH');
}

function runSshCommand(sshConfig, command, timeoutMs = 30 * 1000) {
  return new Promise((resolve, reject) => {
    const ssh = new Client();
    ssh.on('ready', async () => {
      try {
        const result = await runRemoteCommand(ssh, command, timeoutMs);
        ssh.end();
        if (result.code !== 0) {
          const err = new Error(`Comando remoto terminó con código ${result.code}`);
          err.stdout = result.stdout;
          err.stderr = result.stderr;
          return reject(err);
        }
        resolve(result);
      } catch (err) {
        ssh.end();
        reject(err);
      }
    });
    ssh.on('error', reject);
    ssh.connect({
      host: sshConfig.host,
      port: sshConfig.port,
      username: sshConfig.user,
      privateKey: sshConfig.privateKey || undefined,
      readyTimeout: 20000
    });
  });
}

function extractVpsPublicKey(text) {
  if (!text) return '';
  const match = text.match(/VPS Public Key:\s*([A-Za-z0-9+/]{43}=)/);
  return match ? match[1] : '';
}

async function readVpsPublicKeyOverSsh(sshConfig) {
  const cmd = asPrivilegedShellCommand('wg show wg0 public-key');
  const result = await runSshCommand(sshConfig, cmd, 30 * 1000);
  const key = (result.stdout || '').trim();
  return isWireGuardKey(key) ? key : '';
}

async function waitForHandshake(maxWaitMs = 45 * 1000) {
  const intervalMs = 3000;
  const started = Date.now();

  while (Date.now() - started < maxWaitMs) {
    try {
      const status = await wgApi('/status');
      if (status && status.connected) {
        return {
          ok: true,
          handshakedPeers: status.handshakedPeers || 0,
          lastHandshakeAgeSec: status.lastHandshakeAgeSec ?? null
        };
      }
    } catch {
      // Keep polling while wg-api initializes
    }
    await new Promise(resolve => setTimeout(resolve, intervalMs));
  }

  return { ok: false, handshakedPeers: 0, lastHandshakeAgeSec: null };
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
  res.json({
    ...cfg,
    privateKey: cfg.privateKey ? '••••' : '',
    vpsPubKeyFingerprint: keyFingerprint(cfg.vpsPubKey)
  });
});

app.post('/api/config', async (req, res) => {
  try {
    const result = await withConfigLock(async () => {
      const existing = loadConfig();
      const update = req.body || {};
      if (update.privateKey === '••••') update.privateKey = existing.privateKey;

      const cfg = { ...existing, ...update };
      cfg.vpsPort = parseInt(cfg.vpsPort, 10) || 51820;
      cfg.services = Array.isArray(cfg.services)
        ? cfg.services.map(svc => ({
            name: (svc.name || '').trim(),
            subdomain: (svc.subdomain || '').trim().toLowerCase(),
            target: normalizeTargetUrl(svc.target),
            enabled: Boolean(svc.enabled)
          }))
        : [];

      const errors = validateConfig(cfg);
      if (errors.length) return { errors };

      cfg.serviceHealth = await checkServicesHealth(cfg.services);
      saveConfig(cfg);

      const wgConf = generateWgConf(cfg);
      if (wgConf) fs.writeFileSync(WG_CONF, wgConf);
      fs.writeFileSync(CADDYFILE, generateCaddyfile(cfg));

      return { ok: true, serviceHealth: cfg.serviceHealth };
    });

    if (result.errors) return res.status(400).json({ errors: result.errors });
    return res.json(result);
  } catch (err) {
    return res.status(500).json({ error: `Error guardando configuracion: ${err.message}` });
  }
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

app.post('/api/deploy-vps', async (req, res) => {
  const cfg = loadConfig();
  if (!cfg.publicKey || !cfg.vpsIp) {
    return res.status(400).json({ error: 'Configura la IP del VPS y genera las claves primero' });
  }

  const parsed = validateSshDeployInput(req.body || {});
  if (parsed.error) {
    return res.status(400).json({ error: parsed.error });
  }

  const script = generateVpsScript(cfg);
  const jobId = `job_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;

  deployJobs.set(jobId, {
    status: 'running',
    startedAt: Date.now(),
    error: '',
    stdout: '',
    stderr: '',
    vpsPubKey: '',
    autoConfigured: false
  });

  (async () => {
    try {
      const deployRun = await deployWithSshUserFallback(parsed, script);
      const result = deployRun.result;
      const usedSshConfig = deployRun.sshConfig;
      const attemptedSshUsers = deployRun.attemptedUsers || [parsed.user];

      const combinedOutput = `${result.stdout || ''}\n${result.stderr || ''}`;
      const printedVpsPubKey = extractVpsPublicKey(combinedOutput);
      const readbackVpsPubKey = await readVpsPublicKeyOverSsh(usedSshConfig).catch(() => '');
      const vpsPubKey = readbackVpsPubKey || printedVpsPubKey;
      let autoConfigured = false;
      let keySyncStatus = 'missing';
      let keySyncMessage = 'No se pudo detectar la clave publica del VPS';
      let handshake = { ok: false, handshakedPeers: 0, lastHandshakeAgeSec: null };

      if (vpsPubKey) {
        const freshCfg = await withConfigLock(async () => {
          const nextCfg = loadConfig();
          nextCfg.vpsPubKey = vpsPubKey;
          saveConfig(nextCfg);

          const wgConf = generateWgConf(nextCfg);
          if (wgConf) {
            fs.writeFileSync(WG_CONF, wgConf);
            autoConfigured = true;
          }
          fs.writeFileSync(CADDYFILE, generateCaddyfile(nextCfg));
          return nextCfg;
        });

        if (printedVpsPubKey && readbackVpsPubKey && printedVpsPubKey !== readbackVpsPubKey) {
          keySyncStatus = 'readback-corrected';
          keySyncMessage = 'La clave impresa no coincidia con WG; se uso la clave leida directamente del VPS.';
        } else {
          keySyncStatus = 'synced';
          keySyncMessage = 'Clave publica del VPS sincronizada.';
        }

        handshake = await waitForHandshake();

        if (!handshake.ok && readbackVpsPubKey) {
          const retryReadback = await readVpsPublicKeyOverSsh(usedSshConfig).catch(() => '');
          if (retryReadback && retryReadback !== freshCfg.vpsPubKey) {
            await withConfigLock(async () => {
              const retryCfg = loadConfig();
              retryCfg.vpsPubKey = retryReadback;
              saveConfig(retryCfg);
              const retryWgConf = generateWgConf(retryCfg);
              if (retryWgConf) fs.writeFileSync(WG_CONF, retryWgConf);
            });
            keySyncStatus = 'retry-updated';
            keySyncMessage = 'Se detecto cambio de clave en VPS y se aplico una resincronizacion automatica.';
            handshake = await waitForHandshake();
          }
        }

        if (!handshake.ok && keySyncStatus === 'synced') {
          keySyncStatus = 'synced-no-handshake-yet';
          keySyncMessage = 'Clave sincronizada, pero aun sin handshake. Verifica unos segundos y revisa firewall del proveedor.';
        }
      }

      deployJobs.set(jobId, {
        status: 'success',
        startedAt: deployJobs.get(jobId)?.startedAt || Date.now(),
        finishedAt: Date.now(),
        error: '',
        stdout: result.stdout || '',
        stderr: result.stderr || '',
        vpsPubKey,
        vpsPubKeyFingerprint: keyFingerprint(vpsPubKey),
        sshUserUsed: usedSshConfig.user,
        sshUserFallbackUsed: usedSshConfig.user !== parsed.user,
        sshUsersTried: attemptedSshUsers,
        autoConfigured,
        keySyncStatus,
        keySyncMessage,
        handshakeOk: handshake.ok,
        handshakedPeers: handshake.handshakedPeers,
        lastHandshakeAgeSec: handshake.lastHandshakeAgeSec
      });
    } catch (err) {
      deployJobs.set(jobId, {
        status: 'error',
        startedAt: deployJobs.get(jobId)?.startedAt || Date.now(),
        finishedAt: Date.now(),
        error: normalizeDeployError(err),
        stdout: err.stdout || '',
        stderr: err.stderr || ''
      });
    }
  })();

  return res.status(202).json({ ok: true, jobId });
});

app.get('/api/deploy-vps/:jobId', (req, res) => {
  const job = deployJobs.get(req.params.jobId);
  if (!job) {
    return res.status(404).json({ error: 'Job no encontrado' });
  }
  return res.json(job);
});

// ── boot ─────────────────────────────────────────────────────────────────────

ensureDataDir();
const PORT = parseInt(process.env.PORT) || 3000;
app.listen(PORT, () => console.log(`[web] Umbrel Tunnel UI en :${PORT}`));
