# Plan técnico de mejoras — miniweed-tunnel (variante SIN deploy SSH)

> **Variante B.** Elimina el flujo de deploy del VPS desde la UI. La superficie de ataque se reduce drásticamente.
> Versión gemela con deploy: `MEJORAS_CON_DEPLOY.md`.

**Diferencias clave respecto a la variante A:**
- **P0-3**: completamente distinto. Se elimina el endpoint de deploy SSH y todo el manejo de claves SSH.
- **P1-6**: rate limit cambia (no hay `/api/deploy-vps`).
- **P1-4**: el audit log no necesita eventos `deploy.*`.
- **P2-11**: la rotación de claves no puede automatizarse vía SSH; se hace mediante script downloadable.
- **Nueva mejora P0-3-bis**: generador de script de setup mejorado para compensar la pérdida de la automatización.

El resto de las 20 mejoras es idéntico al documento A.

Dirigido a desarrollador. Cada mejora incluye: problema con referencia al código actual, diseño, snippets implementables, migración, tests y esfuerzo.

Convenciones:
- `server.js` se refiere a `miniweed-tunnel/web/server.js`
- `index.html` se refiere a `miniweed-tunnel/web/public/index.html`
- `entrypoint.sh` se refiere a `miniweed-tunnel/wg-client/entrypoint.sh`

---

## Índice

**P0 — Seguridad crítica**
1. Cifrado de secretos en reposo
2. Token de API obligatorio en primer boot
3. **Eliminación completa del deploy SSH** (cambio mayor respecto a A)
3-bis. Script de setup VPS mejorado (sustituye al deploy SSH)

**P1 — Hardening alcanzable**
4. Audit log estructurado
5. PSK en WireGuard
6. Rate limiting por endpoint
7. Headers de seguridad
8. Fingerprinting criptográfico

**P2 — Robustez operacional**
9. Backup/restore cifrado
10. Validación de salud post-cambio
11. Rotación de claves vía script descargable (no SSH automático)
12. Validación de email con MX

**P3 — Arquitectura**
13. Suite de tests
14. CI/CD
15. README + threat model
16. SPA frontend
17. Contrato de API tipado

**P4 — Diferenciación**
18. Auth multicapa
19. Kill switch remoto
20. Multi-VPS / failover
21. CrowdSec en VPS

---

# P0 — Seguridad crítica

## P0-1. Cifrado de secretos en reposo

**Problema.** `server.js:160-172` serializa el config como JSON pretty-printed en `/data/config.json`. La clave privada WireGuard, el subdomain mapping y los targets internos quedan en plaintext.

**Diseño.**
- **Algoritmo**: AES-256-GCM.
- **Derivación**: `scrypt(APP_SEED, "miniweed-tunnel/v1", N=2^17, r=8, p=1, dkLen=32)`.
- **Per-field encryption**: nonce de 12 bytes aleatorio por campo.
- **Versionado**: `_encVersion: 1`.
- **Campos cifrados**: `privateKey`, `presharedKey` (P1-5), `services[].target`.

**Implementación.** `web/lib/cryptobox.js`:

```js
const crypto = require('crypto');
const SALT = Buffer.from('miniweed-tunnel/v1', 'utf8');
const KDF_PARAMS = { N: 1 << 17, r: 8, p: 1, dkLen: 32 };
const ALG = 'aes-256-gcm';

let cachedKey = null;
function getMasterKey() {
  if (cachedKey) return cachedKey;
  const seed = process.env.APP_SEED;
  if (!seed || seed.length < 32) throw new Error('APP_SEED missing or too short');
  cachedKey = crypto.scryptSync(seed, SALT, KDF_PARAMS.dkLen, {
    N: KDF_PARAMS.N, r: KDF_PARAMS.r, p: KDF_PARAMS.p, maxmem: 256 * 1024 * 1024,
  });
  return cachedKey;
}

function seal(plaintext) {
  if (plaintext == null || plaintext === '') return null;
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALG, getMasterKey(), nonce);
  const ct = Buffer.concat([cipher.update(String(plaintext), 'utf8'), cipher.final()]);
  return { v: 1, n: nonce.toString('base64'), c: ct.toString('base64'), t: cipher.getAuthTag().toString('base64') };
}

function open(blob) {
  if (!blob || typeof blob !== 'object' || blob.v !== 1) return null;
  const decipher = crypto.createDecipheriv(ALG, getMasterKey(), Buffer.from(blob.n, 'base64'));
  decipher.setAuthTag(Buffer.from(blob.t, 'base64'));
  return Buffer.concat([decipher.update(Buffer.from(blob.c, 'base64')), decipher.final()]).toString('utf8');
}

const isSealed = v => v && typeof v === 'object' && v.v === 1 && v.n && v.c && v.t;
module.exports = { seal, open, isSealed };
```

Modificaciones en `server.js`:

```js
const { seal, open, isSealed } = require('./lib/cryptobox');
const ENCRYPTED_FIELDS = ['privateKey', 'presharedKey'];

function encryptConfig(cfg) {
  const out = { ...cfg, _encVersion: 1 };
  for (const f of ENCRYPTED_FIELDS) if (out[f] && !isSealed(out[f])) out[f] = seal(out[f]);
  if (Array.isArray(out.services)) out.services = out.services.map(s => ({
    ...s, target: s.target && !isSealed(s.target) ? seal(s.target) : s.target,
  }));
  return out;
}

function decryptConfig(cfg) {
  const out = { ...cfg };
  for (const f of ENCRYPTED_FIELDS) if (isSealed(out[f])) out[f] = open(out[f]);
  if (Array.isArray(out.services)) out.services = out.services.map(s => ({
    ...s, target: isSealed(s.target) ? open(s.target) : s.target,
  }));
  return out;
}

function loadConfig() {
  if (!fs.existsSync(CONFIG_PATH)) return defaultConfig();
  return decryptConfig(JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8')));
}

function saveConfig(cfg) {
  fs.mkdirSync(path.dirname(CONFIG_PATH), { recursive: true });
  const tmp = CONFIG_PATH + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(encryptConfig(cfg), null, 2), { mode: 0o600 });
  fs.renameSync(tmp, CONFIG_PATH);
}
```

**Migración.** Al arranque:

```js
function migrateConfigIfNeeded() {
  if (!fs.existsSync(CONFIG_PATH)) return;
  const raw = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
  if (raw._encVersion === 1) return;
  const backup = CONFIG_PATH + '.v0.bak';
  fs.copyFileSync(CONFIG_PATH, backup);
  fs.chmodSync(backup, 0o600);
  saveConfig(raw);
}
```

**Tests:** roundtrip, tampering detection, key derivation determinismo, distintos seeds producen distintas keys.

**Esfuerzo:** 12-16 horas.

---

## P0-2. Token de API obligatorio en primer boot

**Problema.** `server.js:128` — si `API_AUTH_TOKEN` está vacío, la API queda abierta.

**Diseño.**
- Token derivado deterministamente con `hkdf(APP_SEED, "miniweed-tunnel/v1", "tunnel-api-token-v1", 32)` si hay seed.
- Sin seed → token aleatorio persistido cifrado en `/data/api-token.enc`.
- Sin seed y sin token persistido → **abortar arranque**.

```js
const TOKEN_PATH = path.join(DATA_DIR, 'api-token.enc');

function loadOrCreateApiToken() {
  if (process.env.APP_SEED && process.env.APP_SEED.length >= 32) {
    const tok = crypto.hkdfSync('sha256', process.env.APP_SEED,
      Buffer.from('miniweed-tunnel/v1'), Buffer.from('tunnel-api-token-v1'), 32);
    return Buffer.from(tok).toString('base64url');
  }
  if (fs.existsSync(TOKEN_PATH)) return open(JSON.parse(fs.readFileSync(TOKEN_PATH, 'utf8')));
  if (!process.env.APP_SEED) { console.error('FATAL: no APP_SEED'); process.exit(1); }
  const tok = crypto.randomBytes(32).toString('base64url');
  fs.writeFileSync(TOKEN_PATH, JSON.stringify(seal(tok)), { mode: 0o600 });
  return tok;
}

const API_AUTH_TOKEN = loadOrCreateApiToken();
```

Middleware con `timingSafeEqual`:

```js
app.use('/api', (req, res, next) => {
  const headerTok = req.get('x-tunnel-api-token') || '';
  const cookieTok = req.cookies?.tunnel_api_token || '';
  const buf = s => Buffer.from(s.padEnd(64).slice(0, 64));
  const expected = buf(API_AUTH_TOKEN);
  if (!crypto.timingSafeEqual(buf(headerTok), expected) && !crypto.timingSafeEqual(buf(cookieTok), expected)) {
    auditLog({ action: 'auth.fail', ip: req.ip, ua: req.get('user-agent') });
    return res.status(401).json({ error: 'unauthorized' });
  }
  next();
});
```

**Esfuerzo:** 4-6 horas.

---

## P0-3. Eliminación completa del deploy SSH

**Decisión arquitectónica.** Esta variante elimina la feature de "deploy desde la UI vía SSH". Razones:

1. **Reducción masiva de superficie de ataque.** Sin endpoints SSH, no hay riesgo de:
   - Exfiltración de claves privadas SSH a través de la API
   - MITM SSH (sin `hostVerifier`)
   - Fuga de secretos en stdout/stderr devuelto al cliente
   - Spam de intentos de login en VPS con users `root/debian/ubuntu`
2. **Sin dependencia de `ssh2`.** Una dependencia npm menos (= menos CVEs futuras).
3. **Modelo mental más simple.** El Umbrel solo habla con el VPS por WireGuard, nunca por SSH.
4. **El usuario sigue teniendo control completo** porque el flujo se reemplaza con el script downloadable mejorado (P0-3-bis).

### Cambios en código

**Eliminar:**
- Toda la función `validateSshDeployInput` (`server.js:585-640`)
- Endpoint `POST /api/deploy-vps` (`server.js:940-1080`)
- Endpoint `POST /api/deploy-vps/credential` (no existe en código actual, no se añade)
- Toda la lógica de retry con users alternativos (`server.js:753-786`)
- Polling de estado de deploy (`server.js:990-1040`)
- Toda la sección de UI "Deploy SSH" en `index.html:740-870`
- Dependencia `ssh2` en `package.json`

**Reemplazar el botón "Deploy automático" en la UI** con un único botón: **"Descargar script de setup"**, que abre un modal con:
- El script bash listo para ejecutar
- Botón "Copiar al portapapeles"
- Botón "Descargar como `miniweed-vps-setup.sh`"
- Fingerprint SHA-256 del script (para que el usuario verifique integridad después)
- Instrucciones paso a paso

### Pseudocódigo del nuevo endpoint

```js
// Sustituye toda la sección de deploy-vps
app.get('/api/vps-setup-script', (req, res) => {
  const cfg = loadConfig();
  if (!cfg.privateKey || !cfg.vpsIp || !cfg.domain) {
    return res.status(400).json({ error: 'config incomplete' });
  }
  const script = buildVpsSetupScript(cfg);
  const sha = crypto.createHash('sha256').update(script).digest('hex');
  res.json({ script, sha256: sha, filename: `miniweed-vps-setup-${Date.now()}.sh` });
});
```

### `package.json` delta

```diff
   "dependencies": {
     "express": "^4.18.2",
-    "ssh2": "^1.15.0"
+    "cookie-parser": "^1.4.6"
   }
```

### UI delta

```html
<!-- Reemplaza la sección de deploy SSH completa -->
<section id="vps-setup">
  <h2>Configurar VPS</h2>
  <ol class="setup-steps">
    <li>Genera tu script personalizado de setup haciendo clic abajo</li>
    <li>Copia el script a tu VPS (Debian 12+) por SSH</li>
    <li>Ejecútalo como root: <code>sudo bash miniweed-vps-setup.sh</code></li>
    <li>Anota el fingerprint que muestra al final y verifícalo contra <span id="expectedFp"></span></li>
  </ol>
  <button id="downloadScriptBtn">Descargar script de setup</button>
  <pre id="scriptPreview" class="hidden"></pre>
  <p>SHA-256: <code id="scriptSha"></code></p>
</section>
```

### Beneficios concretos vs variante A

| Aspecto | Con deploy (A) | Sin deploy (B) |
|---|---|---|
| LOC mantenidos | +~600 | ~0 |
| Endpoints API expuestos | +3 (`/deploy-vps`, `/credential`, `/jobs/:id`) | 0 |
| Dependencias npm | +`ssh2` | -- |
| Secretos transitando por la red | Clave SSH privada | Solo config pública (pubkeys) |
| Vector MITM SSH | Existe (mitigado por P0-3 en A) | No existe |
| UX para usuario no técnico | "Un click" | Copy + paste + run |

**Esfuerzo:** 4-8 horas (sobre todo eliminación + UI rework). Comparar con 20-28h de la variante A.

---

## P0-3-bis. Script de setup VPS mejorado

> Esta mejora compensa la pérdida del "deploy automático" haciendo que el script generado sea idempotente, auto-validable, y con mejor UX en terminal.

**Problema.** El script actual generado por `server.js:361-579` ya hace muchas cosas bien (iptables, Fail2ban, sysctl, unattended-upgrades), pero:
- No es idempotente (segunda ejecución puede romper la config)
- No imprime fingerprint final para verificación
- No tiene salida bonita (banners, color)
- No valida prerequisitos
- No tiene modo `--dry-run`

**Diseño.** Reescribir el generador en `server.js` con las siguientes características:

```js
function buildVpsSetupScript(cfg) {
  const psk = cfg.presharedKey; // P1-5
  return `#!/usr/bin/env bash
#
# miniweed-tunnel VPS setup script
# Generado: ${new Date().toISOString()}
# Para: ${cfg.domain} via ${cfg.vpsIp}
#
# Uso: sudo bash $0 [--dry-run] [--no-firewall] [--no-fail2ban]
#
set -euo pipefail

# === Variables (inyectadas) ===
WG_PORT=${cfg.vpsPort || 51820}
TUNNEL_CIDR=10.8.0.0/24
SERVER_IP=10.8.0.1
CLIENT_IP=10.8.0.2
UMBREL_PUBKEY=${shellQuote(cfg.publicKey)}
PRESHARED_KEY=${shellQuote(psk || '')}
SSH_PORT=$(ss -tlnp | awk '/sshd/ {split($4,a,":"); print a[length(a)]; exit}' || echo 22)

# === Parsing flags ===
DRY_RUN=0
SKIP_FIREWALL=0
SKIP_FAIL2BAN=0
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    --no-firewall) SKIP_FIREWALL=1 ;;
    --no-fail2ban) SKIP_FAIL2BAN=1 ;;
  esac
done

# === Helpers ===
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BOLD='\033[1m'; NC='\033[0m'
log()  { printf "%b[+]%b %s\\n" "$GREEN" "$NC" "$1"; }
warn() { printf "%b[!]%b %s\\n" "$YELLOW" "$NC" "$1"; }
err()  { printf "%b[x]%b %s\\n" "$RED" "$NC" "$1" >&2; exit 1; }
run()  { if [ "$DRY_RUN" -eq 1 ]; then echo "  DRY: $*"; else eval "$@"; fi; }

# === Banner ===
cat <<'BANNER'
 __  __ _       _                    _
|  \\/  (_)_ __ (_)_ __ _____      __| |
| |\\/| | | '_ \\| \\ V  V / -_) -_) _\` |
|_|  |_|_|_| |_|_|\\_/\\_/\\___\\___\\__,_|
                       tunnel VPS setup
BANNER

# === Pre-flight checks ===
log "Verificando prerequisitos..."
[ "$(id -u)" -eq 0 ] || err "Debe ejecutarse como root"
[ -f /etc/os-release ] || err "Sistema no soportado"
. /etc/os-release
case "$ID" in debian|ubuntu) : ;; *) warn "Sistema $ID no testeado; continuando" ;; esac
command -v ip >/dev/null || err "iproute2 requerido"

# === Idempotencia: backup y detección de instalación previa ===
BACKUP_DIR=/var/backups/miniweed-$(date +%Y%m%d-%H%M%S)
mkdir -p "$BACKUP_DIR"
[ -f /etc/wireguard/wg0.conf ] && cp /etc/wireguard/wg0.conf "$BACKUP_DIR/"
[ -f /etc/iptables/rules.v4 ]  && cp /etc/iptables/rules.v4  "$BACKUP_DIR/"
log "Backups en $BACKUP_DIR"

# === Instalar paquetes ===
log "Instalando paquetes..."
run "DEBIAN_FRONTEND=noninteractive apt-get update -qq"
PKGS="wireguard wireguard-tools iptables-persistent unattended-upgrades curl"
[ "$SKIP_FAIL2BAN" -eq 0 ] && PKGS="$PKGS fail2ban"
run "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq $PKGS"

# === Sysctl hardening ===
log "Aplicando sysctl hardening..."
cat > /etc/sysctl.d/99-miniweed.conf <<EOF
net.ipv4.ip_forward = 1
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 4096
EOF
run "sysctl --system >/dev/null"

# === Generar claves WireGuard (idempotente) ===
mkdir -p /etc/wireguard
chmod 700 /etc/wireguard
if [ -s /etc/wireguard/wg0.key ]; then
  log "Reutilizando clave existente"
  PRIV=$(cat /etc/wireguard/wg0.key)
else
  log "Generando claves WireGuard"
  PRIV=$(wg genkey)
  echo "$PRIV" > /etc/wireguard/wg0.key
  chmod 600 /etc/wireguard/wg0.key
fi
PUB=$(echo "$PRIV" | wg pubkey)
echo "$PUB" > /etc/wireguard/wg0.pub

# === Construir wg0.conf ===
log "Escribiendo /etc/wireguard/wg0.conf"
PEER_BLOCK="[Peer]
PublicKey = $UMBREL_PUBKEY
AllowedIPs = $CLIENT_IP/32"
if [ -n "$PRESHARED_KEY" ]; then
  echo "$PRESHARED_KEY" > /etc/wireguard/wg0.psk
  chmod 600 /etc/wireguard/wg0.psk
  PEER_BLOCK="$PEER_BLOCK
PresharedKey = $PRESHARED_KEY"
fi
cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
Address = $SERVER_IP/24
ListenPort = $WG_PORT
PrivateKey = $PRIV
PostUp   = iptables -t nat -A POSTROUTING -s $TUNNEL_CIDR -o \$(ip route show default | awk '/default/ {print \$5; exit}') -j MASQUERADE
PostUp   = iptables -t nat -A PREROUTING -p tcp --dport 80  -j DNAT --to-destination $CLIENT_IP:80
PostUp   = iptables -t nat -A PREROUTING -p tcp --dport 443 -j DNAT --to-destination $CLIENT_IP:443
PostDown = iptables -t nat -D POSTROUTING -s $TUNNEL_CIDR -o \$(ip route show default | awk '/default/ {print \$5; exit}') -j MASQUERADE
PostDown = iptables -t nat -D PREROUTING -p tcp --dport 80  -j DNAT --to-destination $CLIENT_IP:80
PostDown = iptables -t nat -D PREROUTING -p tcp --dport 443 -j DNAT --to-destination $CLIENT_IP:443

$PEER_BLOCK
EOF
chmod 600 /etc/wireguard/wg0.conf

# === Firewall (iptables) ===
if [ "$SKIP_FIREWALL" -eq 0 ]; then
  log "Configurando firewall iptables..."
  # Backup automático con rollback en 120s si perdemos SSH
  iptables-save > "$BACKUP_DIR/iptables.before"
  ROLLBACK_SCRIPT=/tmp/miniweed-rollback-$$
  cat > "$ROLLBACK_SCRIPT" <<EOSH
#!/bin/bash
sleep 120
if ! ss -tn state established "( sport = :$SSH_PORT or dport = :$SSH_PORT )" | grep -q ssh; then
  iptables-restore < $BACKUP_DIR/iptables.before
fi
EOSH
  chmod +x "$ROLLBACK_SCRIPT"
  nohup "$ROLLBACK_SCRIPT" >/dev/null 2>&1 &
  ROLLBACK_PID=$!

  iptables -F
  iptables -X
  iptables -P INPUT DROP
  iptables -P FORWARD DROP
  iptables -P OUTPUT ACCEPT
  iptables -A INPUT -i lo -j ACCEPT
  iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
  iptables -A INPUT -p tcp --dport "$SSH_PORT" -m state --state NEW -j ACCEPT
  iptables -A INPUT -p tcp --dport 80 -j ACCEPT
  iptables -A INPUT -p tcp --dport 443 -j ACCEPT
  iptables -A INPUT -p udp --dport "$WG_PORT" -j ACCEPT
  iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT
  iptables -A FORWARD -i wg0 -o wg0 -j ACCEPT
  iptables-save > /etc/iptables/rules.v4

  # Si llegamos aquí y SSH sigue vivo, matar rollback
  kill "$ROLLBACK_PID" 2>/dev/null || true
fi

# === Fail2ban ===
if [ "$SKIP_FAIL2BAN" -eq 0 ]; then
  log "Configurando fail2ban para SSH..."
  cat > /etc/fail2ban/jail.d/miniweed.conf <<EOF
[sshd]
enabled = true
port = $SSH_PORT
maxretry = 5
findtime = 600
bantime = 3600
EOF
  systemctl enable --now fail2ban
fi

# === Unattended upgrades ===
log "Habilitando unattended-upgrades..."
echo 'APT::Periodic::Update-Package-Lists "1";' > /etc/apt/apt.conf.d/20auto-upgrades
echo 'APT::Periodic::Unattended-Upgrade "1";' >> /etc/apt/apt.conf.d/20auto-upgrades

# === SSH hardening (suave: solo si ya hay claves configuradas) ===
if [ -s ~/.ssh/authorized_keys ] || [ -s /root/.ssh/authorized_keys ]; then
  log "Deshabilitando password auth en SSH"
  sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
  if sshd -t 2>/dev/null; then systemctl reload ssh || systemctl reload sshd; else warn "sshd_config syntax error, no se aplicaron cambios"; fi
else
  warn "No hay authorized_keys; no se deshabilita password auth para evitar lockout"
fi

# === Levantar WireGuard ===
log "Activando WireGuard..."
systemctl enable wg-quick@wg0
if systemctl is-active --quiet wg-quick@wg0; then
  log "Reiniciando wg-quick@wg0 (ya estaba activo)"
  systemctl restart wg-quick@wg0
else
  systemctl start wg-quick@wg0
fi
sleep 2
wg show wg0 || err "WireGuard no se activó correctamente"

# === Fingerprint final ===
FP=$(echo "$PUB" | base64 -d 2>/dev/null | sha256sum | head -c 32 | sed 's/../&:/g;s/:$//')
cat <<EOF

${BOLD}=== Setup completado ===${NC}

VPS pubkey:   $PUB
Fingerprint:  $FP
Endpoint:     $(curl -s4 ifconfig.io || echo 'IP-PUBLICA-DESCONOCIDA'):$WG_PORT

Pega la pubkey y el fingerprint en la UI de miniweed-tunnel.
Si el fingerprint NO coincide con el que muestra la UI tras pegar la pubkey,
NO continúes — podría haber un MITM o un error de copy/paste.

Backups en $BACKUP_DIR
EOF
`;
}

function shellQuote(s) {
  if (s == null) return "''";
  return "'" + String(s).replace(/'/g, "'\\''") + "'";
}
```

**Características clave de este script:**

1. **Flags**: `--dry-run`, `--no-firewall`, `--no-fail2ban` para testing y rollback.
2. **Idempotencia**: detecta claves existentes, hace backups con timestamp.
3. **Rollback automático**: si tras configurar iptables se pierde SSH, restaura en 120s.
4. **Fingerprint visible**: el script imprime el SHA-256 de la pubkey al final, permitiendo verificación cruzada con la UI (cierra el vector MITM de la transferencia manual).
5. **Salida con color**: ergonomía terminal.
6. **No deshabilita SSH password auth si no hay authorized_keys**: evita lockout accidental.

**Endpoint para descargar:**

```js
app.get('/api/vps-setup-script', (req, res) => {
  const cfg = loadConfig();
  if (!cfg.publicKey || !cfg.vpsIp || !cfg.vpsPort) {
    return res.status(400).json({ error: 'config incomplete; generate keys and set VPS IP first' });
  }
  const script = buildVpsSetupScript(cfg);
  const sha = crypto.createHash('sha256').update(script).digest('hex');

  if (req.query.format === 'plain') {
    res.setHeader('Content-Type', 'text/plain');
    res.setHeader('Content-Disposition', 'attachment; filename="miniweed-vps-setup.sh"');
    return res.send(script);
  }
  res.json({ script, sha256: sha });
});
```

**Tests:**

```js
test('script is idempotent against pubkey injection', () => {
  const cfg = { publicKey: "'; rm -rf /; #", vpsIp: '1.2.3.4', vpsPort: 51820 };
  const script = buildVpsSetupScript(cfg);
  expect(script).toContain("UMBREL_PUBKEY=''\\''; rm -rf /; #'");
  expect(script).not.toContain('rm -rf /\n');
});

test('script contains required sections', () => {
  const script = buildVpsSetupScript(validCfg);
  expect(script).toMatch(/sysctl/);
  expect(script).toMatch(/iptables -P INPUT DROP/);
  expect(script).toMatch(/fail2ban/);
  expect(script).toMatch(/wg-quick@wg0/);
});

test('shellQuote escapes single quotes', () => {
  expect(shellQuote("can't")).toBe("'can'\\''t'");
});
```

**Esfuerzo:** 16-20 horas.

---

# P1 — Hardening alcanzable

## P1-4. Audit log estructurado

**Problema.** No hay rastro de quién accedió cuándo, ni qué cambios se hicieron.

**Diseño.** Append-only NDJSON en `/data/audit.log`, rotación por tamaño, eventos hash-encadenados.

`web/lib/audit.js`:

```js
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const AUDIT_PATH = path.join(process.env.DATA_DIR || '/data', 'audit.log');
const MAX_SIZE = 10 * 1024 * 1024;
const MAX_FILES = 5;
let lastHash = null;

function init() {
  if (!fs.existsSync(AUDIT_PATH)) { lastHash = '0'.repeat(64); return; }
  const lines = fs.readFileSync(AUDIT_PATH, 'utf8').trim().split('\n').filter(Boolean);
  if (lines.length === 0) { lastHash = '0'.repeat(64); return; }
  try { lastHash = JSON.parse(lines[lines.length - 1]).hash; }
  catch { lastHash = '0'.repeat(64); }
}

function rotateIfNeeded() {
  if (!fs.existsSync(AUDIT_PATH)) return;
  if (fs.statSync(AUDIT_PATH).size < MAX_SIZE) return;
  for (let i = MAX_FILES - 1; i >= 1; i--) {
    const src = `${AUDIT_PATH}.${i}`, dst = `${AUDIT_PATH}.${i + 1}`;
    if (fs.existsSync(src)) fs.renameSync(src, dst);
  }
  fs.renameSync(AUDIT_PATH, `${AUDIT_PATH}.1`);
}

function log(event) {
  rotateIfNeeded();
  const entry = { ts: new Date().toISOString(), prevHash: lastHash, ...event };
  const hash = crypto.createHash('sha256').update(lastHash + JSON.stringify(entry)).digest('hex');
  fs.appendFileSync(AUDIT_PATH, JSON.stringify({ ...entry, hash }) + '\n', { mode: 0o600 });
  lastHash = hash;
}

function verifyChain() {
  if (!fs.existsSync(AUDIT_PATH)) return { ok: true };
  const lines = fs.readFileSync(AUDIT_PATH, 'utf8').trim().split('\n').filter(Boolean);
  let prev = '0'.repeat(64);
  for (let i = 0; i < lines.length; i++) {
    const e = JSON.parse(lines[i]);
    if (e.prevHash !== prev) return { ok: false, brokenAt: i };
    const { hash, ...rest } = e;
    if (crypto.createHash('sha256').update(prev + JSON.stringify(rest)).digest('hex') !== hash)
      return { ok: false, brokenAt: i };
    prev = hash;
  }
  return { ok: true };
}

init();
module.exports = { log, verifyChain };
```

**Eventos auditados (lista delta vs variante A — sin `deploy.*`):**
- `auth.success`, `auth.fail`
- `config.update`
- `service.add`, `service.remove`, `service.toggle`
- `keygen`
- `script.download` (nuevo en esta variante — registra cuándo el usuario descargó el script de setup)
- `key.rotate` (P2-11)

**Esfuerzo:** 8-12 horas.

---

## P1-5. PSK en WireGuard

Idéntico a variante A. La PSK se incluye en el script de setup descargable (ya cubierto en P0-3-bis arriba).

Generación de claves (lado `server.js`, sin API del VPS):

```js
function generateKeys() {
  const privateKey = runWg('genkey');
  const publicKey = runWg('pubkey', `${privateKey}\n`);
  const presharedKey = runWg('genpsk');
  return { privateKey, publicKey, presharedKey };
}

function runWg(subcmd, stdin = null) {
  const args = ['wg', subcmd];
  const proc = spawnSync(args[0], args.slice(1), {
    input: stdin,
    encoding: 'utf8'
  });
  if (proc.status !== 0) throw new Error(`wg ${subcmd} failed`);
  return proc.stdout.trim();
}
```

Template del cliente en `server.js`:

```js
function buildWgClientConfig(cfg) {
  return `[Interface]
PrivateKey = ${cfg.privateKey}
Address = ${cfg.tunnelClientIp}/24

[Peer]
PublicKey = ${cfg.vpsServerPubkey}
${cfg.presharedKey ? `PresharedKey = ${cfg.presharedKey}\n` : ''}AllowedIPs = ${cfg.tunnelServerIp}/32
Endpoint = ${cfg.vpsIp}:${cfg.vpsPort}
PersistentKeepalive = 25
`;
}
```

**Esfuerzo:** 4-6 horas.

---

## P1-6. Rate limiting por endpoint

**Cambio respecto a variante A.** No hay endpoints `/api/deploy-vps`, así que su bucket desaparece. Sí hay nuevo bucket para `/api/vps-setup-script` (P0-3-bis).

```js
const buckets = {
  default: { max: 120, windowMs: 60_000 },
  '/api/keygen': { max: 5, windowMs: 3_600_000 },          // 5/hora
  '/api/vps-setup-script': { max: 10, windowMs: 600_000 }, // 10/10min — limitado pero no agresivo (es solo download)
  '/api/auth/login': { max: 5, windowMs: 60_000 },         // P4-18
  '/api/config': { max: 30, windowMs: 60_000 },
  '/api/backup': { max: 3, windowMs: 3_600_000 },          // P2-9
};

const stores = new Map();
function rateLimit(req) {
  const key = buckets[req.path] ? req.path : 'default';
  const bucket = buckets[key];
  const store = stores.get(key) || new Map(); stores.set(key, store);
  const now = Date.now();
  let entry = store.get(req.ip);
  if (!entry || entry.resetAt < now) entry = { count: 0, resetAt: now + bucket.windowMs };
  entry.count++; store.set(req.ip, entry);
  return { allowed: entry.count <= bucket.max, retryAfter: Math.ceil((entry.resetAt - now) / 1000) };
}
```

Backoff exponencial en `/api/auth/login` (P4-18): 1s, 2s, 4s, 8s, 16s, luego ban 1h.

**Esfuerzo:** 4-6 horas (menor que variante A por menos endpoints).

---

## P1-7. Headers de seguridad

Idéntico a variante A.

**Express:**

```js
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  if (req.secure) res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('Content-Security-Policy',
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'");
  next();
});
```

**Caddyfile generado:**

```caddyfile
{$DOMAIN} {
  encode gzip
  header {
    Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    X-Content-Type-Options "nosniff"
    Referrer-Policy "strict-origin-when-cross-origin"
    -Server
  }
  reverse_proxy {$TARGET}
}
```

**Esfuerzo:** 3-4 horas.

---

## P1-8. Fingerprinting criptográfico

Idéntico a variante A — pero gana relevancia porque ahora el usuario verifica fingerprints manualmente al transferir pubkeys entre Umbrel y VPS (no hay deploy automático).

```js
function keyFingerprint(b64key) {
  if (!b64key) return null;
  const raw = Buffer.from(b64key, 'base64');
  const hash = crypto.createHash('sha256').update(raw).digest();
  return hash.slice(0, 16).toString('hex').match(/.{2}/g).join(':');
}
```

Mostrar fingerprint:
- En la UI tras keygen
- Al final del script de setup VPS (`P0-3-bis` ya lo incluye)
- En endpoint local `/api/rotate/:planId` para verificación cruzada

**UX crítico:** al pegar la pubkey del VPS en la UI, la UI calcula fingerprint en cliente (mismo algoritmo) y lo muestra **antes** de aceptar. Pide al usuario confirmar visualmente contra lo que vio en la terminal del VPS.

**Esfuerzo:** 3 horas (algo más por el flujo de UI extra).

---

# P2 — Robustez operacional

## P2-9. Backup/restore cifrado

Idéntico a variante A.

```js
const tar = require('tar-stream');
const zlib = require('zlib');

app.post('/api/backup', express.json(), (req, res) => {
  const passphrase = req.body.passphrase;
  if (!passphrase || passphrase.length < 12) return res.status(400).json({ error: 'passphrase too short' });
  const salt = crypto.randomBytes(16);
  const key = crypto.scryptSync(passphrase, salt, 32, { N: 1 << 16, r: 8, p: 1 });
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
  const pack = tar.pack();
  pack.entry({ name: 'config.json' }, fs.readFileSync(CONFIG_PATH));
  pack.entry({ name: 'meta.json' }, JSON.stringify({ ts: new Date().toISOString(), v: 1 }));
  pack.finalize();
  res.setHeader('Content-Type', 'application/octet-stream');
  res.setHeader('Content-Disposition', `attachment; filename="miniweed-${Date.now()}.bak"`);
  res.write(Buffer.concat([Buffer.from('MWBK'), salt, nonce]));
  pack.pipe(zlib.createGzip()).pipe(cipher).pipe(res);
  cipher.on('end', () => res.end(cipher.getAuthTag()));
});
```

> Nota: sin `known_hosts.json` que respaldar (no hay SSH).

**Esfuerzo:** 10-14 horas (menos que A por menor footprint).

---

## P2-10. Validación de salud post-cambio

Idéntico a variante A.

```js
async function healthCheckService(svc, cfg) {
  const url = `https://${svc.subdomain}.${cfg.domain}`;
  const checks = {};
  try {
    const addrs = await dns.promises.resolve4(`${svc.subdomain}.${cfg.domain}`);
    checks.dns = { ok: addrs.includes(cfg.vpsIp), addrs };
  } catch (e) { checks.dns = { ok: false, error: e.code }; }
  try {
    const r = await fetch(url, { method: 'HEAD', signal: AbortSignal.timeout(5000) });
    checks.https = { ok: r.status < 500, status: r.status };
  } catch (e) { checks.https = { ok: false, error: e.message }; }
  try {
    const cert = await getCertInfo(url);
    const daysLeft = (new Date(cert.valid_to) - Date.now()) / 86400000;
    checks.cert = { ok: daysLeft > 7 && !cert.self_signed, daysLeft: Math.round(daysLeft), issuer: cert.issuer.O };
  } catch (e) { checks.cert = { ok: false, error: e.message }; }
  return checks;
}
```

Cron interno cada 5 min, badges en UI.

**Esfuerzo:** 10-14 horas.

---

## P2-11. Rotación de claves vía script descargable

**Cambio mayor respecto a variante A.** Sin SSH automático, la rotación debe hacerse por el usuario. Pero podemos hacer que sea casi atómica con un script que el usuario ejecuta en el VPS.

**Diseño.**

1. UI tiene botón "Rotar claves del túnel"
2. Backend genera nuevo par + PSK
3. Persiste como `pending` en config (sin tocar la actual)
4. UI muestra script de rotación + instrucciones:
   ```
   1. Copia este script al VPS
   2. Ejecútalo: sudo bash rotate.sh
   3. Cuando termine, vuelve aquí y pulsa "Confirmar rotación"
   4. El sistema verificará handshake y, si está OK, hará swap. Si no, descartará las claves nuevas.
   ```
5. Mientras el usuario ejecuta el script en el VPS, Umbrel **sigue usando las claves viejas** (la wg0 actual no se toca)
6. Cuando el usuario pulsa "Confirmar", Umbrel hace el swap atómico y verifica handshake con timeout 30s
7. Si el handshake nuevo NO se establece en 30s, descarta las claves nuevas y vuelve a las viejas

**Script de rotación generado:**

```bash
#!/usr/bin/env bash
set -euo pipefail

BACKUP=/etc/wireguard/wg0.conf.rotate-$(date +%s).bak
cp /etc/wireguard/wg0.conf "$BACKUP"
echo "Backup en $BACKUP"

# Nueva config (variables inyectadas)
NEW_PRIV='__NEW_VPS_PRIV__'
NEW_PSK='__NEW_PSK__'
UMBREL_PUB='__NEW_UMBREL_PUB__'
SERVER_IP=10.8.0.1
CLIENT_IP=10.8.0.2
WG_PORT=__WG_PORT__

cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
Address = $SERVER_IP/24
ListenPort = $WG_PORT
PrivateKey = $NEW_PRIV
# (Mismas reglas PostUp/PostDown que el setup original)

[Peer]
PublicKey = $UMBREL_PUB
PresharedKey = $NEW_PSK
AllowedIPs = $CLIENT_IP/32
EOF
chmod 600 /etc/wireguard/wg0.conf

systemctl restart wg-quick@wg0

# Esperar a handshake
for i in $(seq 1 30); do
  HS=$(wg show wg0 latest-handshakes | awk '{print $2}')
  if [ "${HS:-0}" -gt 0 ] && [ $(( $(date +%s) - HS )) -lt 60 ]; then
    echo "ROTATE_OK: handshake establecido"
    exit 0
  fi
  sleep 1
done

echo "ROTATE_FAIL: sin handshake. Restaurando backup."
cp "$BACKUP" /etc/wireguard/wg0.conf
systemctl restart wg-quick@wg0
exit 1
```

**Lado Umbrel** — endpoint `POST /api/keys/rotate/confirm`:

```js
app.post('/api/keys/rotate/confirm', async (req, res) => {
  const cfg = loadConfig();
  if (!cfg._pendingKeys) return res.status(400).json({ error: 'no pending rotation' });

  // Swap atómico: aplica claves nuevas en wg
  const newCfg = { ...cfg,
    privateKey: cfg._pendingKeys.privateKey,
    publicKey: cfg._pendingKeys.publicKey,
    presharedKey: cfg._pendingKeys.presharedKey,
    vpsServerPubkey: cfg._pendingKeys.vpsServerPubkey,
  };

  // Aplica al daemon wg
  await applyWgConfig(newCfg);

  // Espera handshake (30s)
  const ok = await waitForHandshake(30_000);
  if (!ok) {
    console.error('rotation: no handshake, rolling back');
    await applyWgConfig(cfg); // Revierte a claves viejas
    return res.status(500).json({ error: 'no handshake; reverted' });
  }

  // Promote
  delete newCfg._pendingKeys;
  saveConfig(newCfg);
  auditLog({ action: 'key.rotate', fingerprint: keyFingerprint(newCfg.publicKey) });
  res.json({ ok: true });
});

async function waitForHandshake(timeoutMs) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const status = await fetch(`${API_BASE}/api/rotate/${planId}`, {
      headers: { 'x-tunnel-api-token': API_AUTH_TOKEN }
    }).then(r => r.json());
    if (status && status.status === 'applied') return true;
    await new Promise(r => setTimeout(r, 1000));
  }
  return false;
}
```

**Trade-off.** En variante A la rotación es "un click". Aquí requiere copy/paste en el VPS. A cambio:
- Sin claves SSH transitando
- Sin necesidad de mantener `known_hosts.json`
- El usuario tiene control explícito del momento de rotación

**Esfuerzo:** 14-20 horas.

---

## P2-12. Validación de email con MX

Idéntico a variante A.

```js
async function validateEmail(email) {
  const re = /^[A-Za-z0-9._%+\-]+@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})$/;
  const m = email.match(re);
  if (!m) return { ok: false, reason: 'syntax' };
  try {
    const mx = await dns.promises.resolveMx(m[1]);
    return { ok: mx.length > 0, mx };
  } catch (e) { return { ok: false, reason: 'mx_lookup_failed', code: e.code }; }
}
```

**Esfuerzo:** 3-4 horas.

---

# P3 — Arquitectura y mantenibilidad

## P3-13. Suite de tests

Estructura idéntica, pero más simple porque no hay `deploy.test.js`:

```
web/test/
  unit/
    cryptobox.test.js
    validate.test.js
    audit.test.js
    ratelimit.test.js
    script-generator.test.js   # nuevo: tests del generador VPS setup script
  integration/
    api.test.js
  e2e/
    stack.test.js
```

Test específico del script generator (crítico — el script ejecuta como root en el VPS):

```js
describe('buildVpsSetupScript', () => {
  test('shell-injection safe with malicious pubkey', () => {
    const cfg = { publicKey: "fake'; rm -rf /; #", vpsIp: '1.2.3.4', vpsPort: 51820 };
    const script = buildVpsSetupScript(cfg);
    // El pubkey debe estar bajo single quotes con escape
    expect(script).not.toMatch(/UMBREL_PUBKEY=fake.*rm -rf/);
    expect(script).toMatch(/UMBREL_PUBKEY='fake'\\''; rm -rf \/; #'/);
  });

  test('shellcheck passes on generated script', async () => {
    const script = buildVpsSetupScript(validCfg);
    const tmp = path.join(os.tmpdir(), `script-${Date.now()}.sh`);
    fs.writeFileSync(tmp, script);
    const { stdout, status } = await execa('shellcheck', [tmp], { reject: false });
    expect(status).toBe(0);
  });
});
```

**Cobertura objetivo:** 70% en `lib/`, 60% en `server.js`. El generador del script debe tener **>90%** porque ejecuta como root.

**Esfuerzo:** 20-32 horas (menor que A por menos código a testear).

---

## P3-14. CI/CD

`.github/workflows/ci.yml`:

```yaml
name: ci
on: [push, pull_request]
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 20 }
      - run: cd miniweed-tunnel/web && npm ci
      - run: cd miniweed-tunnel/web && npx eslint .
      - run: docker run --rm -v "$PWD":/mnt koalaman/shellcheck:stable miniweed-tunnel/wg-client/entrypoint.sh

  test:
    runs-on: ubuntu-latest
    needs: lint
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 20 }
      - run: cd miniweed-tunnel/web && npm ci && npm test

  script-shellcheck:
    runs-on: ubuntu-latest
    needs: test
    steps:
      - uses: actions/checkout@v4
      - run: cd miniweed-tunnel/web && npm ci
      - name: Generate test script and shellcheck it
        run: |
          cd miniweed-tunnel/web
          node -e "console.log(require('./server.js').buildVpsSetupScript({publicKey:'AAAA',vpsIp:'1.2.3.4',vpsPort:51820,presharedKey:'BBBB'}))" > /tmp/test-script.sh
          docker run --rm -v /tmp:/mnt koalaman/shellcheck:stable /mnt/test-script.sh

  build:
    runs-on: ubuntu-latest
    needs: test
    steps:
      - uses: actions/checkout@v4
      - uses: docker/setup-buildx-action@v3
      - uses: docker/login-action@v3
        with: { registry: ghcr.io, username: ${{ github.actor }}, password: ${{ secrets.GITHUB_TOKEN }} }
      - uses: docker/build-push-action@v5
        with:
          context: miniweed-tunnel/web
          tags: ghcr.io/${{ github.repository_owner }}/umbrel-tunnel-web:${{ github.sha }}
          push: ${{ github.ref == 'refs/heads/main' }}
      - uses: aquasecurity/trivy-action@master
        with:
          image-ref: ghcr.io/${{ github.repository_owner }}/umbrel-tunnel-web:${{ github.sha }}
          format: sarif
          output: trivy.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with: { sarif_file: trivy.sarif }
```

Job nuevo `script-shellcheck`: genera el script con valores de prueba y lo pasa por shellcheck en CI. **Crítico** porque cualquier sintaxis rota en el generador rompería instalaciones en producción.

**Esfuerzo:** 10-14 horas.

---

## P3-15. README + threat model

Idéntico a variante A en estructura, pero el threat model debe documentar **explícitamente** que el deploy SSH **no existe** y por qué:

```markdown
## Threat model

### En scope
- MITM entre cliente final e internet/VPS
- Sniffing en el VPS (compromiso parcial)
- Compromiso de un servicio interno aislado por subdominio
- Exfiltración de config en backup

### Fuera de scope
- Compromiso de root del Umbrel host
- Compromiso de root del VPS (asumimos hardening base por el script)
- Malware en el dispositivo del usuario (que usa la UI)

### Decisiones de diseño explícitas
- **No hay deploy SSH automático del VPS.** Razón: minimizar superficie de ataque. El setup del VPS se hace mediante script descargable, generado y firmado por el Umbrel, que el usuario ejecuta manualmente. Esto elimina:
  - Transmisión de claves SSH privadas por la API
  - Necesidad de validar host keys SSH desde el Umbrel
  - Riesgo de fuga de credenciales en stdout/stderr
- **Verificación de integridad por fingerprint cruzado.** El script de setup imprime el fingerprint de la pubkey del VPS al final; el usuario lo verifica contra lo que muestra la UI tras pegar la pubkey.
```

**Esfuerzo:** 6-10 horas.

---

## P3-16. SPA frontend con build pipeline

Idéntico a variante A. Vite + Preact.

```
web/
  ui/
    src/
      App.jsx
      api.js
      pages/
        Dashboard.jsx
        Services.jsx
        Setup.jsx
        VpsScript.jsx   # nuevo: muestra script y fingerprint
      components/
    package.json
    vite.config.js
  server.js
```

CSP estricta sin `unsafe-inline` tras la migración:

```
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'
```

**Esfuerzo:** 36-56 horas (menor que A por menos UI — sin sección de deploy SSH ni jobs de progreso).

---

## P3-17. Contrato de API tipado

Idéntico a variante A, con menos endpoints en el spec (sin `/deploy-vps/*`).

```js
const { z } = require('zod');

const ServiceSchema = z.object({
  name: z.string().min(1).max(64),
  subdomain: z.string().regex(/^[a-z0-9-]{1,63}$/),
  target: z.string().regex(/^https?:\/\/[^\/\?#]+$/),
  enabled: z.boolean(),
});

const ConfigUpdateSchema = z.object({
  domain: z.string().regex(/^[a-zA-Z0-9.\-]{1,253}$/),
  acmeEmail: z.string().email(),
  services: z.array(ServiceSchema).max(64),
});

const VpsConfigSchema = z.object({
  vpsIp: z.string().ip(),
  vpsPort: z.number().int().min(1).max(65535),
  vpsServerPubkey: z.string().regex(/^[A-Za-z0-9+/]{43}=$/),
});

module.exports = { ServiceSchema, ConfigUpdateSchema, VpsConfigSchema };
```

Middleware genérico:

```js
function validateBody(schema) {
  return (req, res, next) => {
    const r = schema.safeParse(req.body);
    if (!r.success) return res.status(400).json({ error: 'validation', issues: r.error.issues });
    req.body = r.data;
    next();
  };
}
app.post('/api/config', validateBody(ConfigUpdateSchema), handlerConfig);
app.post('/api/vps', validateBody(VpsConfigSchema), handlerVps);
```

**Esfuerzo:** 14-20 horas (menor por menos endpoints).

---

# P4 — Diferenciación

## P4-18. Auth multicapa

Idéntico a variante A. Password Argon2id + claves públicas Ed25519.

```js
const argon2 = require('argon2');

app.post('/api/auth/login', validateBody(z.object({ password: z.string().min(8).max(256) })), async (req, res) => {
  const cfg = loadConfig();
  if (!cfg.auth?.passwordHash) return res.status(400).json({ error: 'no password set' });
  const ok = await argon2.verify(cfg.auth.passwordHash, req.body.password);
  if (!ok) {
    auditLog({ action: 'auth.fail', ip: req.ip });
    await delay(authFailureDelay(req.ip));
    return res.status(401).json({ error: 'invalid' });
  }
  const session = createSession(req);
  res.cookie('mw_session', session.id, { httpOnly: true, secure: true, sameSite: 'strict', maxAge: 24 * 3600 * 1000 });
  auditLog({ action: 'auth.success', ip: req.ip });
  res.json({ ok: true });
});

app.post('/api/auth/password', validateBody(z.object({ password: z.string().min(12).max(256) })), async (req, res) => {
  const hash = await argon2.hash(req.body.password, {
    type: argon2.argon2id, memoryCost: 64 * 1024, timeCost: 3, parallelism: 4,
  });
  mutateConfig(c => { c.auth = { ...c.auth, passwordHash: hash }; });
  res.json({ ok: true });
});
```

**Pubkey flow** (challenge/response Ed25519):

```js
const { verify: edVerify } = require('@noble/ed25519');

const challenges = new Map(); // keyId -> { nonce, expiresAt }

app.post('/api/auth/challenge', validateBody(z.object({ keyId: z.string() })), (req, res) => {
  const nonce = crypto.randomBytes(32);
  challenges.set(req.body.keyId, { nonce, expiresAt: Date.now() + 60_000 });
  res.json({ nonce: nonce.toString('base64') });
});

app.post('/api/auth/verify', validateBody(z.object({
  keyId: z.string(), signature: z.string(),
})), async (req, res) => {
  const ch = challenges.get(req.body.keyId);
  if (!ch || ch.expiresAt < Date.now()) return res.status(401).json({ error: 'no challenge' });
  challenges.delete(req.body.keyId);
  const stored = loadConfig().auth.pubkeys.find(p => p.id === req.body.keyId);
  if (!stored) return res.status(401).json({ error: 'unknown key' });
  const ok = await edVerify(
    Buffer.from(req.body.signature, 'base64'),
    ch.nonce,
    Buffer.from(stored.key, 'base64')
  );
  if (!ok) return res.status(401).json({ error: 'invalid signature' });
  const session = createSession(req);
  res.json({ session: session.id });
});
```

**Esfuerzo:** 32-48 horas.

---

## P4-19. Kill switch remoto

Idéntico a variante A. **Especialmente útil en esta variante**, dado que sin deploy SSH automatizado, el usuario no tiene un mecanismo de "apagar todo desde la UI" si pierde acceso al Umbrel.

Daemon `miniweed-vps-control` en el VPS con socket Unix, autenticación Ed25519:

```bash
# /usr/local/bin/miniweed-killswitch
#!/usr/bin/env bash
set -euo pipefail
EMERGENCY_PUBKEY=$(cat /etc/miniweed/emergency.pub)
ACTION=$(curl -s -X POST --unix-socket /var/run/miniweed.sock http://localhost/get-action || echo "")
if [[ "$ACTION" == "kill" ]]; then
  systemctl stop wg-quick@wg0
  iptables -A INPUT -p udp --dport 51820 -j DROP
  echo "killed" > /var/run/miniweed.status
fi
```

CLI fuera de Umbrel:

```bash
miniweed-cli kill --vps 1.2.3.4 --key ./emergency.key
```

Setup: la clave de emergencia se genera durante el `vps-setup-script` (P0-3-bis) y se muestra al usuario para que la guarde en cold storage.

**Esfuerzo:** 24-40 horas.

---

## P4-20. Multi-VPS / failover

Idéntico a variante A. Más complejidad operacional sin deploy SSH porque cada VPS requiere ejecución manual del script.

Mitigación: la UI permite generar **scripts diferenciados** por VPS (cada uno con sus claves) y mantener N pendings. Se pueden gestionar en paralelo si el usuario tiene un terminal abierto a cada VPS.

**Esfuerzo:** 36-56 horas.

---

## P4-21. CrowdSec en el VPS

Idéntico a variante A. Se integra en `buildVpsSetupScript` como sección opcional (flag `--with-crowdsec`):

```bash
if [ "$WITH_CROWDSEC" -eq 1 ]; then
  log "Instalando CrowdSec..."
  curl -s https://install.crowdsec.net | sh
  apt-get install -y crowdsec
  cscli collections install crowdsecurity/sshd
  apt-get install -y crowdsec-firewall-bouncer-iptables
  systemctl enable --now crowdsec crowdsec-firewall-bouncer
fi
```

**Esfuerzo:** 8-16 horas.

---

# Roadmap sugerido

| Sprint | Tareas | Esfuerzo total |
|---|---|---|
| **Sprint 1** (semana 1-2) | P0-1, P0-2, P0-3 (eliminación), P0-3-bis (nuevo script), P1-7, P1-8 | ~50h |
| **Sprint 2** (semana 3-4) | P1-4, P1-5, P1-6 | ~18h |
| **Sprint 3** (semana 5-6) | P3-13, P3-14, P3-15 | ~50h |
| **Sprint 4** (semana 7-8) | P2-9, P2-10, P2-12 | ~28h |
| **Sprint 5** (semana 9-10) | P2-11, P3-17 | ~32h |
| **Sprint 6** (semana 11-13) | P3-16 | ~50h |
| **Sprint 7** (semana 14+) | P4-18, P4-19, P4-20, P4-21 | ~140h |

**Total estimado: ~365h** (vs ~390h en variante A).

**Ventajas de esta variante vs A:**
- **~25h menos de esfuerzo total** (sin P0-3 complejo, menos test surface, menos UI).
- **Menor superficie de ataque permanente**.
- **Menos dependencias** (`ssh2` fuera, `cookie-parser` quizás de regalo).
- **Modelo mental más simple** para usuario y dev.

**Trade-offs:**
- UX del setup inicial: copy/paste en lugar de un click.
- UX de rotación: copy/paste + confirmación en lugar de automático.
- Pierde la feature "WOW" del deploy desde la UI.

**Recomendación.** Para un proyecto open-source con foco en seguridad, **esta variante es la correcta**. La feature de deploy SSH es atractiva para demos pero su valor de seguridad neto es negativo a menos que se invierta mucho en hardening (P0-3 de la variante A). El compromiso copy/paste es aceptable en el contexto (un setup inicial de pocos minutos cada N meses no es un punto de dolor real).

---

# Apéndice: archivos a crear / modificar

```
miniweed-tunnel/
├── README.md                          # P3-15
├── SECURITY.md                        # P3-15
├── CONTRIBUTING.md                    # P3-15
├── .github/
│   └── workflows/
│       └── ci.yml                     # P3-14
├── web/
│   ├── lib/
│   │   ├── cryptobox.js              # P0-1
│   │   ├── audit.js                  # P1-4
│   │   ├── ratelimit.js              # P1-6
│   │   ├── health.js                 # P2-10
│   │   ├── backup.js                 # P2-9
│   │   ├── auth.js                   # P4-18
│   │   └── vps-script.js             # P0-3-bis (módulo del generador)
│   ├── api-spec/
│   │   ├── schemas.js                # P3-17
│   │   └── openapi.json              # P3-17 (generado)
│   ├── ui/                           # P3-16
│   └── test/                         # P3-13
│       ├── unit/
│       ├── integration/
│       └── e2e/
├── wg-client/
│   └── scripts/
│       └── killswitch.sh             # P4-19
└── vps-setup/
    ├── rotate-template.sh            # P2-11 (template, llenado por server.js)
    ├── crowdsec.sh                   # P4-21
    └── multi-vps.sh                  # P4-20
```

**Archivos a ELIMINAR comparado con el código actual:**
- Toda la sección SSH deploy en `server.js` (líneas ~570-1080)
- Toda la sección de UI deploy SSH en `index.html` (líneas ~740-870)
- Dependencia `ssh2` en `package.json`
