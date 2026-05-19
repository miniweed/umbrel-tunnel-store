const express = require('express');
const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');
const net = require('net');
const zlib = require('zlib');
const crypto = require('crypto');
const dns = require('dns');
const {
  ConfigSchema,
  AuthPasswordSchema,
  AuthLoginSchema,
  RotatePrepareSchema,
  RotateConfirmSchema
} = require('./api-spec/schemas');
const { seal, open, isSealed } = require('./lib/cryptobox');
const audit = require('./lib/audit');

const app = express();
const DATA_DIR = process.env.DATA_DIR || '/data';
const WG_API_HOST = process.env.WG_API_HOST || 'wg';
const WG_API_PORT = 8080;
let API_AUTH_TOKEN = '';
let configLock = Promise.resolve();
const MAX_SERVICES = 64;
const MAX_VPS_TARGETS = 8;
const FAILOVER_POLICY_DEFAULTS = {
  activeFailuresRequired: 2,
  candidateSuccessesRequired: 2,
  cooldownMs: 2 * 60 * 1000
};

const CONFIG_FILE = path.join(DATA_DIR, 'config.json');
const WG_CONF = path.join(DATA_DIR, 'wg0.conf');
const CADDYFILE = path.join(DATA_DIR, 'Caddyfile');
const TOKEN_FILE = path.join(DATA_DIR, 'api-token.enc');
const APP_SEED_FILE = path.join(DATA_DIR, 'app-seed');
const HEALTH_FILE = path.join(DATA_DIR, 'health.json');
const KNOWN_HOSTS_FILE = path.join(DATA_DIR, 'known_hosts.json');
const ENCRYPTED_FIELDS = ['privateKey', 'presharedKey'];
const SESSION_COOKIE = 'mw_session';
const SESSION_TTL_MS = 24 * 60 * 60 * 1000;
const loginFailures = new Map();
const authChallenges = new Map();
const CHALLENGE_TTL_MS = 5 * 60 * 1000;
const rotationPlans = new Map();
const ROTATION_PLAN_TTL_MS = 30 * 60 * 1000;
const failoverState = new Map();
let failoverLastSwitchAt = 0;

const DEFAULT_CONFIG = {
  privateKey: '',
  publicKey: '',
  presharedKey: '',
  vpsIp: '',
  vpsPort: 51820,
  vpsPubKey: '',
  vpsTargets: [],
  activeVpsId: '',
  tunnelClientIp: '10.8.0.2',
  tunnelServerIp: '10.8.0.1',
  domain: '',
  acmeEmail: '',
  services: [],
  serviceHealth: {},
  auth: {
    passwordHash: '',
    sessions: [],
    pubkeys: []
  },
  failoverPolicy: { ...FAILOVER_POLICY_DEFAULTS }
};

const DEFAULT_CADDYFILE = ':80 {\n  respond "Umbrel Tunnel — not configured yet"\n}\n';

app.use(express.json({ limit: '32kb' }));
app.disable('x-powered-by');

function cspHeaderForPath(pathname) {
  const path = String(pathname || '');
  const isLegacy = path === '/legacy' || path.startsWith('/legacy/');
  if (isLegacy) {
    return "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'";
  }
  return "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'";
}

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  const isHttps = req.secure || req.get('x-forwarded-proto') === 'https';
  if (isHttps) {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  res.setHeader('Content-Security-Policy', cspHeaderForPath(req.path));
  next();
});

const rateBuckets = {
  default: { max: 120, windowMs: 60_000 },
  '/api/keygen': { max: 5, windowMs: 3_600_000 },
  '/api/vps-setup-script': { max: 10, windowMs: 600_000 },
  '/api/config': { max: 30, windowMs: 60_000 },
  '/api/auth/login': { max: 5, windowMs: 60_000 },
  '/api/rotate/prepare': { max: 3, windowMs: 300_000 },
  '/api/rotate/confirm': { max: 5, windowMs: 300_000 }
};
const apiRateStore = new Map();
let rateGc = null;
let challengeGc = null;
let rotationGc = null;
let healthTimer = null;
let runningServers = 0;

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

function hashPassword(password) {
  const N = 1 << 15;
  const r = 8;
  const p = 1;
  const salt = crypto.randomBytes(16);
  const key = crypto.scryptSync(password, salt, 32, { N, r, p, maxmem: 128 * 1024 * 1024 });
  return `scrypt$${N}$${r}$${p}$${salt.toString('base64')}$${key.toString('base64')}`;
}

function verifyPassword(password, encoded) {
  if (!encoded || typeof encoded !== 'string') return false;
  const parts = encoded.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
  const N = parseInt(parts[1], 10);
  const r = parseInt(parts[2], 10);
  const p = parseInt(parts[3], 10);
  const salt = Buffer.from(parts[4], 'base64');
  const expected = Buffer.from(parts[5], 'base64');
  const actual = crypto.scryptSync(password, salt, expected.length, { N, r, p, maxmem: 128 * 1024 * 1024 });
  return crypto.timingSafeEqual(actual, expected);
}

function authFailureDelayMs(ip) {
  const now = Date.now();
  const entry = loginFailures.get(ip) || { fails: 0, blockUntil: 0 };
  if (entry.blockUntil > now) return entry.blockUntil - now;
  const nextFails = entry.fails + 1;
  const delay = Math.min(16_000, 1000 * (2 ** (nextFails - 1)));
  const blockUntil = nextFails >= 6 ? now + 60 * 60 * 1000 : 0;
  loginFailures.set(ip, { fails: nextFails, blockUntil });
  return delay;
}

function clearAuthFailures(ip) {
  loginFailures.delete(ip);
}

function parseEd25519PublicKey(input) {
  const value = String(input || '').trim();
  if (!value) return null;

  // 1) Raw DER SPKI in base64
  try {
    const keyObject = crypto.createPublicKey({
      key: Buffer.from(value, 'base64'),
      format: 'der',
      type: 'spki'
    });
    if (keyObject.asymmetricKeyType === 'ed25519') {
      return keyObject.export({ format: 'der', type: 'spki' }).toString('base64');
    }
  } catch {
    // Try next format.
  }

  // 2) OpenSSH format: ssh-ed25519 AAAA... [comment]
  if (value.startsWith('ssh-ed25519 ')) {
    const parts = value.split(/\s+/).filter(Boolean);
    if (parts.length >= 2) {
      try {
        const blob = Buffer.from(parts[1], 'base64');
        let idx = 0;
        const readStr = () => {
          if (idx + 4 > blob.length) throw new Error('short blob');
          const len = blob.readUInt32BE(idx);
          idx += 4;
          if (idx + len > blob.length) throw new Error('short blob');
          const out = blob.slice(idx, idx + len);
          idx += len;
          return out;
        };
        const type = readStr().toString('utf8');
        const rawKey = readStr();
        if (type !== 'ssh-ed25519' || rawKey.length !== 32) return null;
        const jwk = {
          kty: 'OKP',
          crv: 'Ed25519',
          x: rawKey.toString('base64url')
        };
        const keyObject = crypto.createPublicKey({ key: jwk, format: 'jwk' });
        return keyObject.export({ format: 'der', type: 'spki' }).toString('base64');
      } catch {
        return null;
      }
    }
  }

  return null;
}

function cleanupAuthChallenges() {
  const now = Date.now();
  for (const [id, challenge] of authChallenges.entries()) {
    if (!challenge || challenge.expiresAt <= now) authChallenges.delete(id);
  }
}

function cleanupRotationPlans() {
  const now = Date.now();
  for (const [id, plan] of rotationPlans.entries()) {
    if (!plan || plan.expiresAt <= now) rotationPlans.delete(id);
  }
}

function createSession(ip, source = 'web') {
  const now = Date.now();
  return {
    id: crypto.randomBytes(24).toString('base64url'),
    createdAt: now,
    expiresAt: now + SESSION_TTL_MS,
    ip,
    source
  };
}

function cleanupApiRateStore() {
  const now = Date.now();
  for (const [bucketName, bucketStore] of apiRateStore.entries()) {
    for (const [ip, entry] of bucketStore.entries()) {
      if (!entry || now > entry.resetAt) bucketStore.delete(ip);
    }
    if (bucketStore.size === 0) apiRateStore.delete(bucketName);
  }
}

function ensureBackgroundTimers() {
  if (!rateGc) {
    rateGc = setInterval(cleanupApiRateStore, 60 * 1000);
    if (typeof rateGc.unref === 'function') rateGc.unref();
  }
  if (!challengeGc) {
    challengeGc = setInterval(cleanupAuthChallenges, 60 * 1000);
    if (typeof challengeGc.unref === 'function') challengeGc.unref();
  }
  if (!rotationGc) {
    rotationGc = setInterval(cleanupRotationPlans, 60 * 1000);
    if (typeof rotationGc.unref === 'function') rotationGc.unref();
  }
}

function stopBackgroundTimers() {
  if (rateGc) {
    clearInterval(rateGc);
    rateGc = null;
  }
  if (challengeGc) {
    clearInterval(challengeGc);
    challengeGc = null;
  }
  if (rotationGc) {
    clearInterval(rotationGc);
    rotationGc = null;
  }
  if (healthTimer) {
    clearInterval(healthTimer);
    healthTimer = null;
  }
}

function apiRateLimit(req, res, next) {
  const bucketName = rateBuckets[req.path] ? req.path : 'default';
  const bucket = rateBuckets[bucketName];
  const store = apiRateStore.get(bucketName) || new Map();
  apiRateStore.set(bucketName, store);
  const now = Date.now();
  const ip = req.ip || req.socket?.remoteAddress || 'unknown';
  const entry = store.get(ip);

  if (!entry || now > entry.resetAt) {
    store.set(ip, { count: 1, resetAt: now + bucket.windowMs });
    return next();
  }

  entry.count += 1;
  if (entry.count > bucket.max) {
    const retryAfter = Math.max(1, Math.ceil((entry.resetAt - now) / 1000));
    res.setHeader('Retry-After', String(retryAfter));
    return res.status(429).json({ error: 'Demasiadas peticiones, prueba de nuevo en un minuto' });
  }

  return next();
}

function requireApiAuth(req, res, next) {
  if (
    req.path === '/auth/login'
    || req.path === '/api/auth/login'
    || req.path === '/auth/challenge'
    || req.path === '/auth/verify'
    || req.path === '/api/auth/challenge'
    || req.path === '/api/auth/verify'
  ) return next();
  const headerToken = req.get('x-tunnel-api-token') || '';
  const cookieToken = parseCookies(req).tunnel_api_token || '';
  const sessionToken = parseCookies(req)[SESSION_COOKIE] || '';
  const expected = Buffer.from(String(API_AUTH_TOKEN).padEnd(128).slice(0, 128));
  const headerOk = crypto.timingSafeEqual(Buffer.from(String(headerToken).padEnd(128).slice(0, 128)), expected);
  const cookieOk = crypto.timingSafeEqual(Buffer.from(String(cookieToken).padEnd(128).slice(0, 128)), expected);
  const cfg = loadConfig();
  const now = Date.now();
  const sessions = Array.isArray(cfg.auth?.sessions) ? cfg.auth.sessions : [];
  const sessionOk = Boolean(sessionToken && sessions.some(s => s.id === sessionToken && s.expiresAt > now));
  if (!headerOk && !cookieOk && !sessionOk) {
    audit.log({ action: 'auth.fail', ip: req.ip, path: req.path });
    return res.status(401).json({ error: 'No autorizado' });
  }
  if (req.path !== '/status') {
    audit.log({ action: 'auth.success', ip: req.ip, path: req.path });
  }
  return next();
}

app.use('/api', apiRateLimit, requireApiAuth);
app.use((req, res, next) => {
  res.on('finish', () => {
    if (!req.path.startsWith('/api/')) return;
    if (req.method === 'GET' && res.statusCode === 200 && req.path !== '/api/vps-setup-script') return;
    audit.log({
      action: `http.${req.method.toLowerCase()}`,
      path: req.path,
      status: res.statusCode,
      ip: req.ip,
      ua: (req.get('user-agent') || '').slice(0, 120)
    });
  });
  next();
});

function setApiTokenCookie(req, res) {
  if (!API_AUTH_TOKEN) return;
  const secureAttr = req.secure || req.get('x-forwarded-proto') === 'https' ? '; Secure' : '';
  res.setHeader('Set-Cookie', `tunnel_api_token=${encodeURIComponent(API_AUTH_TOKEN)}; Path=/; HttpOnly; SameSite=Strict${secureAttr}`);
}

app.use(express.static(path.join(__dirname, 'public'), { index: false }));

app.get(['/', '/index.html'], (req, res, next) => {
  const spaIndex = path.join(__dirname, 'public', 'app', 'index.html');
  if (fs.existsSync(spaIndex)) {
    setApiTokenCookie(req, res);
    return res.sendFile(spaIndex);
  }

  const legacyIndex = path.join(__dirname, 'public', 'index.html');
  if (!fs.existsSync(legacyIndex)) return next();
  let html = fs.readFileSync(legacyIndex, 'utf8');
  html = html.replace('__TUNNEL_API_TOKEN__', JSON.stringify(''));
  setApiTokenCookie(req, res);
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  return res.send(html);
});

app.get(['/legacy', '/legacy/index.html'], (req, res, next) => {
  const legacyIndex = path.join(__dirname, 'public', 'index.html');
  if (!fs.existsSync(legacyIndex)) return next();
  let html = fs.readFileSync(legacyIndex, 'utf8');
  html = html.replace('__TUNNEL_API_TOKEN__', JSON.stringify(''));
  setApiTokenCookie(req, res);
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  return res.send(html);
});

app.get(['/app', '/app/*'], (req, res, next) => {
  const spaIndex = path.join(__dirname, 'public', 'app', 'index.html');
  if (!fs.existsSync(spaIndex)) return next();
  setApiTokenCookie(req, res);
  return res.sendFile(spaIndex);
});

// ── helpers ──────────────────────────────────────────────────────────────────

function ensureDataDir() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(CADDYFILE)) {
    fs.writeFileSync(CADDYFILE, DEFAULT_CADDYFILE);
  }
}

function encryptConfig(cfg) {
  const out = { ...cfg, _encVersion: 1 };
  for (const f of ENCRYPTED_FIELDS) {
    if (out[f] && !isSealed(out[f])) out[f] = seal(out[f]);
  }
  if (Array.isArray(out.services)) {
    out.services = out.services.map(svc => ({
      ...svc,
      target: svc.target && !isSealed(svc.target) ? seal(svc.target) : svc.target
    }));
  }

  const auth = out.auth && typeof out.auth === 'object' ? { ...out.auth } : {};
  if (auth.passwordHash && !isSealed(auth.passwordHash)) {
    auth.passwordHash = seal(auth.passwordHash);
  }
  if (Array.isArray(auth.sessions) && !isSealed(auth.sessions)) {
    auth.sessions = seal(JSON.stringify(auth.sessions));
  }
  out.auth = auth;

  out.failoverPolicy = normalizeFailoverPolicy(out.failoverPolicy);
  return out;
}

function decryptConfig(cfg) {
  const out = { ...cfg };
  for (const f of ENCRYPTED_FIELDS) {
    if (isSealed(out[f])) out[f] = open(out[f]);
  }
  if (Array.isArray(out.services)) {
    out.services = out.services.map(svc => ({
      ...svc,
      target: isSealed(svc.target) ? open(svc.target) : svc.target
    }));
  }

  const auth = out.auth && typeof out.auth === 'object' ? { ...out.auth } : {};
  if (isSealed(auth.passwordHash)) {
    auth.passwordHash = open(auth.passwordHash) || '';
  }
  if (isSealed(auth.sessions)) {
    try {
      const dec = open(auth.sessions);
      const parsed = dec ? JSON.parse(dec) : [];
      auth.sessions = Array.isArray(parsed) ? parsed : [];
    } catch {
      auth.sessions = [];
    }
  }
  out.auth = auth;

  return out;
}

function normalizeFailoverPolicy(input) {
  const policy = input && typeof input === 'object' ? input : {};
  const activeRaw = parseInt(policy.activeFailuresRequired, 10);
  const candidateRaw = parseInt(policy.candidateSuccessesRequired, 10);
  const cooldownRaw = parseInt(policy.cooldownMs, 10);
  return {
    activeFailuresRequired: Number.isFinite(activeRaw) && activeRaw >= 1 && activeRaw <= 10
      ? activeRaw
      : FAILOVER_POLICY_DEFAULTS.activeFailuresRequired,
    candidateSuccessesRequired: Number.isFinite(candidateRaw) && candidateRaw >= 1 && candidateRaw <= 10
      ? candidateRaw
      : FAILOVER_POLICY_DEFAULTS.candidateSuccessesRequired,
    cooldownMs: Number.isFinite(cooldownRaw) && cooldownRaw >= 0 && cooldownRaw <= 3_600_000
      ? cooldownRaw
      : FAILOVER_POLICY_DEFAULTS.cooldownMs
  };
}

function extractFailoverPolicy(cfg) {
  return normalizeFailoverPolicy(cfg?.failoverPolicy);
}

function openApiFailoverPolicySchema() {
  return {
    type: 'object',
    properties: {
      activeFailuresRequired: { type: 'integer', minimum: 1, maximum: 10 },
      candidateSuccessesRequired: { type: 'integer', minimum: 1, maximum: 10 },
      cooldownMs: { type: 'integer', minimum: 0, maximum: 3600000 }
    }
  };
}

function migrateConfigIfNeeded() {
  if (!fs.existsSync(CONFIG_FILE)) return;
  try {
    const raw = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
    if (raw && raw._encVersion === 1) return;
    const backup = CONFIG_FILE + '.v0.bak';
    fs.copyFileSync(CONFIG_FILE, backup);
    fs.chmodSync(backup, 0o600);
    saveConfig(raw || {});
    console.log('[migration] config.json encrypted v0 -> v1');
  } catch (err) {
    console.error('[migration] failed to migrate config:', err.message);
  }
}

function loadOrCreateApiToken() {
  const seed = (process.env.APP_SEED || process.env.TUNNEL_API_TOKEN || '').trim();
  if (seed.length >= 32) {
    const tok = crypto.hkdfSync(
      'sha256',
      Buffer.from(seed, 'utf8'),
      Buffer.from('miniweed-tunnel/v1', 'utf8'),
      Buffer.from('tunnel-api-token-v1', 'utf8'),
      32
    );
    return Buffer.from(tok).toString('base64url');
  }

  if (fs.existsSync(TOKEN_FILE)) {
    try {
      const blob = JSON.parse(fs.readFileSync(TOKEN_FILE, 'utf8'));
      const token = open(blob);
      if (token && token.length >= 32) return token;
    } catch {
      // Continue with failure path.
    }
  }

  const fallback = crypto.randomBytes(32).toString('base64url');
  try {
    fs.writeFileSync(TOKEN_FILE, JSON.stringify(seal(fallback)), { mode: 0o600 });
  } catch (err) {
    console.error(`[warn] could not persist API token: ${err.message}`);
  }
  return fallback;
}

function loadOrCreateAppSeed() {
  const envSeed = (process.env.APP_SEED || process.env.TUNNEL_API_TOKEN || '').trim();
  if (envSeed.length >= 32) return envSeed;

  if (fs.existsSync(APP_SEED_FILE)) {
    try {
      const stored = String(fs.readFileSync(APP_SEED_FILE, 'utf8') || '').trim();
      if (stored.length >= 32) return stored;
    } catch {
      // Continue to regeneration path.
    }
  }

  const generated = crypto.randomBytes(48).toString('base64url');
  try {
    fs.writeFileSync(APP_SEED_FILE, `${generated}\n`, { mode: 0o600 });
  } catch (err) {
    console.error(`[warn] could not persist app seed: ${err.message}`);
  }
  return generated;
}

function loadConfig() {
  try {
    const raw = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
    const dec = decryptConfig(raw);
    const cfg = { ...DEFAULT_CONFIG, ...dec };
    cfg.auth = {
      ...DEFAULT_CONFIG.auth,
      ...(cfg.auth || {}),
      sessions: Array.isArray(cfg.auth?.sessions) ? cfg.auth.sessions : []
    };
    cfg.failoverPolicy = normalizeFailoverPolicy(cfg.failoverPolicy);
    ensureVpsTargets(cfg);
    return cfg;
  } catch {
    const cfg = { ...DEFAULT_CONFIG };
    cfg.failoverPolicy = normalizeFailoverPolicy(cfg.failoverPolicy);
    ensureVpsTargets(cfg);
    return cfg;
  }
}

function saveConfig(cfg) {
  fs.mkdirSync(path.dirname(CONFIG_FILE), { recursive: true });
  const tmp = CONFIG_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(encryptConfig(cfg), null, 2), { mode: 0o600 });
  fs.renameSync(tmp, CONFIG_FILE);
}

function normalizeVpsTarget(raw, index = 0) {
  const idRaw = String(raw?.id || '').trim();
  const id = idRaw || crypto.createHash('sha256').update(`${Date.now()}-${Math.random()}-${index}`).digest('hex').slice(0, 16);
  const name = String(raw?.name || '').trim() || `VPS ${index + 1}`;
  const ip = String(raw?.ip || '').trim();
  const portRaw = parseInt(raw?.port, 10);
  const port = Number.isFinite(portRaw) ? portRaw : 51820;
  const pubKey = String(raw?.pubKey || '').trim();
  const enabled = raw?.enabled !== false;
  const priorityRaw = parseInt(raw?.priority, 10);
  const priority = Number.isFinite(priorityRaw) ? priorityRaw : index;
  const lastHealth = raw?.lastHealth && typeof raw.lastHealth === 'object'
    ? {
        ok: Boolean(raw.lastHealth.ok),
        checkedAt: String(raw.lastHealth.checkedAt || ''),
        message: String(raw.lastHealth.message || ''),
        latencyMs: Number.isFinite(raw.lastHealth.latencyMs) ? raw.lastHealth.latencyMs : null
      }
    : null;
  return { id, name, ip, port, pubKey, enabled, priority, lastHealth };
}

function ensureVpsTargets(cfg) {
  const targets = [];
  if (Array.isArray(cfg.vpsTargets)) {
    for (const [i, raw] of cfg.vpsTargets.entries()) {
      const t = normalizeVpsTarget(raw, i);
      if (!t.ip && !t.pubKey) continue;
      targets.push(t);
    }
  }

  if (!targets.length && (cfg.vpsIp || cfg.vpsPubKey)) {
    targets.push(normalizeVpsTarget({
      id: 'primary',
      name: 'VPS principal',
      ip: cfg.vpsIp,
      port: cfg.vpsPort,
      pubKey: cfg.vpsPubKey,
      enabled: true,
      priority: 0
    }, 0));
  }

  cfg.vpsTargets = targets.slice(0, MAX_VPS_TARGETS);
  const preferred = String(cfg.activeVpsId || '').trim();
  const active = cfg.vpsTargets.find(t => t.id === preferred)
    || cfg.vpsTargets.find(t => t.enabled && t.ip)
    || cfg.vpsTargets[0]
    || null;
  cfg.activeVpsId = active ? active.id : '';

  if (active) {
    cfg.vpsIp = active.ip;
    cfg.vpsPort = active.port;
    cfg.vpsPubKey = active.pubKey;
  }
}

function getActiveVpsTarget(cfg) {
  ensureVpsTargets(cfg);
  return cfg.vpsTargets.find(t => t.id === cfg.activeVpsId) || null;
}

function recordVpsProbeResult(targetId, ok) {
  const current = failoverState.get(targetId) || { okStreak: 0, failStreak: 0 };
  const next = ok
    ? { okStreak: current.okStreak + 1, failStreak: 0 }
    : { okStreak: 0, failStreak: current.failStreak + 1 };
  failoverState.set(targetId, next);
  return next;
}

function getVpsProbeState(targetId) {
  return failoverState.get(targetId) || { okStreak: 0, failStreak: 0 };
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
  const raw = Buffer.from(key, 'base64');
  const hash = crypto.createHash('sha256').update(raw).digest();
  return hash.slice(0, 16).toString('hex').match(/.{2}/g).join(':');
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

async function validateEmailWithMx(value) {
  if (!value) return { ok: true, reason: 'empty' };
  const match = String(value).match(/^[A-Za-z0-9._%+\-]+@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})$/);
  if (!match) return { ok: false, reason: 'syntax' };
  try {
    const mx = await dns.promises.resolveMx(match[1]);
    if (!Array.isArray(mx) || mx.length === 0) return { ok: false, reason: 'mx_empty' };
    return { ok: true, mxCount: mx.length };
  } catch (err) {
    return { ok: false, reason: 'mx_lookup_failed', code: err.code || 'unknown' };
  }
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

function validateBody(schema) {
  return (req, res, next) => {
    const parsed = schema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: 'validation', issues: parsed.error.issues });
    }
    req.body = parsed.data;
    return next();
  };
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

function probeTcpPort(hostname, port, timeoutMs = 1500) {
  return new Promise(resolve => {
    const started = Date.now();
    const socket = new net.Socket();
    let settled = false;
    const done = (result) => {
      if (settled) return;
      settled = true;
      try { socket.destroy(); } catch {}
      resolve(result);
    };
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => {
      done({ ok: true, latencyMs: Date.now() - started, message: `tcp:${port}` });
    });
    socket.once('timeout', () => done({ ok: false, message: `timeout tcp:${port}` }));
    socket.once('error', err => done({ ok: false, message: err.message }));
    try {
      socket.connect(port, hostname);
    } catch (err) {
      done({ ok: false, message: err.message });
    }
  });
}

async function probeVpsTarget(target, timeoutMs = 1500) {
  if (!target || !target.ip) {
    return { ok: false, message: 'sin ip' };
  }
  const wgProbe = await probeTcpPort(target.ip, 22, timeoutMs);
  if (wgProbe.ok) {
    return { ok: true, message: `ssh reachable (${wgProbe.message})`, latencyMs: wgProbe.latencyMs };
  }
  const webProbe = await probeTcpPort(target.ip, 443, timeoutMs);
  if (webProbe.ok) {
    return { ok: true, message: `https reachable (${webProbe.message})`, latencyMs: webProbe.latencyMs };
  }
  return { ok: false, message: `${wgProbe.message}; ${webProbe.message}` };
}

async function computeVpsHealth(targets) {
  const out = {};
  await Promise.all((targets || []).map(async target => {
    if (!target?.id) return;
    if (!target.enabled) {
      out[target.id] = {
        ok: false,
        checked: false,
        checkedAt: new Date().toISOString(),
        message: 'Desactivado'
      };
      return;
    }
    const probe = await probeVpsTarget(target);
    const streak = recordVpsProbeResult(target.id, Boolean(probe.ok));
    out[target.id] = {
      ok: Boolean(probe.ok),
      checked: true,
      checkedAt: new Date().toISOString(),
      message: probe.message || (probe.ok ? 'ok' : 'sin respuesta'),
      latencyMs: Number.isFinite(probe.latencyMs) ? probe.latencyMs : null,
      okStreak: streak.okStreak,
      failStreak: streak.failStreak
    };
  }));
  return out;
}

function pickBestFailoverTarget(cfg, vpsHealth, policy) {
  ensureVpsTargets(cfg);
  const candidates = (cfg.vpsTargets || []).filter(t => t.enabled && t.ip && t.pubKey);
  if (!candidates.length) return null;
  const activeId = cfg.activeVpsId;
  const activeHealth = activeId ? vpsHealth[activeId] : null;
  const activeState = activeId ? getVpsProbeState(activeId) : { failStreak: 0 };
  const activeDegraded = Boolean(activeHealth && !activeHealth.ok && activeState.failStreak >= policy.activeFailuresRequired);
  if (!activeDegraded) return null;

  if (Date.now() - failoverLastSwitchAt < policy.cooldownMs) return null;

  const healthy = candidates
    .filter(t => {
      const health = vpsHealth[t.id];
      const state = getVpsProbeState(t.id);
      return Boolean(health?.ok && state.okStreak >= policy.candidateSuccessesRequired);
    })
    .sort((a, b) => (a.priority - b.priority) || a.name.localeCompare(b.name));
  if (!healthy.length) return null;
  const next = healthy[0];
  if (next.id === activeId) return null;
  return next;
}

async function maybeFailover(cfg, reason = 'auto') {
  const policy = extractFailoverPolicy(cfg);
  const vpsHealth = await computeVpsHealth(cfg.vpsTargets || []);
  const next = pickBestFailoverTarget(cfg, vpsHealth, policy);
  let switched = false;

  if (next) {
    cfg.activeVpsId = next.id;
    ensureVpsTargets(cfg);
    saveConfig(cfg);
    const wgConf = generateWgConf(cfg);
    if (wgConf) fs.writeFileSync(WG_CONF, wgConf);
    switched = true;
    failoverLastSwitchAt = Date.now();
    audit.log({
      action: 'vps.failover',
      reason,
      to: next.id,
      toIp: next.ip
    });
  }

  return {
    switched,
    next: next ? { id: next.id, name: next.name, ip: next.ip } : null,
    vpsHealth,
    policy
  };
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
  ensureVpsTargets(cfg);

  if ((cfg.services || []).length > MAX_SERVICES) {
    errors.push(`Demasiados servicios: máximo ${MAX_SERVICES}`);
  }

  if (cfg.privateKey && !isWireGuardKey(cfg.privateKey)) errors.push('La clave privada de Umbrel no es válida');
  if (cfg.publicKey && !isWireGuardKey(cfg.publicKey)) errors.push('La clave pública de Umbrel no es válida');

  if ((cfg.vpsTargets || []).length > MAX_VPS_TARGETS) {
    errors.push(`Demasiados VPS configurados: máximo ${MAX_VPS_TARGETS}`);
  }

  for (const [index, target] of (cfg.vpsTargets || []).entries()) {
    const label = target.name || `VPS ${index + 1}`;
    if (target.port < 1 || target.port > 65535) {
      errors.push(`El puerto WireGuard de ${label} debe estar entre 1 y 65535`);
    }
    if (target.pubKey && !isWireGuardKey(target.pubKey)) {
      errors.push(`La clave pública de ${label} no es válida`);
    }
    if (target.ip && !/^\d{1,3}(?:\.\d{1,3}){3}$/.test(target.ip) && !isHostname(target.ip)) {
      errors.push(`La IP/host de ${label} no es válida`);
    }
  }

  if (!(cfg.vpsTargets || []).some(t => t.enabled && t.ip)) {
    errors.push('Configura al menos un VPS habilitado con IP/host');
  }

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
  const active = getActiveVpsTarget(cfg);
  if (!cfg.privateKey || !active?.pubKey || !active?.ip) return null;
  const pskLine = cfg.presharedKey ? `PresharedKey = ${cfg.presharedKey}` : null;
  return [
    '[Interface]',
    `Address = ${cfg.tunnelClientIp}/32`,
    `PrivateKey = ${cfg.privateKey}`,
    '',
    '[Peer]',
    `PublicKey = ${active.pubKey}`,
    pskLine,
    `Endpoint = ${active.ip}:${active.port}`,
    `AllowedIPs = ${cfg.tunnelServerIp}/32`,
    'PersistentKeepalive = 25',
    ''
  ].filter(Boolean).join('\n');
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

function generateVpsScript(cfg, target, options = {}) {
  const selected = target || getActiveVpsTarget(cfg);
  if (!selected) throw new Error('No hay VPS seleccionado');
  const withCrowdsec = Boolean(options.withCrowdsec);
  const pskLine = cfg.presharedKey
    ? `PresharedKey = ${cfg.presharedKey}`
    : '';
  const crowdsecBlock = withCrowdsec
    ? `
# CrowdSec opcional
echo "Instalando CrowdSec..."
if ! command -v cscli >/dev/null 2>&1; then
  curl -fsSL https://install.crowdsec.net | sh
fi
apt-get -o DPkg::Lock::Timeout=300 install -y -qq crowdsec crowdsec-firewall-bouncer-iptables
cscli collections install crowdsecurity/sshd || true
systemctl enable crowdsec crowdsec-firewall-bouncer >/dev/null 2>&1 || true
systemctl restart crowdsec crowdsec-firewall-bouncer >/dev/null 2>&1 || true
for i in 1 2 3 4 5; do
  if systemctl is-active --quiet crowdsec && systemctl is-active --quiet crowdsec-firewall-bouncer; then
    break
  fi
  sleep 1
done
if ! systemctl is-active --quiet crowdsec; then
  echo "Advertencia: crowdsec no quedo activo"
fi
if ! systemctl is-active --quiet crowdsec-firewall-bouncer; then
  echo "Advertencia: crowdsec-firewall-bouncer no quedo activo"
fi
cscli lapi status >/dev/null 2>&1 || echo "Advertencia: cscli no pudo validar LAPI"
cscli bouncers list >/dev/null 2>&1 || echo "Advertencia: cscli no pudo listar bouncers"
iptables-save | grep -qi crowdsec || echo "Advertencia: no se detecto hook iptables de CrowdSec"
`
    : '';
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

WG_PORT=${selected.port}
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
${crowdsecBlock}

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
ListenPort = ${selected.port}
PrivateKey = $VPS_PRIV

[Peer]
PublicKey = ${cfg.publicKey}
${pskLine}
AllowedIPs = ${cfg.tunnelClientIp}/32
WGEOF

chmod 600 /etc/wireguard/wg0.conf

systemctl enable wg-quick@wg0
if systemctl is-active --quiet wg-quick@wg0; then
  systemctl restart wg-quick@wg0
else
  systemctl start wg-quick@wg0
fi

if ! systemctl is-active --quiet wg-quick@wg0; then
  /root/miniweed-rollback-firewall.sh || true
  echo "WireGuard no arrancó correctamente. Firewall restaurado."
  exit 1
fi

ACTIVE_PUB=$(wg show wg0 public-key 2>/dev/null || true)
if [ -z "$ACTIVE_PUB" ]; then
  /root/miniweed-rollback-firewall.sh || true
  echo "No se pudo leer la clave publica activa de wg0 tras aplicar la configuracion."
  exit 1
fi
if [ "$ACTIVE_PUB" != "$VPS_PUB" ]; then
  /root/miniweed-rollback-firewall.sh || true
  echo "La clave activa de wg0 no coincide con la nueva clave generada."
  echo "Esperada: $VPS_PUB"
  echo "Activa:   $ACTIVE_PUB"
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

function buildKillSwitchScript() {
  return `#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "[killswitch] must run as root"
  exit 1
fi

WG_PORT="\${WG_PORT:-51820}"
STATUS_FILE="\${STATUS_FILE:-/var/run/miniweed.status}"

echo "[killswitch] stopping wg0"
systemctl stop wg-quick@wg0 || true

echo "[killswitch] blocking udp/\${WG_PORT}"
iptables -w -C INPUT -p udp --dport "$WG_PORT" -j DROP 2>/dev/null || iptables -w -A INPUT -p udp --dport "$WG_PORT" -j DROP

echo "killed at $(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$STATUS_FILE"
echo "[killswitch] completed"
`;
}

function buildVpsRotateScript(cfg, next, target) {
  const selected = target || getActiveVpsTarget(cfg);
  if (!selected) throw new Error('No hay VPS activo para rotación');
  const pskLine = next.presharedKey ? `PresharedKey = ${next.presharedKey}` : '';
  return `#!/usr/bin/env bash
set -euo pipefail

BACKUP="/etc/wireguard/wg0.conf.rotate-$(date +%s).bak"
NEW_CONF_FILE="/tmp/wg0.rotate.new.conf"

rollback() {
  echo "ROTATE_FAIL: restoring $BACKUP"
  cp "$BACKUP" /etc/wireguard/wg0.conf
  wg-quick down wg0 2>/dev/null || true
  wg-quick up wg0
  exit 1
}

trap rollback ERR

cp /etc/wireguard/wg0.conf "$BACKUP"

cat > "$NEW_CONF_FILE" <<'WGEOF'
[Interface]
Address = ${cfg.tunnelServerIp}/24
ListenPort = ${selected.port}
PrivateKey = __KEEP_EXISTING_VPS_PRIVATE_KEY__

[Peer]
PublicKey = ${next.publicKey}
${pskLine}
AllowedIPs = ${cfg.tunnelClientIp}/32
WGEOF

if grep -q '^PrivateKey' /etc/wireguard/wg0.conf; then
  VPS_PRIV=$(awk -F' = ' '/^PrivateKey/ {print $2; exit}' /etc/wireguard/wg0.conf)
else
  echo "No se pudo leer PrivateKey actual de /etc/wireguard/wg0.conf"
  exit 1
fi

sed -i "s|__KEEP_EXISTING_VPS_PRIVATE_KEY__|$VPS_PRIV|g" "$NEW_CONF_FILE"
cp "$NEW_CONF_FILE" /etc/wireguard/wg0.conf
chmod 600 /etc/wireguard/wg0.conf

wg-quick down wg0 || true
wg-quick up wg0

for i in $(seq 1 30); do
  HS=$(wg show wg0 latest-handshakes | awk '{print $2}' | head -n1)
  if [ -n "$HS" ] && [ "$HS" -gt 0 ] 2>/dev/null; then
    NOW=$(date +%s)
    AGE=$((NOW - HS))
    if [ "$AGE" -lt 90 ]; then
      echo "ROTATE_OK"
      exit 0
    fi
  fi
  sleep 1
done

rollback
`;
}

async function computeHealth(cfg) {
  const active = getActiveVpsTarget(cfg);
  const services = cfg?.services || [];
  const out = {};
  await Promise.all(services.map(async svc => {
    const key = serviceKey(svc);
    if (!svc.enabled || !svc.target) {
      out[key] = { ok: false, checked: false, message: 'Desactivado o incompleto' };
      return;
    }
    const dnsHost = cfg.domain ? (svc.subdomain ? `${svc.subdomain}.${cfg.domain}` : cfg.domain) : null;
    const item = { checkedAt: new Date().toISOString() };
    if (dnsHost) {
      try {
        const addrs = await dns.promises.resolve4(dnsHost);
        item.dns = { ok: active?.ip ? addrs.includes(active.ip) : false, addrs, expected: active?.ip || '' };
      } catch (err) {
        item.dns = { ok: false, error: err.code || err.message };
      }
    }
    const targetProbe = await probeServiceTarget(svc.target, 5000);
    item.target = targetProbe.ok
      ? { ok: true, statusCode: targetProbe.statusCode }
      : { ok: false, error: targetProbe.error || 'probe_failed' };
    item.ok = Boolean((item.dns ? item.dns.ok : true) && item.target.ok);
    out[key] = item;
  }));
  return out;
}

async function refreshHealthSnapshot() {
  try {
    const cfg = loadConfig();
    const failover = await maybeFailover(cfg, 'health-refresh');
    const health = await computeHealth(cfg);
    fs.writeFileSync(HEALTH_FILE, JSON.stringify({
      services: health,
      vps: failover.vpsHealth,
      failover: {
        switched: failover.switched,
        next: failover.next,
        activeVpsId: cfg.activeVpsId || ''
      }
    }, null, 2));
  } catch {
    // best effort background task
  }
}

function buildBackupPayload(passphrase, includeAudit = true) {
  const chunks = [];
  const pushEntry = (name, value) => {
    const body = Buffer.from(value, 'utf8');
    chunks.push(Buffer.from(`${name}:${body.length}\n`, 'utf8'));
    chunks.push(body);
  };

  if (fs.existsSync(CONFIG_FILE)) pushEntry('config.json', fs.readFileSync(CONFIG_FILE, 'utf8'));
  if (fs.existsSync(KNOWN_HOSTS_FILE)) pushEntry('known_hosts.json', fs.readFileSync(KNOWN_HOSTS_FILE, 'utf8'));
  if (includeAudit) {
    const auditPath = path.join(DATA_DIR, 'audit.log');
    if (fs.existsSync(auditPath)) pushEntry('audit.log', fs.readFileSync(auditPath, 'utf8'));
  }
  pushEntry('meta.json', JSON.stringify({ ts: new Date().toISOString(), version: 1 }));

  const compressed = zlib.gzipSync(Buffer.concat(chunks));
  const salt = crypto.randomBytes(16);
  const key = crypto.scryptSync(passphrase, salt, 32, { N: 1 << 16, r: 8, p: 1 });
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
  const ciphertext = Buffer.concat([cipher.update(compressed), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([Buffer.from('MWBK', 'utf8'), salt, nonce, ciphertext, tag]);
}

function parseBackupEntries(buffer) {
  const out = {};
  let idx = 0;
  while (idx < buffer.length) {
    const nl = buffer.indexOf(10, idx);
    if (nl === -1) break;
    const header = buffer.slice(idx, nl).toString('utf8');
    idx = nl + 1;
    const sep = header.lastIndexOf(':');
    if (sep <= 0) break;
    const name = header.slice(0, sep);
    const len = parseInt(header.slice(sep + 1), 10);
    if (!Number.isFinite(len) || len < 0 || idx + len > buffer.length) break;
    out[name] = buffer.slice(idx, idx + len).toString('utf8');
    idx += len;
  }
  return out;
}

function restoreBackupPayload(payload, passphrase) {
  if (!Buffer.isBuffer(payload) || payload.length < 48) throw new Error('backup payload inválido');
  if (payload.slice(0, 4).toString('utf8') !== 'MWBK') throw new Error('backup magic inválido');
  const salt = payload.slice(4, 20);
  const nonce = payload.slice(20, 32);
  const tag = payload.slice(payload.length - 16);
  const ciphertext = payload.slice(32, payload.length - 16);
  const key = crypto.scryptSync(passphrase, salt, 32, { N: 1 << 16, r: 8, p: 1 });
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce);
  decipher.setAuthTag(tag);
  const compressed = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  const data = zlib.gunzipSync(compressed);
  const entries = parseBackupEntries(data);
  if (!entries['meta.json']) throw new Error('backup sin meta.json');
  return entries;
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
  const active = getActiveVpsTarget(cfg);
  const failoverPolicy = extractFailoverPolicy(cfg);
  // Never expose private key to the frontend
  const auth = cfg.auth || { passwordHash: '', sessions: [] };
  res.json({
    ...cfg,
    vpsIp: active?.ip || '',
    vpsPort: active?.port || 51820,
    vpsPubKey: active?.pubKey || '',
    vpsTargets: cfg.vpsTargets || [],
    activeVpsId: cfg.activeVpsId || '',
    failoverPolicy,
    auth: {
      passwordEnabled: Boolean(auth.passwordHash),
      sessionCount: Array.isArray(auth.sessions) ? auth.sessions.length : 0
    },
    privateKey: cfg.privateKey ? '••••' : '',
    vpsPubKeyFingerprint: keyFingerprint(active?.pubKey || ''),
    vpsFingerprints: Object.fromEntries((cfg.vpsTargets || []).map(t => [t.id, keyFingerprint(t.pubKey)]))
  });
});

app.post('/api/config', async (req, res) => {
  if (!req.body || typeof req.body !== 'object' || Array.isArray(req.body)) {
    return res.status(400).json({ error: 'validation', issues: [{ path: [], message: 'body must be an object' }] });
  }
  try {
    const result = await withConfigLock(async () => {
      const existing = loadConfig();
      const update = req.body || {};
      if (update.privateKey === '••••') update.privateKey = existing.privateKey;

      const cfg = { ...existing, ...update };
      const updateTargets = Array.isArray(update.vpsTargets)
        ? update.vpsTargets.map((raw, i) => normalizeVpsTarget(raw, i))
        : null;
      if (updateTargets) {
        cfg.vpsTargets = updateTargets.slice(0, MAX_VPS_TARGETS);
      } else if (update.vpsIp || update.vpsPubKey || update.vpsPort || existing.vpsTargets.length === 0) {
        const preserved = existing.vpsTargets.filter(t => t.id !== (existing.activeVpsId || ''));
        const legacyTarget = normalizeVpsTarget({
          id: existing.activeVpsId || 'primary',
          name: existing.vpsTargets.find(t => t.id === existing.activeVpsId)?.name || 'VPS principal',
          ip: update.vpsIp ?? existing.vpsIp,
          port: update.vpsPort ?? existing.vpsPort,
          pubKey: update.vpsPubKey ?? existing.vpsPubKey,
          enabled: true,
          priority: 0
        }, 0);
        cfg.vpsTargets = [legacyTarget, ...preserved].slice(0, MAX_VPS_TARGETS);
      }
      if (typeof update.activeVpsId === 'string') {
        cfg.activeVpsId = update.activeVpsId.trim();
      }
      if (update.failoverPolicy && typeof update.failoverPolicy === 'object') {
        cfg.failoverPolicy = normalizeFailoverPolicy(update.failoverPolicy);
      }
      ensureVpsTargets(cfg);
      cfg.services = Array.isArray(cfg.services)
        ? cfg.services.map(svc => ({
            name: (svc.name || '').trim(),
            subdomain: (svc.subdomain || '').trim().toLowerCase(),
            target: normalizeTargetUrl(svc.target),
            enabled: Boolean(svc.enabled)
          }))
        : [];

      const errors = validateConfig(cfg);
      const emailCheck = await validateEmailWithMx(cfg.acmeEmail);
      if (!emailCheck.ok) {
        errors.push(`El email de Let's Encrypt no supera validación MX (${emailCheck.reason})`);
      }
      if (errors.length) return { errors };

      cfg.serviceHealth = await checkServicesHealth(cfg.services);
      saveConfig(cfg);
      refreshHealthSnapshot();
      audit.log({
        action: 'config.update',
        domain: cfg.domain,
        serviceCount: cfg.services.length,
        ip: req.ip
      });

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

app.post('/api/auth/password', validateBody(AuthPasswordSchema), async (req, res) => {
  const password = String(req.body?.password || '');
  await withConfigLock(async () => {
    const cfg = loadConfig();
    cfg.auth = cfg.auth || {};
    cfg.auth.passwordHash = hashPassword(password);
    cfg.auth.sessions = [];
    saveConfig(cfg);
  });
  audit.log({ action: 'auth.password.set', ip: req.ip });
  return res.json({ ok: true });
});

app.post('/api/auth/login', validateBody(AuthLoginSchema), async (req, res) => {
  const password = String(req.body?.password || '');
  const ip = req.ip || req.socket?.remoteAddress || 'unknown';

  const cfg = loadConfig();
  const hash = cfg.auth?.passwordHash || '';
  if (!hash) return res.status(400).json({ error: 'password no configurada' });

  const ok = verifyPassword(password, hash);
  if (!ok) {
    const delay = authFailureDelayMs(ip);
    await new Promise(resolve => setTimeout(resolve, delay));
    audit.log({ action: 'auth.fail', ip, path: '/api/auth/login' });
    return res.status(401).json({ error: 'credenciales inválidas' });
  }

  clearAuthFailures(ip);
  const now = Date.now();
  const session = createSession(ip, 'web-password');
  await withConfigLock(async () => {
    const current = loadConfig();
    current.auth = current.auth || {};
    const sessions = Array.isArray(current.auth.sessions) ? current.auth.sessions : [];
    current.auth.sessions = sessions
      .filter(s => s.expiresAt > now)
      .concat([session]);
    saveConfig(current);
  });

  const secureAttr = req.secure || req.get('x-forwarded-proto') === 'https' ? '; Secure' : '';
  res.setHeader('Set-Cookie', `${SESSION_COOKIE}=${encodeURIComponent(session.id)}; Path=/; HttpOnly; SameSite=Strict${secureAttr}; Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`);
  audit.log({ action: 'auth.success', ip, path: '/api/auth/login' });
  return res.json({ ok: true });
});

app.get('/api/auth/sessions', (req, res) => {
  const cfg = loadConfig();
  const now = Date.now();
  const sessions = Array.isArray(cfg.auth?.sessions) ? cfg.auth.sessions.filter(s => s.expiresAt > now) : [];
  const cookies = parseCookies(req);
  const currentSessionId = cookies[SESSION_COOKIE] || '';
  return res.json({
    sessions: sessions.map(s => ({
      id: s.id,
      createdAt: s.createdAt,
      expiresAt: s.expiresAt,
      ip: s.ip,
      source: s.source || 'unknown',
      current: s.id === currentSessionId
    }))
  });
});

app.delete('/api/auth/sessions/:id', async (req, res) => {
  const sessionId = String(req.params.id || '').trim();
  if (!sessionId) return res.status(400).json({ error: 'session id requerida' });
  const now = Date.now();
  await withConfigLock(async () => {
    const cfg = loadConfig();
    cfg.auth = cfg.auth || {};
    const sessions = Array.isArray(cfg.auth.sessions) ? cfg.auth.sessions : [];
    cfg.auth.sessions = sessions.filter(s => s.expiresAt > now && s.id !== sessionId);
    saveConfig(cfg);
  });
  audit.log({ action: 'auth.session.revoke', ip: req.ip || req.socket?.remoteAddress || 'unknown', sessionId });
  return res.json({ ok: true });
});

app.post('/api/auth/pubkeys', async (req, res) => {
  const name = String(req.body?.name || '').trim();
  const inputKey = String(req.body?.publicKey || '').trim();
  if (!name || !inputKey) return res.status(400).json({ error: 'name y publicKey requeridos' });
  const publicKey = parseEd25519PublicKey(inputKey);
  if (!publicKey) {
    return res.status(400).json({ error: 'publicKey inválida (acepta base64 DER SPKI o ssh-ed25519)' });
  }
  const keyObject = crypto.createPublicKey({ key: Buffer.from(publicKey, 'base64'), format: 'der', type: 'spki' });
  if (keyObject.asymmetricKeyType !== 'ed25519') {
    return res.status(400).json({ error: 'solo se permiten claves ed25519' });
  }
  const keyId = crypto.createHash('sha256').update(publicKey).digest('hex').slice(0, 16);
  await withConfigLock(async () => {
    const cfg = loadConfig();
    cfg.auth = cfg.auth || {};
    const pubkeys = Array.isArray(cfg.auth.pubkeys) ? cfg.auth.pubkeys : [];
    const next = pubkeys.filter(p => p.id !== keyId);
    next.push({ id: keyId, name, publicKey, addedAt: Date.now() });
    cfg.auth.pubkeys = next;
    saveConfig(cfg);
  });
  audit.log({ action: 'auth.pubkey.add', ip: req.ip || req.socket?.remoteAddress || 'unknown', keyId, name });
  return res.json({ ok: true, keyId });
});

app.get('/api/auth/pubkeys', (req, res) => {
  const cfg = loadConfig();
  const pubkeys = Array.isArray(cfg.auth?.pubkeys) ? cfg.auth.pubkeys : [];
  res.json({ pubkeys: pubkeys.map(p => ({ id: p.id, name: p.name, addedAt: p.addedAt })) });
});

app.delete('/api/auth/pubkeys/:id', async (req, res) => {
  const keyId = String(req.params.id || '').trim();
  if (!keyId) return res.status(400).json({ error: 'key id requerida' });
  await withConfigLock(async () => {
    const cfg = loadConfig();
    cfg.auth = cfg.auth || {};
    const pubkeys = Array.isArray(cfg.auth.pubkeys) ? cfg.auth.pubkeys : [];
    cfg.auth.pubkeys = pubkeys.filter(p => p.id !== keyId);
    saveConfig(cfg);
  });
  audit.log({ action: 'auth.pubkey.remove', ip: req.ip || req.socket?.remoteAddress || 'unknown', keyId });
  return res.json({ ok: true });
});

app.post('/api/auth/challenge', (req, res) => {
  const keyId = String(req.body?.keyId || '').trim();
  if (!keyId) return res.status(400).json({ error: 'keyId requerido' });
  const cfg = loadConfig();
  const pubkeys = Array.isArray(cfg.auth?.pubkeys) ? cfg.auth.pubkeys : [];
  const key = pubkeys.find(p => p.id === keyId);
  if (!key) return res.status(401).json({ error: 'clave no registrada' });
  const challengeId = crypto.randomBytes(16).toString('hex');
  const nonce = crypto.randomBytes(32).toString('base64');
  const now = Date.now();
  authChallenges.set(challengeId, {
    keyId,
    nonce,
    createdAt: now,
    expiresAt: now + CHALLENGE_TTL_MS,
    ip: req.ip || req.socket?.remoteAddress || 'unknown'
  });
  return res.json({ challengeId, nonce, expiresInSec: Math.floor(CHALLENGE_TTL_MS / 1000) });
});

app.post('/api/auth/verify', async (req, res) => {
  const challengeId = String(req.body?.challengeId || '').trim();
  const signatureB64 = String(req.body?.signature || '').trim();
  if (!challengeId || !signatureB64) {
    return res.status(400).json({ error: 'challengeId y signature requeridos' });
  }
  const challenge = authChallenges.get(challengeId);
  if (!challenge || challenge.expiresAt <= Date.now()) {
    authChallenges.delete(challengeId);
    return res.status(401).json({ error: 'challenge expirada o inválida' });
  }
  authChallenges.delete(challengeId);

  const cfg = loadConfig();
  const pubkeys = Array.isArray(cfg.auth?.pubkeys) ? cfg.auth.pubkeys : [];
  const key = pubkeys.find(p => p.id === challenge.keyId);
  if (!key) return res.status(401).json({ error: 'clave no encontrada' });

  let verified = false;
  try {
    const publicKey = crypto.createPublicKey({ key: Buffer.from(key.publicKey, 'base64'), format: 'der', type: 'spki' });
    verified = crypto.verify(null, Buffer.from(challenge.nonce, 'base64'), publicKey, Buffer.from(signatureB64, 'base64'));
  } catch {
    verified = false;
  }
  if (!verified) {
    audit.log({ action: 'auth.fail', ip: req.ip || req.socket?.remoteAddress || 'unknown', path: '/api/auth/verify' });
    return res.status(401).json({ error: 'firma inválida' });
  }

  const ip = req.ip || req.socket?.remoteAddress || 'unknown';
  const session = createSession(ip, `pubkey:${challenge.keyId}`);
  await withConfigLock(async () => {
    const current = loadConfig();
    current.auth = current.auth || {};
    const now = Date.now();
    const sessions = Array.isArray(current.auth.sessions) ? current.auth.sessions : [];
    current.auth.sessions = sessions.filter(s => s.expiresAt > now).concat([session]);
    saveConfig(current);
  });
  audit.log({ action: 'auth.success', ip, path: '/api/auth/verify', keyId: challenge.keyId });
  return res.json({ ok: true, sessionToken: session.id, expiresAt: session.expiresAt });
});

app.post('/api/auth/logout', async (req, res) => {
  const cookies = parseCookies(req);
  const sessionId = cookies[SESSION_COOKIE] || '';
  const now = Date.now();
  await withConfigLock(async () => {
    const cfg = loadConfig();
    cfg.auth = cfg.auth || {};
    const sessions = Array.isArray(cfg.auth.sessions) ? cfg.auth.sessions : [];
    cfg.auth.sessions = sessions.filter(s => s.expiresAt > now && s.id !== sessionId);
    saveConfig(cfg);
  });
  const secureAttr = req.secure || req.get('x-forwarded-proto') === 'https' ? '; Secure' : '';
  res.setHeader('Set-Cookie', `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict${secureAttr}; Max-Age=0`);
  audit.log({ action: 'auth.logout', ip: req.ip || req.socket?.remoteAddress || 'unknown' });
  return res.json({ ok: true });
});

app.get('/api/keygen', async (req, res) => {
  try {
    const keys = await wgApi('/keygen');
    // Save private key immediately, return only public key
    const cfg = loadConfig();
    cfg.privateKey = keys.privateKey;
    cfg.publicKey = keys.publicKey;
    cfg.presharedKey = keys.presharedKey || '';
    saveConfig(cfg);
    audit.log({ action: 'keygen', ip: req.ip, publicKeyFingerprint: keyFingerprint(keys.publicKey) });
    res.json({ publicKey: keys.publicKey, publicKeyFingerprint: keyFingerprint(keys.publicKey) });
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

app.get('/api/health', (req, res) => {
  if (!fs.existsSync(HEALTH_FILE)) return res.json({});
  try {
    return res.json(JSON.parse(fs.readFileSync(HEALTH_FILE, 'utf8')));
  } catch {
    return res.json({});
  }
});

app.post('/api/health/refresh', async (req, res) => {
  await refreshHealthSnapshot();
  if (!fs.existsSync(HEALTH_FILE)) return res.json({ ok: false, health: {} });
  try {
    const health = JSON.parse(fs.readFileSync(HEALTH_FILE, 'utf8'));
    return res.json({ ok: true, health });
  } catch {
    return res.json({ ok: false, health: {} });
  }
});

app.post('/api/vps/failover', async (req, res) => {
  const requestedId = String(req.body?.targetId || '').trim();
  const cfg = loadConfig();
  ensureVpsTargets(cfg);
  if (!requestedId) {
    const result = await maybeFailover(cfg, 'manual-auto');
    return res.json({
      ok: true,
      ...result,
      activeVpsId: loadConfig().activeVpsId || '',
      policy: result.policy || extractFailoverPolicy(cfg)
    });
  }
  const target = (cfg.vpsTargets || []).find(t => t.id === requestedId && t.enabled && t.ip && t.pubKey);
  if (!target) {
    return res.status(404).json({ error: 'VPS objetivo no encontrado o incompleto' });
  }
  cfg.activeVpsId = target.id;
  ensureVpsTargets(cfg);
  saveConfig(cfg);
  const wgConf = generateWgConf(cfg);
  if (wgConf) fs.writeFileSync(WG_CONF, wgConf);
  audit.log({ action: 'vps.failover.manual', ip: req.ip, to: target.id, toIp: target.ip });
  return res.json({ ok: true, switched: true, next: { id: target.id, name: target.name, ip: target.ip }, activeVpsId: cfg.activeVpsId });
});

app.get('/api/vps/targets', async (req, res) => {
  const cfg = loadConfig();
  ensureVpsTargets(cfg);
  const vpsHealth = await computeVpsHealth(cfg.vpsTargets || []);
  res.json({
    activeVpsId: cfg.activeVpsId || '',
    targets: (cfg.vpsTargets || []).map(t => ({
      ...t,
      fingerprint: keyFingerprint(t.pubKey),
      health: vpsHealth[t.id] || null
    }))
  });
});

app.post('/api/backup', (req, res) => {
  const passphrase = String(req.body?.passphrase || '');
  const includeAudit = req.body?.includeAudit !== false;
  if (passphrase.length < 12) {
    return res.status(400).json({ error: 'passphrase demasiado corta' });
  }
  try {
    const payload = buildBackupPayload(passphrase, includeAudit);
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="miniweed-backup-${Date.now()}.bak"`);
    audit.log({ action: 'backup.create', ip: req.ip, includeAudit: Boolean(includeAudit) });
    return res.send(payload);
  } catch (err) {
    return res.status(500).json({ error: `backup failed: ${err.message}` });
  }
});

app.post('/api/restore', express.raw({ type: 'application/octet-stream', limit: '15mb' }), (req, res) => {
  const passphrase = req.get('x-backup-passphrase') || '';
  if (!passphrase || passphrase.length < 12) {
    return res.status(400).json({ error: 'passphrase inválida' });
  }
  try {
    const entries = restoreBackupPayload(Buffer.from(req.body), passphrase);
    const meta = entries['meta.json'] ? JSON.parse(entries['meta.json']) : null;
    if (!meta || meta.version !== 1) {
      return res.status(400).json({ error: 'meta inválida en backup' });
    }

    if (entries['config.json']) JSON.parse(entries['config.json']);
    if (entries['known_hosts.json']) JSON.parse(entries['known_hosts.json']);

    const restoreDir = path.join(DATA_DIR, '.restore-staging');
    fs.mkdirSync(restoreDir, { recursive: true });
    if (entries['config.json']) fs.writeFileSync(path.join(restoreDir, 'config.json'), entries['config.json'], { mode: 0o600 });
    if (entries['known_hosts.json']) fs.writeFileSync(path.join(restoreDir, 'known_hosts.json'), entries['known_hosts.json'], { mode: 0o600 });
    if (entries['audit.log']) fs.writeFileSync(path.join(restoreDir, 'audit.log'), entries['audit.log'], { mode: 0o600 });

    if (entries['config.json']) fs.renameSync(path.join(restoreDir, 'config.json'), CONFIG_FILE);
    if (entries['known_hosts.json']) fs.renameSync(path.join(restoreDir, 'known_hosts.json'), KNOWN_HOSTS_FILE);
    if (entries['audit.log']) fs.renameSync(path.join(restoreDir, 'audit.log'), path.join(DATA_DIR, 'audit.log'));

    migrateConfigIfNeeded();
    refreshHealthSnapshot();
    audit.log({ action: 'backup.restore', ip: req.ip });
    return res.json({ ok: true, restored: Object.keys(entries) });
  } catch (err) {
    return res.status(400).json({ error: `restore failed: ${err.message}` });
  }
});

app.get('/api/vps-setup-script', (req, res) => {
  const cfg = loadConfig();
  const targetId = String(req.query.vpsId || '').trim();
  const selected = targetId
    ? (cfg.vpsTargets || []).find(t => t.id === targetId)
    : getActiveVpsTarget(cfg);
  if (!cfg.publicKey || !selected?.ip) {
    return res.status(400).json({ error: 'Configura la IP del VPS y genera las claves primero' });
  }
  const withCrowdsec = String(req.query.withCrowdsec || '').trim() === '1';
  const script = generateVpsScript(cfg, selected, { withCrowdsec });
  const sha256 = crypto.createHash('sha256').update(script).digest('hex');
  if (req.query.format === 'plain') {
    audit.log({ action: 'script.download', format: 'plain', ip: req.ip, vpsId: selected.id, withCrowdsec });
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="miniweed-tunnel-vps-setup.sh"');
    return res.send(script);
  }
  audit.log({ action: 'script.download', format: 'json', ip: req.ip, vpsId: selected.id, withCrowdsec });
  return res.json({
    script,
    sha256,
    filename: 'miniweed-tunnel-vps-setup.sh',
    vps: { id: selected.id, name: selected.name, ip: selected.ip, port: selected.port },
    withCrowdsec
  });
});

app.get('/api/audit', (req, res) => {
  const limitRaw = parseInt(req.query.limit, 10);
  const limit = Number.isFinite(limitRaw) ? Math.min(Math.max(limitRaw, 1), 1000) : 100;
  const entries = audit.readLatest(limit);
  res.json({ entries, total: entries.length });
});

app.get('/api/audit/verify', (req, res) => {
  res.json(audit.verifyChain());
});

app.get('/api/openapi.json', (req, res) => {
  res.json({
    openapi: '3.1.0',
    info: {
      title: 'Tunnel API',
      version: '1.4.0'
    },
    components: {
      schemas: {
        RotatePrepareRequest: {
          type: 'object',
          properties: {
            nextPrivateKey: { type: 'string', pattern: '^[A-Za-z0-9+/]{43}=$' },
            nextPublicKey: { type: 'string', pattern: '^[A-Za-z0-9+/]{43}=$' },
            nextPresharedKey: { type: 'string', pattern: '^[A-Za-z0-9+/]{43}=$' }
          }
        },
        RotateConfirmRequest: {
          type: 'object',
          required: ['planId'],
          properties: {
            planId: { type: 'string', pattern: '^[a-f0-9]{32}$' },
            apply: { type: 'boolean', default: true }
          }
        },
        RotatePrepareResponse: {
          type: 'object',
          required: ['ok', 'planId', 'expiresInSec', 'nextPublicKey', 'nextPublicKeyFingerprint', 'script', 'scriptSha256'],
          properties: {
            ok: { type: 'boolean' },
            planId: { type: 'string' },
            expiresInSec: { type: 'integer' },
            nextPublicKey: { type: 'string' },
            nextPublicKeyFingerprint: { type: 'string' },
            script: { type: 'string' },
            scriptSha256: { type: 'string', pattern: '^[a-f0-9]{64}$' }
          }
        },
        RotateStatusResponse: {
          type: 'object',
          required: ['id', 'createdAt', 'expiresAt', 'nextPublicKey', 'nextPublicKeyFingerprint', 'scriptSha256'],
          properties: {
            id: { type: 'string' },
            createdAt: { type: 'integer' },
            expiresAt: { type: 'integer' },
            nextPublicKey: { type: 'string' },
            nextPublicKeyFingerprint: { type: 'string' },
            scriptSha256: { type: 'string', pattern: '^[a-f0-9]{64}$' }
          }
        },
        RotateConfirmResponse: {
          type: 'object',
          required: ['ok'],
          properties: {
            ok: { type: 'boolean' },
            cancelled: { type: 'boolean' },
            applied: { type: 'boolean' },
            nextPublicKey: { type: 'string' },
            nextPublicKeyFingerprint: { type: 'string' }
          }
        },
        KillSwitchScriptResponse: {
          type: 'object',
          required: ['script', 'sha256', 'filename'],
          properties: {
            script: { type: 'string' },
            sha256: { type: 'string', pattern: '^[a-f0-9]{64}$' },
            filename: { type: 'string' }
          }
        },
        VpsTarget: {
          type: 'object',
          required: ['id', 'name', 'ip', 'port', 'enabled', 'priority'],
          properties: {
            id: { type: 'string' },
            name: { type: 'string' },
            ip: { type: 'string' },
            port: { type: 'integer', minimum: 1, maximum: 65535 },
            pubKey: { type: 'string', pattern: '^[A-Za-z0-9+/]{43}=$' },
            enabled: { type: 'boolean' },
            priority: { type: 'integer', minimum: 0, maximum: 99 },
            fingerprint: { type: 'string' },
            health: {
              type: 'object',
              properties: {
                ok: { type: 'boolean' },
                checked: { type: 'boolean' },
                checkedAt: { type: 'string' },
                message: { type: 'string' },
                latencyMs: { type: ['integer', 'null'] },
                okStreak: { type: 'integer' },
                failStreak: { type: 'integer' }
              }
            }
          }
        },
        VpsTargetsResponse: {
          type: 'object',
          required: ['activeVpsId', 'targets'],
          properties: {
            activeVpsId: { type: 'string' },
            targets: {
              type: 'array',
              items: { $ref: '#/components/schemas/VpsTarget' }
            }
          }
        },
        VpsFailoverRequest: {
          type: 'object',
          properties: {
            targetId: { type: 'string' }
          }
        },
        VpsFailoverResponse: {
          type: 'object',
          required: ['ok', 'activeVpsId'],
          properties: {
            ok: { type: 'boolean' },
            switched: { type: 'boolean' },
            activeVpsId: { type: 'string' },
            policy: {
              ...openApiFailoverPolicySchema()
            },
            next: {
              type: 'object',
              properties: {
                id: { type: 'string' },
                name: { type: 'string' },
                ip: { type: 'string' }
              }
            }
          }
        },
        VpsSetupScriptResponse: {
          type: 'object',
          required: ['script', 'sha256', 'filename', 'vps', 'withCrowdsec'],
          properties: {
            script: { type: 'string' },
            sha256: { type: 'string', pattern: '^[a-f0-9]{64}$' },
            filename: { type: 'string' },
            withCrowdsec: { type: 'boolean' },
            vps: {
              type: 'object',
              required: ['id', 'name', 'ip', 'port'],
              properties: {
                id: { type: 'string' },
                name: { type: 'string' },
                ip: { type: 'string' },
                port: { type: 'integer' }
              }
            }
          }
        },
        AuditVerifyResponse: {
          type: 'object',
          required: ['ok', 'entries'],
          properties: {
            ok: { type: 'boolean' },
            entries: { type: 'integer' },
            brokenAt: { type: 'integer' },
            reason: { type: 'string' }
          }
        },
        ConfigUpdateRequest: {
          type: 'object',
          additionalProperties: true,
          properties: {
            vpsIp: { type: 'string' },
            vpsPort: { type: 'integer' },
            vpsPubKey: { type: 'string' },
            activeVpsId: { type: 'string' },
            domain: { type: 'string' },
            acmeEmail: { type: 'string', format: 'email' },
            failoverPolicy: openApiFailoverPolicySchema(),
            privateKey: { type: 'string' },
            services: {
              type: 'array',
              items: {
                type: 'object',
                additionalProperties: true,
                properties: {
                  name: { type: 'string' },
                  subdomain: { type: 'string' },
                  target: { type: 'string' },
                  enabled: { type: 'boolean' }
                }
              }
            },
            vpsTargets: {
              type: 'array',
              items: { $ref: '#/components/schemas/VpsTarget' }
            }
          }
        },
        ConfigResponse: {
          type: 'object',
          additionalProperties: true,
          required: ['vpsTargets', 'activeVpsId', 'auth', 'privateKey', 'vpsPubKeyFingerprint', 'vpsFingerprints'],
          properties: {
            vpsIp: { type: 'string' },
            vpsPort: { type: 'integer' },
            vpsPubKey: { type: 'string' },
            activeVpsId: { type: 'string' },
            domain: { type: 'string' },
            acmeEmail: { type: 'string' },
            failoverPolicy: openApiFailoverPolicySchema(),
            vpsTargets: {
              type: 'array',
              items: { $ref: '#/components/schemas/VpsTarget' }
            },
            auth: {
              type: 'object',
              required: ['passwordEnabled', 'sessionCount'],
              properties: {
                passwordEnabled: { type: 'boolean' },
                sessionCount: { type: 'integer' }
              }
            },
            privateKey: { type: 'string' },
            vpsPubKeyFingerprint: { type: 'string' },
            vpsFingerprints: {
              type: 'object',
              additionalProperties: { type: 'string' }
            },
            services: {
              type: 'array',
              items: {
                type: 'object',
                additionalProperties: true,
                properties: {
                  name: { type: 'string' },
                  subdomain: { type: 'string' },
                  target: { type: 'string' },
                  enabled: { type: 'boolean' }
                }
              }
            },
            serviceHealth: {
              type: 'object',
              additionalProperties: {
                type: 'object',
                additionalProperties: true,
                properties: {
                  ok: { type: 'boolean' },
                  checked: { type: 'boolean' },
                  statusCode: { type: 'integer' },
                  message: { type: 'string' }
                }
              }
            }
          }
        },
        ConfigUpdateResponse: {
          type: 'object',
          required: ['ok', 'serviceHealth'],
          properties: {
            ok: { type: 'boolean' },
            serviceHealth: {
              type: 'object',
              additionalProperties: {
                type: 'object',
                additionalProperties: true,
                properties: {
                  ok: { type: 'boolean' },
                  checked: { type: 'boolean' },
                  statusCode: { type: 'integer' },
                  message: { type: 'string' }
                }
              }
            }
          }
        },
        KeygenResponse: {
          type: 'object',
          required: ['publicKey', 'publicKeyFingerprint'],
          properties: {
            publicKey: { type: 'string', pattern: '^[A-Za-z0-9+/]{43}=$' },
            publicKeyFingerprint: { type: 'string' }
          }
        },
        StatusResponse: {
          type: 'object',
          additionalProperties: true,
          required: ['connected', 'raw'],
          properties: {
            connected: { type: 'boolean' },
            raw: { type: 'string' },
            peerCount: { type: 'integer' }
          }
        },
        AuthOkResponse: {
          type: 'object',
          required: ['ok'],
          properties: {
            ok: { type: 'boolean' }
          }
        },
        PasswordRequest: {
          type: 'object',
          required: ['password'],
          properties: {
            password: { type: 'string', minLength: 12, maxLength: 256 }
          }
        },
        LoginRequest: {
          type: 'object',
          required: ['password'],
          properties: {
            password: { type: 'string' }
          }
        },
        AuthSession: {
          type: 'object',
          required: ['id', 'createdAt', 'expiresAt', 'ip', 'source', 'current'],
          properties: {
            id: { type: 'string' },
            createdAt: { type: 'integer' },
            expiresAt: { type: 'integer' },
            ip: { type: 'string' },
            source: { type: 'string' },
            current: { type: 'boolean' }
          }
        },
        AuthSessionsResponse: {
          type: 'object',
          required: ['sessions'],
          properties: {
            sessions: {
              type: 'array',
              items: { $ref: '#/components/schemas/AuthSession' }
            }
          }
        },
        AuthPubkeyItem: {
          type: 'object',
          required: ['id', 'name', 'addedAt'],
          properties: {
            id: { type: 'string' },
            name: { type: 'string' },
            addedAt: { type: 'integer' }
          }
        },
        AuthPubkeysResponse: {
          type: 'object',
          required: ['pubkeys'],
          properties: {
            pubkeys: {
              type: 'array',
              items: { $ref: '#/components/schemas/AuthPubkeyItem' }
            }
          }
        },
        AuthPubkeyAddRequest: {
          type: 'object',
          required: ['name', 'publicKey'],
          properties: {
            name: { type: 'string' },
            publicKey: { type: 'string' }
          }
        },
        AuthPubkeyAddResponse: {
          type: 'object',
          required: ['ok', 'keyId'],
          properties: {
            ok: { type: 'boolean' },
            keyId: { type: 'string' }
          }
        },
        AuthChallengeRequest: {
          type: 'object',
          required: ['keyId'],
          properties: {
            keyId: { type: 'string' }
          }
        },
        AuthChallengeResponse: {
          type: 'object',
          required: ['challengeId', 'nonce', 'expiresInSec'],
          properties: {
            challengeId: { type: 'string' },
            nonce: { type: 'string' },
            expiresInSec: { type: 'integer' }
          }
        },
        AuthVerifyRequest: {
          type: 'object',
          required: ['challengeId', 'signature'],
          properties: {
            challengeId: { type: 'string' },
            signature: { type: 'string' }
          }
        },
        AuthVerifyResponse: {
          type: 'object',
          required: ['ok', 'sessionToken', 'expiresAt'],
          properties: {
            ok: { type: 'boolean' },
            sessionToken: { type: 'string' },
            expiresAt: { type: 'integer' }
          }
        }
      }
    },
    paths: {
      '/api/config': {
        get: {
          summary: 'Get configuration',
          responses: {
            '200': {
              description: 'Current configuration snapshot for UI',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/ConfigResponse' }
                }
              }
            }
          }
        },
        post: {
          summary: 'Update configuration',
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/ConfigUpdateRequest' }
              }
            }
          },
          responses: {
            '200': {
              description: 'Configuration persisted and health recalculated',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/ConfigUpdateResponse' }
                }
              }
            }
          }
        }
      },
      '/api/status': {
        get: {
          summary: 'Get tunnel runtime status',
          responses: {
            '200': {
              description: 'WireGuard runtime status',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/StatusResponse' }
                }
              }
            }
          }
        }
      },
      '/api/keygen': {
        get: {
          summary: 'Generate a new WireGuard key pair',
          responses: {
            '200': {
              description: 'Generated key metadata',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/KeygenResponse' }
                }
              }
            }
          }
        }
      },
      '/api/health/refresh': {
        post: { summary: 'Refresh service and VPS health checks now' }
      },
      '/api/auth/login': {
        post: {
          summary: 'Password login',
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/LoginRequest' }
              }
            }
          },
          responses: {
            '200': {
              description: 'Session established',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/AuthOkResponse' }
                }
              }
            }
          }
        }
      },
      '/api/auth/password': {
        post: {
          summary: 'Set or rotate UI password',
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/PasswordRequest' }
              }
            }
          },
          responses: {
            '200': {
              description: 'Password configured',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/AuthOkResponse' }
                }
              }
            }
          }
        }
      },
      '/api/auth/pubkeys': {
        get: {
          summary: 'List allowed Ed25519 public keys',
          responses: {
            '200': {
              description: 'Allowed keys',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/AuthPubkeysResponse' }
                }
              }
            }
          }
        },
        post: {
          summary: 'Add allowed Ed25519 public key',
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/AuthPubkeyAddRequest' }
              }
            }
          },
          responses: {
            '200': {
              description: 'Key registered',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/AuthPubkeyAddResponse' }
                }
              }
            }
          }
        }
      },
      '/api/auth/pubkeys/{id}': {
        delete: {
          summary: 'Delete allowed Ed25519 public key',
          responses: {
            '200': {
              description: 'Key deleted',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/AuthOkResponse' }
                }
              }
            }
          }
        }
      },
      '/api/auth/sessions': {
        get: {
          summary: 'List active UI sessions',
          responses: {
            '200': {
              description: 'Active sessions',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/AuthSessionsResponse' }
                }
              }
            }
          }
        }
      },
      '/api/auth/sessions/{id}': {
        delete: {
          summary: 'Revoke UI session',
          responses: {
            '200': {
              description: 'Session revoked',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/AuthOkResponse' }
                }
              }
            }
          }
        }
      },
      '/api/auth/logout': {
        post: {
          summary: 'Logout current session',
          responses: {
            '200': {
              description: 'Session removed',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/AuthOkResponse' }
                }
              }
            }
          }
        }
      },
      '/api/auth/challenge': {
        post: {
          summary: 'Get challenge for pubkey auth',
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/AuthChallengeRequest' }
              }
            }
          },
          responses: {
            '200': {
              description: 'Challenge generated',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/AuthChallengeResponse' }
                }
              }
            }
          }
        }
      },
      '/api/auth/verify': {
        post: {
          summary: 'Verify challenge signature and issue session',
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/AuthVerifyRequest' }
              }
            }
          },
          responses: {
            '200': {
              description: 'Signature accepted and session issued',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/AuthVerifyResponse' }
                }
              }
            }
          }
        }
      },
      '/api/rotate/prepare': {
        post: {
          summary: 'Prepare key rotation and generate rollback script',
          requestBody: {
            required: false,
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/RotatePrepareRequest' }
              }
            }
          },
          responses: {
            '200': {
              description: 'Rotation plan created',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/RotatePrepareResponse' }
                }
              }
            }
          }
        }
      },
      '/api/rotate/confirm': {
        post: {
          summary: 'Confirm or cancel prepared key rotation',
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/RotateConfirmRequest' }
              }
            }
          },
          responses: {
            '200': {
              description: 'Rotation plan applied or cancelled',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/RotateConfirmResponse' }
                }
              }
            }
          }
        }
      },
      '/api/rotate/{planId}': {
        get: {
          summary: 'Get prepared rotation plan status',
          parameters: [
            {
              in: 'path',
              name: 'planId',
              required: true,
              schema: { type: 'string' }
            }
          ],
          responses: {
            '200': {
              description: 'Rotation plan status',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/RotateStatusResponse' }
                }
              }
            }
          }
        }
      },
      '/api/kill-switch/script': {
        get: {
          summary: 'Download VPS killswitch script',
          responses: {
            '200': {
              description: 'Script metadata or plain script',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/KillSwitchScriptResponse' }
                }
              }
            }
          }
        }
      },
      '/api/vps/targets': {
        get: {
          summary: 'List VPS targets with health and active target',
          responses: {
            '200': {
              description: 'VPS targets and current active target',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/VpsTargetsResponse' }
                }
              }
            }
          }
        }
      },
      '/api/vps/failover': {
        post: {
          summary: 'Trigger automatic failover or force specific target',
          requestBody: {
            required: false,
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/VpsFailoverRequest' }
              }
            }
          },
          responses: {
            '200': {
              description: 'Failover result',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/VpsFailoverResponse' }
                }
              }
            }
          }
        }
      },
      '/api/vps-setup-script': {
        get: {
          summary: 'Generate setup script for selected VPS target',
          parameters: [
            {
              in: 'query',
              name: 'vpsId',
              required: false,
              schema: { type: 'string' }
            },
            {
              in: 'query',
              name: 'withCrowdsec',
              required: false,
              schema: { type: 'string', enum: ['1'] }
            }
          ],
          responses: {
            '200': {
              description: 'Setup script payload with hash and selected VPS',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/VpsSetupScriptResponse' }
                }
              }
            }
          }
        }
      },
      '/api/audit/verify': {
        get: {
          summary: 'Verify audit log hash chain integrity',
          responses: {
            '200': {
              description: 'Audit chain verification report',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/AuditVerifyResponse' }
                }
              }
            }
          }
        }
      }
    }
  });
});

app.get('/api/kill-switch/script', (req, res) => {
  const script = buildKillSwitchScript();
  const sha256 = crypto.createHash('sha256').update(script).digest('hex');
  if (req.query.format === 'plain') {
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="miniweed-killswitch.sh"');
    return res.send(script);
  }
  return res.json({ script, sha256, filename: 'miniweed-killswitch.sh' });
});

app.post('/api/rotate/prepare', validateBody(RotatePrepareSchema), async (req, res) => {
  const cfg = loadConfig();
  const active = getActiveVpsTarget(cfg);
  if (!active?.ip || !active?.pubKey || !cfg.publicKey || !cfg.privateKey) {
    return res.status(400).json({ error: 'Configuración incompleta para rotación' });
  }
  try {
    const body = req.body || {};
    let keys = null;
    if (body.nextPrivateKey && body.nextPublicKey) {
      if (!isWireGuardKey(body.nextPrivateKey) || !isWireGuardKey(body.nextPublicKey)) {
        return res.status(400).json({ error: 'nextPrivateKey/nextPublicKey inválidas' });
      }
      if (body.nextPresharedKey && !isWireGuardKey(body.nextPresharedKey)) {
        return res.status(400).json({ error: 'nextPresharedKey inválida' });
      }
      keys = {
        privateKey: body.nextPrivateKey,
        publicKey: body.nextPublicKey,
        presharedKey: body.nextPresharedKey || cfg.presharedKey || ''
      };
    } else {
      keys = await wgApi('/keygen');
    }
    const planId = crypto.randomBytes(16).toString('hex');
    const now = Date.now();
    const next = {
      privateKey: keys.privateKey,
      publicKey: keys.publicKey,
      presharedKey: keys.presharedKey || cfg.presharedKey || ''
    };
    const script = buildVpsRotateScript(cfg, next, active);
    rotationPlans.set(planId, {
      id: planId,
      createdAt: now,
      expiresAt: now + ROTATION_PLAN_TTL_MS,
      previous: {
        privateKey: cfg.privateKey,
        publicKey: cfg.publicKey,
        presharedKey: cfg.presharedKey || ''
      },
      next,
      script,
      scriptSha256: crypto.createHash('sha256').update(script).digest('hex'),
      target: { id: active.id, name: active.name, ip: active.ip }
    });
    audit.log({ action: 'key.rotate.prepare', ip: req.ip, planId, nextFingerprint: keyFingerprint(next.publicKey) });
    return res.json({
      ok: true,
      planId,
      expiresInSec: Math.floor(ROTATION_PLAN_TTL_MS / 1000),
      nextPublicKey: next.publicKey,
      nextPublicKeyFingerprint: keyFingerprint(next.publicKey),
      script,
      scriptSha256: crypto.createHash('sha256').update(script).digest('hex'),
      target: { id: active.id, name: active.name, ip: active.ip }
    });
  } catch (err) {
    return res.status(503).json({ error: `No se pudo preparar rotación: ${err.message}` });
  }
});

app.post('/api/rotate/confirm', validateBody(RotateConfirmSchema), async (req, res) => {
  const planId = String(req.body?.planId || '').trim();
  const apply = req.body?.apply !== false;
  const plan = rotationPlans.get(planId);
  if (!plan || plan.expiresAt <= Date.now()) {
    rotationPlans.delete(planId);
    return res.status(404).json({ error: 'Plan de rotación no encontrado o expirado' });
  }

  if (!apply) {
    rotationPlans.delete(planId);
    audit.log({ action: 'key.rotate.cancel', ip: req.ip, planId });
    return res.json({ ok: true, cancelled: true });
  }

  await withConfigLock(async () => {
    const cfg = loadConfig();
    cfg.privateKey = plan.next.privateKey;
    cfg.publicKey = plan.next.publicKey;
    cfg.presharedKey = plan.next.presharedKey;
    saveConfig(cfg);
    const wgConf = generateWgConf(cfg);
    if (wgConf) fs.writeFileSync(WG_CONF, wgConf);
  });

  rotationPlans.delete(planId);
  audit.log({ action: 'key.rotate.commit', ip: req.ip, planId, publicKeyFingerprint: keyFingerprint(plan.next.publicKey) });
  return res.json({ ok: true, applied: true, nextPublicKey: plan.next.publicKey, nextPublicKeyFingerprint: keyFingerprint(plan.next.publicKey) });
});

app.get('/api/rotate/:planId', (req, res) => {
  const plan = rotationPlans.get(req.params.planId);
  if (!plan || plan.expiresAt <= Date.now()) {
    if (plan) rotationPlans.delete(req.params.planId);
    return res.status(404).json({ error: 'Plan no encontrado o expirado' });
  }
  return res.json({
    id: plan.id,
    createdAt: plan.createdAt,
    expiresAt: plan.expiresAt,
    nextPublicKey: plan.next.publicKey,
    nextPublicKeyFingerprint: keyFingerprint(plan.next.publicKey),
    scriptSha256: plan.scriptSha256
  });
});

// ── boot ─────────────────────────────────────────────────────────────────────

function startServer() {
  ensureDataDir();
  ensureBackgroundTimers();
  process.env.APP_SEED = loadOrCreateAppSeed();
  API_AUTH_TOKEN = loadOrCreateApiToken();
  migrateConfigIfNeeded();
  refreshHealthSnapshot();
  if (!healthTimer) {
    healthTimer = setInterval(() => {
      refreshHealthSnapshot();
    }, 5 * 60 * 1000);
    if (typeof healthTimer.unref === 'function') healthTimer.unref();
  }
  const parsedPort = parseInt(process.env.PORT, 10);
  const PORT = Number.isFinite(parsedPort) ? parsedPort : 3000;
  const server = app.listen(PORT, () => {
    const actualPort = server.address() && server.address().port ? server.address().port : PORT;
    console.log(`[web] Umbrel Tunnel UI en :${actualPort}`);
  });
  server.keepAliveTimeout = 0;
  runningServers += 1;
  server.on('close', () => {
    runningServers = Math.max(0, runningServers - 1);
    if (runningServers === 0) {
      stopBackgroundTimers();
    }
  });
  return server;
}

if (require.main === module) {
  startServer();
}

module.exports = {
  app,
  startServer,
  stopBackgroundTimers,
  _internals: {
    keyFingerprint,
    validateEmailWithMx,
    buildBackupPayload,
    restoreBackupPayload,
    loadConfig,
    saveConfig
  }
};
