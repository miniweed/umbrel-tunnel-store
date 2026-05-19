const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

jest.mock('dns', () => ({
  promises: {
    resolveMx: jest.fn(async () => [{ exchange: 'mail.example.com', priority: 10 }]),
    resolve4: jest.fn(async () => ['127.0.0.1'])
  }
}));

const dns = require('dns');

async function startAppServer(tempDir) {
  process.env.DATA_DIR = tempDir;
  process.env.APP_SEED = 'a'.repeat(64);
  process.env.PORT = '0';
  jest.resetModules();
  const mod = require('../server');
  const server = mod.startServer();
  await new Promise(resolve => server.on('listening', resolve));
  const port = server.address().port;
  return { server, port };
}

function req(port, method, pathname, body = null, headers = {}) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: '127.0.0.1',
      port,
      path: pathname,
      method,
      headers
    };
    const client = require('http').request(options, res => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        resolve({
          status: res.statusCode,
          headers: res.headers,
          body: data
        });
      });
    });
    client.on('error', reject);
    if (body) client.write(body);
    client.end();
  });
}

describe('api hardening', () => {
  let tmpDir;
  let server;
  let port;
  let token;

  beforeEach(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'miniweed-web-'));
    const started = await startAppServer(tmpDir);
    server = started.server;
    port = started.port;
    token = Buffer.from(require('crypto').hkdfSync(
      'sha256',
      Buffer.from(process.env.APP_SEED, 'utf8'),
      Buffer.from('miniweed-tunnel/v1', 'utf8'),
      Buffer.from('tunnel-api-token-v1', 'utf8'),
      32
    )).toString('base64url');
  });

  afterEach(done => {
    server.close(done);
  });

  test('rejects unauthorized api call', async () => {
    const r = await req(port, 'GET', '/api/config');
    expect(r.status).toBe(401);
  });

  test('returns script with sha for authorized call', async () => {
    const payload = JSON.stringify({
      vpsIp: '1.2.3.4',
      vpsPort: 51820,
      vpsPubKey: 'A'.repeat(43) + '=',
      domain: 'example.com',
      acmeEmail: 'ops@example.com',
      privateKey: 'A'.repeat(43) + '=',
      publicKey: 'B'.repeat(43) + '=',
      services: []
    });
    await req(port, 'POST', '/api/config', payload, {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });

    const r = await req(port, 'GET', '/api/vps-setup-script', null, {
      'x-tunnel-api-token': token
    });
    expect(r.status).toBe(200);
    const body = JSON.parse(r.body);
    expect(typeof body.script).toBe('string');
    expect(body.sha256).toMatch(/^[a-f0-9]{64}$/);
    expect(body.vps).toBeTruthy();
    expect(body.vps.ip).toBe('1.2.3.4');
  });

  test('supports multi-vps config and manual failover switch', async () => {
    const payload = JSON.stringify({
      vpsTargets: [
        {
          id: 'vps-a',
          name: 'VPS A',
          ip: '10.10.10.10',
          port: 51820,
          pubKey: 'A'.repeat(43) + '=',
          enabled: true,
          priority: 1
        },
        {
          id: 'vps-b',
          name: 'VPS B',
          ip: '11.11.11.11',
          port: 51821,
          pubKey: 'B'.repeat(43) + '=',
          enabled: true,
          priority: 0
        }
      ],
      activeVpsId: 'vps-a',
      domain: 'example.com',
      acmeEmail: 'ops@example.com',
      privateKey: 'C'.repeat(43) + '=',
      publicKey: 'D'.repeat(43) + '=',
      services: []
    });
    const saved = await req(port, 'POST', '/api/config', payload, {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });
    expect(saved.status).toBe(200);

    const switchRes = await req(port, 'POST', '/api/vps/failover', JSON.stringify({ targetId: 'vps-b' }), {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });
    expect(switchRes.status).toBe(200);
    const switched = JSON.parse(switchRes.body);
    expect(switched.ok).toBe(true);
    expect(switched.activeVpsId).toBe('vps-b');

    const cfgRes = await req(port, 'GET', '/api/config', null, {
      'x-tunnel-api-token': token
    });
    expect(cfgRes.status).toBe(200);
    const cfgBody = JSON.parse(cfgRes.body);
    expect(Array.isArray(cfgBody.vpsTargets)).toBe(true);
    expect(cfgBody.activeVpsId).toBe('vps-b');
    expect(cfgBody.vpsIp).toBe('11.11.11.11');
  });

  test('can request setup script with crowdsec for specific vps', async () => {
    const payload = JSON.stringify({
      vpsTargets: [
        {
          id: 'vps-c',
          name: 'VPS C',
          ip: '12.12.12.12',
          port: 51820,
          pubKey: 'A'.repeat(43) + '=',
          enabled: true,
          priority: 0
        }
      ],
      activeVpsId: 'vps-c',
      domain: 'example.com',
      acmeEmail: 'ops@example.com',
      privateKey: 'A'.repeat(43) + '=',
      publicKey: 'B'.repeat(43) + '=',
      services: []
    });
    const saved = await req(port, 'POST', '/api/config', payload, {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });
    expect(saved.status).toBe(200);

    const r = await req(port, 'GET', '/api/vps-setup-script?vpsId=vps-c&withCrowdsec=1', null, {
      'x-tunnel-api-token': token
    });
    expect(r.status).toBe(200);
    const body = JSON.parse(r.body);
    expect(body.withCrowdsec).toBe(true);
    expect(body.script).toContain('Instalando CrowdSec');
    expect(body.vps.id).toBe('vps-c');
  });

  test('health refresh endpoint works', async () => {
    const r = await req(port, 'POST', '/api/health/refresh', null, {
      'x-tunnel-api-token': token
    });
    expect(r.status).toBe(200);
    const body = JSON.parse(r.body);
    expect(body.ok).toBe(true);
  });

  test('validation rejects malformed email', async () => {
    const payload = JSON.stringify({
      vpsIp: '1.2.3.4',
      vpsPort: 51820,
      domain: 'example.com',
      acmeEmail: 'bad-email',
      privateKey: 'A'.repeat(43) + '=',
      publicKey: 'B'.repeat(43) + '=',
      services: []
    });
    const r = await req(port, 'POST', '/api/config', payload, {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });
    expect(r.status).toBe(400);
  });

  test('can set and use UI password session login', async () => {
    const setPwd = await req(port, 'POST', '/api/auth/password', JSON.stringify({ password: 'S3gura__pass__123' }), {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });
    expect(setPwd.status).toBe(200);

    const login = await req(port, 'POST', '/api/auth/login', JSON.stringify({ password: 'S3gura__pass__123' }), {
      'Content-Type': 'application/json'
    });
    expect(login.status).toBe(200);
    const setCookie = Array.isArray(login.headers['set-cookie']) ? login.headers['set-cookie'][0] : String(login.headers['set-cookie'] || '');
    expect(setCookie).toContain('mw_session=');

    const sessionValue = setCookie.split(';')[0].split('=')[1];
    const bySession = await req(port, 'GET', '/api/config', null, {
      Cookie: `mw_session=${sessionValue}`
    });
    expect(bySession.status).toBe(200);

    const logout = await req(port, 'POST', '/api/auth/logout', null, {
      Cookie: `mw_session=${sessionValue}`
    });
    expect(logout.status).toBe(200);

    const afterLogout = await req(port, 'GET', '/api/config', null, {
      Cookie: `mw_session=${sessionValue}`
    });
    expect(afterLogout.status).toBe(401);
  });

  test('pubkey challenge verify flow creates CLI session', async () => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const publicDerB64 = publicKey.export({ format: 'der', type: 'spki' }).toString('base64');

    const add = await req(port, 'POST', '/api/auth/pubkeys', JSON.stringify({
      name: 'cli-test',
      publicKey: publicDerB64
    }), {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });
    expect(add.status).toBe(200);
    const addBody = JSON.parse(add.body);
    expect(addBody.keyId).toBeTruthy();

    const challenge = await req(port, 'POST', '/api/auth/challenge', JSON.stringify({ keyId: addBody.keyId }), {
      'Content-Type': 'application/json'
    });
    expect(challenge.status).toBe(200);
    const challengeBody = JSON.parse(challenge.body);
    expect(challengeBody.challengeId).toBeTruthy();
    const signature = crypto.sign(null, Buffer.from(challengeBody.nonce, 'base64'), privateKey).toString('base64');

    const verify = await req(port, 'POST', '/api/auth/verify', JSON.stringify({
      challengeId: challengeBody.challengeId,
      signature
    }), {
      'Content-Type': 'application/json'
    });
    expect(verify.status).toBe(200);
    const verifyBody = JSON.parse(verify.body);
    expect(verifyBody.sessionToken).toBeTruthy();

    const bySession = await req(port, 'GET', '/api/config', null, {
      Cookie: `mw_session=${verifyBody.sessionToken}`
    });
    expect(bySession.status).toBe(200);
  });

  test('accepts OpenSSH ssh-ed25519 public key format', async () => {
    const { publicKey } = crypto.generateKeyPairSync('ed25519');
    const der = publicKey.export({ format: 'der', type: 'spki' });
    const rawKey = der.slice(-32);
    const type = Buffer.from('ssh-ed25519', 'utf8');
    const blob = Buffer.concat([
      Buffer.from([0, 0, 0, type.length]),
      type,
      Buffer.from([0, 0, 0, rawKey.length]),
      rawKey
    ]);
    const rawOpenSsh = `ssh-ed25519 ${blob.toString('base64')} openssh-cli@test`;
    const add = await req(port, 'POST', '/api/auth/pubkeys', JSON.stringify({
      name: 'openssh-cli',
      publicKey: rawOpenSsh
    }), {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });
    expect(add.status).toBe(200);
    const body = JSON.parse(add.body);
    expect(body.keyId).toBeTruthy();
  });

  test('rotation prepare and commit flow works', async () => {
    const seedPayload = JSON.stringify({
      vpsIp: '1.2.3.4',
      vpsPort: 51820,
      vpsPubKey: 'A'.repeat(43) + '=',
      domain: 'example.com',
      acmeEmail: 'ops@example.com',
      privateKey: 'A'.repeat(43) + '=',
      publicKey: 'B'.repeat(43) + '=',
      services: []
    });
    const saved = await req(port, 'POST', '/api/config', seedPayload, {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });
    expect(saved.status).toBe(200);

    const prep = await req(port, 'POST', '/api/rotate/prepare', JSON.stringify({
      nextPrivateKey: 'C'.repeat(43) + '=',
      nextPublicKey: 'D'.repeat(43) + '=',
      nextPresharedKey: 'E'.repeat(43) + '='
    }), {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });
    expect(prep.status).toBe(200);
    const prepBody = JSON.parse(prep.body);
    expect(prepBody.planId).toBeTruthy();
    expect(prepBody.scriptSha256).toMatch(/^[a-f0-9]{64}$/);

    const confirm = await req(port, 'POST', '/api/rotate/confirm', JSON.stringify({ planId: prepBody.planId, apply: true }), {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });
    expect(confirm.status).toBe(200);
    const confirmBody = JSON.parse(confirm.body);
    expect(confirmBody.applied).toBe(true);
    expect(confirmBody.nextPublicKey).toBeTruthy();
  });

  test('returns kill switch script with sha', async () => {
    const r = await req(port, 'GET', '/api/kill-switch/script', null, {
      'x-tunnel-api-token': token
    });
    expect(r.status).toBe(200);
    const body = JSON.parse(r.body);
    expect(body.filename).toBe('miniweed-killswitch.sh');
    expect(body.sha256).toMatch(/^[a-f0-9]{64}$/);
    expect(body.script).toContain('wg-quick@wg0');
    expect(body.script).toContain('must run as root');
    expect(body.script).toContain('WG_PORT="${WG_PORT:-51820}"');
    expect(body.script).toContain('iptables -w -C INPUT -p udp --dport "$WG_PORT" -j DROP');
    expect(body.script).toContain('STATUS_FILE="${STATUS_FILE:-/var/run/miniweed.status}"');
  });

  test('returns audit chain verification status', async () => {
    const r = await req(port, 'GET', '/api/audit/verify', null, {
      'x-tunnel-api-token': token
    });
    expect(r.status).toBe(200);
    const body = JSON.parse(r.body);
    expect(typeof body.ok).toBe('boolean');
    expect(typeof body.entries).toBe('number');
  });

  test('rejects rotate prepare with only one key', async () => {
    const r = await req(port, 'POST', '/api/rotate/prepare', JSON.stringify({
      nextPrivateKey: 'C'.repeat(43) + '='
    }), {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });
    expect(r.status).toBe(400);
    const body = JSON.parse(r.body);
    expect(body.error).toBe('validation');
  });

  test('openapi includes rotate and audit schemas', async () => {
    const r = await req(port, 'GET', '/api/openapi.json', null, {
      'x-tunnel-api-token': token
    });
    expect(r.status).toBe(200);
    const body = JSON.parse(r.body);
    expect(body.components.schemas.RotatePrepareRequest).toBeTruthy();
    expect(body.paths['/api/rotate/{planId}']).toBeTruthy();
    expect(body.paths['/api/audit/verify']).toBeTruthy();
  });
});
