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

jest.mock('net', () => {
  const { EventEmitter } = require('events');
  class MockSocket extends EventEmitter {
    setTimeout() {
      return this;
    }

    connect(port, hostname) {
      const key = `${hostname}:${port}`;
      const mock = global.__NET_SOCKET_MOCK__ || {};
      const seq = mock.sequence && mock.sequence[key];
      let outcome = null;
      if (Array.isArray(seq) && seq.length > 0) {
        outcome = seq.shift();
      }
      if (!outcome && mock.rules) {
        outcome = mock.rules[key] || mock.rules[hostname] || null;
      }
      if (!outcome) outcome = 'fail';

      setImmediate(() => {
        if (outcome === 'ok') {
          this.emit('connect');
          return;
        }
        if (outcome === 'timeout') {
          this.emit('timeout');
          return;
        }
        this.emit('error', new Error(`mock-${outcome}`));
      });

      return this;
    }

    destroy() {
      return this;
    }
  }

  return { Socket: MockSocket };
});

const dns = require('dns');

function setNetMock(rules = {}, sequence = {}) {
  global.__NET_SOCKET_MOCK__ = { rules: { ...rules }, sequence: { ...sequence } };
}

async function startAppServer(tempDir) {
  process.env.DATA_DIR = tempDir;
  process.env.APP_SEED = 'a'.repeat(64);
  process.env.PORT = '0';
  jest.resetModules();
  const mod = require('../server');
  const server = mod.startServer();
  await new Promise(resolve => server.on('listening', resolve));
  const port = server.address().port;
  return { server, port, stopBackgroundTimers: mod.stopBackgroundTimers };
}

function req(port, method, pathname, body = null, headers = {}) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: '127.0.0.1',
      port,
      path: pathname,
      method,
      agent: false,
      headers: {
        Connection: 'close',
        ...headers
      }
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
  let stopBackgroundTimers;
  let logSpy;

  beforeEach(async () => {
    setNetMock();
    logSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'miniweed-web-'));
    const started = await startAppServer(tmpDir);
    server = started.server;
    port = started.port;
    stopBackgroundTimers = started.stopBackgroundTimers;
    token = Buffer.from(require('crypto').hkdfSync(
      'sha256',
      Buffer.from(process.env.APP_SEED, 'utf8'),
      Buffer.from('miniweed-tunnel/v1', 'utf8'),
      Buffer.from('tunnel-api-token-v1', 'utf8'),
      32
    )).toString('base64url');
  });

  afterEach(done => {
    server.close(() => {
      if (typeof stopBackgroundTimers === 'function') stopBackgroundTimers();
      if (logSpy) logSpy.mockRestore();
      done();
    });
  });

  test('rejects unauthorized api call', async () => {
    const r = await req(port, 'GET', '/api/config');
    expect(r.status).toBe(401);
  });

  test('bootstraps persistent app seed when env seed is missing', async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'miniweed-web-seed-'));
    const prevSeed = process.env.APP_SEED;
    const prevToken = process.env.TUNNEL_API_TOKEN;
    const prevData = process.env.DATA_DIR;
    const prevPort = process.env.PORT;

    delete process.env.APP_SEED;
    delete process.env.TUNNEL_API_TOKEN;
    process.env.DATA_DIR = tempDir;
    process.env.PORT = '0';

    jest.resetModules();
    const mod = require('../server');
    const s1 = mod.startServer();
    await new Promise(resolve => s1.on('listening', resolve));
    await new Promise(resolve => s1.close(resolve));
    if (typeof mod.stopBackgroundTimers === 'function') mod.stopBackgroundTimers();

    const seedPath = path.join(tempDir, 'app-seed');
    expect(fs.existsSync(seedPath)).toBe(true);
    const firstSeed = String(fs.readFileSync(seedPath, 'utf8')).trim();
    expect(firstSeed.length).toBeGreaterThanOrEqual(32);

    jest.resetModules();
    const mod2 = require('../server');
    const s2 = mod2.startServer();
    await new Promise(resolve => s2.on('listening', resolve));
    await new Promise(resolve => s2.close(resolve));
    if (typeof mod2.stopBackgroundTimers === 'function') mod2.stopBackgroundTimers();

    const secondSeed = String(fs.readFileSync(seedPath, 'utf8')).trim();
    expect(secondSeed).toBe(firstSeed);

    if (prevSeed === undefined) delete process.env.APP_SEED; else process.env.APP_SEED = prevSeed;
    if (prevToken === undefined) delete process.env.TUNNEL_API_TOKEN; else process.env.TUNNEL_API_TOKEN = prevToken;
    if (prevData === undefined) delete process.env.DATA_DIR; else process.env.DATA_DIR = prevData;
    if (prevPort === undefined) delete process.env.PORT; else process.env.PORT = prevPort;

    jest.resetModules();
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

  test('returns vps targets with health metadata', async () => {
    const payload = JSON.stringify({
      vpsTargets: [
        {
          id: 'vps-h1',
          name: 'VPS Health 1',
          ip: '127.0.0.1',
          port: 51820,
          pubKey: 'A'.repeat(43) + '=',
          enabled: true,
          priority: 0
        }
      ],
      activeVpsId: 'vps-h1',
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

    const r = await req(port, 'GET', '/api/vps/targets', null, {
      'x-tunnel-api-token': token
    });
    expect(r.status).toBe(200);
    const body = JSON.parse(r.body);
    expect(body.activeVpsId).toBe('vps-h1');
    expect(Array.isArray(body.targets)).toBe(true);
    expect(body.targets[0].id).toBe('vps-h1');
    expect(typeof body.targets[0].fingerprint).toBe('string');
    expect(body.targets[0].health).toBeTruthy();
    expect(typeof body.targets[0].health.ok).toBe('boolean');
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
    expect(body.script).toContain('curl -fsSL https://install.crowdsec.net | sh');
    expect(body.script).toContain('cscli lapi status >/dev/null 2>&1 || echo "Advertencia: cscli no pudo validar LAPI"');
    expect(body.script).toContain('iptables-save | grep -qi crowdsec || echo "Advertencia: no se detecto hook iptables de CrowdSec"');
    expect(body.vps.id).toBe('vps-c');
  });

  test('auto failover respects streaks, cooldown, and recovery after cooldown', async () => {
    const nowSpy = jest.spyOn(Date, 'now');
    let now = 1_000_000;
    nowSpy.mockImplementation(() => now);

    // Keep everyone healthy during initial save/health refresh.
    setNetMock(
      {
        '10.0.0.1:22': 'ok',
        '10.0.0.1:443': 'ok',
        '10.0.0.2:22': 'ok',
        '10.0.0.2:443': 'ok'
      }
    );

    const payload = JSON.stringify({
      vpsTargets: [
        {
          id: 'vps-a',
          name: 'VPS A',
          ip: '10.0.0.1',
          port: 51820,
          pubKey: 'A'.repeat(43) + '=',
          enabled: true,
          priority: 0
        },
        {
          id: 'vps-b',
          name: 'VPS B',
          ip: '10.0.0.2',
          port: 51820,
          pubKey: 'B'.repeat(43) + '=',
          enabled: true,
          priority: 1
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

    // Active starts failing, candidate remains healthy.
    setNetMock(
      {
        '10.0.0.1:22': 'fail',
        '10.0.0.1:443': 'fail',
        '10.0.0.2:22': 'ok',
        '10.0.0.2:443': 'ok'
      }
    );

    let auto1 = await req(port, 'POST', '/api/vps/failover', JSON.stringify({}), {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });
    expect(auto1.status).toBe(200);
    expect(JSON.parse(auto1.body).switched).toBe(false);

    now += 1000;
    let auto2 = await req(port, 'POST', '/api/vps/failover', JSON.stringify({}), {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });
    expect(auto2.status).toBe(200);
    const switchedToB = JSON.parse(auto2.body);
    expect(switchedToB.switched).toBe(true);
    expect(switchedToB.activeVpsId).toBe('vps-b');

    setNetMock(
      {
        '10.0.0.1:22': 'ok',
        '10.0.0.1:443': 'ok',
        '10.0.0.2:22': 'fail',
        '10.0.0.2:443': 'fail'
      }
    );

    now += 1000;
    await req(port, 'POST', '/api/vps/failover', JSON.stringify({}), {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });

    now += 1000;
    const cooldownBlocked = await req(port, 'POST', '/api/vps/failover', JSON.stringify({}), {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });
    expect(cooldownBlocked.status).toBe(200);
    const blockedBody = JSON.parse(cooldownBlocked.body);
    expect(blockedBody.switched).toBe(false);
    expect(blockedBody.activeVpsId).toBe('vps-b');

    now += (2 * 60 * 1000) + 1000;
    const recovered = await req(port, 'POST', '/api/vps/failover', JSON.stringify({}), {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });
    expect(recovered.status).toBe(200);
    const recoveredBody = JSON.parse(recovered.body);
    expect(recoveredBody.switched).toBe(true);
    expect(recoveredBody.activeVpsId).toBe('vps-a');

    nowSpy.mockRestore();
  });

  test('auto failover tie-break uses lexical name when priorities equal', async () => {
    // Keep everyone healthy during initial save/health refresh.
    setNetMock(
      {
        '10.1.0.1:22': 'ok',
        '10.1.0.1:443': 'ok',
        '10.1.0.2:22': 'ok',
        '10.1.0.2:443': 'ok',
        '10.1.0.3:22': 'ok',
        '10.1.0.3:443': 'ok'
      }
    );

    const payload = JSON.stringify({
      vpsTargets: [
        {
          id: 'active',
          name: 'Active-Z',
          ip: '10.1.0.1',
          port: 51820,
          pubKey: 'A'.repeat(43) + '=',
          enabled: true,
          priority: 5
        },
        {
          id: 'alpha',
          name: 'Alpha',
          ip: '10.1.0.2',
          port: 51820,
          pubKey: 'B'.repeat(43) + '=',
          enabled: true,
          priority: 1
        },
        {
          id: 'beta',
          name: 'Beta',
          ip: '10.1.0.3',
          port: 51820,
          pubKey: 'C'.repeat(43) + '=',
          enabled: true,
          priority: 1
        }
      ],
      activeVpsId: 'active',
      domain: 'example.com',
      acmeEmail: 'ops@example.com',
      privateKey: 'D'.repeat(43) + '=',
      publicKey: 'E'.repeat(43) + '=',
      services: []
    });
    const saved = await req(port, 'POST', '/api/config', payload, {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });
    expect(saved.status).toBe(200);

    // Active degrades, both candidates healthy with same priority.
    setNetMock(
      {
        '10.1.0.1:22': 'fail',
        '10.1.0.1:443': 'fail',
        '10.1.0.2:22': 'ok',
        '10.1.0.2:443': 'ok',
        '10.1.0.3:22': 'ok',
        '10.1.0.3:443': 'ok'
      }
    );

    await req(port, 'POST', '/api/vps/failover', JSON.stringify({}), {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });

    const auto = await req(port, 'POST', '/api/vps/failover', JSON.stringify({}), {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });
    expect(auto.status).toBe(200);
    const body = JSON.parse(auto.body);
    expect(body.switched).toBe(true);
    expect(body.activeVpsId).toBe('alpha');
    expect(body.next.name).toBe('Alpha');
  });

  test('manual switch and later auto failover recovery interoperate correctly', async () => {
    setNetMock(
      {
        '10.2.0.1:22': 'ok',
        '10.2.0.1:443': 'ok',
        '10.2.0.2:22': 'ok',
        '10.2.0.2:443': 'ok'
      }
    );

    const payload = JSON.stringify({
      vpsTargets: [
        {
          id: 'vps-a',
          name: 'VPS A',
          ip: '10.2.0.1',
          port: 51820,
          pubKey: 'A'.repeat(43) + '=',
          enabled: true,
          priority: 0
        },
        {
          id: 'vps-b',
          name: 'VPS B',
          ip: '10.2.0.2',
          port: 51820,
          pubKey: 'B'.repeat(43) + '=',
          enabled: true,
          priority: 1
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

    const manual = await req(port, 'POST', '/api/vps/failover', JSON.stringify({ targetId: 'vps-b' }), {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });
    expect(manual.status).toBe(200);
    const manualBody = JSON.parse(manual.body);
    expect(manualBody.switched).toBe(true);
    expect(manualBody.activeVpsId).toBe('vps-b');

    setNetMock(
      {
        '10.2.0.1:22': 'ok',
        '10.2.0.1:443': 'ok',
        '10.2.0.2:22': 'fail',
        '10.2.0.2:443': 'fail'
      }
    );

    const auto1 = await req(port, 'POST', '/api/vps/failover', JSON.stringify({}), {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });
    expect(auto1.status).toBe(200);
    expect(JSON.parse(auto1.body).switched).toBe(false);

    const auto2 = await req(port, 'POST', '/api/vps/failover', JSON.stringify({}), {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });
    expect(auto2.status).toBe(200);
    const autoBody = JSON.parse(auto2.body);
    expect(autoBody.switched).toBe(true);
    expect(autoBody.activeVpsId).toBe('vps-a');
  });

  test('auto failover recovers when current active target is incomplete', async () => {
    setNetMock(
      {
        '10.3.0.1:22': 'fail',
        '10.3.0.1:443': 'fail',
        '10.3.0.2:22': 'fail',
        '10.3.0.2:443': 'fail'
      }
    );

    const payload = JSON.stringify({
      vpsTargets: [
        {
          id: 'vps-incomplete',
          name: 'VPS Incomplete',
          ip: '10.3.0.1',
          port: 51820,
          enabled: true,
          priority: 0
        },
        {
          id: 'vps-ok',
          name: 'VPS OK',
          ip: '10.3.0.2',
          port: 51820,
          pubKey: 'B'.repeat(43) + '=',
          enabled: true,
          priority: 1
        }
      ],
      activeVpsId: 'vps-incomplete',
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

    setNetMock(
      {
        '10.3.0.1:22': 'fail',
        '10.3.0.1:443': 'fail',
        '10.3.0.2:22': 'ok',
        '10.3.0.2:443': 'ok'
      }
    );

    const auto1 = await req(port, 'POST', '/api/vps/failover', JSON.stringify({}), {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });
    expect(auto1.status).toBe(200);
    expect(JSON.parse(auto1.body).switched).toBe(false);

    const auto2 = await req(port, 'POST', '/api/vps/failover', JSON.stringify({}), {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });
    expect(auto2.status).toBe(200);
    const body = JSON.parse(auto2.body);
    expect(body.switched).toBe(true);
    expect(body.activeVpsId).toBe('vps-ok');
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

  test('accepts minimal progressive setup payload and returns validation details for malformed body', async () => {
    const minimal = await req(port, 'POST', '/api/config', JSON.stringify({
      vpsIp: '1.2.3.4',
      domain: 'example.com',
      acmeEmail: 'ops@example.com'
    }), {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });
    expect(minimal.status).toBe(200);

    const malformed = await req(port, 'POST', '/api/config', JSON.stringify([]), {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });
    expect(malformed.status).toBe(400);
    const malformedBody = JSON.parse(malformed.body);
    expect(malformedBody.error).toBe('validation');
    expect(Array.isArray(malformedBody.issues)).toBe(true);
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

  test('auth endpoints enforce zod validation', async () => {
    const badSetPwd = await req(port, 'POST', '/api/auth/password', JSON.stringify({ password: 'short' }), {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });
    expect(badSetPwd.status).toBe(400);
    expect(JSON.parse(badSetPwd.body).error).toBe('validation');

    const badLogin = await req(port, 'POST', '/api/auth/login', JSON.stringify({ password: '' }), {
      'Content-Type': 'application/json'
    });
    expect(badLogin.status).toBe(400);
    expect(JSON.parse(badLogin.body).error).toBe('validation');
  });

  test('stores auth secrets encrypted at rest', async () => {
    const setPwd = await req(port, 'POST', '/api/auth/password', JSON.stringify({ password: 'S3gura__pass__123' }), {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });
    expect(setPwd.status).toBe(200);

    const login = await req(port, 'POST', '/api/auth/login', JSON.stringify({ password: 'S3gura__pass__123' }), {
      'Content-Type': 'application/json'
    });
    expect(login.status).toBe(200);

    const raw = JSON.parse(fs.readFileSync(path.join(tmpDir, 'config.json'), 'utf8'));
    expect(raw.auth).toBeTruthy();
    expect(raw.auth.passwordHash).toMatchObject({ v: 1 });
    expect(raw.auth.sessions).toMatchObject({ v: 1 });
  });

  test('supports configurable failover policy via config', async () => {
    const payload = JSON.stringify({
      vpsTargets: [
        {
          id: 'vps-a',
          name: 'VPS A',
          ip: '10.4.0.1',
          port: 51820,
          pubKey: 'A'.repeat(43) + '=',
          enabled: true,
          priority: 0
        },
        {
          id: 'vps-b',
          name: 'VPS B',
          ip: '10.4.0.2',
          port: 51820,
          pubKey: 'B'.repeat(43) + '=',
          enabled: true,
          priority: 1
        }
      ],
      activeVpsId: 'vps-a',
      domain: 'example.com',
      acmeEmail: 'ops@example.com',
      privateKey: 'C'.repeat(43) + '=',
      publicKey: 'D'.repeat(43) + '=',
      failoverPolicy: {
        activeFailuresRequired: 1,
        candidateSuccessesRequired: 1,
        cooldownMs: 0
      },
      services: []
    });
    const saved = await req(port, 'POST', '/api/config', payload, {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });
    expect(saved.status).toBe(200);

    setNetMock(
      {
        '10.4.0.1:22': 'fail',
        '10.4.0.1:443': 'fail',
        '10.4.0.2:22': 'ok',
        '10.4.0.2:443': 'ok'
      }
    );

    const auto = await req(port, 'POST', '/api/vps/failover', JSON.stringify({}), {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });
    expect(auto.status).toBe(200);
    const body = JSON.parse(auto.body);
    expect(body.switched).toBe(true);
    expect(body.policy).toMatchObject({
      activeFailuresRequired: 1,
      candidateSuccessesRequired: 1,
      cooldownMs: 0
    });
  });

  test('applies strict CSP for SPA routes and compatibility CSP for legacy routes', async () => {
    const appRes = await req(port, 'GET', '/app/index.html');
    expect(appRes.status).toBe(200);
    const appCsp = String(appRes.headers['content-security-policy'] || '');
    expect(appCsp).toContain("script-src 'self'");
    expect(appCsp).not.toContain("script-src 'self' 'unsafe-inline'");

    const legacyRes = await req(port, 'GET', '/legacy');
    expect(legacyRes.status).toBe(200);
    const legacyCsp = String(legacyRes.headers['content-security-policy'] || '');
    expect(legacyCsp).toContain("script-src 'self' 'unsafe-inline'");
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
    expect(body.paths['/api/vps/failover']).toBeTruthy();
    expect(body.paths['/api/vps/targets']).toBeTruthy();
    expect(body.paths['/api/vps-setup-script']).toBeTruthy();
    expect(body.components.schemas.VpsFailoverResponse).toBeTruthy();
  });
});
