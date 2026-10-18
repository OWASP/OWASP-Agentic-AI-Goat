'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createApplicationCors } = require('../server/middleware/applicationCors');

async function fixture(t, options) {
  const app = express();
  let effects = 0;
  app.use(createApplicationCors(options));
  app.use((req, res) => { effects++; res.json({ ok: true }); });
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  return { request: (path, options) => fetch(`http://127.0.0.1:${server.address().port}${path}`, options),
    effects: () => effects };
}

test('SecureShop rejects disallowed and opaque origins before preflight or request effects', async t => {
  const f = await fixture(t, { secureShopOrigins: ['http://localhost:3000', 'null'] });
  for (const origin of ['https://untrusted.example', 'null']) {
    for (const path of ['/api/secureshop', '/api/secureshop/admin/users', '/API/SecureShop/v2/customer']) {
      for (const method of ['OPTIONS', 'POST']) {
        const r = await f.request(path, { method, headers: { Origin: origin,
          'Access-Control-Request-Method': 'POST', 'Access-Control-Request-Headers': 'authorization' } });
        assert.equal(r.status, 403);
        assert.equal(r.headers.get('access-control-allow-origin'), null);
        assert.equal(r.headers.get('access-control-allow-credentials'), null);
        assert.match(r.headers.get('vary'), /Origin/);
        assert.doesNotMatch(await r.text(), /untrusted\.example/);
      }
    }
  }
  assert.equal(f.effects(), 0);
});

test('allowlisted SecureShop preflight and actual request preserve browser authorization contract', async t => {
  const f = await fixture(t);
  for (const origin of ['http://localhost:3000', 'http://127.0.0.1:3000']) {
    const preflight = await f.request('/api/secureshop/admin/agent/chat', {
      method: 'OPTIONS', headers: { Origin: origin, 'Access-Control-Request-Method': 'POST',
        'Access-Control-Request-Headers': 'authorization,content-type' },
    });
    assert.equal(preflight.status, 204);
    assert.equal(preflight.headers.get('access-control-allow-origin'), origin);
    assert.equal(preflight.headers.get('access-control-allow-credentials'), 'true');
    assert.match(preflight.headers.get('access-control-allow-headers'), /authorization/);
    const actual = await f.request('/api/secureshop/admin/agent/chat', { method: 'POST', headers: { Origin: origin } });
    assert.equal(actual.status, 200);
    assert.equal(actual.headers.get('access-control-allow-origin'), origin);
  }
  assert.equal(f.effects(), 2);
});

test('configured hosted origins and Origin-free clients remain supported', async t => {
  const f = await fixture(t, { secureShopOrigins: ['https://workshop.example'] });
  assert.equal((await f.request('/api/secureshop/customer')).status, 200);
  const r = await f.request('/api/secureshop/customer', { headers: { Origin: 'https://workshop.example' } });
  assert.equal(r.status, 200);
  assert.equal(r.headers.get('access-control-allow-origin'), 'https://workshop.example');
  assert.equal((await f.request('/api/secureshop/customer', { headers: { Origin: 'http://localhost:3000' } })).status, 403);
});

test('unrelated challenge routes retain the intentional reflective CORS behavior', async t => {
  const f = await fixture(t);
  for (const path of ['/api/vulnerabilities/xxe', '/api/secureshop-example']) {
    const r = await f.request(path, { method: 'OPTIONS', headers: {
      Origin: 'https://untrusted.example', 'Access-Control-Request-Method': 'POST' } });
    assert.equal(r.status, 204);
    assert.equal(r.headers.get('access-control-allow-origin'), 'https://untrusted.example');
    assert.equal(r.headers.get('access-control-allow-credentials'), 'true');
  }
  assert.equal(f.effects(), 0);
});

test('production static assets remain readable by the opaque frame while authenticated APIs reject it', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'dvaia-production-assets-'));
  fs.mkdirSync(path.join(root, 'assets'));fs.writeFileSync(path.join(root, 'assets', 'frame.js'), 'export const ready=true;');
  const app = express();app.use(createApplicationCors());app.use(express.static(root));
  app.use((_req, res) => res.status(404).end());
  const server = app.listen(0, '127.0.0.1');await new Promise(resolve => server.once('listening', resolve));
  t.after(async () => { server.closeAllConnections();await new Promise(resolve => server.close(resolve));
    fs.rmSync(root, { recursive: true, force: true }); });
  const base = `http://127.0.0.1:${server.address().port}`;
  for (const method of ['GET', 'HEAD']) {
    const asset = await fetch(base + '/assets/frame.js', { method, headers: { Origin: 'null' } });
    assert.equal(asset.status, 200);assert.equal(asset.headers.get('access-control-allow-origin'), 'null');
  }
  const api = await fetch(base + '/api/secureshop/v2/auth/login', { headers: { Origin: 'null' } });
  assert.equal(api.status, 403);assert.equal(api.headers.get('access-control-allow-origin'), null);
});

test('platform identity, administration, progress and evidence paths reject untrusted preflight and effects', async t => {
  const f = await fixture(t);
  const paths = ['/api/auth/status', '/API/Auth/login', '/api/admin/users', '/api/admin/agent-runs',
    '/api/agent-runs/run/retry', '/api/changes', '/api/workshop/config', '/api/workshop/student/stats',
    '/api/workshop/progress/reset/example', '/api/workshop/challenges', '/api/workshop/instructor/students',
    '/api/workshop/objective/complete', '/api/workshop/user-activity', '/api/workshop/time/heartbeat',
    '/api/solutions/example', '/api/hints/example', '/api/ctf/admin/stats', '/api/monitoring/health',
    '/event-gate/login', '/api/workshop/csrf/browser-attempt'];
  for (const path of paths) {
    for (const origin of ['null', 'https://untrusted.example']) {
      for (const method of ['OPTIONS', 'GET', 'POST']) {
        const r = await f.request(path, { method, headers: { Origin: origin,
          'Access-Control-Request-Method': 'POST', 'Access-Control-Request-Headers': 'authorization,content-type' } });
        assert.equal(r.status, 403, `${method} ${path} ${origin}`);
        assert.equal(r.headers.get('access-control-allow-origin'), null);
        assert.equal(r.headers.get('access-control-allow-credentials'), null);
        assert.match(r.headers.get('vary'), /Origin/);
      }
    }
  }
  assert.equal(f.effects(), 0);
});

test('platform uses configured origins without trusting Host or forwarding headers', async t => {
  const f = await fixture(t, { secureShopOrigins: ['https://workshop.example'] });
  const allowed = await f.request('/api/auth/status', { headers: { Origin: 'https://workshop.example' } });
  assert.equal(allowed.status, 200);
  assert.equal(allowed.headers.get('access-control-allow-origin'), 'https://workshop.example');
  const denied = await f.request('/api/admin/users', { headers: {
    Origin: 'https://untrusted.example', Host: 'untrusted.example',
    'X-Forwarded-Host': 'untrusted.example', 'X-Forwarded-Proto': 'https' } });
  assert.equal(denied.status, 403);
  assert.equal((await f.request('/api/monitoring/health')).status, 200);
});

test('platform boundaries do not consume neighboring challenge routes or prefix lookalikes', async t => {
  const f = await fixture(t);
  for (const path of ['/api/administer', '/api/workshop/configuration-attack', '/api/ctf/administrator',
    '/api/workshop/csrf/transfer', '/api/workshop/rag-injection/chat', '/api/ctf/attempt']) {
    const r = await f.request(path, { method: 'OPTIONS', headers: {
      Origin: 'null', 'Access-Control-Request-Method': 'POST' } });
    assert.equal(r.status, 204);
    assert.equal(r.headers.get('access-control-allow-origin'), 'null');
  }
});

test('trusted origins receive only the reviewed method and header contract', async t => {
  const f = await fixture(t);
  for (const path of ['/api/auth/status', '/api/secureshop/customer/cart']) {
    for (const requested of [
      { 'Access-Control-Request-Method': 'TRACE' },
      { 'Access-Control-Request-Method': 'POST', 'Access-Control-Request-Headers': 'Authorization, X-Forwarded-Host' },
    ]) {
      const r = await f.request(path, { method: 'OPTIONS', headers: { Origin: 'http://localhost:3000', ...requested } });
      assert.equal(r.status, 403);
      assert.equal(r.headers.get('access-control-allow-origin'), null);
      assert.equal(r.headers.get('access-control-allow-credentials'), null);
    }
    const r = await f.request(path, { method: 'OPTIONS', headers: { Origin: 'http://localhost:3000',
      'Access-Control-Request-Method': 'PATCH',
      'Access-Control-Request-Headers': 'Authorization, Content-Type, X-Request-ID' } });
    assert.equal(r.status, 204);
    assert.deepEqual(r.headers.get('access-control-allow-headers').split(','),
      path.startsWith('/api/secureshop/')
        ? ['authorization', 'content-type', 'accept', 'x-request-id',
          'x-dvaia-secureshop-launch', 'x-api-key']
        : ['authorization', 'content-type', 'accept', 'x-request-id']);
    assert.match(r.headers.get('access-control-allow-methods'), /PATCH/);
  }
  assert.equal(f.effects(), 0);
});

test('custom teaching headers remain available on legacy challenge preflights', async t => {
  const f = await fixture(t);
  const r = await f.request('/api/excessive-agency/session', { method: 'OPTIONS', headers: {
    Origin: 'http://localhost:3000', 'Access-Control-Request-Method': 'POST',
    'Access-Control-Request-Headers': 'x-lab-session' } });
  assert.equal(r.status, 204);
  assert.equal(r.headers.get('access-control-allow-headers'), 'x-lab-session');
});

test('launch credential preflight is allowed only on trusted SecureShop origins', async t => {
  const f = await fixture(t);
  const headers = { Origin: 'http://localhost:3000', 'Access-Control-Request-Method': 'POST',
    'Access-Control-Request-Headers': 'Authorization, Content-Type, X-DVAIA-SecureShop-Launch, X-API-Key' };
  const accepted = await f.request('/api/secureshop/bound/sessions', { method: 'OPTIONS', headers });
  assert.equal(accepted.status, 204);
  assert.match(accepted.headers.get('access-control-allow-headers'), /x-dvaia-secureshop-launch/);
  assert.match(accepted.headers.get('access-control-allow-headers'), /x-api-key/);
  for (const path of ['/api/admin/users', '/api/auth/login', '/api/agent-runs']) {
    assert.equal((await f.request(path, { method: 'OPTIONS', headers })).status, 403);
  }
  for (const Origin of ['null', 'https://untrusted.example']) {
    assert.equal((await f.request('/api/secureshop/bound/sessions', { method: 'OPTIONS', headers: { ...headers, Origin } })).status, 403);
  }
  assert.equal((await f.request('/api/secureshop/bound/sessions', { method: 'OPTIONS', headers: {
    ...headers, 'Access-Control-Request-Headers': 'x-dvaia-secureshop-launch,x-forged-owner',
  } })).status, 403);
  assert.equal(f.effects(), 0);
});
