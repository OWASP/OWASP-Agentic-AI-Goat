'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const { applicationProxyTrust } = require('../server/services/applicationProxyTrust');

test('direct startup trusts no proxy and configuration accepts only explicit IP boundaries', () => {
  assert.equal(applicationProxyTrust({}), false);
  assert.equal(applicationProxyTrust({ TRUSTED_PROXY_CIDRS: '' }), false);
  assert.deepEqual(applicationProxyTrust({ TRUSTED_PROXY_CIDRS: '10.2.1.0/24, ::1,10.2.1.0/24' }), ['10.2.1.0/24', '::1']);
  for (const value of ['true', 'false', '1', 'loopback', 'localhost', '*', '0.0.0.0/0', '::/0',
    '127.0.0.1,', ' ', '10.2.1.0/33', '::1/129', '::1/-1', '::1/01', '::1/64/1',
    'fe80::1%en0', '10.0.0.999', true, ['127.0.0.1'], Array(34).fill('127.0.0.1').join(',')]) {
    assert.throws(() => applicationProxyTrust({ TRUSTED_PROXY_CIDRS: value }),
      { code: 'INVALID_PROXY_TRUST_CONFIGURATION' });
  }
});

async function fixture(t, setting, configure) {
  const app = express();
  app.set('trust proxy', applicationProxyTrust({ TRUSTED_PROXY_CIDRS: setting }));
  configure?.(app);
  app.get('/identity', (req, res) => res.json({ ip: req.ip, ips: req.ips,
    protocol: req.protocol, hostname: req.hostname }));
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  return (path = '/identity', options = {}) => fetch(`http://127.0.0.1:${server.address().port}${path}`, options);
}

test('direct callers cannot replace IP, protocol or hostname using forwarded headers', async t => {
  const request = await fixture(t);
  const result = await (await request('/identity', { headers: {
    'X-Forwarded-For': '198.51.100.25', 'X-Forwarded-Proto': 'https', 'X-Forwarded-Host': 'untrusted.example',
  } })).json();
  assert.equal(result.ip, '127.0.0.1');
  assert.deepEqual(result.ips, []);
  assert.equal(result.protocol, 'http');
  assert.equal(result.hostname, '127.0.0.1');
});

test('trusted proxy chain stops at the first untrusted client and ignores spoofed earlier IPs', async t => {
  const request = await fixture(t, '127.0.0.1/32,10.20.1.0/24');
  const result = await (await request('/identity', { headers: {
    'X-Forwarded-For': '203.0.113.99,198.51.100.25,10.20.1.7',
    'X-Forwarded-Proto': 'https', 'X-Forwarded-Host': 'workshop.example',
  } })).json();
  assert.equal(result.ip, '198.51.100.25');
  assert.deepEqual(result.ips, ['198.51.100.25', '10.20.1.7']);
  assert.equal(result.protocol, 'https');
  assert.equal(result.hostname, 'workshop.example');
});

test('configured remote proxy range does not trust a direct local caller', async t => {
  const request = await fixture(t, '10.20.1.0/24');
  const result = await (await request('/identity', { headers: { 'X-Forwarded-For': '198.51.100.25' } })).json();
  assert.equal(result.ip, '127.0.0.1');
  assert.deepEqual(result.ips, []);
});

test('IPv6 proxy boundaries compile and distinguish trusted from untrusted peers', () => {
  const app = express();
  app.set('trust proxy', applicationProxyTrust({ TRUSTED_PROXY_CIDRS: '2001:db8:abcd::/48,::1/128' }));
  const trusted = app.get('trust proxy fn');
  assert.equal(trusted('2001:db8:abcd::12'), true);
  assert.equal(trusted('2001:db8:abce::12'), false);
  assert.equal(trusted('::1'), true);
  assert.equal(trusted('::2'), false);
});

test('event gate cookie secure attribute follows trusted transport, not raw forwarded text', async t => {
  const previous = { enabled: process.env.EVENT_GATE_ENABLED, password: process.env.EVENT_GATE_PASSWORD };
  process.env.EVENT_GATE_ENABLED = 'true';
  process.env.EVENT_GATE_PASSWORD = 'isolated-test-event-password';
  t.after(() => {
    for (const [key, value] of [['EVENT_GATE_ENABLED', previous.enabled], ['EVENT_GATE_PASSWORD', previous.password]]) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
  });
  const { loginHandler } = require('../server/middleware/eventGate');
  for (const [setting, secure] of [[undefined, false], ['127.0.0.1/32', true]]) {
    const request = await fixture(t, setting, app => {
      app.use(express.json()); app.post('/login', loginHandler);
    });
    const response = await request('/login', { method: 'POST', redirect: 'manual',
      headers: { 'Content-Type': 'application/json', 'X-Forwarded-Proto': 'https' },
      body: JSON.stringify({ password: process.env.EVENT_GATE_PASSWORD }) });
    assert.equal(response.status, 302);
    assert.equal(/; Secure(?:;|$)/.test(response.headers.get('set-cookie')), secure);
  }
});
