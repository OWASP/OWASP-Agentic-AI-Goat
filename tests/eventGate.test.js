'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const express = require('express');
const cookieParser = require('cookie-parser');
const {
  COOKIE_MAX_AGE_MS,
  assertEventGateConfiguration,
  createEventGateHandlers,
  makeCookieValue,
  safeLocalRedirect,
  verifyCookie,
} = require('../server/middleware/eventGate');

const PASSWORD = 'owned-event-password';
const START = Date.UTC(2026, 8, 15, 12, 0, 0);

function signedValue(password, issuedAt, expiresAt) {
  const payload = `v1.${issuedAt}.${expiresAt}`;
  const key = crypto.createHash('sha256').update(`event-gate:${password}`).digest();
  const signature = crypto.createHmac('sha256', key).update(payload).digest('hex');
  return `${payload}.${signature}`;
}

function env(overrides = {}) {
  return { EVENT_GATE_ENABLED: 'true', EVENT_GATE_PASSWORD: PASSWORD, ...overrides };
}

async function serve(t, { environment = env(), clock = { value: START } } = {}) {
  const handlers = createEventGateHandlers({ environment, now: () => clock.value });
  const app = express();
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));
  app.use(cookieParser());
  app.post('/event-gate/login', handlers.loginHandler);
  app.use(handlers.eventGate);
  app.get('/api/monitoring/health', (_req, res) => res.json({ status: 'ok' }));
  app.get('/private', (_req, res) => res.json({ allowed: true }));
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}`;
  return {
    clock,
    request: (path, options = {}) => fetch(`${base}${path}`, { redirect: 'manual', ...options }),
  };
}

function form(password) {
  return { headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ password }).toString() };
}

function bareCookie(response) {
  return response.headers.get('set-cookie')?.split(';', 1)[0] || null;
}

test('enabled configuration requires a bounded explicit non-sample password', () => {
  assert.deepEqual(assertEventGateConfiguration({}), { enabled: false, password: null });
  assert.deepEqual(assertEventGateConfiguration({ EVENT_GATE_ENABLED: 'false' }), { enabled: false, password: null });
  assert.deepEqual(assertEventGateConfiguration(env()), { enabled: true, password: PASSWORD });
  assert.deepEqual(assertEventGateConfiguration(env({ EVENT_GATE_PASSWORD: 'a'.repeat(12) })),
    { enabled: true, password: 'a'.repeat(12) });
  assert.deepEqual(assertEventGateConfiguration(env({ EVENT_GATE_PASSWORD: 'a'.repeat(256) })),
    { enabled: true, password: 'a'.repeat(256) });
  assert.deepEqual(assertEventGateConfiguration(env({ EVENT_GATE_PASSWORD: '🔐'.repeat(6) })),
    { enabled: true, password: '🔐'.repeat(6) });
  for (const password of [undefined, '', 'short', 'a'.repeat(11), 'a'.repeat(257),
    ' owned-event-password', 'owned-event-password ', 'DefconHack2026!', '🔐'.repeat(65),
    123, ['owned-event-password']]) {
    assert.throws(() => assertEventGateConfiguration(env({ EVENT_GATE_PASSWORD: password })),
      { code: 'INVALID_EVENT_GATE_CONFIGURATION' });
  }
});

test('versioned cookie enforces signature, future time, exact expiry, maximum lifetime and rotation', () => {
  const value = makeCookieValue(PASSWORD, { now: () => START });
  assert.equal(verifyCookie(value, PASSWORD, { now: () => START }), true);
  assert.equal(verifyCookie(value, PASSWORD, { now: () => START + COOKIE_MAX_AGE_MS - 1000 }), true);
  assert.equal(verifyCookie(value, PASSWORD, { now: () => START + COOKIE_MAX_AGE_MS }), false);
  assert.equal(verifyCookie(value, 'rotated-event-password', { now: () => START }), false);
  assert.equal(verifyCookie(`${value.slice(0, -1)}${value.endsWith('0') ? '1' : '0'}`, PASSWORD,
    { now: () => START }), false);
  const future = makeCookieValue(PASSWORD, { now: () => START + 1000 });
  assert.equal(verifyCookie(future, PASSWORD, { now: () => START }), false);
  const issuedAt = Math.floor(START / 1000);
  assert.equal(verifyCookie(signedValue(PASSWORD, issuedAt, issuedAt + COOKIE_MAX_AGE_MS / 1000 + 1),
    PASSWORD, { now: () => START }), false);
  for (const malformed of [null, {}, '', 'ok', `ok.${'0'.repeat(64)}`,
    `v1.${issuedAt}.${issuedAt + 1}.not-hex`, 'v2.1.2.' + '0'.repeat(64)]) {
    assert.equal(verifyCookie(malformed, PASSWORD, { now: () => START }), false);
  }
});

test('local redirects remain supported while unsafe or malformed destinations fall back to root', () => {
  assert.equal(safeLocalRedirect('/workshop/sql?tab=history#latest'), '/workshop/sql?tab=history#latest');
  for (const value of [undefined, null, {}, [], '', 'workshop/sql', 'https://outside.example/path',
    '//outside.example/path', '/\\outside.example/path', '/path\r\nlocation:https://outside.example',
    '/a/..//outside.example', '/a/%2e%2e//outside.example',
    `/${'x'.repeat(2049)}`]) assert.equal(safeLocalRedirect(value), '/');
});

test('actual HTTP login compares a string exactly, preserves a valid local next and rejects malformed bodies', async t => {
  const { request } = await serve(t);
  const correct = await request('/event-gate/login?next=%2Fworkshop%2Fsql%3Ftab%3Dhistory', {
    method: 'POST', ...form(PASSWORD),
  });
  assert.equal(correct.status, 302);
  assert.equal(correct.headers.get('location'), '/workshop/sql?tab=history');
  assert.match(correct.headers.get('set-cookie'), /Max-Age=21600/);
  const wrong = await request('/event-gate/login', { method: 'POST', ...form(` ${PASSWORD} `) });
  assert.equal(wrong.status, 401);
  const malformed = await request('/event-gate/login', { method: 'POST',
    headers: { 'content-type': 'application/json' }, body: JSON.stringify({ password: { nested: true } }) });
  assert.equal(malformed.status, 401);
  assert.equal(malformed.headers.get('set-cookie'), null);
});

test('actual HTTP rejects external, protocol-relative, backslash and normalized protocol-relative redirects', async t => {
  const { request } = await serve(t);
  for (const next of ['https://outside.example/collect', '//outside.example/collect', '/\\outside.example/collect',
    '/a/..//outside.example/collect', '/a/%2e%2e//outside.example/collect']) {
    const response = await request(`/event-gate/login?next=${encodeURIComponent(next)}`, {
      method: 'POST', ...form(PASSWORD),
    });
    assert.equal(response.status, 302);
    assert.equal(response.headers.get('location'), '/');
  }
});

test('cookie survives restart within six hours and is rejected at the exact server-side boundary', async t => {
  const first = await serve(t);
  const login = await first.request('/event-gate/login', { method: 'POST', ...form(PASSWORD) });
  const cookie = bareCookie(login);
  assert.ok(cookie);
  const secondClock = { value: START + COOKIE_MAX_AGE_MS - 1000 };
  const second = await serve(t, { clock: secondClock });
  assert.equal((await second.request('/private', { headers: { cookie } })).status, 200);
  secondClock.value = START + COOKIE_MAX_AGE_MS;
  assert.equal((await second.request('/private', { headers: { cookie } })).status, 401);
});

test('disabled gate and health allowlist remain available without a password', async t => {
  const disabled = await serve(t, { environment: { EVENT_GATE_ENABLED: 'false' } });
  assert.equal((await disabled.request('/private')).status, 200);
  const enabled = await serve(t);
  assert.equal((await enabled.request('/api/monitoring/health')).status, 200);
  const blockedApi = await enabled.request('/private', { headers: { accept: 'application/json' } });
  assert.equal(blockedApi.status, 401);
});
