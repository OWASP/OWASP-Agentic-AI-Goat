'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const { createSecureShopBoundDispatch } = require('../server/middleware/secureshopBoundDispatch');

async function fixture(t) {
  let gateway = null; let legacyEffects = 0;
  const app = express();
  app.use('/api/secureshop', createSecureShopBoundDispatch({ getGateway: () => gateway }));
  app.use('/api/secureshop', (_req, res) => { legacyEffects++; res.json({ legacy: true }); });
  const server = await new Promise(resolve => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  return { setGateway: value => { gateway = value; }, effects: () => legacyEffects,
    request: (headers = {}) => fetch(`${origin}/api/secureshop/v2/auth/login`, { method: 'POST', headers }) };
}

test('unready bound requests cannot fall through to legacy auth or mutations', async t => {
  const f = await fixture(t);
  for (const value of ['', 'invalid', 'a'.repeat(43)]) {
    const result = await f.request({ 'x-dvaia-secureshop-launch': value });
    assert.equal(result.status, 503);
    assert.equal(result.headers.get('cache-control'), 'no-store');
    await result.arrayBuffer();
  }
  assert.equal(f.effects(), 0);
  const legacy = await f.request();
  assert.equal(legacy.status, 200); await legacy.arrayBuffer();
  assert.equal(f.effects(), 1);
});

test('ready dispatch never lets an unmatched or failed gateway select legacy handlers', async t => {
  const f = await fixture(t);
  for (const gateway of [(_req, _res, next) => next(), (_req, _res, next) => next('route'),
    () => { throw new Error('private details'); }, async () => { throw new Error('private async details'); }]) {
    f.setGateway(gateway);
    const result = await f.request({ 'x-dvaia-secureshop-launch': 'a'.repeat(43) });
    assert.ok([404, 503].includes(result.status));
    assert.doesNotMatch(await result.text(), /private/);
  }
  assert.equal(f.effects(), 0);
  f.setGateway((_req, res) => res.json({ bound: true }));
  const result = await f.request({ 'x-dvaia-secureshop-launch': 'a'.repeat(43) });
  assert.deepEqual(await result.json(), { bound: true });
  assert.equal(f.effects(), 0);
});
