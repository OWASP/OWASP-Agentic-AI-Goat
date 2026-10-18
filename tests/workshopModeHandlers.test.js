'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

function response() {
  return { statusCode: 200, body: null, headers: {}, status(code) { this.statusCode = code; return this; }, set(k, v) { this.headers[k] = v; return this; }, json(body) { this.body = body; return this; } };
}

test('mode handlers use authenticated identity and ignore body/query identity', async () => {
  const { createWorkshopModeHandlers } = require('../server/services/workshopModeHandlers');
  const calls = [];
  const handlers = createWorkshopModeHandlers({
    workshopKey: 'sql_injection_workshop',
    modeService: {
      async getMode(input) { calls.push(['get', input]); return 'fixed'; },
      async setMode(input) { calls.push(['set', input]); return 'vuln'; },
    },
  });
  const readRes = response();
  const writeRes = response();
  await handlers.get({ user: { id: 11 }, query: { userId: 22 } }, readRes);
  await handlers.set({ user: { id: 11 }, body: { userId: 22, mode: 'vuln' } }, writeRes);
  assert.deepEqual(calls, [
    ['get', { userId: 11, workshopKey: 'sql_injection_workshop' }],
    ['set', { userId: 11, workshopKey: 'sql_injection_workshop', mode: 'vuln' }],
  ]);
  assert.equal(readRes.body.mode, 'fixed');
  assert.equal(writeRes.body.mode, 'vuln');
  assert.deepEqual(readRes.body.selectableModes, ['fixed', 'vuln']);
  assert.deepEqual(readRes.body.scope, { kind: 'tool', id: 'search_products' });
  assert.equal(readRes.body.fixedSupported, true);
});

test('mode handlers reject unauthenticated requests and invalid catalog values', async () => {
  const { createWorkshopModeHandlers } = require('../server/services/workshopModeHandlers');
  const handlers = createWorkshopModeHandlers({ workshopKey: 'supply_chain_rce', modeService: { async getMode() {}, async setMode() { throw new TypeError('Invalid mode'); } } });
  const readRes = response();
  const writeRes = response();
  await handlers.get({}, readRes);
  await handlers.set({ user: { id: 1 }, body: { mode: 'vuln' } }, writeRes);
  assert.equal(readRes.statusCode, 401);
  assert.equal(writeRes.statusCode, 400);
});
