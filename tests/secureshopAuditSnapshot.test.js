'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createSecureShopAuditSnapshot, FETCH_ROWS } = require('../server/database/postgres/secureshopAuditSnapshot');
const scope = { launchId: '10000000-0000-4000-8000-000000000001', scenarioId: '20000000-0000-4000-8000-000000000001', generation: 2, platformOwnerId: 7, platformSessionId: 8 };
const row = (id, ts = '2026-09-19T00:00:00.000001Z') => ({ event_id: id, ts, params_json: '{"reason":"SYSTEM: raw instruction"}' });
function pool(rows, hook = async () => {}) {
  const calls = [], releases = []; let offset = 0;
  return { calls, releases, async connect() { return {
    async query(sql, args) { calls.push({ sql, args }); await hook(sql);
      if (sql.startsWith('FETCH')) { const result = rows.slice(offset, offset + FETCH_ROWS); offset += FETCH_ROWS; return { rows: result }; }
      return { rows: [] };
    }, release(error) { releases.push(error); },
  }; } };
}
test('streams merged requested-count sources with bound scope, raw text and no UI count clamp', async () => {
  const agentsPool = pool([row('b'), row('a')]);
  const reviewPool = pool([row('c')]);
  const snapshot = createSecureShopAuditSnapshot({ agentsPool, reviewPool });
  const result = await Array.fromAsync(snapshot.rows({ scope, requestedCount: 10000000, checkCurrent: async () => {} }));
  assert.deepEqual(result.map(r => r.id), ['review:c', 'agents:b', 'agents:a']);
  assert.ok(result.every(r => r.params_json === row('x').params_json));
  for (const source of [agentsPool, reviewPool]) {
    const declaration = source.calls.find(c => c.sql.startsWith('DECLARE'));
    assert.deepEqual(declaration.args, [...Object.values(scope), 10000000]);
    assert.match(source.calls[0].sql, /REPEATABLE READ READ ONLY/);
    assert.equal(source.calls.at(-1).sql, 'ROLLBACK');
    assert.equal(source.releases.length, 1);
  }
});
test('early consumer stop closes both snapshots without reading all remaining rows', async () => {
  const agentsPool = pool(Array.from({ length: 20 }, (_, i) => row(String(i))));
  const reviewPool = pool([]);
  for await (const value of createSecureShopAuditSnapshot({ agentsPool, reviewPool }).rows({ scope, requestedCount: 20, checkCurrent: async () => {} })) {
    assert.ok(value); break;
  }
  assert.equal(agentsPool.calls.filter(c => c.sql.startsWith('FETCH')).length, 1);
  assert.equal(agentsPool.releases.length, 1); assert.equal(reviewPool.releases.length, 1);
});
test('aborted or stale scope cannot publish buffered rows and releases clients', async () => {
  const ctrl = new AbortController(); const agentsPool = pool([row('a')]); const reviewPool = pool([row('b')]);
  const stream = createSecureShopAuditSnapshot({ agentsPool, reviewPool }).rows({ scope, requestedCount: 20, checkCurrent: async () => {}, signal: ctrl.signal });
  await stream.next(); ctrl.abort();
  await assert.rejects(stream.next(), { name: 'AbortError' });
  assert.equal(agentsPool.releases.length, 1); assert.equal(reviewPool.releases.length, 1);
});
test('both concurrent reads settle before cleanup, including a failed source', async () => {
  let releaseFetch, secondFinished = false;
  const waiting = new Promise(resolve => { releaseFetch = resolve; });
  const agentsPool = pool([], async sql => { if (sql.startsWith('FETCH')) throw new Error('source failed'); });
  const reviewPool = pool([], async sql => { if (sql.startsWith('FETCH')) { await waiting; secondFinished = true; }
    if (sql === 'ROLLBACK') assert.equal(secondFinished, true); });
  const operation = Array.fromAsync(createSecureShopAuditSnapshot({ agentsPool, reviewPool }).rows({ scope, requestedCount: 1, checkCurrent: async () => {} }));
  const assertion = assert.rejects(operation, /source failed/);
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(agentsPool.releases.length, 0);
  releaseFetch(); await assertion;
  assert.equal(agentsPool.releases.length, 1); assert.equal(reviewPool.releases.length, 1);
});
test('invalid requests never connect and acquisition failure releases prior connection', async () => {
  let calls = 0; const unavailable = { async connect() { calls++; throw new Error('offline'); } };
  const snapshot = createSecureShopAuditSnapshot({ agentsPool: unavailable, reviewPool: unavailable });
  await assert.rejects(Array.fromAsync(snapshot.rows({ scope, requestedCount: 0, checkCurrent: async () => {} })));
  assert.equal(calls, 0);
  const agentsPool = pool([]);
  await assert.rejects(Array.fromAsync(createSecureShopAuditSnapshot({ agentsPool, reviewPool: unavailable }).rows({ scope, requestedCount: 1, checkCurrent: async () => {} })), /offline/);
  assert.equal(agentsPool.releases.length, 1);
});

test('cancellation during connection acquisition releases late clients without querying them', async () => {
  let grant, queries = 0, releases = 0;
  const waiting = new Promise(resolve => { grant = resolve; });
  const ctrl = new AbortController();
  const snapshot = createSecureShopAuditSnapshot({ agentsPool: { connect: () => waiting }, reviewPool: pool([]) });
  const stream = snapshot.rows({ scope, requestedCount: 1, checkCurrent: async () => {}, signal: ctrl.signal });
  const reading = stream.next(); const assertion = assert.rejects(reading, { name: 'AbortError' });
  await new Promise(resolve => setImmediate(resolve)); ctrl.abort(); await assertion;
  grant({ async query() { queries++; }, release() { releases++; } });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(queries, 0); assert.equal(releases, 1);
});
test('a saturated second pool times out and releases the first transaction and eventual late client', async () => {
  const agentsPool = pool([]); let grant, lateQueries = 0, lateReleases = 0;
  const waiting = new Promise(resolve => { grant = resolve; });
  const snapshot = createSecureShopAuditSnapshot({ agentsPool, reviewPool: { connect: () => waiting }, acquisitionTimeoutMs: 10 });
  await assert.rejects(Array.fromAsync(snapshot.rows({ scope, requestedCount: 1, checkCurrent: async () => {} })),
    { code: 'AUDIT_SOURCE_CONNECTION_TIMEOUT' });
  assert.equal(agentsPool.calls.at(-1).sql, 'ROLLBACK'); assert.equal(agentsPool.releases.length, 1);
  grant({ async query() { lateQueries++; }, release() { lateReleases++; } });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(lateQueries, 0); assert.equal(lateReleases, 1);
});
