'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { createPostgresRunLedger } = require('../server/agent-runtime/postgresRunLedger');

function deferred() {
  let resolve;
  return { promise: new Promise(done => { resolve = done; }), resolve };
}
function fixture() {
  const events = [], effects = new Map(), statements = [];
  let activeQueries = 0, maxQueries = 0, released = false, generation = '0';
  const client = new EventEmitter();
  client.release = destroyed => { released = true; events.push(destroyed ? 'destroyed' : 'released'); };
  client.query = async (sql, args = []) => {
    activeQueries += 1; maxQueries = Math.max(maxQueries, activeQueries);
    if (activeQueries > 1) throw new Error('concurrent raw client query');
    try {
      await new Promise(resolve => setImmediate(resolve));
      const text = String(sql);
      statements.push(text);
      if (text.includes('pg_try_advisory_lock')) return { rows: [{ acquired: true }] };
      if (text.includes('pg_advisory_unlock')) { events.push('unlock'); return { rows: [] }; }
      if (text.includes('SELECT generation FROM graph_runtime.owners')) return { rows: [{ generation }] };
      if (text.includes('INSERT INTO graph_runtime.effects')) {
        if (effects.has(args[2])) return { rowCount: 0, rows: [] };
        effects.set(args[2], 'started'); return { rowCount: 1, rows: [{ effect_key: args[2] }] };
      }
      if (text.includes("SET status='completed'")) effects.set(args[2], 'completed');
      if (text.includes("SET status='uncertain'") && args.length >= 3) effects.set(args[2], 'uncertain');
      return { rowCount: 1, rows: [] };
    } finally { activeQueries -= 1; }
  };
  return { client, effects, events, statements, bumpGeneration() { generation = String(Number(generation) + 1); },
    get maxQueries() { return maxQueries; }, get released() { return released; } };
}

test('one lease query lane preserves parallel effects and drains before release', async () => {
  const f = fixture();
  const ledger = createPostgresRunLedger({ async query(sql) { assert.equal(sql,'SELECT generation FROM graph_runtime.owners WHERE owner_key=$1'); return {rows:[{generation:'0'}]}; } }, {
    leasePool: { async connect() { return f.client; } },
  });
  const context = { runId: 'run-parallel', ownerKey: '["test","parallel"]', generation: 0 };
  Object.assign(context, await ledger.begin(context, { signal: new AbortController().signal }));
  const entered = [], releaseBusiness = deferred();
  let activeBusiness = 0, maxBusiness = 0;
  const operations = Array.from({ length: 3 }, (_, index) => ledger.effect(context, `effect-${index}`, async () => {
    activeBusiness += 1; maxBusiness = Math.max(maxBusiness, activeBusiness); entered.push(index);
    if (entered.length === 3) releaseBusiness.resolve();
    await releaseBusiness.promise;
    activeBusiness -= 1;
    if (index === 1) throw new Error('owned effect failure');
    return index;
  }));
  const results = await Promise.allSettled(operations);
  assert.deepEqual(results.map(result => result.status), ['fulfilled', 'rejected', 'fulfilled']);
  assert.equal(maxBusiness, 3, 'business callbacks remain parallel');
  assert.equal(f.maxQueries, 1, 'raw lease client never receives concurrent queries');
  assert.deepEqual([...f.effects.values()].sort(), ['completed', 'completed', 'uncertain']);

  await Promise.all([
    ledger.recordEvent(context, { node: 'parallel', type: 'decision', data: { provider: 'fixture' } }),
    ledger.checkpoint(context, { node: 'parallel-complete' }),
  ]);
  await ledger.finish(context, { status: 'failed' });
  assert.deepEqual(f.events.slice(-2), ['unlock', 'released']);
  assert.equal(f.released, true);
  await assert.rejects(ledger.assertCurrent(context), { name: 'AbortError' });
});

test('completed admission releases the durable owner lease without inserting a run', async () => {
  const f = fixture();
  const ledger = createPostgresRunLedger({ async query(sql) { assert.equal(sql,'SELECT generation FROM graph_runtime.owners WHERE owner_key=$1'); return {rows:[{generation:'0'}]}; } }, {
    leasePool: { async connect() { return f.client; } },
  });
  const context = { runId: 'run-replay', ownerKey: '["test","replay"]', generation: 0 };
  const result = await ledger.begin(context, { signal: new AbortController().signal,
    admit: async () => ({ skip: true, value: { replayed: true } }) });
  assert.deepEqual(result, { skipped: true, value: { replayed: true } });
  assert.equal(f.statements.some(sql => sql.includes('INSERT INTO graph_runtime.runs')), false);
  assert.deepEqual(f.events.slice(-2), ['unlock', 'released']);
});

test('generation invalidated during admission is rejected instead of adopted', async () => {
  const f = fixture();
  const ledger = createPostgresRunLedger({ async query(sql) { assert.equal(sql,'SELECT generation FROM graph_runtime.owners WHERE owner_key=$1'); return {rows:[{generation:'0'}]}; } }, {
    leasePool: { async connect() { return f.client; } },
  });
  const context = { runId: 'run-reset-race', ownerKey: '["test","reset-race"]', generation: 0 };
  await assert.rejects(ledger.begin(context, { signal: new AbortController().signal,
    admit: async () => { f.bumpGeneration(); return { skip: false, value: 'claimed' }; } }), { name: 'AbortError' });
  assert.equal(f.statements.some(sql => sql.includes('INSERT INTO graph_runtime.runs')), false);
  assert.deepEqual(f.events.slice(-2), ['unlock', 'released']);
});
