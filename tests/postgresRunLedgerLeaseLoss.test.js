'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { createPostgresRunLedger } = require('../server/agent-runtime/postgresRunLedger');

function leaseFixture() {
  const statements = [];
  let injectLeaseLoss = false;
  let destroyed = false;
  const client = new EventEmitter();
  client.release = value => { destroyed = value === true; };
  client.query = async (sql, args = []) => {
    const text = String(sql); statements.push(text);
    if (text.includes('pg_try_advisory_lock')) return { rows: [{ acquired: true }] };
    if (text.includes('pg_advisory_unlock')) return { rows: [] };
    if (text.includes('SELECT generation FROM graph_runtime.owners')) {
      const result = { rows: [{ generation: '4' }] };
      if (injectLeaseLoss) {
        injectLeaseLoss = false;
        client.emit('error', new Error('controlled lease connection loss'));
      }
      return result;
    }
    if (text.includes('INSERT INTO graph_runtime.effects')) {
      return { rowCount: 1, rows: [{ effect_key: args[2] }] };
    }
    return { rowCount: 1, rows: [] };
  };
  const ledger = createPostgresRunLedger({ async query(sql) { assert.equal(sql,'SELECT generation FROM graph_runtime.owners WHERE owner_key=$1'); return {rows:[{generation:'4'}]}; } }, {
    leasePool: { async connect() { return client; } },
  });
  return { ledger, client, statements,
    loseLeaseOnCurrentHeartbeat() { injectLeaseLoss = true; },
    get destroyed() { return destroyed; } };
}

async function begin(fixture, runId) {
  const context = { runId, ownerKey: '["LeaseLoss","owner"]', generation: 0 };
  Object.assign(context, await fixture.ledger.begin(context, { signal: new AbortController().signal }));
  assert.equal(context.durableGeneration, '4');
  return context;
}

async function closeLostFixture(fixture, context) {
  await assert.rejects(fixture.ledger.finish(context, { status: 'failed' }),
    /controlled lease connection loss/);
  assert.equal(fixture.destroyed, true, 'an errored lease client must not return to the pool');
  assert.equal(fixture.client.listenerCount('error'), 0);
}

test('active current heartbeat rejects when its client errors while returning generation', async () => {
  const fixture = leaseFixture();
  const context = await begin(fixture, 'lease-loss-current-run');

  fixture.loseLeaseOnCurrentHeartbeat();
  let mutations = 0;
  await assert.rejects((async () => {
    await fixture.ledger.assertCurrent(context);
    mutations += 1;
  })(), { name: 'AbortError' });
  assert.equal(mutations, 0, 'A non-ledger mutation must not follow a lost-lease check');
  await closeLostFixture(fixture, context);
});

test('effect claim lane blocks business callback when its own current heartbeat loses the client', async () => {
  const fixture = leaseFixture();
  const context = await begin(fixture, 'lease-loss-effect-run');
  fixture.loseLeaseOnCurrentHeartbeat();

  let callbacks = 0;
  await assert.rejects(fixture.ledger.effect(context, 'effect-after-loss', async () => {
    callbacks += 1;
    return 'must not run';
  }), /controlled lease connection loss|lease connection was lost/i);
  assert.equal(callbacks, 0, 'the effect claim query lane must reject before business work starts');
  assert.equal(fixture.statements.some(sql => sql.includes('INSERT INTO graph_runtime.effects')), false,
    'the errored lane rejects before sending an effect claim statement to PostgreSQL');
  await closeLostFixture(fixture, context);
});
