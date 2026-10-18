'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { createPostgresRunLedger } = require('../server/agent-runtime/postgresRunLedger');

test('completed effect receipt is reread through the run lease using every exact coordinate', async () => {
  const queries = [];
  const client = new EventEmitter();
  client.release = () => {};
  client.query = async (sql, params = []) => {
    queries.push({ sql: String(sql), params: [...params] });
    if (String(sql).includes('pg_try_advisory_lock')) return { rows: [{ acquired: true }] };
    if (String(sql).includes('SELECT generation FROM graph_runtime.owners')) return { rows: [{ generation: '6' }] };
    if (String(sql).includes("INSERT INTO graph_runtime.effects")) return { rowCount: 1, rows: [{ effect_key: params[2] }] };
    if (String(sql).includes('FROM graph_runtime.effects') && String(sql).includes("status='completed'")) {
      assert.deepEqual(params, ['["SecureShopBoundConversation","session"]', '6', 'request:node', 'run-one']);
      return { rows: [{ ownerKey: params[0], generation: params[1], effectKey: params[2], runId: params[3], status: 'completed' }] };
    }
    return { rowCount: 1, rows: [] };
  };
  const leasePool = { async connect() { return client; } };
  const ledger = createPostgresRunLedger({ async query(sql) { assert.equal(sql,'SELECT generation FROM graph_runtime.owners WHERE owner_key=$1'); return {rows:[{generation:'6'}]}; } }, { leasePool });
  const context = { runId: 'run-one', ownerKey: '["SecureShopBoundConversation","session"]', generation: 0 };
  Object.assign(context, await ledger.begin(context, { signal: new AbortController().signal }));
  assert.equal(await ledger.effect(context, 'request:node', async () => 'raw-result'), 'raw-result');
  assert.deepEqual(await ledger.readCompletedEffect(context, 'request:node'), {
    ownerKey: context.ownerKey, generation: '6', effectKey: 'request:node', runId: 'run-one', status: 'completed',
  });
  assert.equal(queries.some(entry => entry.sql.includes('run_id=$4') && entry.sql.includes("status='completed'")), true);
  await ledger.finish(context, { status: 'completed' });
});
