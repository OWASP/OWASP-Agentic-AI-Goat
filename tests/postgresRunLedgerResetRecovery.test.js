'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { createPostgresRunLedger } = require('../server/agent-runtime/postgresRunLedger');
const defer = () => { let resolve; const promise = new Promise(r => { resolve = r; }); return { promise, resolve }; };
function fixture({ failure = false } = {}) {
  const connection = defer();
  const events = [];
  let generation = '1';
  const runs = [{ owner: 'one', status: 'running' }, { owner: 'one', status: 'completed' }, { owner: 'two', status: 'running' }];
  const effects = [{ owner: 'one', status: 'started' }, { owner: 'one', status: 'completed' }, { owner: 'two', status: 'started' }];
  const client = new EventEmitter();
  client.release = destroyed => events.push(destroyed ? 'destroyed' : 'released');
  client.query = async (sql, args) => {
    if (sql.includes('pg_try_advisory_lock')) { events.push('locked'); return { rows: [{ acquired: true }] }; }
    if (sql.includes('pg_advisory_unlock')) { events.push('unlocked'); return { rows: [] }; }
    if (sql.startsWith('SELECT generation FROM graph_runtime.owners')) {
      events.push('current'); return { rows: [{ generation }] };
    }
    if (sql.startsWith('UPDATE graph_runtime.runs')) {
      events.push('runs');
      for (const run of runs) if (run.owner === args[0] && run.status === 'running') run.status = 'interrupted';
      return { rowCount: 1, rows: [] };
    }
    if (sql.startsWith('UPDATE graph_runtime.effects')) {
      events.push('effects');
      if (failure) throw new Error('write unavailable');
      for (const effect of effects) if (effect.owner === args[0] && effect.status === 'started') effect.status = 'uncertain';
      return { rowCount: 1, rows: [] };
    }
    throw new Error('Unexpected lease query');
  };
  const ledger = createPostgresRunLedger({ async query(sql, args) {
    assert.match(sql, /INSERT INTO graph_runtime\.owners/);
    assert.match(sql, /RETURNING generation/);
    assert.deepEqual(args, ['one']); events.push('invalidated'); return { rows: [{ generation }] };
  } }, { leasePool: { async connect() { events.push('waiting'); await connection.promise; return client; } } });
  return { ledger, events, runs, effects, client, admit: () => connection.resolve(),
    supersede() { generation = String(Number(generation) + 1); } };
}

test('reset settles crashed-holder records only after obtaining exclusive lease and preserves siblings/terminal outcomes', async () => {
  const f = fixture(); const lease = await f.ledger.invalidate({ ownerKey: 'one' });
  assert.deepEqual(f.events, ['invalidated']);
  const acquiring = lease.acquire();
  await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(f.events, ['invalidated', 'waiting']);
  assert.equal(f.runs[0].status, 'running'); assert.equal(f.effects[0].status, 'started');
  f.admit(); await acquiring;
  assert.deepEqual(f.runs.map(row => row.status), ['interrupted', 'completed', 'running']);
  assert.deepEqual(f.effects.map(row => row.status), ['uncertain', 'completed', 'started']);
  assert.deepEqual(f.events, ['invalidated', 'waiting', 'locked', 'current', 'runs', 'effects', 'current']);
  await lease.assertCurrent();
  assert.equal(f.events.at(-1), 'current');
  await lease.release(); await lease.release();
  assert.equal(f.events.filter(event => event === 'released').length, 1);
  assert.equal(f.events.filter(event => event === 'unlocked').length, 1);
});

test('failed orphan settlement releases the lease and rejects reset acquisition', async () => {
  const f = fixture({ failure: true }); const lease = await f.ledger.invalidate({ ownerKey: 'one' });
  f.admit(); await assert.rejects(lease.acquire(), /write unavailable/);
  await lease.release();
  assert.deepEqual(f.events, ['invalidated', 'waiting', 'locked', 'current', 'runs', 'effects', 'unlocked', 'released']);
  assert.equal(f.effects[0].status, 'started');
});

test('reset lease current check rejects generation supersession on its held connection', async () => {
  const f = fixture(); const lease = await f.ledger.invalidate({ ownerKey: 'one' });
  f.admit(); await lease.acquire(); f.supersede();
  await assert.rejects(lease.assertCurrent(), { name: 'AbortError' });
  await lease.release();
  assert.deepEqual(f.events.slice(-2), ['unlocked', 'released']);
});

test('reset lease connection loss is observed without an unhandled error and destroys the client', async () => {
  const f = fixture(); const lease = await f.ledger.invalidate({ ownerKey: 'one' });
  f.admit(); await lease.acquire();
  f.client.emit('error', new Error('lease connection lost'));
  await assert.rejects(lease.assertCurrent(), { name: 'AbortError' });
  await lease.release();
  assert.equal(f.events.at(-1), 'destroyed');
  assert.equal(f.client.listenerCount('error'), 0);
});

test('reset heartbeat rejects a client error delivered with its generation result', async () => {
  const f = fixture(); const lease = await f.ledger.invalidate({ ownerKey: 'one' });
  f.admit(); await lease.acquire();
  const query = f.client.query.bind(f.client); let inject = true;
  f.client.query = async (sql, args) => {
    const result = await query(sql, args);
    if (inject && String(sql).startsWith('SELECT generation FROM graph_runtime.owners')) {
      inject = false; f.client.emit('error', new Error('lease lost after heartbeat result'));
    }
    return result;
  };
  await assert.rejects(lease.assertCurrent(), { name: 'AbortError' });
  await lease.release();
  assert.equal(f.events.at(-1), 'destroyed');
});
