'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const { EventEmitter } = require('node:events'), { randomUUID } = require('node:crypto');
const { DatabaseError } = require('pg');
const { createExecutor } = require('../sidecars/analytics-sql-target/executor');
function pgError(code = '22P02', message = 'invalid input syntax for type integer: "SYNTHETIC_KEY_owned"') {
  const error = new DatabaseError(message, 1, 'error'); error.code = code; return error;
}
function fixture({ error = pgError(), phase = 'query', callback = false, rollbackError,
  drainError, poolError, abortAt, rows = null } = {}) {
  const calls = [], controller = new AbortController(), client = new EventEmitter(), pool = new EventEmitter();
  client.release = destroy => { assert.equal(destroy, true); calls.push('release'); };
  client.query = async query => {
    if (typeof query !== 'string') {
      calls.push('query');
      queueMicrotask(() => {
        if (abortAt === 'query') controller.abort(Error('cancelled'));
        if (rows) {
          for (const row of rows) query.emit('row', row);
          query.emit('end', { fields: Object.keys(rows[0] || {}).map(name => ({ name })), rowCount: rows.length });
        } else if (callback) query.callback(error); else query.emit('error', error);
      });
      return;
    }
    calls.push(query);
    if (phase === 'metadata' && query.includes('pg_backend_pid')) throw error;
    if (query.includes('pg_backend_pid')) return { rows: [{ pid: 42, backend_start: '2026-10-14T00:00:00Z' }] };
    if (phase === 'begin' && query === 'BEGIN READ ONLY') throw error;
    if (phase === 'set' && query.startsWith('SET LOCAL')) throw error;
    if (query === 'ROLLBACK') {
      if (abortAt === 'rollback') controller.abort(Error('cancelled'));
      if (rollbackError) throw rollbackError;
    }
    return { rows: [] };
  };
  pool.connect = async () => client;
  pool.end = async () => {
    calls.push('pool-end'); if (abortAt === 'pool') controller.abort(Error('cancelled'));
    if (poolError) pool.emit('error', poolError);
  };
  const targetId = randomUUID();
  const execute = createExecutor({ connection: {}, createPool: () => pool,
    verifyTarget: async () => { if (phase === 'verify') throw error; },
    controlPool: { async query(query) {
      calls.push(query.text.startsWith('SELECT 1') ? 'absence' : 'terminate');
      assert.deepEqual(query.values, [42, '2026-10-14T00:00:00Z', 'analytics_' + targetId.replaceAll('-', ''), 'analytics_' + targetId.replaceAll('-', '')]);
      if (abortAt === 'absence') controller.abort(Error('cancelled'));
      if (drainError) throw drainError;
      return { rows: [] };
    } },
  });
  return { calls, run: (options = {}) => execute({ targetId }, 'a'.repeat(64), 'SELECT CAST(api_key AS integer) FROM shop_users',
    { signal: controller.signal, ...options }) };
}
test('opted-in genuine query-local PostgreSQL 22P02 returns exact bytes only after rollback, backend absence and pool drain', async () => {
  for (const callback of [false, true]) {
    const error = pgError(), f = fixture({ error, callback });
    assert.deepEqual(await f.run({ captureQueryError: true }), { queryError: { sqlstate: '22P02', message: error.message } });
    assert.deepEqual(f.calls.slice(f.calls.indexOf('query')), ['query', 'ROLLBACK', 'release', 'absence', 'pool-end']);
  }
});
test('capture remains default-off and never captures a plain code spoof or another SQLSTATE', async () => {
  const original = pgError(), off = fixture({ error: original });
  await assert.rejects(off.run(), error => error === original);
  for (const error of [Object.assign(Error('spoof'), { code: '22P02' }), pgError('42601'), pgError('57014'),
    pgError('22P02', 'x'.repeat(8193)), pgError('22P02', '\0'), pgError('22P02', '\ud800')]) {
    const f = fixture({ error }); await assert.rejects(f.run({ captureQueryError: true }), observed => observed === error);
    assert.ok(f.calls.includes('pool-end'));
  }
});
test('preflight, BEGIN and SET errors cannot masquerade as an admitted-query observation', async () => {
  for (const phase of ['verify', 'metadata', 'begin', 'set']) {
    const error = pgError(), f = fixture({ error, phase });
    await assert.rejects(f.run({ captureQueryError: true }), observed => observed === error);
    assert.equal(f.calls.includes('query'), false); assert.ok(f.calls.includes('pool-end'));
  }
});
test('rollback, backend drain, pool drain and cancellation failures cannot publish a captured error', async () => {
  const rollbackError = pgError(), rollback = fixture({ rollbackError });
  await assert.rejects(rollback.run({ captureQueryError: true }), error => error === rollbackError);
  assert.ok(rollback.calls.includes('terminate'));
  const drain = fixture({ drainError: Error('control unavailable') });
  await assert.rejects(drain.run({ captureQueryError: true }), { code: 'ANALYTICS_QUERY_DRAIN_UNCERTAIN' });
  const pool = fixture({ poolError: Error('pool lost') });
  await assert.rejects(pool.run({ captureQueryError: true }), { code: 'ANALYTICS_POOL_DRAIN_UNCERTAIN' });
  for (const abortAt of ['query', 'rollback', 'absence', 'pool']) {
    const f = fixture({ abortAt }); await assert.rejects(f.run({ captureQueryError: true }), /cancelled/);
    assert.ok(f.calls.includes('pool-end'));
  }
});
test('ordinary success and default callers retain existing results; opt-in options are closed booleans', async () => {
  for (const options of [{}, { captureQueryError: true }]) {
    const f = fixture({ rows: [{ value: 1 }] }), result = await f.run(options);
    assert.deepEqual(result.rows, [{ value: 1 }]); assert.equal(result.row_count, 1); assert.equal(result.error, null);
    assert.equal(Object.hasOwn(result, 'queryError'), false);
  }
  for (const options of [{ captureQueryError: 'yes' }, { captureQueryError: true, captureProtected: true }]) {
    const f = fixture(); await assert.rejects(f.run(options), { code: 'ANALYTICS_QUERY_PARAMETERS' }); assert.deepEqual(f.calls, []);
  }
});
