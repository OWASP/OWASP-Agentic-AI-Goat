'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createStudentDeletionStoreCleanup } = require('../server/services/studentDeletionStoreCleanup');

function pool(rows, calls) { return { async query(sql, args) { calls.push([sql, args]); return { rows }; } }; }
function transactionPool(respond, calls, state = {}) {
  state.active = false;
  const client = {
    async query(sql, args) {
      calls.push([sql, args]);
      if (sql === 'BEGIN') { state.active = true; return { rows: [] }; }
      if (sql === 'COMMIT') { state.active = false; state.committed = true; return { rows: [] }; }
      if (sql === 'ROLLBACK') { state.active = false; state.rolledBack = true; return { rows: [] }; }
      return respond(sql, args);
    },
    release(error) { state.released = true; state.releaseError = error; },
  };
  return { async query() { throw new Error('identity cleanup must use one transaction client'); },
    async connect() { state.connected = true; return client; } };
}
test('XSS and FinFlow cleanup bind the exact internal owner and check lease around effects', async () => {
  const calls = [], checks = [];
  const cleanup = createStudentDeletionStoreCleanup({ identityPool: pool([{ finalized: true }], calls),
    xssPool: pool([{ removed: '7' }], calls), finflowPool: pool([{ removed: 4 }], calls) });
  const scope = { subjectId: 17, jobId: '11111111-1111-4111-8111-111111111111', check: async () => checks.push('check') };
  assert.deepEqual(await cleanup.xss(scope), { completed: true, removed: 7 });
  assert.deepEqual(await cleanup.finflow(scope), { completed: true, removed: 4 });
  assert.deepEqual(calls.map(([,args]) => args), [[17], [17, scope.jobId]]);
  assert.equal(checks.length, 4);
});
test('CodeBot absence proof requires the exact persistent deletion block and zero durable history', async () => {
  for (const [proof, expected] of [
    [{ blocked: true, absent: true }, true],
    [{ blocked: true, absent: false }, false],
  ]) {
    const calls = [], checks = [];
    const cleanup = createStudentDeletionStoreCleanup({ identityPool: pool([proof], calls),
      xssPool: pool([], []), finflowPool: pool([], []) });
    const scope = { subjectId: 17, jobId: '11111111-1111-4111-8111-111111111111',
      check: async () => checks.push('check') };
    assert.equal(await cleanup.codeBotExecutionAbsent(scope), expected);
    assert.deepEqual(calls[0][1], [17, '["CodeBot","17"]', scope.jobId]);
    assert.match(calls[0][0], /student_deletion_run_blocks/);
    assert.match(calls[0][0], /graph_runtime\.runs/);
    assert.match(calls[0][0], /graph_runtime\.effects/);
    assert.match(calls[0][0], /graph_runtime\.codebot_requests/);
    assert.deepEqual(checks, ['check', 'check']);
  }
});
test('CodeBot absence proof fails closed on missing authority or malformed database result', async () => {
  for (const proof of [{ blocked: false, absent: true }, { blocked: true, absent: null }, null]) {
    const cleanup = createStudentDeletionStoreCleanup({ identityPool: pool(proof ? [proof] : [], []),
      xssPool: pool([], []), finflowPool: pool([], []) });
    await assert.rejects(cleanup.codeBotExecutionAbsent({ subjectId: 17,
      jobId: '11111111-1111-4111-8111-111111111111', check: async () => {} }), error =>
      proof?.blocked !== true ? error?.code === 'DELETION_RUN_BLOCK_MISMATCH'
        : /Invalid CodeBot execution absence proof/.test(error?.message));
  }
});
test('identity finalization atomically removes MCP conversation content and retains request bindings', async () => {
  const calls = [], state = {}, checks = [];
  const identityPool = transactionPool((sql) => {
    if (sql.includes('finalize_student_deletion')) return { rows: [{ finalized: true }] };
    if (sql.startsWith('DELETE FROM workshop_conversations.turns')) return { rows: [], rowCount: 2 };
    if (sql.startsWith('UPDATE workshop_conversations.requests')) return { rows: [], rowCount: 3 };
    if (sql.startsWith('SELECT') && sql.includes('identity.student_deletion_jobs')) {
      return { rows: [{ current: true }] };
    }
    if (sql.startsWith('SELECT') && sql.includes('workshop_conversations.turns WHERE user_id=$1')) {
      return { rows: [{ turns_remain: false, request_content_remains: false }] };
    }
    throw new Error(`Unexpected query: ${sql}`);
  }, calls, state);
  const cleanup = createStudentDeletionStoreCleanup({
    identityPool, xssPool: pool([], calls), finflowPool: pool([], calls) });
  assert.deepEqual(await cleanup.identity({ subjectId: 17,
    jobId: '11111111-1111-4111-8111-111111111111',
    leaseToken: '22222222-2222-4222-8222-222222222222',
    check: async () => { assert.equal(state.active, false, 'lease renewal must stay outside the transaction');checks.push('check'); } }),
  { completed: true });
  assert.deepEqual(calls.map(([sql]) => sql === 'BEGIN' || sql === 'COMMIT' ? sql
    : sql.trim().split(/\s+/).slice(0, 3).join(' ')), [
    'BEGIN', 'SELECT identity.finalize_student_deletion($1::uuid,$2::uuid,$3::integer) AS',
    'DELETE FROM workshop_conversations.turns', 'UPDATE workshop_conversations.requests SET',
    'SELECT EXISTS(SELECT 1', 'SELECT EXISTS( SELECT', 'COMMIT']);
  assert.deepEqual(calls[1][1], ['11111111-1111-4111-8111-111111111111',
    '22222222-2222-4222-8222-222222222222', 17]);
  for (const index of [2, 3, 4]) assert.deepEqual(calls[index][1], [17]);
  assert.deepEqual(calls[5][1], ['11111111-1111-4111-8111-111111111111',
    '22222222-2222-4222-8222-222222222222', 17]);
  assert.match(calls[2][0], /WHERE user_id=\$1$/); assert.doesNotMatch(calls[2][0], /owner_key/);
  assert.match(calls[3][0], /SET user_text=NULL,response_json=NULL WHERE user_id=\$1/);
  assert.doesNotMatch(calls[3][0], /owner_key/);
  assert.equal(calls.some(([sql]) => /DELETE FROM workshop_conversations\.requests/.test(sql)), false);
  assert.deepEqual(checks, ['check', 'check']); assert.equal(state.committed, true); assert.equal(state.released, true);
});

test('identity finalization rolls back on invalid authority, content debt, or commit-time lease expiry', async () => {
  for (const failure of ['authority', 'postcondition', 'lease']) {
    const calls = [], state = {};
    const identityPool = transactionPool(sql => {
      if (sql.includes('finalize_student_deletion')) {
        return { rows: [{ finalized: failure !== 'authority' }] };
      }
      if (sql.startsWith('DELETE FROM workshop_conversations.turns')
          || sql.startsWith('UPDATE workshop_conversations.requests')) return { rows: [], rowCount: 1 };
      if (sql.startsWith('SELECT') && sql.includes('identity.student_deletion_jobs')) {
        return { rows: [{ current: failure !== 'lease' }] };
      }
      if (sql.startsWith('SELECT') && sql.includes('workshop_conversations.turns WHERE user_id=$1')) {
        return { rows: [{ turns_remain: false, request_content_remains: failure === 'postcondition' }] };
      }
      throw new Error(`Unexpected query: ${sql}`);
    }, calls, state);
    const bad = createStudentDeletionStoreCleanup({ identityPool,
      xssPool: pool([], []), finflowPool: pool([], []) });
    await assert.rejects(bad.identity({ subjectId: 17,
      jobId: '11111111-1111-4111-8111-111111111111',
      leaseToken: '22222222-2222-4222-8222-222222222222', check: async () => {} }),
    failure === 'authority' ? /Invalid identity deletion receipt/
      : failure === 'postcondition' ? /MCP conversation deletion is incomplete/
        : error => error?.code === 'STALE_DELETION_LEASE');
    assert.equal(state.rolledBack, true); assert.equal(state.committed, undefined); assert.equal(state.released, true);
    if (failure === 'authority') {
      assert.equal(calls.some(([sql]) => sql.startsWith('DELETE FROM workshop_conversations.turns')), false);
    }
  }
});

test('identity cleanup observes cancellation after redaction and before commit', async () => {
  const calls = [], state = {}, controller = new AbortController();
  const identityPool = transactionPool(sql => {
    if (sql.includes('finalize_student_deletion')) return { rows: [{ finalized: true }] };
    if (sql.startsWith('DELETE FROM workshop_conversations.turns')
        || sql.startsWith('UPDATE workshop_conversations.requests')) return { rows: [], rowCount: 1 };
    if (sql.startsWith('SELECT') && sql.includes('identity.student_deletion_jobs')) {
      controller.abort(new Error('cancel deletion before commit'));
      return { rows: [{ current: true }] };
    }
    if (sql.startsWith('SELECT') && sql.includes('workshop_conversations.turns WHERE user_id=$1')) {
      return { rows: [{ turns_remain: false, request_content_remains: false }] };
    }
    throw new Error(`Unexpected query: ${sql}`);
  }, calls, state);
  const cleanup = createStudentDeletionStoreCleanup({ identityPool,
    xssPool: pool([], []), finflowPool: pool([], []) });
  await assert.rejects(cleanup.identity({ subjectId: 17,
    jobId: '11111111-1111-4111-8111-111111111111',
    leaseToken: '22222222-2222-4222-8222-222222222222', check: async () => {}, signal: controller.signal }),
  /cancel deletion before commit/);
  assert.equal(state.rolledBack, true); assert.equal(state.committed, undefined); assert.equal(state.released, true);
  assert.equal(calls.at(-1)[0], 'ROLLBACK');
});

test('identity finalization rejects false receipts', async () => {
  const calls = [], state = {};
  const identityPool = transactionPool(sql => {
    if (sql.includes('finalize_student_deletion')) return { rows: [{ finalized: false }] };
    throw new Error(`Unexpected query: ${sql}`);
  }, calls, state);
  const bad = createStudentDeletionStoreCleanup({ identityPool,
    xssPool: pool([], []), finflowPool: pool([], []) });
  await assert.rejects(bad.identity({ subjectId: 17, jobId: 'a', leaseToken: 'b', check: async () => {} }),
    /Invalid identity deletion receipt/);
});
test('cleanup rejects malformed owners and receipts before acknowledging deletion', async () => {
  const calls=[]; const cleanup=createStudentDeletionStoreCleanup({identityPool:pool([],calls),
    xssPool:pool([{removed:1000001}],calls),finflowPool:pool([],calls)});
  await assert.rejects(cleanup.xss({subjectId:'17',check:async()=>{}}),TypeError);
  await assert.rejects(cleanup.xss({subjectId:17,check:async()=>{}}),/Invalid XSS/);
});
