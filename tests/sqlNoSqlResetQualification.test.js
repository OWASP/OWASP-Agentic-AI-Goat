'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { qualifySqlNoSqlResetBeforeJudge: qualify } = require('./fixtures/sqlNoSqlResetQualification');
function fixture() {
  const boundary = new AbortController();
  const invocation = { tool: 'search_products', params: { searchTerm: "'" } };
  const dto = { toolUsed: 'search_products', toolResult: { error: 'controlled native-shape observation' } };
  const execution = { runId: 'actual-fixture-run', signal: boundary.signal };
  let grades = 0; let agentFinished;
  const finished = new Promise(resolve => { agentFinished = resolve; });
  const agent = { async invoke(_owner, _message, _mode, hooks) {
    await hooks.onStart(execution);
    try {
      return await hooks.onResult(dto, async () => {
        if (boundary.signal.aborted) throw Object.assign(new Error('cancelled'), { name: 'AbortError' });
      }, execution, invocation);
    } finally { agentFinished(); }
  } };
  return { boundary, invocation, dto, execution, agent, finished, grade: async () => { grades++; }, grades: () => grades };
}

test('actual reset abort unblocks actor before reset waits for completion; grader never runs', async () => {
  const f = fixture(); const resetResult = { generation: 2 };
  const result = await qualify({ agent: f.agent, owner: 1, message: 'search', grade: f.grade,
    reset: async () => { f.boundary.abort(); await f.finished; return resetResult; } });
  assert.equal(result.cancelled, true); assert.equal(result.gradeCalls, 0); assert.equal(f.grades(), 0);
  assert.equal(result.dto, f.dto); assert.equal(result.invocation, f.invocation);
  assert.equal(result.execution, f.execution); assert.equal(result.runId, f.execution.runId);
  assert.equal(result.resetResult, resetResult); assert.equal(result.actorError.name, 'AbortError');
});

test('actor failure or completion before observation rejects promptly without reset', async () => {
  for (const invoke of [async () => { throw Error('controlled actor error'); }, async () => ({ status: 'no_tool' })]) {
    let resets = 0;
    await assert.rejects(qualify({ agent: { invoke }, owner: 1, message: 'search', grade: async () => {}, reset: async () => { resets++; } }), /ACTOR_FAILED|NO_OBSERVATION|ACTOR_ENDED_BEFORE_RESET/);
    assert.equal(resets, 0);
  }
});

test('noncancelling reset meets a bounded deadline and releases actor wait', async () => {
  const f = fixture();
  await assert.rejects(qualify({ agent: f.agent, owner: 1, message: 'search', grade: f.grade,
    reset: async () => ({ generation: 2 }), deadlineMs: 20 }), { code: 'RESET_QUALIFICATION_TIMEOUT' });
  await f.finished; assert.equal(f.grades(), 0);
});

test('failed reset rejects promptly and releases the actor latch', async () => {
  const f = fixture();
  await assert.rejects(qualify({ agent: f.agent, owner: 1, message: 'search', grade: f.grade,
    reset: async () => { throw Error('controlled reset failure'); } }), { code: 'RESET_QUALIFICATION_RESET_FAILED' });
  await f.finished; assert.equal(f.grades(), 0);
});

test('a broken cancellation check is reported rather than fabricating no-grade proof', async () => {
  const boundary = new AbortController(); let grades = 0;
  const execution = { runId: 'broken-check', signal: boundary.signal };
  const result = await qualify({ owner: 1, message: 'search',
    agent: { invoke: async (_owner,_message,_mode,hooks) => hooks.onResult({}, async () => {}, execution, {}) },
    reset: async () => { boundary.abort(); return {}; }, grade: async () => { grades++; } });
  assert.equal(result.cancelled, false); assert.equal(result.gradeCalls, 1); assert.equal(grades, 1);
});

test('real onStart admission completes before observation and reset receives captured identity', async () => {
  const f = fixture(); let admitted = false;
  const result = await qualify({ agent: f.agent, owner: 1, message: 'search', grade: f.grade,
    onStart: async execution => { assert.equal(execution, f.execution); await Promise.resolve(); admitted = true; },
    reset: async captured => {
      assert.equal(admitted, true); assert.equal(captured.execution, f.execution);
      assert.equal(captured.invocation, f.invocation); assert.equal(captured.dto, f.dto);
      f.boundary.abort(); return { success: true };
    } });
  assert.equal(result.cancelled, true);
});
