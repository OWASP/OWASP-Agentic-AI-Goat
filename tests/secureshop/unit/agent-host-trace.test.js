'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');
const path = require('node:path');
const crypto = require('node:crypto');

const REPO = path.resolve(__dirname, '../../..');
const persistedBatches = [];
let releaseWrite;
const writeHeld = new Promise(resolve => { releaseWrite = resolve; });
const repository = {
  async appendTraces(rows) {
    assert.ok(Array.isArray(rows));
    persistedBatches.push(structuredClone(rows));
    await writeHeld;
  },
};

const originalLoad = Module._load;
Module._load = function injectAsyncTraceRepository(request, parent, isMain) {
  if (request.endsWith('/database/postgres/secureshopAgentsDb')) {
    return { getSecureShopAgentsDb: () => repository };
  }
  return originalLoad.call(this, request, parent, isMain);
};
const trace = require(path.join(REPO, 'agent-host/shared/trace.js'));
test.after(() => { Module._load = originalLoad; });

test('recordTrace forwards owner-bound provenance and raw trace fields to the injected async repository', async () => {
  const sessionId = `owner-session-${crypto.randomUUID()}`;
  const rawParams = '{"q":"<img src=x onerror=fixture()>","owner":41}';
  const rawResult = '{"rows":[{"secret":"synthetic"}]}';

  trace.recordTrace({
    session_id: sessionId,
    step: 1,
    actor: 'supervisor',
    kind: 'llm_call_start',
    provider: 'controlled-provider',
    tokens_in: 17,
  });
  trace.recordTrace({
    session_id: sessionId,
    step: 2,
    actor: 'supervisor→task',
    kind: 'mcp_call',
    agent_ns: 'product-search',
    tool_name: 'search',
    params_json: rawParams,
    result_json: rawResult,
    latency_ms: 42,
    policy_violation: 'denied-by-acl',
  });

  const flushing = trace.flush();
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(persistedBatches.length, 1, 'flush delegates one ordered batch');
  assert.equal(typeof flushing.then, 'function', 'flush exposes async repository completion');

  const rows = persistedBatches[0];
  assert.equal(rows.length, 2);
  assert.deepEqual(rows.map(row => row.session_id), [sessionId, sessionId]);
  assert.deepEqual(rows.map(row => row.step), [1, 2]);
  assert.equal(rows[0].provider, 'controlled-provider');
  assert.equal(rows[0].tokens_in, 17);
  assert.equal(rows[1].actor, 'supervisor→task');
  assert.equal(rows[1].agent_ns, 'product-search');
  assert.equal(rows[1].tool_name, 'search');
  assert.equal(rows[1].params_json, rawParams, 'raw parameters remain byte-for-byte caller data');
  assert.equal(rows[1].result_json, rawResult, 'raw result remains byte-for-byte tool data');
  assert.equal(rows[1].latency_ms, 42);
  assert.equal(rows[1].policy_violation, 'denied-by-acl');
  for (const row of rows) assert.match(row.event_id, /^[0-9a-f-]{36}$/);
  assert.notEqual(rows[0].event_id, rows[1].event_id);

  let completed = false;
  flushing.then(() => { completed = true; });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(completed, false, 'flush waits for the injected async write');
  releaseWrite();
  await flushing;
  assert.equal(completed, true);
});
