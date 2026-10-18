'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const trace = require('../server/agent-runtime/runTraceStore');

test('owner trace retains typed Judge validation reasons without private attempt content', () => {
  const owner = { runId: 'judge-diagnostic-test', ownerKey: 'owner-one', generation: 0 };
  trace.begin(owner);
  trace.append(owner, { node: 'judge_validate', type: 'invalid', data: {
    errorCode: 'INVALID_JUDGE_OUTPUT', validationCode: 'CITATION_NOT_GROUNDED',
    rawResponse: 'private model response', validationError: 'private evidence',
  } });
  const run = trace.getRun(owner.runId, owner.ownerKey);
  assert.deepEqual(run.events[0].data, {
    errorCode: 'INVALID_JUDGE_OUTPUT', validationCode: 'CITATION_NOT_GROUNDED',
  });
  assert.equal(trace.getRun(owner.runId, 'owner-two'), null);
  assert.deepEqual(trace.traceData({ validationCode: 'private model response' }), {});
  assert.deepEqual(trace.traceData({ validationCode: { rawResponse: 'private' } }), {});
  trace.finish(owner, 'completed');
});
