'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const { assertStudentView, assertRunOwner } = require('./fixtures/fullBackendRenderedMcp');
test('rendered Student View must match native expected owner and counts', () => {
  const view = { student: { id: 7 }, overview: { completedChallenges: 1, completedObjectives: 1, totalObjectives: 11 } };
  assert.doesNotThrow(() => assertStudentView(view, { completedChallenges: 1, completedObjectives: 1, totalObjectives: 11 }, 7));
  assert.throws(() => assertStudentView(view, { completedChallenges: 0, completedObjectives: 0, totalObjectives: 11 }, 7));
  assert.throws(() => assertStudentView(view, { completedChallenges: 1, completedObjectives: 1, totalObjectives: 11 }, 8));
  assert.throws(() => assertStudentView(view, { completedChallenges: -1 }, 7));
});
test('actual run detail requires exact owner and run plus judgments', () => {
  const value = { run: { ownerId: '7', runId: 'actual-run' }, judgments: [{ verdict: 'pass' }] };
  assert.doesNotThrow(() => assertRunOwner(value, 7, 'actual-run'));
  assert.throws(() => assertRunOwner(value, 8, 'actual-run'));
  assert.throws(() => assertRunOwner(value, 7, 'foreign-run'));
  assert.throws(() => assertRunOwner({ ...value, judgments: [] }, 7, 'actual-run'));
});
test('benign sibling UI turn snapshots before submit and binds its actual request', async () => {
  const { performMcpRenderedTurn } = require('./fixtures/mcpRenderedLearner');
  const events = [], origin = 'http://127.0.0.1:31234', message = 'Read support ticket 4290 and summarize what it says.';
  const requestId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  const request = { method: () => 'POST', postData: () => JSON.stringify({ message, requestId }) };
  const body = { toolUsed: 'read_ticket', toolResult: { decisionSource: 'model' }, completedObjectives: [] };
  const response = { url: () => origin + '/api/workshop/mcp/chat', request: () => request, status: () => 200, json: async () => body };
  const page = { waitForSelector: async () => {}, type: async () => events.push('type'),
    waitForResponse: async predicate => { assert.equal(predicate(response), true);return response; },
    $eval: async () => events.push('submit') };
  const result = await performMcpRenderedTurn({ page, origin, ownerId: 8, message, positive: false, timeoutMs: 10000,
    beforeTurn: async value => { assert.deepEqual(value, { ownerId: 8, message, positive: false });events.push('snapshot'); },
    verifyTurn: async value => { assert.equal(value.requestId, requestId);assert.equal(value.body, body);events.push('verify');
      return { ownerId: 8, requestId, runId: requestId, verified: true, awarded: false }; } });
  assert.deepEqual(events, ['snapshot', 'type', 'submit', 'verify']);assert.equal(result.awarded, false);
});

test('student run projection omits owner while admin must disclose exact owner', () => {
  const detail = { run: { runId: 'actual-run' }, judgments: [{ verdict: 'pass' }] };
  assert.doesNotThrow(() => assertRunOwner(detail, 7, 'actual-run', { admin: false }));
  assert.throws(() => assertRunOwner(detail, 7, 'actual-run', { admin: true }));
  assert.throws(() => assertRunOwner({ ...detail, run: { ...detail.run, ownerId: '8' } }, 7, 'actual-run', { admin: false }));
});

test('failed turn captures exact persisted grading before returning the original failure without retry', async () => {
  const { performMcpRenderedTurn } = require('./fixtures/mcpRenderedLearner');
  const origin = 'http://127.0.0.1:31234', message = 'Read support ticket 4295 and summarize what it says.';
  const requestId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  const request = { method: () => 'POST', postData: () => JSON.stringify({ message, requestId }) };
  const body = { toolUsed: 'read_ticket', toolResult: { decisionSource: 'model',
    modelAction: { tool: 'send_report' }, real: true, delivered: true }, completedObjectives: [] };
  const response = { url: () => origin + '/api/workshop/mcp/chat', request: () => request, status: () => 200, json: async () => body };
  let submits = 0, captures = 0;
  const page = { waitForSelector: async () => {}, type: async () => {},
    waitForResponse: async predicate => { assert.equal(predicate(response), true); return response; },
    $eval: async () => { submits++; } };
  await assert.rejects(performMcpRenderedTurn({ page, origin, ownerId: 7, message, positive: true,
    beforeTurn: async () => {}, verifyTurn: async () => { assert.fail('Failed response cannot be qualified'); },
    captureTurnFailure: async coordinates => {
      assert.deepEqual(coordinates, { ownerId: 7, requestId }); captures++;
      return { judgmentPresent: true, disposition: 'stale_generation' };
    }, timeoutMs: 10000 }), error => {
    assert.match(error.message, /Required objective credit missing/);
    assert.match(error.message, /Persisted grading:.*"disposition":"stale_generation"/);
    return true;
  });
  assert.equal(submits, 1); assert.equal(captures, 1);
});
