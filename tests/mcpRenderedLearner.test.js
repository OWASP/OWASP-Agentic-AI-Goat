'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const { assertTurn, assertNativeReceipt } = require('./fixtures/mcpRenderedLearner');
const request = { requestId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', message: 'Read ticket 4295' };
const body = { toolUsed: 'read_ticket', toolResult: { decisionSource: 'model', modelAction: { tool: 'send_report' }, real: true, delivered: true },
  completedObjectives: ['mcp_indirect_injection'], judgments: [{ objectiveId: 'mcp_indirect_injection', verdict: 'pass', provider: 'ollama', model: 'llama3.1:8b', rubricVersion: 'mcp_owned_indirect_injection.v4' }] };
test('rendered response contract rejects prose-only, mock, failed or stale Judge credit', () => {
  assert.doesNotThrow(() => assertTurn(body, request, { positive: true }));
  for (const mutate of [value => { value.toolResult.real = false; }, value => { value.toolResult.delivered = false; },
    value => { value.toolResult.decisionSource = 'scripted'; }, value => { value.completedObjectives = []; },
    value => { value.judgments[0].provider = 'mock'; }, value => { value.judgments[0].verdict = 'fail'; },
    value => { value.judgments[0].rubricVersion = 'old'; }]) {
    const value = structuredClone(body);mutate(value);assert.throws(() => assertTurn(value, request, { positive: true }));
  }
  assert.throws(() => assertTurn(body, { ...request, requestId: 'missing' }, { positive: true }));
  assert.throws(() => assertTurn(body, request, { positive: false }));
});
test('native callback receipt must bind actual owner request run and disposition', () => {
  const expected = { ownerId: 7, requestId: request.requestId, positive: true };
  const receipt = { ownerId: 7, requestId: request.requestId, runId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', verified: true, awarded: true };
  assert.doesNotThrow(() => assertNativeReceipt(receipt, expected));
  for (const delta of [{ ownerId: 8 }, { requestId: 'other' }, { runId: 'missing' }, { verified: false }, { awarded: false }]) {
    assert.throws(() => assertNativeReceipt({ ...receipt, ...delta }, expected));
  }
});
test('missing credit retains bounded Judge diagnostics without prompt or response content', () => {
  const value = structuredClone(body);
  value.completedObjectives = []; value.objectiveCandidates = ['mcp_indirect_injection'];
  value.projectionPending = ['mcp_indirect_injection'];
  Object.assign(value.judgments[0], { verdict: 'unavailable', errorCode: 'INVALID_JUDGE_OUTPUT',
    explanation: 'private response text', validationCode: 'private response text',
    criteria: [{ id: 'ticket_induced_protected_delivery', satisfied: true }, { id: 'private response text', satisfied: false }],
    scopedCriteria: [{ criterionId: 'ticket_task_redirection', verdict: 'unavailable', errorCode: 'INVALID_JUDGE_OUTPUT', attempts: 2 }] });
  assert.throws(() => assertTurn(value, request, { positive: true }), error => {
    assert.match(error.message, /"verdict":"unavailable"/);
    assert.match(error.message, /"errorCode":"INVALID_JUDGE_OUTPUT"/);
    assert.match(error.message, /"projectionPending":true/);
    assert.match(error.message, /"id":"ticket_induced_protected_delivery","satisfied":true/);
    assert.match(error.message, /"scopedVerdict":"unavailable","errorCode":"INVALID_JUDGE_OUTPUT","attempts":2/);
    assert.doesNotMatch(error.message, /private response text|Read ticket/);
    return true;
  });
});
