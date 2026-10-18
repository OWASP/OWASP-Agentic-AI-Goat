'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createCouponAgentProposalService } = require('../server/services/secureshopCouponAgentProposalService');
const Contract = require('../server/services/secureshopCouponAgentContract');
const S = '00000000-0000-4000-8000-000000000001';
const R = '00000000-0000-4000-8000-000000000002';
const E = n => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const code = "' OR 1=1--";
const origin = { turnSessionId: S, turnRequestId: R, toolKey: Contract.TOOL,
  invocationStep: 1, callId: 'original-call' };

function source(prepared) {
  const result = { content: [{ type: 'text', text: JSON.stringify(prepared) }] };
  const traces = [
    { id: 1, event_id: E(1), session_id: S, step: 1, kind: 'model_decision',
      actor: 'supervisor', provider: 'ollama',
      params_json: JSON.stringify({ decision: 'tool_use', toolCalls: [{ id: origin.callId,
        name: Contract.TOOL, args: { code } }] }),
      result_json: JSON.stringify({ model: 'llama3.1:8b', mocked: false }) },
    { id: 2, event_id: E(2), session_id: S, step: 1, kind: 'local_tool_call',
      actor: 'supervisor→task', agent_ns: 'cart', tool_name: 'coupon_prepare',
      params_json: JSON.stringify({ code }) },
    { id: 3, event_id: E(3), session_id: S, step: 1, kind: 'local_tool_result',
      actor: 'task→supervisor', agent_ns: 'cart', tool_name: 'coupon_prepare',
      result_json: JSON.stringify(result) },
    { id: 4, event_id: E(4), session_id: S, step: 2, kind: 'terminal',
      actor: 'supervisor', provider: 'ollama',
      result_json: JSON.stringify({ stopReason: 'end_turn', steps: 2, hops: 1,
        model: 'llama3.1:8b', mocked: false }) },
  ];
  return { message: `Apply coupon ${code}`, traces,
    turn: { session_id: S, request_id: R, status: 'completed',
      result_json: { stopReason: 'end_turn', steps: 2, hops: [{ step: 1, tool: Contract.TOOL,
        params: { code }, result }], taskMetadata: { customerChat: {
          couponOrigin: prepared.couponOrigin, couponProposal: prepared.couponProposal,
          traceEventIds: traces.map(row => row.event_id),
        } } } } };
}

test('protected completed model selection supplies exact code to trusted confirmation', async () => {
  const calls = [], service = createCouponAgentProposalService({
    readOriginal: async () => source(prepared),
    assertCurrent: async () => {},
    applyCoupon: async (_context, input) => { calls.push(input); return { ok: true, code: 'HALF' }; },
    qualifyModel: identity => identity.provider === 'ollama' && identity.mocked === false,
  });
  const prepared = service.prepare({ code, message: `Apply coupon ${code}`, sourceOrigin: origin });
  assert.deepEqual(prepared, { status: 'confirmation_required',
    couponProposal: Contract.prepare({ code, message: `Apply coupon ${code}`, sourceOrigin: origin }),
    couponOrigin: origin });
  assert.equal(calls.length, 0);
  const request = { sessionId: S, requestId: R, proposalId: prepared.couponProposal.proposalId };
  const result = await service.confirm(request, Object.freeze({ current: true }));
  assert.deepEqual(calls, [{ code, operationId: prepared.couponProposal.proposalId }]);
  assert.equal(result.source.decisionEventId, E(1));
  assert.equal(result.source.callEventId, E(2));
  assert.equal(result.source.terminalEventId, E(4));
  assert.equal(result.result.ok, true);
  await assert.rejects(service.confirm({ ...request, code }, {}),
    error => error.code === 'COUPON_AGENT_SOURCE_INVALID');
  assert.equal(calls.length, 1);
});

test('mismatched saved hop, reused-session trace, and mock decision never call the coupon workflow', async () => {
  const prepared = { status: 'confirmation_required',
    couponProposal: Contract.prepare({ code, message: `Apply coupon ${code}`, sourceOrigin: origin }),
    couponOrigin: origin };
  const request = { sessionId: S, requestId: R, proposalId: prepared.couponProposal.proposalId };
  let calls = 0, current = source(prepared);
  const service = createCouponAgentProposalService({ readOriginal: async () => current,
    assertCurrent: async () => {}, applyCoupon: async () => { calls++; },
    qualifyModel: identity => identity.provider === 'ollama' && identity.mocked === false });
  current = source(prepared);
  current.turn.result_json.hops[0].params.code = 'WELCOME10';
  await assert.rejects(service.confirm(request, {}), error => error.code === 'COUPON_AGENT_SOURCE_INVALID');
  current = source(prepared);
  current.traces[0].event_id = E(9);
  await assert.rejects(service.confirm(request, {}), error => error.code === 'COUPON_AGENT_SOURCE_INVALID');
  current = source(prepared);
  current.traces[0].result_json = JSON.stringify({ model: 'fixture', mocked: true });
  await assert.rejects(service.confirm(request, {}), error => error.code === 'COUPON_AGENT_SOURCE_INVALID');
  current = source(prepared);
  current.traces.splice(1, 1);
  current.turn.result_json.taskMetadata.customerChat.traceEventIds = current.traces.map(row => row.event_id);
  await assert.rejects(service.confirm(request, {}), error => error.code === 'COUPON_AGENT_SOURCE_INVALID');
  current = source(prepared);
  current.traces[0].params_json = JSON.stringify({ decision: 'final', toolCalls: [
    { id: origin.callId, name: Contract.TOOL, args: { code } }] });
  await assert.rejects(service.confirm(request, {}), error => error.code === 'COUPON_AGENT_SOURCE_INVALID');
  current = source(prepared);
  current.traces[3].result_json = JSON.stringify({ stopReason: 'end_turn', steps: 2,
    hops: 2, model: 'llama3.1:8b', mocked: false });
  await assert.rejects(service.confirm(request, {}), error => error.code === 'COUPON_AGENT_SOURCE_INVALID');
  current = source(prepared);
  current.traces.push({ ...current.traces[3], id: 5, event_id: E(5) });
  current.turn.result_json.taskMetadata.customerChat.traceEventIds = current.traces.map(row => row.event_id);
  await assert.rejects(service.confirm(request, {}), error => error.code === 'COUPON_AGENT_SOURCE_INVALID');
  assert.equal(calls, 0);
});
