'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const Ticket = require('../server/services/secureshopTicketContract');
const { createTicketAgentProposalService, originalSelection } = require('../server/services/secureshopTicketAgentProposal');

const S = '00000000-0000-4000-8000-000000000001';
const R = '00000000-0000-4000-8000-000000000002';
const RUN = '00000000-0000-4000-8000-000000000003';
const E = n => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const subject = 'Practice order', body = '<img src=x onerror=alert(1)>';
const message = JSON.stringify({ subject, body });
const origin = { turnSessionId: S, turnRequestId: R, toolKey: Ticket.TOOL,
  invocationStep: 1, callId: 'selected-ticket-call' };
const prepared = { status: 'confirmation_required', ticketOrigin: origin,
  ticketProposal: Ticket.prepare({ subject, body, message, sourceOrigin: origin }) };
const ids = { sessionId: S, requestId: R, proposalId: prepared.ticketProposal.proposalId };

function source() {
  const result = { content: [{ type: 'text', text: JSON.stringify(prepared) }] };
  const traces = [
    { id: 1, event_id: E(1), session_id: S, step: 1, kind: 'model_decision', actor: 'supervisor',
      provider: 'ollama', params_json: JSON.stringify({ decision: 'tool_use', toolCalls: [
        { id: origin.callId, name: Ticket.TOOL, args: { subject, body } }] }),
      result_json: JSON.stringify({ model: 'llama3.1:8b', mocked: false }) },
    { id: 2, event_id: E(2), session_id: S, step: 1, kind: 'local_tool_call',
      actor: 'supervisor→task', agent_ns: 'support', tool_name: 'ticket_prepare',
      params_json: JSON.stringify({ subject, body }) },
    { id: 3, event_id: E(3), session_id: S, step: 1, kind: 'local_tool_result',
      actor: 'task→supervisor', agent_ns: 'support', tool_name: 'ticket_prepare',
      result_json: JSON.stringify(result) },
    { id: 4, event_id: E(4), session_id: S, step: 2, kind: 'terminal', actor: 'supervisor',
      provider: 'ollama', result_json: JSON.stringify({ stopReason: 'end_turn', steps: 2,
        hops: 1, model: 'llama3.1:8b', mocked: false }) },
  ];
  return { message, traces, turn: { session_id: S, request_id: R, status: 'completed',
    request_version: 1, request_hash: 'a'.repeat(64), result_json: { stopReason: 'end_turn',
      steps: 2, hops: [{ step: 1, tool: Ticket.TOOL, params: { subject, body }, result }],
      taskMetadata: { ticketAgent: { version: 1, runId: RUN, origin: structuredClone(origin),
        proposal: structuredClone(prepared.ticketProposal), traceEventIds: traces.map(row => row.event_id) } } } } };
}

test('selected original ticket tool supplies exact customer bytes and run to confirmation', async () => {
  let calls = 0, current = source();
  const service = createTicketAgentProposalService({
    readOriginal: async () => current, assertCurrent: async () => {},
    applyTicket: async (_, selected) => { calls++; assert.equal(selected.runId, RUN);
      assert.equal(selected.message, message); assert.equal(selected.requestSha256, 'a'.repeat(64));
      assert.deepEqual(selected.proposal, prepared.ticketProposal); return { ticketId: '1' }; },
    qualifyModel: identity => identity.provider === 'ollama' && identity.mocked === false,
  });
  assert.deepEqual(service.prepare({ subject, body, message, sourceOrigin: origin }), prepared);
  const confirmed = await service.confirm(ids, {});
  assert.equal(confirmed.result.ticketId, '1');
  assert.equal(confirmed.source.runId, RUN);
  assert.deepEqual(confirmed.source.traceEventIds, [E(1), E(2), E(3), E(4)]);
  for (const mutate of [
    value => { value.turn.result_json.taskMetadata.ticketAgent.runId = 'browser'; },
    value => { value.turn.result_json.taskMetadata.ticketAgent.proposal.body = 'forged'; },
    value => { value.turn.result_json.hops[0].params.body = 'forged'; },
    value => { value.traces[0].params_json = JSON.stringify({ decision: 'final', toolCalls: [] }); },
    value => { value.traces[0].result_json = JSON.stringify({ model: 'fixture', mocked: true }); },
    value => { value.traces[2].result_json = JSON.stringify({ content: [] }); },
    value => { value.traces.splice(1, 1); },
  ]) {
    current = source(); mutate(current);
    await assert.rejects(service.confirm(ids, {}), { code: 'TICKET_AGENT_SOURCE_INVALID' });
  }
  assert.equal(calls, 1);
});

test('v2 selected reference resolves only the protected original request while v1 remains byte-exact', () => {
  const value = source(), envelopeSha256 = 'c'.repeat(64);
  value.turn.result_json.taskMetadata.customerChat = { envelopeSha256 };
  const ref = Ticket.requestRef({ requestHash: value.turn.request_hash, envelopeSha256 });
  const args = { requestRef: ref }, meta = value.turn.result_json.taskMetadata.ticketAgent;
  meta.version = 2; meta.requestRef = ref;
  value.turn.result_json.hops[0].params = args;
  const decision = JSON.parse(value.traces[0].params_json);
  decision.toolCalls[0].args = args;
  value.traces[0].params_json = JSON.stringify(decision);
  value.traces[1].params_json = JSON.stringify(args);
  const qualify = row => row.provider === 'ollama' && row.mocked === false;
  const selected = originalSelection(value, ids, qualify);
  assert.deepEqual({ sourceVersion: selected.sourceVersion, requestRef: selected.requestRef },
    { sourceVersion: 2, requestRef: ref });
  assert.deepEqual(selected.proposal, prepared.ticketProposal);
  for (const mutate of [
    row => { row.turn.result_json.taskMetadata.ticketAgent.requestRef = Ticket.requestRef({ requestHash: 'b'.repeat(64), envelopeSha256 }); },
    row => { row.turn.result_json.hops[0].params = { subject, body }; },
    row => { const d = JSON.parse(row.traces[0].params_json); d.toolCalls[0].args = { subject, body }; row.traces[0].params_json = JSON.stringify(d); },
    row => { row.traces[1].params_json = JSON.stringify({ requestRef: Ticket.requestRef({ requestHash: 'b'.repeat(64), envelopeSha256 }) }); },
    row => { row.turn.result_json.taskMetadata.customerChat.envelopeSha256 = 'd'.repeat(64); },
    row => { row.turn.request_hash = 'b'.repeat(64); },
  ]) {
    const altered = structuredClone(value); mutate(altered);
    assert.throws(() => originalSelection(altered, ids, qualify),
      { code: 'TICKET_AGENT_SOURCE_INVALID' });
  }
  const legacy = source();
  assert.equal(Object.hasOwn(originalSelection(legacy, ids, qualify), 'requestRef'), false);
});
