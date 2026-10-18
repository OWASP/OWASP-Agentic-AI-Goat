'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createTicketAgentConfirmation } = require('../server/services/secureshopTicketAgentConfirmation');
const { createSceneBinding } = require('../server/services/secureshopSceneBinding');
const { capture } = require('../server/database/postgres/secureshopCustomerChatBindingRepository');
const { projectFeatureMode } = require('../server/services/secureshopFeatureModeAuthority');
const Ticket = require('../server/services/secureshopTicketContract');

const E = n => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const S = E(1), R = E(2), RUN = E(3);
const scope = { launchId: E(10), scenarioId: E(11), generation: 2,
  platformOwnerId: 8, platformSessionId: 9 };
const persona = { id: 10, role: 'customer' };
const personaSession = { sessionId: E(12), authorityVersion: '3' };
const retainedScene = createSceneBinding({ ...scope, targetId: E(13) },
  { sceneId: E(14), sceneGeneration: 1, grantId: E(15), execution: scope,
    withLease: async work => work() });
const subject = 'Practice order', body = '<img src=x onerror=alert(1)>';
const message = JSON.stringify({ subject, body });
const origin = { turnSessionId: S, turnRequestId: R, toolKey: Ticket.TOOL,
  invocationStep: 1, callId: 'model-selected-ticket' };
const proposal = Ticket.prepare({ subject, body, message, sourceOrigin: origin });
const ids = { sessionId: S, requestId: R, proposalId: proposal.proposalId };
const envelope = JSON.stringify({ version: 1, sceneId: retainedScene.scene.sceneId,
  sceneGeneration: 1, targetId: retainedScene.targetId, requestId: R, message });
const captured = capture({ sessionId: S, requestId: R, scope, persona,
  personaSession, target: retainedScene, message: envelope });
const columnPairs = [['session_id', 'sessionId'], ['request_id', 'requestId'],
  ['launch_id', 'launchId'], ['scenario_id', 'scenarioId'], ['generation', 'generation'],
  ['owner_id', 'ownerId'], ['execution_session_id', 'executionSessionId'],
  ['persona_id', 'personaId'], ['persona_session_id', 'personaSessionId'],
  ['authority_version', 'authorityVersion'], ['scene_id', 'sceneId'],
  ['scene_generation', 'sceneGeneration'], ['grant_id', 'grantId'],
  ['target_id', 'targetId'], ['envelope_sha256', 'envelopeSha256'],
  ['request_hash', 'requestHash']];
const receipt = { version: 1, kind: 'support_ticket', ticketId: '1',
  operationId: proposal.proposalId, requestId: R, runId: RUN, proposalId: proposal.proposalId,
  status: 'open', subjectSha256: proposal.subjectSha256, bodySha256: proposal.bodySha256,
  receiptSha256: 'a'.repeat(64) };

function feature(featureId, state) {
  return { snapshot: { featureId, policyVersion: featureId === 'support_tickets'
    ? 'owned-ticket-render-v1' : 'v1', mode: 'vuln' },
  assertCurrent: async () => { if (state.stale) throw Object.assign(new Error('stale'),
    { code: 'SHOP_SCENE_STALE' }); } };
}
function fixture() {
  const state = { stale: false, staleAfterEffect: false, effects: [], reads: [], saved: null, checks: 0 };
  const mode = feature('customer_chat', state), ticketMode = feature('support_tickets', state);
  const binding = Object.fromEntries(columnPairs.map(([db, js]) => [db, captured[js]]));
  const hopResult = { content: [{ type: 'text', text: JSON.stringify({ status: 'confirmation_required',
    ticketProposal: proposal, ticketOrigin: origin }) }] };
  const traces = [
    { id: 1, event_id: E(21), session_id: S, step: 1, actor: 'supervisor',
      kind: 'model_decision', provider: 'ollama',
      params_json: JSON.stringify({ decision: 'tool_use', toolCalls: [
        { id: origin.callId, name: Ticket.TOOL, args: { subject, body } }] }),
      result_json: JSON.stringify({ model: 'llama3.1:8b', mocked: false }) },
    { id: 2, event_id: E(22), session_id: S, step: 1, actor: 'supervisor→task',
      kind: 'local_tool_call', agent_ns: 'support', tool_name: 'ticket_prepare',
      params_json: JSON.stringify({ subject, body }) },
    { id: 3, event_id: E(23), session_id: S, step: 1, actor: 'task→supervisor',
      kind: 'local_tool_result', agent_ns: 'support', tool_name: 'ticket_prepare',
      result_json: JSON.stringify(hopResult) },
    { id: 4, event_id: E(24), session_id: S, step: 2, actor: 'supervisor',
      kind: 'terminal', provider: 'ollama', result_json: JSON.stringify({ stopReason: 'end_turn',
        steps: 2, hops: 1, model: 'llama3.1:8b', mocked: false }) },
  ];
  const customerChat = { version: 1, sceneId: captured.sceneId,
    sceneGeneration: captured.sceneGeneration, targetId: captured.targetId,
    envelopeSha256: captured.envelopeSha256, cards: [], orderPage: null,
    paymentSetup: null, addressSetup: null, refundSetup: null,
    profileProposal: null, profileOrigin: null, couponOrigin: null, couponProposal: null,
    traceEventIds: traces.map(row => row.event_id) };
  const turn = { session_id: S, status: 'completed', request_version: 1,
    request_hash: captured.requestHash, result_json: { stopReason: 'end_turn', steps: 2,
      hops: [{ step: 1, tool: Ticket.TOOL, params: { subject, body }, result: hopResult }],
      taskMetadata: { customerChat, ticketAgent: { version: 1, runId: RUN,
        origin, proposal, traceEventIds: traces.map(row => row.event_id) } },
      modeCapability: projectFeatureMode(mode) } };
  const service = createTicketAgentConfirmation({
    captureCurrent: async () => ({ scope, persona, personaSession,
      target: retainedScene, retainedScene, mode, ticketMode,
      withEffect: async work => work(),
      check: async () => { state.checks++; if (state.stale) throw Object.assign(new Error('stale'),
        { code: 'SHOP_SCENE_STALE' }); } }),
    bindingRepository: { read: async () => binding },
    journal: { readBoundRequest: async () => turn },
    conversations: { getMessages: async () => [{ role: 'user', content: envelope,
      modeCapability: projectFeatureMode(mode) }], getTraceEvents: async () => traces },
    qualifyModel: identity => identity.provider === 'ollama' && identity.mocked === false,
    confirmTicket: async input => { state.effects.push(input);
      if (state.staleAfterEffect) state.stale = true;
      return receipt; },
    readSavedTicket: async input => { state.reads.push(input); return state.saved; },
  });
  return { service, state, turn, traces };
}

test('closed original IDs confirm the exact ticket and protected GET never repeats an effect', async () => {
  const f = fixture();
  assert.deepEqual(await f.service.readSaved({}, ids), { status: 'unconfirmed' });
  assert.equal(f.state.effects.length, 0);
  assert.deepEqual(await f.service.confirm({}, ids), { result: receipt,
    source: { sessionId: S, requestId: R, runId: RUN, operationId: proposal.proposalId,
      subjectSha256: proposal.subjectSha256, bodySha256: proposal.bodySha256,
      traceEventIds: [E(21), E(22), E(23), E(24)], decisionEventId: E(21),
      callEventId: E(22), resultEventId: E(23), terminalEventId: E(24) } });
  const input = f.state.effects[0];
  assert.deepEqual(input.source.scene.birth, scope);
  assert.equal(input.source.scene.grantId, retainedScene.scene.grantId);
  assert.equal(input.source.turn.runId, RUN);
  assert.equal(input.originalMessage, message);
  assert.deepEqual(input.sourceOrigin, origin);
  assert.equal(input.requestSha256, captured.requestHash);
  f.state.saved = receipt;
  assert.deepEqual(await f.service.readSaved({}, ids), { status: 'completed', result: receipt });
  assert.equal(f.state.effects.length, 1);
  assert.equal(f.state.reads.at(-1).operationId, proposal.proposalId);
  f.state.saved = { ...receipt, subjectSha256: 'b'.repeat(64) };
  await assert.rejects(f.service.readSaved({}, ids), { code: 'TICKET_CONTRACT_INVALID' });
  assert.equal(f.state.effects.length, 1);
  await assert.rejects(f.service.confirm({}, { ...ids, subject }),
    { code: 'TICKET_AGENT_SOURCE_INVALID' });
  f.state.stale = true;
  await assert.rejects(f.service.readSaved({}, ids), { code: 'SHOP_SCENE_STALE' });
  assert.equal(f.state.effects.length, 1);
});

test('post-effect authority loss reports uncertainty and cannot publish a completed confirmation', async () => {
  const f = fixture();
  f.state.staleAfterEffect = true;
  await assert.rejects(f.service.confirm({}, ids),
    { code: 'PERSONA_EFFECT_OUTCOME_UNCERTAIN', executionBoundary: true });
  assert.equal(f.state.effects.length, 1);
  assert.equal(f.state.reads.length, 0);
});
