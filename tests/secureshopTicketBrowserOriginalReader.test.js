'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createTicketBrowserOriginalReader } = require('../server/services/secureshopTicketBrowserOriginalReader');
const { createSceneBinding } = require('../server/services/secureshopSceneBinding');
const { createConversationBinding } = require('../server/services/secureshopConversationBinding');
const { ticketSource } = require('../server/services/secureshopTicketAgentConfirmation');
const { capture } = require('../server/database/postgres/secureshopCustomerChatBindingRepository');
const { projectFeatureMode } = require('../server/services/secureshopFeatureModeAuthority');
const Ticket = require('../server/services/secureshopTicketContract');

const E = n => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const scope = { launchId: E(10), scenarioId: E(11), generation: 2,
  platformOwnerId: 8, platformSessionId: 9 };
const persona = { id: 10, role: 'customer' };
const personaSession = { sessionId: E(12), authorityVersion: '3' };
const retainedScene = createSceneBinding({ ...scope, targetId: E(13) },
  { sceneId: E(14), sceneGeneration: 1, grantId: E(15), execution: scope,
    withLease: async work => work() });
const sessionId = E(1), requestId = E(2), runId = E(3);
const subject = 'Practice order', body = '<img src=x onerror=alert(1)>';
const message = JSON.stringify({ subject, body });
const origin = { turnSessionId: sessionId, turnRequestId: requestId,
  toolKey: Ticket.TOOL, invocationStep: 1, callId: 'model-selected-ticket' };
const proposal = Ticket.prepare({ subject, body, message, sourceOrigin: origin });
const source = ticketSource({ scope, persona, personaSession, retainedScene },
  { origin, proposal, runId });
const envelope = JSON.stringify({ version: 1, sceneId: retainedScene.scene.sceneId,
  sceneGeneration: 1, targetId: retainedScene.targetId, requestId, message });
const expected = capture({ sessionId, requestId, scope, persona, personaSession,
  target: retainedScene, message: envelope });
const pairs = [['session_id','sessionId'], ['request_id','requestId'],
  ['launch_id','launchId'], ['scenario_id','scenarioId'], ['generation','generation'],
  ['owner_id','ownerId'], ['execution_session_id','executionSessionId'],
  ['persona_id','personaId'], ['persona_session_id','personaSessionId'],
  ['authority_version','authorityVersion'], ['scene_id','sceneId'],
  ['scene_generation','sceneGeneration'], ['grant_id','grantId'],
  ['target_id','targetId'], ['envelope_sha256','envelopeSha256'],
  ['request_hash','requestHash']];
const modeCapability = projectFeatureMode({ snapshot: { version: 1,
  featureId: 'customer_chat', policyVersion: 'v1', mode: 'vuln', scope } });

function fixture() {
  const state = { calls: [], bound: Object.fromEntries(pairs.map(([db, js]) => [db, expected[js]])) };
  state.session = { id: sessionId, state: 'active',
    binding: createConversationBinding(scope, persona), purpose: 'secureshop_customer_chat' };
  state.messages = [{ role: 'user', content: envelope, modeCapability }];
  state.traces = [1,2,3,4].map((n, i) => ({ id: n, event_id: E(20+n),
    session_id: sessionId, kind: i === 3 ? 'terminal' : 'model_decision' }));
  state.turn = { session_id: sessionId, status: 'completed',
    request_version: 1, request_hash: expected.requestHash,
    result_json: { modeCapability, taskMetadata: {
      customerChat: { version: 1, sceneId: expected.sceneId,
        sceneGeneration: expected.sceneGeneration, targetId: expected.targetId,
        envelopeSha256: expected.envelopeSha256, cards: [], orderPage: null,
        paymentSetup: null, addressSetup: null, refundSetup: null,
        profileProposal: null, profileOrigin: null, couponOrigin: null,
        couponProposal: null, traceEventIds: state.traces.map(row => row.event_id) },
      ticketAgent: { version: 1, runId, origin, proposal,
        traceEventIds: state.traces.map(row => row.event_id) } } } };
  const reader = createTicketBrowserOriginalReader({
    bindingRepository: { read: async input => { state.calls.push(['binding',input]); return state.bound; } },
    journal: { readBoundRequest: async input => { state.calls.push(['turn',input]); return state.turn; } },
    conversations: {
      getBoundSession: async id => { state.calls.push(['session',id]); return state.session; },
      getMessages: async (...args) => { state.calls.push(['messages',args]); return state.messages; },
      getTraceEvents: async (...args) => { state.calls.push(['traces',args]); return state.traces; },
    },
  });
  return { state, reader, ticket: { source, proposal, requestSha256: expected.requestHash } };
}

test('historical reader binds original customer bytes and ordered trace without persona reactivation', async () => {
  const f = fixture();
  const value = await f.reader(f.ticket);
  assert.equal(value.message, message);
  assert.equal(value.turn.request_id, requestId);
  assert.deepEqual(value.traces.map(row => row.event_id), f.state.traces.map(row => row.event_id));
  assert.deepEqual(f.state.calls.map(row => row[0]),
    ['session','binding','turn','messages','traces']);
  assert.equal(f.state.calls[1][1].persona.role, 'customer');
  assert.equal(f.state.calls[3][1][2], 'secureshop_customer_chat');
});

test('historical reader rejects altered request, grant, origin and trace before evidence use', async () => {
  for (const change of [
    f => { f.state.bound.grant_id = E(99); },
    f => { f.state.turn.request_hash = 'f'.repeat(64); },
    f => { f.state.messages[0].content = JSON.stringify({ ...JSON.parse(envelope),
      message: JSON.stringify({ subject, body: 'changed' }) }); },
    f => { f.state.traces[1].event_id = E(99); },
    f => { f.state.session.purpose = 'general'; },
    f => { f.state.turn.result_json.taskMetadata.ticketAgent.runId = E(99); },
  ]) {
    const f = fixture(); change(f);
    await assert.rejects(f.reader(f.ticket), { code: 'TICKET_BROWSER_ORIGINAL_UNAVAILABLE' });
  }
});

test('historical reader accepts only the original turn-derived v2 request reference', async () => {
  const f = fixture();
  f.state.turn.result_json.taskMetadata.ticketAgent = {
    ...f.state.turn.result_json.taskMetadata.ticketAgent,
    version: 2, requestRef: Ticket.requestRef({ requestHash: expected.requestHash,
      envelopeSha256: expected.envelopeSha256 }),
  };
  assert.equal((await f.reader(f.ticket)).message, message);
  f.state.turn.result_json.taskMetadata.ticketAgent.requestRef = Ticket.requestRef({
    requestHash: 'b'.repeat(64), envelopeSha256: expected.envelopeSha256 });
  await assert.rejects(f.reader(f.ticket), { code: 'TICKET_BROWSER_ORIGINAL_UNAVAILABLE' });
});

test('current customer metadata catalog page preserves historical ticket source and exact closed shapes', async () => {
  const page = { version: 1, search: 'notebook', status: 'active', afterCursor: null,
    nextCursor: null, sourceRequestId: null, total: 0, returnedCount: 0 };
  for (const catalogPageSource of [null, page]) {
    const f = fixture(); f.state.turn.result_json.taskMetadata.customerChat.catalogPageSource = catalogPageSource;
    assert.equal((await f.reader(f.ticket)).message, message);
    assert.deepEqual(f.state.calls.map(row => row[0]), ['session','binding','turn','messages','traces']);
  }
  for (const value of [undefined, {}, { ...page, extra: true }, { ...page, version: 2 },
    { ...page, status: 'inactive' }, { ...page, search: 'é'.repeat(65) },
    { ...page, search: '\ud800' }, { ...page, search: 'a\0b' },
    { ...page, afterCursor: E(90) }, { ...page, sourceRequestId: E(90) },
    { ...page, nextCursor: E(90) }, { ...page, total: -1 },
    { ...page, returnedCount: 13, total: 13 }, { ...page, returnedCount: 1, total: 0 },
    { ...page, sourceRequestId: 'not-a-uuid', afterCursor: E(90) }]) {
    const f = fixture(); f.state.turn.result_json.taskMetadata.customerChat.catalogPageSource = value;
    await assert.rejects(f.reader(f.ticket), { code: 'TICKET_BROWSER_ORIGINAL_UNAVAILABLE' });
    assert.equal(f.state.calls.some(row => row[0] === 'traces'), false);
  }
  for (const current of [false, true]) {
    const f = fixture(); if (current) f.state.turn.result_json.taskMetadata.customerChat.catalogPageSource = null;
    f.state.turn.result_json.taskMetadata.customerChat.unknown = null;
    await assert.rejects(f.reader(f.ticket), { code: 'TICKET_BROWSER_ORIGINAL_UNAVAILABLE' });
  }
});
