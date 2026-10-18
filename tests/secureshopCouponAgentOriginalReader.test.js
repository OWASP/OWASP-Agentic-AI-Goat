'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createCouponAgentOriginalReader } = require('../server/services/secureshopCouponAgentOriginalReader');
const { createSceneBinding } = require('../server/services/secureshopSceneBinding');
const { capture } = require('../server/database/postgres/secureshopCustomerChatBindingRepository');
const { projectFeatureMode } = require('../server/services/secureshopFeatureModeAuthority');
const S = '00000000-0000-4000-8000-000000000001';
const R = '00000000-0000-4000-8000-000000000002';
const E = '00000000-0000-4000-8000-000000000003';
const scope = { launchId: '00000000-0000-4000-8000-000000000004',
  scenarioId: '00000000-0000-4000-8000-000000000005', generation: 2,
  platformOwnerId: 8, platformSessionId: 9 };
const persona = { id: 10, role: 'customer' };
const personaSession = { sessionId: '00000000-0000-4000-8000-000000000006', authorityVersion: '3' };
const target = createSceneBinding({ ...scope, targetId: '00000000-0000-4000-8000-000000000007' },
  { sceneId: '00000000-0000-4000-8000-000000000008', sceneGeneration: 1,
    grantId: '00000000-0000-4000-8000-000000000009', execution: scope,
    withLease: async work => work() });
const mode = { snapshot: { featureId: 'customer_chat', policyVersion: 'v1', mode: 'vuln' } };
const message = "Apply coupon ' OR 1=1--";
const envelope = JSON.stringify({ version: 1, sceneId: target.scene.sceneId,
  sceneGeneration: 1, targetId: target.targetId, requestId: R, message });
const captured = capture({ sessionId: S, requestId: R, scope, persona,
  personaSession, target, message: envelope });
const columnPairs = [['session_id', 'sessionId'], ['request_id', 'requestId'],
  ['launch_id', 'launchId'], ['scenario_id', 'scenarioId'], ['generation', 'generation'],
  ['owner_id', 'ownerId'], ['execution_session_id', 'executionSessionId'],
  ['persona_id', 'personaId'], ['persona_session_id', 'personaSessionId'],
  ['authority_version', 'authorityVersion'], ['scene_id', 'sceneId'],
  ['scene_generation', 'sceneGeneration'], ['grant_id', 'grantId'],
  ['target_id', 'targetId'], ['envelope_sha256', 'envelopeSha256'],
  ['request_hash', 'requestHash']];
function fixture() {
  const bound = Object.fromEntries(columnPairs.map(([db, js]) => [db, captured[js]]));
  const customerChat = { version: 1, sceneId: captured.sceneId,
    sceneGeneration: captured.sceneGeneration, targetId: captured.targetId,
    envelopeSha256: captured.envelopeSha256, cards: [], orderPage: null,
    paymentSetup: null, addressSetup: null, refundSetup: null,
    profileProposal: null, profileOrigin: null,
    couponOrigin: {}, couponProposal: {}, traceEventIds: [E] };
  const turn = { session_id: S, status: 'completed', request_version: 1,
    request_hash: captured.requestHash,
    result_json: { taskMetadata: { customerChat }, modeCapability: projectFeatureMode(mode) } };
  const messages = [{ role: 'user', content: envelope, modeCapability: projectFeatureMode(mode) }];
  const traces = [{ id: 1, event_id: E, session_id: S }];
  const calls = [];
  const reader = createCouponAgentOriginalReader({
    current: async () => ({ scope, persona, personaSession, target, mode,
      check: async () => { calls.push('check'); } }),
    bindingRepository: { read: async input => { calls.push(['binding', input]); return bound; } },
    journal: { readBoundRequest: async input => { calls.push(['turn', input]); return turn; } },
    conversations: {
      getMessages: async (...args) => { calls.push(['messages', args]); return messages; },
      getTraceEvents: async (...args) => { calls.push(['traces', args]); return traces; },
    },
  });
  return { reader, bound, turn, messages, traces, calls };
}

test('protected reader binds original customer envelope and exact saved trace IDs', async () => {
  const value = fixture(), source = await value.reader({}, { sessionId: S, requestId: R });
  assert.equal(source.message, message);
  assert.equal(source.turn.request_id, R);
  assert.deepEqual(source.traces, value.traces);
  assert.deepEqual(value.calls.find(row => row[0] === 'traces')[1],
    [S, { ...scope, shopUserId: persona.id, role: 'customer' }, [E], 'secureshop_customer_chat']);
  assert.equal(value.calls.filter(row => row === 'check').length, 5);
});

test('reader rejects changed original bytes and binding before trace disclosure', async () => {
  const wrongMessage = fixture();
  wrongMessage.messages[0].content = wrongMessage.messages[0].content.replace('1=1', '1=2');
  await assert.rejects(wrongMessage.reader({}, { sessionId: S, requestId: R }),
    error => error.code === 'COUPON_AGENT_SOURCE_INVALID');
  assert.equal(wrongMessage.calls.some(row => row[0] === 'traces'), false);
  const wrongBinding = fixture();
  wrongBinding.bound.envelope_sha256 = '0'.repeat(64);
  await assert.rejects(wrongBinding.reader({}, { sessionId: S, requestId: R }),
    error => error.code === 'COUPON_AGENT_SOURCE_INVALID');
  assert.equal(wrongBinding.calls.some(row => row[0] === 'traces'), false);
  const browserMessage = fixture();
  await assert.rejects(browserMessage.reader({}, { sessionId: S, requestId: R, message }),
    error => error.code === 'COUPON_AGENT_SOURCE_INVALID');
  const duplicate = fixture();
  duplicate.messages.push({ ...duplicate.messages[0] });
  await assert.rejects(duplicate.reader({}, { sessionId: S, requestId: R }),
    error => error.code === 'COUPON_AGENT_SOURCE_INVALID');
  const wrongTrace = fixture();
  wrongTrace.traces[0].event_id = '00000000-0000-4000-8000-00000000000a';
  await assert.rejects(wrongTrace.reader({}, { sessionId: S, requestId: R }),
    error => error.code === 'COUPON_AGENT_SOURCE_INVALID');
});

test('reader accepts current producer catalog metadata without altering original saved bytes', async () => {
  for (const page of [null, { version: 1, search: 'products', status: 'active',
    afterCursor: null, nextCursor: null, sourceRequestId: null, total: 1, returnedCount: 1 },
  { version: 1, search: 'products', status: 'active', afterCursor: S,
    nextCursor: E, sourceRequestId: R, total: 25, returnedCount: 12 }]) {
    const value = fixture();
    value.turn.result_json.taskMetadata.customerChat.catalogPageSource = page;
    const before = structuredClone(value.turn);
    const source = await value.reader({}, { sessionId: S, requestId: R });
    assert.deepEqual(source.turn, { ...before, request_id: R });
    assert.deepEqual(value.turn, before);
    assert.deepEqual(source.traces, value.traces);
  }
});

test('reader rejects malformed current catalog metadata and unknown keys before traces', async () => {
  const valid = { version: 1, search: 'products', status: 'active', afterCursor: null,
    nextCursor: null, sourceRequestId: null, total: 1, returnedCount: 1 };
  const invalid = [undefined, [], {}, { ...valid, version: 2 }, { ...valid, status: 'all' },
    { ...valid, extra: true }, { ...valid, search: '' }, { ...valid, search: '\ud800' },
    { ...valid, search: 'x\0' }, { ...valid, search: 'x'.repeat(129) },
    { ...valid, total: -1 }, { ...valid, total: Number.MAX_SAFE_INTEGER + 1 },
    { ...valid, returnedCount: 13 }, { ...valid, returnedCount: 1.5 },
    { ...valid, afterCursor: S }, { ...valid, sourceRequestId: R },
    { ...valid, nextCursor: 'not-a-uuid' }, { ...valid, nextCursor: S },
    { ...valid, total: 12, returnedCount: 12, nextCursor: S }];
  for (const page of invalid) {
    const value = fixture();
    value.turn.result_json.taskMetadata.customerChat.catalogPageSource = page;
    await assert.rejects(value.reader({}, { sessionId: S, requestId: R }),
      error => error.code === 'COUPON_AGENT_SOURCE_INVALID');
    assert.equal(value.calls.some(row => row[0] === 'traces'), false);
  }
  for (const current of [false, true]) {
    const value = fixture();
    const meta = value.turn.result_json.taskMetadata.customerChat;
    if (current) meta.catalogPageSource = null;
    meta.unrecognized = null;
    await assert.rejects(value.reader({}, { sessionId: S, requestId: R }),
      error => error.code === 'COUPON_AGENT_SOURCE_INVALID');
    assert.equal(value.calls.some(row => row[0] === 'traces'), false);
  }
});

test('current metadata compatibility preserves owner, mode, request and trace fences', async () => {
  for (const mutate of [value => { value.bound.owner_id += 1; },
    value => { value.bound.grant_id = E; },
    value => { value.turn.request_hash = '0'.repeat(64); },
    value => { value.turn.result_json.modeCapability = { mode: 'fixed' }; },
    value => { value.traces[0].event_id = S; }]) {
    const value = fixture();
    value.turn.result_json.taskMetadata.customerChat.catalogPageSource = null;
    mutate(value);
    await assert.rejects(value.reader({}, { sessionId: S, requestId: R }),
      error => error.code === 'COUPON_AGENT_SOURCE_INVALID');
  }
});
