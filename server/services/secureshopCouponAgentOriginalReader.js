'use strict';

// Unmounted protected reader for a coupon proposal's original customer turn.
// The caller supplies current server authority, never a browser message/code.
const { isDeepStrictEqual } = require('node:util');
const { createConversationBinding } = require('./secureshopConversationBinding');
const { projectFeatureMode } = require('./secureshopFeatureModeAuthority');
const { capture } = require('../database/postgres/secureshopCustomerChatBindingRepository');
const { createTurnRequest } = require('./secureshopTurnRequest');
const { SECURESHOP_CONVERSATION_PURPOSES } = require('./secureshopConversationPurpose');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const fail = () => Object.assign(new Error('Saved coupon proposal unavailable'),
  { code: 'COUPON_AGENT_SOURCE_INVALID' });
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Reflect.ownKeys(value).length === keys.length
  && keys.every(key => Object.hasOwn(value, key));
const CUSTOMER_KEYS = Object.freeze(['version', 'sceneId', 'sceneGeneration', 'targetId',
  'envelopeSha256', 'cards', 'orderPage', 'paymentSetup', 'addressSetup', 'refundSetup',
  'profileProposal', 'profileOrigin', 'couponOrigin', 'couponProposal', 'traceEventIds']);
function customerMetadata(value) {
  if (exact(value, CUSTOMER_KEYS)) return true; // Saved pre-pagination turns.
  if (!exact(value, [...CUSTOMER_KEYS, 'catalogPageSource'])) return false;
  const page = value.catalogPageSource;
  if (page === null) return true;
  // Catalog provenance is not coupon authority, but its known version remains
  // closed and bounded. Never accept arbitrary additional saved metadata.
  const cursor = value => value === null || typeof value === 'string' && UUID.test(value);
  return exact(page, ['version', 'search', 'status', 'afterCursor', 'nextCursor',
    'sourceRequestId', 'total', 'returnedCount'])
    && page.version === 1 && page.status === 'active'
    && typeof page.search === 'string' && !!page.search.trim()
    && page.search.isWellFormed() && !page.search.includes('\0')
    && Buffer.byteLength(page.search, 'utf8') <= 128
    && cursor(page.afterCursor) && cursor(page.nextCursor) && cursor(page.sourceRequestId)
    && (page.afterCursor === null) === (page.sourceRequestId === null)
    && Number.isSafeInteger(page.total) && Number.isSafeInteger(page.returnedCount)
    && page.returnedCount >= 0 && page.returnedCount <= 12 && page.total >= page.returnedCount
    && (page.nextCursor === null || page.returnedCount === 12 && page.total > page.returnedCount);
}
const FIELDS = Object.freeze([
  ['session_id', 'sessionId'], ['request_id', 'requestId'], ['launch_id', 'launchId'],
  ['scenario_id', 'scenarioId'], ['generation', 'generation'], ['owner_id', 'ownerId'],
  ['execution_session_id', 'executionSessionId'], ['persona_id', 'personaId'],
  ['persona_session_id', 'personaSessionId'], ['authority_version', 'authorityVersion'],
  ['scene_id', 'sceneId'], ['scene_generation', 'sceneGeneration'], ['grant_id', 'grantId'],
  ['target_id', 'targetId'], ['envelope_sha256', 'envelopeSha256'],
  ['request_hash', 'requestHash'],
]);

function createCouponAgentOriginalReader({ current, bindingRepository, journal, conversations } = {}) {
  if (typeof current !== 'function' || typeof bindingRepository?.read !== 'function'
    || typeof journal?.readBoundRequest !== 'function'
    || typeof conversations?.getMessages !== 'function'
    || typeof conversations?.getTraceEvents !== 'function') throw new TypeError('Coupon original reader dependencies required');
  return async function readOriginal(context, request = {}) {
    if (!exact(request, ['sessionId', 'requestId'])) throw fail();
    const { sessionId, requestId } = request;
    if (typeof sessionId !== 'string' || !UUID.test(sessionId)
      || typeof requestId !== 'string' || !UUID.test(requestId)) throw fail();
    let state;
    try {
      state = await current(context);
      const { scope, persona, personaSession, target, mode, check } = state;
      if (typeof check !== 'function') throw fail();
      const binding = createConversationBinding(scope, persona);
      if (binding.role !== 'customer') throw fail();
      await check();
      const bound = await bindingRepository.read({ sessionId, requestId, scope: binding, persona });
      await check();
      if (!bound) throw fail();
      const purpose = SECURESHOP_CONVERSATION_PURPOSES.customerChat;
      const turn = await journal.readBoundRequest({ sessionId, requestId, binding, purpose });
      await check();
      if (!turn || turn.session_id !== sessionId || turn.status !== 'completed'
        || turn.request_version !== 1) throw fail();
      const rows = await conversations.getMessages(sessionId, binding, purpose);
      await check();
      if (!Array.isArray(rows)) throw fail();
      const original = rows.filter(row => {
        if (row?.role !== 'user' || typeof row.content !== 'string') return false;
        let envelope;
        try { envelope = JSON.parse(row.content); } catch { return false; }
        return envelope?.requestId === requestId;
      });
      if (original.length !== 1 || !isDeepStrictEqual(original[0].modeCapability,
        projectFeatureMode(mode))) throw fail();
      const envelopeText = original[0].content, envelope = JSON.parse(envelopeText);
      if (!exact(envelope, ['version', 'sceneId', 'sceneGeneration', 'targetId', 'requestId', 'message'])
        || envelope.version !== 1 || typeof envelope.message !== 'string'
        || !envelope.message.trim()) throw fail();
      const expected = capture({ sessionId, requestId, scope: binding, persona,
        personaSession, target, message: envelopeText });
      const requestHash = createTurnRequest({ sessionId, requestId, binding,
        message: envelopeText, version: turn.request_version }).hash;
      if (FIELDS.some(([db, js]) => String(bound[db]) !== String(expected[js]))
        || requestHash !== expected.requestHash
        || turn.request_hash !== bound.request_hash || turn.request_hash !== requestHash
        || !customerMetadata(turn.result_json?.taskMetadata?.customerChat)
        || turn.result_json.taskMetadata.customerChat.version !== 1
        || turn.result_json.taskMetadata.customerChat.sceneId !== expected.sceneId
        || turn.result_json.taskMetadata.customerChat.sceneGeneration !== expected.sceneGeneration
        || turn.result_json.taskMetadata.customerChat.targetId !== expected.targetId
        || turn.result_json.taskMetadata.customerChat.envelopeSha256 !== expected.envelopeSha256
        || !isDeepStrictEqual(turn.result_json.modeCapability, projectFeatureMode(mode))) throw fail();
      const ids = turn.result_json.taskMetadata.customerChat.traceEventIds;
      const traces = await conversations.getTraceEvents(sessionId, binding, ids, purpose);
      await check();
      if (!Array.isArray(ids) || !Array.isArray(traces)
        || traces.length !== ids.length
        || traces.some((row, index) => row?.event_id !== ids[index]
          || row.session_id !== sessionId)) throw fail();
      return Object.freeze({ message: envelope.message,
        turn: Object.freeze({ ...turn, request_id: requestId }),
        traces: Object.freeze([...traces]) });
    } catch { throw fail(); }
  };
}

module.exports = { createCouponAgentOriginalReader };
