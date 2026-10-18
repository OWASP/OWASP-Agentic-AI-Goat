'use strict';

// Historical customer provenance is read only after the ticket repository has
// authorized a current administrator and validated the immutable source row.
// It never reactivates the customer's persona session or accepts source fields
// from the browser.
const { isDeepStrictEqual: equal } = require('node:util');
const { createHash } = require('node:crypto');
const Ticket = require('./secureshopTicketContract');
const { createConversationBinding } = require('./secureshopConversationBinding');
const { createTurnRequest } = require('./secureshopTurnRequest');
const { SECURESHOP_CONVERSATION_PURPOSES } = require('./secureshopConversationPurpose');

const fail = () => Object.assign(new Error('Historical ticket turn unavailable'),
  { code: 'TICKET_BROWSER_ORIGINAL_UNAVAILABLE' });
const FIELDS = Object.freeze([
  ['session_id', 'sessionId'], ['request_id', 'requestId'],
  ['launch_id', 'launchId'], ['scenario_id', 'scenarioId'],
  ['generation', 'generation'], ['owner_id', 'ownerId'],
  ['execution_session_id', 'executionSessionId'],
  ['persona_id', 'personaId'], ['persona_session_id', 'personaSessionId'],
  ['authority_version', 'authorityVersion'], ['scene_id', 'sceneId'],
  ['scene_generation', 'sceneGeneration'], ['grant_id', 'grantId'],
  ['target_id', 'targetId'], ['envelope_sha256', 'envelopeSha256'],
  ['request_hash', 'requestHash'],
]);
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Reflect.ownKeys(value).length === keys.length
  && keys.every(key => Object.hasOwn(value, key));

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const CUSTOMER_KEYS = Object.freeze(['version', 'sceneId', 'sceneGeneration', 'targetId',
  'envelopeSha256', 'cards', 'orderPage', 'paymentSetup', 'addressSetup', 'refundSetup',
  'profileProposal', 'profileOrigin', 'couponOrigin', 'couponProposal', 'traceEventIds']);
function customerMetadata(value) {
  if (exact(value, CUSTOMER_KEYS)) return true; // Saved pre-pagination turns.
  if (!exact(value, [...CUSTOMER_KEYS, 'catalogPageSource'])) return false;
  const page = value.catalogPageSource;
  if (page === null) return true;
  // Catalog provenance is not ticket authority, but its known version remains
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

function createTicketBrowserOriginalReader({ bindingRepository, journal, conversations } = {}) {
  if (typeof bindingRepository?.read !== 'function'
      || typeof journal?.readBoundRequest !== 'function'
      || typeof conversations?.getBoundSession !== 'function'
      || typeof conversations?.getMessages !== 'function'
      || typeof conversations?.getTraceEvents !== 'function')
    throw new TypeError('Historical ticket reader dependencies required');

  return async function readOriginal(ticket) {
    try {
      const source = Ticket.source(ticket?.source);
      const proposal = ticket?.proposal;
      const persona = Object.freeze({ id: source.customer.shopUserId, role: 'customer' });
      const binding = createConversationBinding(source.execution, persona);
      const sessionId = source.turn.sessionId, requestId = source.turn.requestId;
      const purpose = SECURESHOP_CONVERSATION_PURPOSES.customerChat;
      const boundSession = await conversations.getBoundSession(sessionId);
      if (!boundSession || boundSession.state !== 'active'
          || boundSession.purpose !== purpose || !equal(boundSession.binding, binding)) throw fail();
      const bound = await bindingRepository.read({ sessionId, requestId,
        scope: binding, persona });
      if (!bound) throw fail();
      const turn = await journal.readBoundRequest({ sessionId, requestId,
        binding, purpose });
      if (!turn || turn.session_id !== sessionId || turn.status !== 'completed'
          || turn.request_version !== 1 || turn.request_hash !== ticket.requestSha256)
        throw fail();
      const messages = await conversations.getMessages(sessionId, binding, purpose);
      if (!Array.isArray(messages)) throw fail();
      const matching = messages.filter(row => {
        if (row?.role !== 'user' || typeof row.content !== 'string') return false;
        try { return JSON.parse(row.content)?.requestId === requestId; }
        catch { return false; }
      });
      if (matching.length !== 1 || typeof matching[0].content !== 'string') throw fail();
      const envelopeText = matching[0].content, envelope = JSON.parse(envelopeText);
      if (!exact(envelope, ['version', 'sceneId', 'sceneGeneration',
        'targetId', 'requestId', 'message']) || envelope.version !== 1
          || envelope.sceneId !== source.scene.sceneId
          || envelope.sceneGeneration !== source.scene.sceneGeneration
          || envelope.targetId !== source.scene.targetId
          || typeof envelope.message !== 'string') throw fail();
      // Reconstruct the original binding document from the repository-verified
      // immutable source; a historical read must not mint a new scene binding.
      const expected = {
        sessionId, requestId, launchId: source.execution.launchId,
        scenarioId: source.execution.scenarioId,
        generation: source.execution.generation,
        ownerId: source.execution.platformOwnerId,
        executionSessionId: source.execution.platformSessionId,
        personaId: persona.id,
        personaSessionId: source.customer.personaSessionId,
        authorityVersion: source.customer.authorityVersion,
        sceneId: source.scene.sceneId,
        sceneGeneration: source.scene.sceneGeneration,
        grantId: source.scene.grantId, targetId: source.scene.targetId,
      };
      expected.envelopeSha256 = createHash('sha256').update(JSON.stringify([
        'customer-chat-v1', expected, envelopeText])).digest('hex');
      expected.requestHash = createTurnRequest({ sessionId, requestId,
        binding, message: envelopeText, version: turn.request_version }).hash;
      if (FIELDS.some(([db, js]) => String(bound[db]) !== String(expected[js]))
          || turn.request_hash !== expected.requestHash
          || turn.request_hash !== createTurnRequest({ sessionId, requestId,
            binding, message: envelopeText, version: turn.request_version }).hash)
        throw fail();
      const meta = turn.result_json?.taskMetadata;
      if (!meta || !(meta.ticketAgent?.version === 1 && exact(meta.ticketAgent,
        ['version', 'runId', 'origin', 'proposal', 'traceEventIds'])
          || meta.ticketAgent?.version === 2 && exact(meta.ticketAgent,
            ['version', 'runId', 'origin', 'proposal', 'requestRef', 'traceEventIds']))
          || meta.ticketAgent.version === 2
            && meta.ticketAgent.requestRef !== Ticket.requestRef({
              requestHash: turn.request_hash, envelopeSha256: expected.envelopeSha256 })
          || meta.ticketAgent.runId !== source.turn.runId
          || !equal(meta.ticketAgent.proposal, proposal)
          || meta.ticketAgent.proposal?.proposalId !== source.proposalId
          || !customerMetadata(meta.customerChat)
          || meta.customerChat.sceneId !== expected.sceneId
          || meta.customerChat.sceneGeneration !== expected.sceneGeneration
          || meta.customerChat.targetId !== expected.targetId
          || meta.customerChat.envelopeSha256 !== expected.envelopeSha256
          || !equal(turn.result_json.modeCapability, matching[0].modeCapability))
        throw fail();
      const ids = meta.ticketAgent.traceEventIds;
      if (!Array.isArray(ids) || ids.length < 4 || ids.length > 4096
          || new Set(ids).size !== ids.length) throw fail();
      const traces = await conversations.getTraceEvents(sessionId, binding, ids, purpose);
      if (!Array.isArray(traces) || traces.length !== ids.length
          || traces.some((row, index) => row.event_id !== ids[index]
            || row.session_id !== sessionId)) throw fail();
      return Object.freeze({ message: envelope.message,
        turn: Object.freeze({ ...turn, request_id: requestId }),
        traces: Object.freeze([...traces]) });
    } catch { throw fail(); }
  };
}

module.exports = { createTicketBrowserOriginalReader };
