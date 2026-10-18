'use strict';

const { createConversationBinding, conversationBindingMatches } = require('./secureshopConversationBinding');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function invalid(message = 'Persona inbox request authority unavailable') {
  return Object.assign(new Error(message), { code: 'PERSONA_INBOX_REQUEST_AUTHORITY_UNAVAILABLE' });
}

function normalize(input) {
  let binding;
  try { binding = createConversationBinding(input?.binding, {
    id: input?.binding?.shopUserId,
    role: input?.binding?.role,
  }); } catch { throw invalid(); }
  if (typeof input?.sessionId !== 'string' || !UUID.test(input.sessionId)
      || typeof input?.requestId !== 'string' || !UUID.test(input.requestId)
      || typeof input?.targetId !== 'string' || !UUID.test(input.targetId)
      || !Number.isSafeInteger(input?.messageId) || input.messageId < 1) throw invalid();
  return Object.freeze({ binding, sessionId: input.sessionId.toLowerCase(),
    requestId: input.requestId.toLowerCase(), targetId: input.targetId.toLowerCase(),
    messageId: input.messageId });
}

function createSecureShopPersonaInboxRequestAuthority() {
  const records = new WeakMap();
  return Object.freeze({
    issue(input) {
      const record = normalize(input);
      const token = Object.freeze(Object.create(null));
      records.set(token, record);
      let active = true;
      return Object.freeze({ token, revoke() {
        if (!active) return;
        active = false;
        records.delete(token);
      } });
    },
    resolve(token, input) {
      if (!token || (typeof token !== 'object' && typeof token !== 'function')) throw invalid();
      const record = records.get(token);
      if (!record) throw invalid();
      const expected = normalize({ ...input, targetId: record.targetId, messageId: record.messageId });
      if (!conversationBindingMatches(record.binding, expected.binding)
          || record.sessionId !== expected.sessionId || record.requestId !== expected.requestId) throw invalid();
      return Object.freeze({ targetId: record.targetId, messageId: record.messageId });
    },
  });
}

module.exports = { createSecureShopPersonaInboxRequestAuthority };
