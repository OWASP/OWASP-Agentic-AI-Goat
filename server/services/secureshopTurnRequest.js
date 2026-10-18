'use strict';
const { createHash } = require('node:crypto');
const { createConversationBinding } = require('./secureshopConversationBinding');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

// Retain the version-one encoding when future encodings are introduced:
// retries must be hashed using the persisted journal row's version.
function createTurnRequest({ sessionId, requestId, binding, message, version = 1 }) {
  if (version !== 1) throw Object.assign(new Error('Unsupported turn request version'), { code: 'TURN_VERSION_UNAVAILABLE' });
  if (typeof sessionId !== 'string' || !UUID.test(sessionId) || typeof requestId !== 'string' || !UUID.test(requestId)
    || typeof message !== 'string' || !message.trim() || Buffer.byteLength(message, 'utf8') > 65536) {
    throw Object.assign(new Error('Invalid turn request'), { code: 'INVALID_TURN_REQUEST' });
  }
  const trusted = createConversationBinding(binding, { id: binding.shopUserId, role: binding.role });
  // JSON arrays encode field boundaries unambiguously without normalizing the
  // raw teaching message. Persist only the digest, never this input packet.
  const encoded = JSON.stringify(['dvaia-secureshop-turn', version, sessionId.toLowerCase(),
    trusted.launchId, trusted.scenarioId, trusted.generation, trusted.platformOwnerId,
    trusted.platformSessionId, trusted.shopUserId, trusted.role, message]);
  return Object.freeze({ sessionId: sessionId.toLowerCase(), requestId: requestId.toLowerCase(),
    version, hash: createHash('sha256').update(encoded, 'utf8').digest('hex') });
}
module.exports = { createTurnRequest };
