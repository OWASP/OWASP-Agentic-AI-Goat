'use strict';

// Purpose is selected by a production workflow factory. It is never accepted
// from an HTTP request. `general` preserves the existing shared conversation
// used by the legacy SecureShop agent experience and its intentional memory
// teaching surfaces.
const PURPOSES = Object.freeze({
  general: 'general',
  mcpRogueRegistration: 'mcp_rogue_registration',
  mcpRugPull: 'mcp_rug_pull',
  personaInbox: 'persona_inbox',
  controlledSsrf: 'controlled_ssrf',
  reviewModeration: 'review_moderation',
});
const ALLOWED = new Set(Object.values(PURPOSES));

function normalizeConversationPurpose(value = PURPOSES.general) {
  if (typeof value !== 'string' || !ALLOWED.has(value)) {
    throw new TypeError('Invalid conversation purpose');
  }
  return value;
}

module.exports = { SECURESHOP_CONVERSATION_PURPOSES: PURPOSES, normalizeConversationPurpose };
