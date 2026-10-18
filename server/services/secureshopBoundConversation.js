'use strict';
const { randomUUID } = require('node:crypto');
const { createConversationBinding, conversationBindingMatches } = require('./secureshopConversationBinding');
const { normalizeConversationPurpose } = require('./secureshopConversationPurpose');

// Creation spans two databases. Pending rows are unusable until the exact
// binding is activated; failures retain identity rather than reassigning rows.
function createBoundConversationService({ conversations, launches, makeId = randomUUID }) {
  async function assertOwned(id, binding, purpose) {
    purpose = normalizeConversationPurpose(purpose);
    const stored = await conversations.getBoundSession(id);
    if (!stored || stored.id !== id || stored.state !== 'active'
      || normalizeConversationPurpose(stored.purpose) !== purpose
      || !conversationBindingMatches(stored.binding, binding)) {
      throw Object.assign(new Error('Conversation unavailable'), { code: 'CONVERSATION_UNAVAILABLE' });
    }
    const { shopUserId, role, ...launchScope } = binding;
    await launches.assertCurrent(launchScope);
    return binding;
  }
  return Object.freeze({
    async assertOwned(id, scope, persona, purpose) {
      return assertOwned(id, createConversationBinding(scope, persona), purpose);
    },
    async getMessages(id, scope, persona, purpose) {
      purpose = normalizeConversationPurpose(purpose);
      const binding = createConversationBinding(scope, persona);
      await assertOwned(id, binding, purpose);
      const messages = await conversations.getMessages(id, binding, purpose);
      await assertOwned(id, binding, purpose);
      return messages;
    },
    async getTrace(id, scope, persona, limit, purpose) {
      purpose = normalizeConversationPurpose(purpose);
      const binding = createConversationBinding(scope, persona);
      await assertOwned(id, binding, purpose);
      const rows = await conversations.getTrace(id, binding, limit, purpose);
      await assertOwned(id, binding, purpose);
      return rows;
    },
    async latestTrace(scope, persona, limit, purpose) {
      purpose = normalizeConversationPurpose(purpose);
      const binding = createConversationBinding(scope, persona);
      const { shopUserId, role, ...launchScope } = binding;
      await launches.assertCurrent(launchScope);
      const rows = await conversations.latestTrace(binding, limit, purpose);
      await launches.assertCurrent(launchScope);
      return rows;
    },
    async runExclusive(id, scope, persona, operation, purpose) {
      purpose = normalizeConversationPurpose(purpose);
      const binding = createConversationBinding(scope, persona);
      return conversations.runExclusive(id, async () => {
        // Recheck inside the queue before any append, model call or tool work.
        await assertOwned(id, binding, purpose);
        return operation(binding);
      });
    },
    async create(scope, persona, purpose) {
      purpose = normalizeConversationPurpose(purpose);
      const binding = createConversationBinding(scope, persona);
      const { shopUserId, role, ...launchScope } = binding;
      const current = () => launches.assertCurrent(launchScope);
      await current();
      // Authority rejection can be a temporary lock. Retain records for retry;
      // explicit lifecycle cleanup, not a failed request, owns abandonment.
      const acquired = await conversations.acquireBoundSession({ id: makeId(), binding, purpose });
      const id = acquired.id;
      await current();
      if (acquired.state === 'pending') {
        const activated = await conversations.activateBoundSession(id, binding, purpose);
        if (!activated) {
          // Another retry may already have activated this exact record.
          const stored = await conversations.getBoundSession(id);
          if (!stored || stored.id !== id || stored.state !== 'active'
            || normalizeConversationPurpose(stored.purpose) !== purpose
            || !conversationBindingMatches(stored.binding, binding)) {
            throw Object.assign(new Error('Conversation activation failed'), { code: 'CONVERSATION_UNAVAILABLE' });
          }
        }
      } else if (acquired.state !== 'active') {
        throw Object.assign(new Error('Conversation unavailable'), { code: 'CONVERSATION_UNAVAILABLE' });
      }
      await current();
      return Object.freeze({ id });
    },
  });
}
module.exports = { createBoundConversationService };
