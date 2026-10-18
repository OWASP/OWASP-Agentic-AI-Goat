'use strict';
const { createConversationBinding } = require('./secureshopConversationBinding');
const { normalizeConversationPurpose } = require('./secureshopConversationPurpose');

// Supply one shared run coordinator backed by the dedicated PostgreSQL lease
// pool. Do not construct a coordinator per request or use the storage pool as
// a model-duration lock connection.
function createBoundTurns({ conversations, coordinator }) {
  if (typeof conversations?.assertOwned !== 'function' || typeof coordinator?.run !== 'function') {
    throw new TypeError('Conversation authority and run coordinator required');
  }
  return Object.freeze({
    async retire(sessionId, cleanup) {
      if (typeof cleanup !== 'function') throw new TypeError('Retirement cleanup callback required');
      if (typeof coordinator.reset !== 'function') throw new Error('Conversation retirement coordinator unavailable');
      return coordinator.reset(sessionId, cleanup);
    },
    async run(sessionId, scope, persona, options, operation) {
      const binding = createConversationBinding(scope, persona);
      const purpose = normalizeConversationPurpose(options?.conversationPurpose);
      const trustedPersona = Object.freeze({ id: binding.shopUserId, role: binding.role });
      await conversations.assertOwned(sessionId, binding, trustedPersona, purpose);
      const admit = typeof options?.admit === 'function' ? async () => {
        await conversations.assertOwned(sessionId, binding, trustedPersona, purpose);
        const decision = await options.admit();
        await conversations.assertOwned(sessionId, binding, trustedPersona, purpose);
        return decision;
      } : undefined;
      return coordinator.run(sessionId, { signal: options?.signal, timeoutMs: options?.timeoutMs,
        idempotencyKey: options?.idempotencyKey, ...(admit ? { admit } : {}) }, async run => {
        if (typeof run.runId !== 'string' || !run.runId || typeof run.ownerKey !== 'string' || !run.ownerKey) {
          throw new Error('Coordinator run identity unavailable');
        }
        const identity = Object.freeze({ runId: run.runId, ownerKey: run.ownerKey,
          generation: run.generation, durableGeneration: run.durableGeneration ?? null });
        const check = async () => {
          await run.check();
          await conversations.assertOwned(sessionId, binding, trustedPersona, purpose);
          await run.check();
        };
        const effect = async (key, callback) => {
          await check();
          return run.effect(key, async () => {
            await check();
            return callback();
          });
        };
        const effectWithReceipt = async (key, callback) => {
          await check();
          if (typeof run.effectWithReceipt !== 'function') {
            return Object.freeze({ value: await effect(key, callback), receipt: null });
          }
          return run.effectWithReceipt(key, async () => {
            await check();
            return callback();
          });
        };
        const trace = typeof run.trace === 'function' ? async event => {
          await check();
          await run.trace(event);
          await check();
        } : undefined;
        await check();
        const result = await operation(Object.freeze({ identity, signal: run.signal, check, effect, effectWithReceipt,
          ...(trace ? { trace } : {}) }));
        await check();
        return result;
      });
    },
  });
}
function createConfiguredBoundTurns({ conversations }) {
  if (process.env.PLATFORM_DATABASE_ENGINE !== 'postgres') {
    throw new Error('Launch-bound turns require PostgreSQL');
  }
  const { createRunCoordinator } = require('../agent-runtime/runCoordinator');
  // The coordinator resolves the existing dedicated lease pool lazily on the
  // first run. Retain this adapter in the route/service factory, not per turn.
  return createBoundTurns({ conversations, coordinator: createRunCoordinator({
    family: 'SecureShopBoundConversation',
  }) });
}
module.exports = { createBoundTurns, createConfiguredBoundTurns };
