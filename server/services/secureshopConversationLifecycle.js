'use strict';

const { createLaunchScope } = require('./secureshopConversationBinding');
const { buildReceipt } = require('../database/postgres/secureshopConversationLifecycleRepository');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const STATUSES = new Set(['fenced', 'committed', 'aborted']);
function fail(code) { return Object.assign(new Error('Conversation cleanup unavailable'), { code }); }
function id(value) {
  if (typeof value !== 'string' || !UUID.test(value)) throw fail('INVALID_ARGUMENT');
  return value.toLowerCase();
}

// Private orchestration: only an existing durable reset ID selects authority.
// The retained turns adapter must be shared with the bound agent runner.
function createSecureShopConversationLifecycle({ repository, turns, cleanupAuthority } = {}) {
  if ([repository?.beginRetirement, repository?.listRetirableSessions, repository?.retireSession,
    repository?.completeRetirement, repository?.readRetirementReceipt, turns?.retire,
    cleanupAuthority?.getOperation].some(fn => typeof fn !== 'function')) {
    throw fail('INVALID_CONFIGURATION');
  }
  async function authorized(resetId, signal) {
    signal?.throwIfAborted();
    const value = await cleanupAuthority.getOperation(resetId);
    signal?.throwIfAborted();
    if (value?.resetId !== resetId || !STATUSES.has(value.status)) throw fail('RESET_CLEANUP_AUTHORITY_REQUIRED');
    return Object.freeze({ resetId, binding: createLaunchScope(value.binding) });
  }
  async function context(value, signal) {
    const resetId = id(value);
    const scope = await authorized(resetId, signal);
    const check = async () => {
      const current = await authorized(resetId, signal);
      if (JSON.stringify(current) !== JSON.stringify(scope)) throw fail('RETIREMENT_SCOPE_MISMATCH');
    };
    const read = async () => {
      await check();
      const receipt = await repository.readRetirementReceipt(scope);
      const expected = buildReceipt({ resetId, ...scope.binding }, receipt);
      if (Object.keys(expected).some(key => receipt?.[key] !== expected[key])) {
        throw fail('INVALID_RETIREMENT_RECEIPT');
      }
      await check();
      return expected;
    };
    return { scope, check, read };
  }
  return Object.freeze({
    async retireGeneration(resetId, { signal } = {}) {
      const { scope, check, read } = await context(resetId, signal);
      const started = await repository.beginRetirement(scope);
      await check();
      if (started?.resetId !== scope.resetId || !['pending', 'completed'].includes(started.status)) {
        throw fail('RETIREMENT_SCOPE_MISMATCH');
      }
      if (started.status === 'completed') return read();
      const sessions = await repository.listRetirableSessions(scope);
      await check();
      if (!Array.isArray(sessions) || sessions.length > 256) throw fail('RETIREMENT_SCOPE_MISMATCH');
      const sessionIds = sessions.map(session => {
        if (!['pending', 'active', 'abandoned'].includes(session?.state)) throw fail('RETIREMENT_SCOPE_MISMATCH');
        return id(session.sessionId);
      }).sort();
      if (new Set(sessionIds).size !== sessionIds.length) throw fail('RETIREMENT_SCOPE_MISMATCH');
      for (const sessionId of sessionIds) {
        await check();
        // Never race an abort promise against this drain. Admitted effects must
        // settle under the durable run lease before repository retirement.
        await turns.retire(sessionId, async () => {
          await check();
          await repository.retireSession({ ...scope, sessionId });
          await check();
        });
        await check();
      }
      await repository.completeRetirement(scope);
      return read();
    },
    async readReceipt(resetId, { signal } = {}) {
      return (await context(resetId, signal)).read();
    },
  });
}

module.exports = { createSecureShopConversationLifecycle };
