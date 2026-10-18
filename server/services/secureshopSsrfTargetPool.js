'use strict';

const { isDeepStrictEqual } = require('node:util');
const { createSecureShopSsrfOwnedTarget, cleanupSecureShopSsrfOwnedTarget } = require('./secureshopSsrfOwnedTarget');

const SCOPE_KEYS = Object.freeze(['targetId', 'launchId', 'scenarioId', 'generation', 'platformOwnerId', 'platformSessionId']);
function scopeOf(value) {
  if (!value || SCOPE_KEYS.some(key => value[key] == null)) throw new TypeError('Owned SSRF target scope required');
  return Object.freeze(Object.fromEntries(SCOPE_KEYS.map(key => [key, value[key]])));
}

function createSecureShopSsrfTargetPool({ root, createTarget = createSecureShopSsrfOwnedTarget,
  cleanupTarget = cleanupSecureShopSsrfOwnedTarget } = {}) {
  if (typeof root !== 'string' || !root) throw new TypeError('Owned SSRF target root required');
  if (typeof cleanupTarget !== 'function') throw new TypeError('Owned SSRF cleanup required');
  const targets = new Map(), pending = new Map(), pendingScopes = new Map(), retired = new Map();
  let closed = false, closing;
  function assertOpen() { if (closed) throw new Error('Owned SSRF target pool closed'); }
  function assertEntry(entry, binding) {
    if (!isDeepStrictEqual(entry.scope, scopeOf(binding))) throw new Error('Owned SSRF target scope mismatch');
  }
  async function get(binding) {
    assertOpen();
    const scope = scopeOf(binding);
    const retiredScope = retired.get(scope.targetId);
    if (retiredScope) { assertEntry({ scope: retiredScope }, scope); throw new Error('Owned SSRF target retired'); }
    const existing = targets.get(scope.targetId);
    if (existing) { assertEntry(existing, scope); return existing.target; }
    const creating = pending.get(scope.targetId);
    if (creating) {
      assertEntry({ scope: pendingScopes.get(scope.targetId) }, scope);
      const entry = await creating; assertEntry(entry, scope);
      if (retired.has(scope.targetId)) throw new Error('Owned SSRF target retired');
      return entry.target;
    }
    const promise = Promise.resolve(createTarget({ root, targetId: scope.targetId })).then(target => {
      const entry = Object.freeze({ scope, target }); targets.set(scope.targetId, entry); return entry;
    }).finally(() => { pending.delete(scope.targetId); pendingScopes.delete(scope.targetId); });
    pendingScopes.set(scope.targetId, scope); pending.set(scope.targetId, promise); const entry = await promise;
    if (retired.has(scope.targetId)) throw new Error('Owned SSRF target retired');
    return entry.target;
  }
  return Object.freeze({
    async issue(binding, input) { const target = await get(binding); assertOpen(); return target.issue(input); },
    assertIssuedPublicRequest(binding, input) {
      assertOpen();
      const entry = targets.get(binding?.targetId);
      if (!entry || retired.has(binding.targetId)) throw new Error('Owned SSRF target unavailable');
      assertEntry(entry, binding);
      return entry.target.assertIssuedPublicRequest(input);
    },
    consume(binding, input) {
      const entry = targets.get(binding?.targetId); if (!entry) throw new Error('Owned SSRF target unavailable');
      assertEntry(entry, binding); return entry.target.consume(input);
    },
    readReceipt(binding, input) {
      const entry = targets.get(binding?.targetId); if (!entry) throw new Error('Owned SSRF target unavailable');
      assertEntry(entry, binding); return entry.target.readReceipt(input);
    },
    pendingReceipts(binding) {
      const entry = targets.get(binding?.targetId); if (!entry) return 0;
      assertEntry(entry, binding); return entry.target.pendingReceipts();
    },
    async retire(binding) {
      const scope = scopeOf(binding), targetId = scope.targetId;
      const retiredScope = retired.get(targetId);
      if (retiredScope) assertEntry({ scope: retiredScope }, scope);
      const existing = targets.get(targetId);
      if (existing) assertEntry(existing, scope);
      const creating = pending.get(targetId);
      if (creating) assertEntry({ scope: pendingScopes.get(targetId) }, scope);
      if (!retiredScope && !existing && !creating) throw new Error('Owned SSRF target unavailable');
      retired.set(targetId, scope);
      const entry = existing || (creating ? await creating : null);
      if (!entry) return Object.freeze({ ok: true, replayed: true });
      assertEntry(entry, scope); const result = await entry.target.cleanup(); targets.delete(targetId); return result;
    },
    // Only the reset adapter may call this after durable cleanup authority has
    // fenced the exact target scope. It never creates a listener or payload.
    async retireRecovered(binding) {
      const scope=scopeOf(binding),targetId=scope.targetId,retiredScope=retired.get(targetId);
      if(retiredScope)assertEntry({scope:retiredScope},scope);
      const existing=targets.get(targetId);if(existing)assertEntry(existing,scope);
      const creating=pending.get(targetId);if(creating)assertEntry({scope:pendingScopes.get(targetId)},scope);
      retired.set(targetId,scope);
      const entry=existing||(creating?await creating:null);
      if(entry){assertEntry(entry,scope);const result=await entry.target.cleanup();targets.delete(targetId);return result;}
      return cleanupTarget({root,targetId});
    },
    state(binding) {
      const entry = targets.get(binding?.targetId); if (!entry) return null;
      assertEntry(entry, binding); return Object.freeze({ active: !closed, scope: entry.scope });
    },
    close() {
      closed = true;
      closing ||= (async () => {
        await Promise.allSettled([...pending.values()]);
        const results = await Promise.allSettled([...targets.values()].map(async ({ target }) => {
          if (typeof target.disconnect !== 'function') throw new Error('Owned SSRF target cannot disconnect');
          return target.disconnect();
        }));
        const failures = results.filter(result => result.status === 'rejected').map(result => result.reason);
        if (failures.length) throw new AggregateError(failures, 'Owned SSRF shutdown failed');
      })();
      return closing;
    },
  });
}

module.exports = { createSecureShopSsrfTargetPool, SSRF_SCOPE_KEYS: SCOPE_KEYS };
