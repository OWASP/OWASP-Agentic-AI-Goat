const { toWorkshopKey } = require('../config/workshopCatalog');

function resolveAdminChangeScope(change = {}) {
  if (change.targetUserId !== undefined && change.targetUserId !== null) {
    return { scopeType: 'user', scopeKey: String(change.targetUserId), category: 'admin_visibility' };
  }
  if (change.type !== 'challengeVisibility' && change.workshopKey) {
    const workshopKey = toWorkshopKey(String(change.workshopKey));
    return { scopeType: 'workshop', scopeKey: workshopKey, category: 'admin_visibility' };
  }
  return { scopeType: 'global', scopeKey: '*', category: 'admin_visibility' };
}

function createAdminChangeRecorder(store, logger = console, scheduler = { setTimeout }) {
  if (!store || typeof store.bump !== 'function') throw new TypeError('Change revision store is required');
  const pendingRetries = new Map();
  const retryKey = (scope) => `${scope.scopeType}:${scope.scopeKey}:${scope.category}`;

  function scheduleRetry(scope, attempt = 0) {
    const key = retryKey(scope);
    if (pendingRetries.has(key)) return;
    const delay = Math.min(30000, 1000 * (2 ** attempt));
    const timer = scheduler.setTimeout(async () => {
      pendingRetries.delete(key);
      try { await store.bump(scope); }
      catch (error) {
        logger.error?.('Failed to retry admin change revision', error);
        scheduleRetry(scope, attempt + 1);
      }
    }, delay);
    timer?.unref?.();
    pendingRetries.set(key, timer);
  }

  return {
    async record(change) {
      const scope = resolveAdminChangeScope(change);
      try {
        await store.bump(scope);
        return true;
      } catch (error) {
        logger.error?.('Failed to record admin change revision', error);
        scheduleRetry(scope);
        return false;
      }
    },
  };
}

module.exports = { createAdminChangeRecorder, resolveAdminChangeScope };
