const RESTART_CHANGE = { scopeType: 'global', scopeKey: '*', category: 'server_restart' };

function createChangeRevisionService(store, logger = console, scheduler = globalThis) {
  if (!store || typeof store.initialize !== 'function' || typeof store.bump !== 'function' || typeof store.getSnapshot !== 'function') {
    throw new TypeError('Change revision store is required');
  }

  let retryDelayMs = 1000;
  let retryPending = false;
  let initialized = false;
  let readyPromise = null;

  async function recordRestart() {
    try {
      await store.bump(RESTART_CHANGE);
      retryDelayMs = 1000;
      retryPending = false;
    } catch (error) {
      logger.error?.('Failed to record server restart revision', error);
      if (retryPending) return;
      retryPending = true;
      const delay = retryDelayMs;
      retryDelayMs = Math.min(retryDelayMs * 2, 30000);
      const timer = scheduler.setTimeout(async () => {
        retryPending = false;
        await recordRestart();
      }, delay);
      timer?.unref?.();
    }
  }

  function ensureReady() {
    if (initialized) return Promise.resolve();
    if (readyPromise) return readyPromise;

    const initializing = (async () => {
      await store.initialize();
      await recordRestart();
      initialized = true;
    })();
    readyPromise = initializing;
    initializing.then(
      () => { if (readyPromise === initializing) readyPromise = null; },
      () => { if (readyPromise === initializing) readyPromise = null; },
    );
    return initializing;
  }

  return {
    async bump(change) { await ensureReady(); return store.bump(change); },
    async getSnapshot(scopes) { await ensureReady(); return store.getSnapshot(scopes); },
  };
}

module.exports = { createChangeRevisionService, RESTART_CHANGE };
