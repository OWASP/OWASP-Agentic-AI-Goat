const defaultScheduler = {
  setTimeout,
  clearTimeout,
  setInterval,
  clearInterval,
};

function createLeaderboardRefreshCoordinator({
  updateLeaderboard,
  scheduler = defaultScheduler,
  debounceMs = 250,
  retryMs = 5000,
  reconcileMs = 60000,
  logger = console,
} = {}) {
  if (typeof updateLeaderboard !== 'function') {
    throw new TypeError('Leaderboard update function is required');
  }

  let started = false;
  let dirty = false;
  let running = false;
  let runPromise = null;
  let lastRunError = null;
  let requestedGeneration = 0;
  let completedGeneration = 0;
  let refreshTimer = null;
  let reconcileTimer = null;

  function clearRefreshTimer() {
    if (refreshTimer !== null) scheduler.clearTimeout(refreshTimer);
    refreshTimer = null;
  }

  function scheduleRefresh(delay) {
    if (!started || running || refreshTimer !== null) return;
    refreshTimer = scheduler.setTimeout(() => {
      refreshTimer = null;
      return runOnce();
    }, delay);
    refreshTimer?.unref?.();
  }

  function requestRefresh() {
    if (!started) return;
    requestedGeneration += 1;
    dirty = true;
    scheduleRefresh(debounceMs);
  }

  async function runOnce() {
    if (!started) return true;
    if (running) return runPromise;
    if (!dirty) return true;

    clearRefreshTimer();
    const runGeneration = requestedGeneration;
    dirty = false;
    running = true;
    runPromise = (async () => {
      let failed = false;
      try {
        await updateLeaderboard();
        completedGeneration = Math.max(completedGeneration, runGeneration);
        lastRunError = null;
      } catch (error) {
        failed = true;
        lastRunError = error;
        try {
          logger.error('Failed to refresh CTF leaderboard', error);
        } catch {
          // Diagnostics must not break reconciliation recovery.
        }
      } finally {
        running = false;
        runPromise = null;
        dirty = started && completedGeneration < requestedGeneration;
        if (started && dirty) scheduleRefresh(failed ? retryMs : debounceMs);
      }
      return !failed;
    })();
    return runPromise;
  }

  async function flush({ throwOnError = false } = {}) {
    if (!started) return true;

    const requiredGeneration = requestedGeneration;
    while (started && completedGeneration < requiredGeneration) {
      const succeeded = await runOnce();
      if (!succeeded) {
        if (throwOnError) throw lastRunError;
        return false;
      }
    }
    return completedGeneration >= requiredGeneration;
  }

  function start() {
    if (started) return;
    started = true;
    reconcileTimer = scheduler.setInterval(requestRefresh, reconcileMs);
    reconcileTimer?.unref?.();
    requestRefresh();
  }

  function stop() {
    started = false;
    dirty = false;
    clearRefreshTimer();
    if (reconcileTimer !== null) scheduler.clearInterval(reconcileTimer);
    reconcileTimer = null;
  }

  function getState() {
    return { started, dirty, running };
  }

  return { start, stop, requestRefresh, flush, getState };
}

module.exports = { createLeaderboardRefreshCoordinator };
