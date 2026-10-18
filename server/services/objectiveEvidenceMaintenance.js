'use strict';

function startObjectiveEvidenceMaintenance({
  repository, intervalMs = 300000, batchSize = 1000,
  logger = console, scheduler = globalThis
} = {}) {
  if (!repository?.purgeExpired || !Number.isInteger(intervalMs) || intervalMs < 1000
    || !Number.isInteger(batchSize) || batchSize < 1 || batchSize > 10000) {
    throw new TypeError('Invalid evidence maintenance configuration');
  }
  let stopped = false;
  let inFlight = null;

  function tick() {
    if (stopped || inFlight) return inFlight;
    inFlight = Promise.resolve()
      .then(() => repository.purgeExpired({ limit: batchSize }))
      .catch(error => logger.error?.('objective_evidence_purge_failed', {
        code: error.code || 'database_error'
      }))
      .finally(() => { inFlight = null; });
    return inFlight;
  }

  const timer = scheduler.setInterval(tick, intervalMs);
  timer?.unref?.();
  tick();
  return {
    tick,
    async stop() {
      stopped = true;
      scheduler.clearInterval(timer);
      await inFlight;
    }
  };
}

module.exports = { startObjectiveEvidenceMaintenance };
