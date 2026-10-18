'use strict';

// Internal worker. Only reviewed, idempotent cleanup adapters may be registered;
// the admin application admits durable jobs only after the full production
// composition passes readiness.
function createStudentDeletionWorker({ repository, adapters }) {
  if (!repository || !adapters || typeof adapters !== 'object') throw new TypeError('Deletion dependencies required');
  const registry = new Map(Object.entries(adapters));
  if ([...registry.values()].some(adapter => typeof adapter !== 'function')) throw new TypeError('Cleanup adapters must be functions');
  return {
    async run(jobId, { signal, leaseMs = 30000 } = {}) {
      if (!Number.isInteger(leaseMs) || leaseMs < 1000 || leaseMs > 300000) throw new TypeError('Invalid lease duration');
      if (signal !== undefined && !(signal instanceof AbortSignal)) throw new TypeError('Valid abort signal required');
      if (signal?.aborted) return { state: 'cancelled', code: 'DELETION_CANCELLED' };
      const lease = await repository.claim(jobId, leaseMs);
      if (!lease) return { state: 'not_claimed' };
      const scope = { jobId, leaseToken: lease.leaseToken };
      const controller = new AbortController();
      const abort = () => controller.abort(signal.reason);
      signal?.addEventListener('abort', abort, { once: true });
      if (signal?.aborted) abort();
      let timer;
      let stopped = false;
      let renewal = Promise.resolve();
      const schedule = () => {
        if (stopped || controller.signal.aborted) return;
        timer = setTimeout(() => {
          if (stopped || controller.signal.aborted) return;
          renewal = Promise.resolve().then(() => {
            controller.signal.throwIfAborted();
            return repository.renew({ ...scope, leaseMs });
          })
            .then(schedule, error => controller.abort(error));
        }, Math.floor(leaseMs / 3));
      };
      const check = async () => {
        controller.signal.throwIfAborted();
        await renewal;
        controller.signal.throwIfAborted();
        await repository.renew({ ...scope, leaseMs });
        controller.signal.throwIfAborted();
      };
      const stopRenewal = async () => {
        stopped = true;
        clearTimeout(timer);
        await renewal;
      };
      let current;
      try {
        controller.signal.throwIfAborted();
        schedule();
        while ((current = await repository.nextStep(scope))) {
          const adapter = registry.get(current.stepKey);
          if (!adapter) throw new Error('Cleanup adapter unavailable');
          await check();
          const result = await adapter({ subjectId: current.subjectId, jobId,
            leaseToken: lease.leaseToken, idempotencyKey: `${jobId}:${current.stepKey}`,
            check, signal: controller.signal });
          controller.signal.throwIfAborted();
          if (result?.completed !== true) throw new Error('Cleanup did not confirm completion');
          await repository.acknowledge({ ...scope, stepKey: current.stepKey });
        }
        await stopRenewal();
        controller.signal.throwIfAborted();
        return await repository.complete(scope);
      } catch (error) {
        if (error?.code === 'DELETION_MANIFEST_MISMATCH' && !controller.signal.aborted) {
          try {
            await stopRenewal();
            controller.signal.throwIfAborted();
            return await repository.quarantine(scope);
          } catch (quarantineError) {
            error = quarantineError;
          }
        }
        // Losing a lease prohibits updating the successor worker's state.
        if (current && !controller.signal.aborted && error?.code !== 'STALE_DELETION_LEASE') {
          try { await repository.fail({ ...scope, stepKey: current.stepKey }); } catch { /* Recovery uses the stored lease/job state. */ }
        }
        if (signal?.aborted) return { state: 'cancelled', code: 'DELETION_CANCELLED' };
        return { state: 'incomplete', code: error?.code === 'STALE_DELETION_LEASE' ? 'STALE_DELETION_LEASE' : 'DELETION_INCOMPLETE' };
      } finally {
        await stopRenewal();
        signal?.removeEventListener('abort', abort);
      }
    },
  };
}
module.exports = { createStudentDeletionWorker };
