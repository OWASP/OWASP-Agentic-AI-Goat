'use strict';

function createApplicationLifecycle({ timeoutMs = 10000, exit = code => process.exit(code) } = {}) {
  const cleanup = [];
  const finalizers = [];
  let stopping;
  let exitCode = 0;
  return {
    register(fn) { cleanup.push(fn); },
    registerFinalizer(fn) {
      if (stopping || typeof fn !== 'function') throw new TypeError('Finalizer must be registered before shutdown');
      finalizers.push(fn);
    },
    get stopping() { return Boolean(stopping); },
    shutdown(code = 0) {
      exitCode = Math.max(exitCode, code);
      if (stopping) return stopping;
      stopping = new Promise(resolve => {
        let finished = false;
        const deadline = Date.now() + timeoutMs;
        const finish = () => {
          if (finished) return;
          finished = true;
          clearTimeout(timer);
          exit(exitCode);
          resolve();
        };
        const timer = setTimeout(() => { exitCode = Math.max(exitCode, 1); finish(); }, timeoutMs);
        Promise.allSettled(cleanup.map(fn => Promise.resolve().then(fn))).then(async results => {
          if (finished) return;
          if (results.some(result => result.status === 'rejected')) {
            exitCode = Math.max(exitCode, 1);
            finish();
            return;
          }
          // Resource authority is released only after every ordinary drain
          // succeeded. One shutdown deadline includes all finalizers; late
          // cleanup completion must never start a release after timeout.
          for (const finalize of finalizers) {
            if (finished) return;
            if (Date.now() >= deadline) { exitCode = Math.max(exitCode, 1); finish(); return; }
            try { await finalize(); }
            catch { exitCode = Math.max(exitCode, 1); finish(); return; }
          }
          finish();
        });
      });
      return stopping;
    },
  };
}

async function closeApplicationOwnedResources({ closeStudentDeletion, closeCtfRuntime = async () => {}, closeSensitiveInfoReset,
  closeSecureShopBoundReview, closeOwnedAudit = async () => {}, closeSecureShop, closeSessionDisclosure,
  closeSecureShopReviewDb, closePostgresPools } = {}) {
  // Deletion can still require ordered CTF delivery while draining. Stop that
  // worker before closing its runtime, and close shared database pools last.
  const steps = [closeStudentDeletion, closeCtfRuntime, closeSensitiveInfoReset, closeSecureShopBoundReview,
    closeOwnedAudit, closeSecureShop, closeSessionDisclosure, closeSecureShopReviewDb, closePostgresPools];
  if (steps.some(step => typeof step !== 'function')) {
    throw new TypeError('Complete application resource cleanup dependencies are required');
  }
  return settleApplicationCleanup(steps);
}

// A failed browser or service close must not skip later owned pools/processes.
// Preserve ordering: callers put HTTP draining before database shutdown.
async function settleApplicationCleanup(steps) {
  if (!Array.isArray(steps) || steps.some(step => typeof step !== 'function')) {
    throw new TypeError('Application cleanup steps must be functions');
  }
  const failures = [];
  for (const step of steps) {
    try { await step(); }
    catch (error) {
      if (error instanceof AggregateError) failures.push(...error.errors);
      else failures.push(error);
    }
  }
  if (failures.length) throw new AggregateError(failures, 'Application owned resource cleanup failed');
}

module.exports = { createApplicationLifecycle, closeApplicationOwnedResources, settleApplicationCleanup };
