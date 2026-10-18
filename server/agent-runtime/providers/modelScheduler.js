'use strict';
const { AsyncResource } = require('node:async_hooks');

function createModelScheduler({ concurrency = 2, queueLimit = 256, ownerQueueLimit = 16, now = () => performance.now() } = {}) {
  if (!Number.isInteger(concurrency) || concurrency < 1 || !Number.isInteger(queueLimit) || queueLimit < 0 || !Number.isInteger(ownerQueueLimit) || ownerQueueLimit < 1 || ownerQueueLimit > 2000) throw new RangeError('Invalid model scheduler bounds');
  if (typeof now !== 'function') throw new TypeError('Scheduler clock must be a function');
  const counters = { accepted: 0, rejected: 0, queuedCancelled: 0, preDispatchCancelled: 0, settled: 0 };
  const queues = new Map(), owners = [];
  let active = 0, queued = 0;
  function pump() {
    while (active < concurrency && owners.length) {
      const owner = owners.shift(), queue = queues.get(owner), job = queue.shift();
      queued--;
      if (queue.length) owners.push(owner); else queues.delete(owner);
      job.signal?.removeEventListener('abort', job.abort);
      if (job.signal?.aborted) { counters.preDispatchCancelled++; job.resource.emitDestroy(); job.reject(job.signal.reason); continue; }
      active++;
      // Keep the slot until transport settles, even if its caller aborts first.
      Promise.resolve().then(() => {
        // Admission and invocation are separated by a microtask. Cancellation
        // in that interval must not start a new provider request.
        if (job.signal?.aborted) { counters.preDispatchCancelled++; throw job.signal.reason; }
        job.started = true;
        return job.resource.runInAsyncScope(job.work);
      }).then(job.resolve, job.reject)
        .finally(() => { if (job.started) counters.settled++; job.resource.emitDestroy(); active--; pump(); });
    }
  }
  return {
    run(owner, signal, work) {
      return new Promise((resolve, reject) => {
        if (signal?.aborted) { counters.rejected++; return reject(signal.reason); }
        const key = String(owner ?? 'background');
        if (active >= concurrency && (queued >= queueLimit || (queues.get(key)?.length || 0) >= ownerQueueLimit)) {
          counters.rejected++;
          const error = new Error('Model queue is full; retry later'); error.code = 'AI_QUEUE_FULL'; return reject(error);
        }
        // Capture the submitter's AsyncLocalStorage context. The scheduler's
        // pump runs from whichever prior job settled; invoking work directly
        // there would silently attribute queued model calls to that context.
        const job = { work, signal, resolve, reject, abort: null, enqueuedAt: now(), started: false,
          resource: new AsyncResource('dvaia-model-scheduler-job') };
        job.abort = () => {
          const queue = queues.get(key), index = queue?.indexOf(job) ?? -1;
          if (index < 0) return;
          queue.splice(index, 1); queued--; counters.queuedCancelled++;
          if (!queue.length) { queues.delete(key); owners.splice(owners.indexOf(key), 1); }
          job.resource.emitDestroy();
          reject(signal.reason);
        };
        if (!queues.has(key)) { queues.set(key, []); owners.push(key); }
        queues.get(key).push(job); queued++; counters.accepted++;
        signal?.addEventListener('abort', job.abort, { once: true });
        pump();
      });
    },
    setConcurrency(value) {
      if (!Number.isInteger(value) || value < 1 || value > 64) throw new RangeError('Invalid concurrency');
      concurrency = value; pump();
    },
    snapshot: () => {
      const time = now();
      let oldestQueuedAgeMs = 0;
      for (const queue of queues.values()) {
        oldestQueuedAgeMs = Math.max(oldestQueuedAgeMs, time - queue[0].enqueuedAt);
      }
      return { active, queued, owners: owners.length, concurrency, queueLimit, ownerQueueLimit,
        oldestQueuedAgeMs, ...counters };
    },
  };
}
const shared = new Map();
function sharedModelScheduler(provider, endpoint) {
  // URL serialization normalizes host case, default ports and the root slash.
  // Preserve distinct paths/ports and non-URL region identifiers.
  let canonicalEndpoint = endpoint || 'default';
  if (endpoint) {
    try {
      const parsed = new URL(endpoint);
      if (parsed.protocol === 'http:' || parsed.protocol === 'https:') canonicalEndpoint = parsed.href;
    } catch { /* Cloud region identifiers are not URLs. */ }
  }
  const key = JSON.stringify([provider, canonicalEndpoint]);
  if (!shared.has(key)) {
    const prefix = `AI_${provider.toUpperCase()}`;
    const positive = (value, fallback, max) => { const n = Number(value); return Number.isInteger(n) && n > 0 && n <= max ? n : fallback; };
    shared.set(key, createModelScheduler({
      concurrency: positive(process.env[`${prefix}_CONCURRENCY`], provider === 'ollama' || provider === 'lmstudio' ? 2 : 8, 64),
      queueLimit: positive(process.env[`${prefix}_QUEUE_LIMIT`], 256, 2000),
      ownerQueueLimit: positive(process.env[`${prefix}_OWNER_QUEUE_LIMIT`], 16, 2000),
    }));
  }
  return shared.get(key);
}
module.exports = { createModelScheduler, sharedModelScheduler };
