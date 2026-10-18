const DEFAULT_INTERVAL_MS = 12000;
const MAX_VISIBLE_INTERVAL_MS = 15000;
const DEFAULT_MAX_INTERVAL_MS = MAX_VISIBLE_INTERVAL_MS;
const DEFAULT_RECONCILIATION_TIMEOUT_MS = 10000;
const DEFAULT_RECONCILIATION_TIMEOUT_BACKOFF_THRESHOLD = 2;
const DEFAULT_RECONCILIATION_TIMEOUT_BACKOFF_BASE_MS = 30000;
const DEFAULT_RECONCILIATION_TIMEOUT_BACKOFF_MAX_MS = 120000;
const DEFAULT_RECONCILIATION_TIMEOUT_BACKOFF_JITTER_RATIO = 0.2;

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (!value || typeof value !== 'object') return value;
  return Object.keys(value).sort().reduce((result, key) => {
    result[key] = canonicalize(value[key]);
    return result;
  }, {});
}

function fingerprint(snapshot) {
  return JSON.stringify(canonicalize(snapshot));
}

function createReconciliationGuard() {
  const generations = new Map();
  const foregroundOwners = new Map();
  const generation = (domain) => generations.get(domain) || 0;
  const assertCurrent = (domain, token) => {
    if (token !== generation(domain)) {
      const error = new Error(`Stale ${domain} reconciliation`);
      error.code = 'STALE_RECONCILIATION';
      throw error;
    }
  };
  return {
    begin(domain) {
      const next = generation(domain) + 1;
      generations.set(domain, next);
      return next;
    },
    beginBackground(domain) {
      if (foregroundOwners.has(domain)) return null;
      const next = generation(domain) + 1;
      generations.set(domain, next);
      return next;
    },
    beginRequiredBackground(domain) {
      if (foregroundOwners.has(domain)) {
        assertCurrent(domain, null);
      }
      const next = generation(domain) + 1;
      generations.set(domain, next);
      return next;
    },
    beginForeground(domain) {
      const next = generation(domain) + 1;
      generations.set(domain, next);
      foregroundOwners.set(domain, next);
      return next;
    },
    endForeground(domain, token) {
      if (foregroundOwners.get(domain) === token) foregroundOwners.delete(domain);
    },
    capture(domain) {
      return generation(domain);
    },
    mark(domain) {
      const next = generation(domain) + 1;
      generations.set(domain, next);
      return next;
    },
    commit(domain, token, apply) {
      assertCurrent(domain, token);
      return apply();
    },
    commitAll(tokens, apply) {
      for (const [domain, token] of Object.entries(tokens)) assertCurrent(domain, token);
      return apply();
    },
  };
}

const defaultScheduler = {
  setTimeout(callback, delay) {
    if (typeof window !== 'undefined') return window.setTimeout(callback, delay);
    const timer = setTimeout(callback, delay);
    timer.unref?.();
    return timer;
  },
  clearTimeout(timer) {
    if (typeof window !== 'undefined') return window.clearTimeout(timer);
    return clearTimeout(timer);
  },
};

function browserVisibility() {
  if (typeof document === 'undefined') {
    return { state: 'visible', subscribe: () => () => {} };
  }

  return {
    get state() {
      return document.visibilityState || 'visible';
    },
    subscribe(listener) {
      const handleChange = () => listener(document.visibilityState || 'visible');
      document.addEventListener('visibilitychange', handleChange);
      return () => document.removeEventListener('visibilitychange', handleChange);
    },
  };
}

function visibilityState(source, getVisibility) {
  if (typeof getVisibility === 'function') return getVisibility();
  if (typeof source?.getVisibility === 'function') return source.getVisibility();
  return source?.state || 'visible';
}

function subscribeToVisibility(source, listener) {
  if (typeof source?.subscribe === 'function') return source.subscribe(listener);
  if (typeof source?.addEventListener === 'function') {
    const handleChange = () => listener(visibilityState(source));
    source.addEventListener('visibilitychange', handleChange);
    return () => source.removeEventListener?.('visibilitychange', handleChange);
  }
  return () => {};
}

function boundedRandom(random) {
  const value = Number(random());
  if (!Number.isFinite(value)) return 0;
  return Math.min(1, Math.max(0, value));
}

function createRevisionPoller({
  fetchSnapshot,
  onChange,
  notifyOnBaseline = false,
  intervalMs = DEFAULT_INTERVAL_MS,
  maxIntervalMs = DEFAULT_MAX_INTERVAL_MS,
  scheduler = defaultScheduler,
  visibility = browserVisibility(),
  getVisibility,
  random = Math.random,
  onError,
  reconciliationTimeoutMs = DEFAULT_RECONCILIATION_TIMEOUT_MS,
  reconciliationTimeoutBackoffThreshold = DEFAULT_RECONCILIATION_TIMEOUT_BACKOFF_THRESHOLD,
  reconciliationTimeoutBackoffBaseMs = DEFAULT_RECONCILIATION_TIMEOUT_BACKOFF_BASE_MS,
  reconciliationTimeoutBackoffMaxMs = DEFAULT_RECONCILIATION_TIMEOUT_BACKOFF_MAX_MS,
  reconciliationTimeoutBackoffJitterRatio = DEFAULT_RECONCILIATION_TIMEOUT_BACKOFF_JITTER_RATIO,
  reconciliationScheduler = defaultScheduler,
} = {}) {
  if (typeof fetchSnapshot !== 'function' || typeof onChange !== 'function') {
    throw new TypeError('Polling requires fetchSnapshot and onChange functions');
  }

  const visibleIntervalMs = Math.min(Math.max(0, intervalMs), MAX_VISIBLE_INTERVAL_MS);
  const maximumIntervalMs = Math.min(
    MAX_VISIBLE_INTERVAL_MS,
    Math.max(visibleIntervalMs, maxIntervalMs),
  );
  const reconciliationDeadlineMs = Math.min(
    MAX_VISIBLE_INTERVAL_MS,
    Math.max(1, Number(reconciliationTimeoutMs) || DEFAULT_RECONCILIATION_TIMEOUT_MS),
  );
  const configuredJitterRatio = Number(reconciliationTimeoutBackoffJitterRatio);
  const timeoutBackoffJitterRatio = Number.isFinite(configuredJitterRatio)
    ? Math.min(0.5, Math.max(0, configuredJitterRatio))
    : DEFAULT_RECONCILIATION_TIMEOUT_BACKOFF_JITTER_RATIO;
  const minimumTimeoutBackoffBaseMs = Math.ceil(
    (MAX_VISIBLE_INTERVAL_MS + 1) / (1 - timeoutBackoffJitterRatio),
  );
  const configuredTimeoutBackoffBaseMs = Number(reconciliationTimeoutBackoffBaseMs);
  const timeoutBackoffBaseMs = Math.max(
    minimumTimeoutBackoffBaseMs,
    Number.isFinite(configuredTimeoutBackoffBaseMs)
      ? configuredTimeoutBackoffBaseMs
      : DEFAULT_RECONCILIATION_TIMEOUT_BACKOFF_BASE_MS,
  );
  const configuredTimeoutBackoffMaxMs = Number(reconciliationTimeoutBackoffMaxMs);
  const timeoutBackoffMaxMs = Math.max(
    timeoutBackoffBaseMs,
    Number.isFinite(configuredTimeoutBackoffMaxMs)
      ? configuredTimeoutBackoffMaxMs
      : DEFAULT_RECONCILIATION_TIMEOUT_BACKOFF_MAX_MS,
  );
  const configuredTimeoutBackoffThreshold = Number(reconciliationTimeoutBackoffThreshold);
  const timeoutBackoffThreshold = Math.max(
    2,
    Number.isFinite(configuredTimeoutBackoffThreshold)
      ? Math.floor(configuredTimeoutBackoffThreshold)
      : DEFAULT_RECONCILIATION_TIMEOUT_BACKOFF_THRESHOLD,
  );
  let stopped = true;
  let timer = null;
  let unsubscribe = null;
  let inFlight = null;
  let abortController = null;
  let generation = 0;
  let previousSnapshot;
  let hasBaseline = false;
  let failureCount = 0;
  let consecutiveReconciliationTimeouts = 0;

  function isActive(requestGeneration) {
    return !stopped && requestGeneration === generation;
  }

  function clearTimer() {
    if (timer !== null) scheduler.clearTimeout(timer);
    timer = null;
  }

  function visibleDelay() {
    const jitterCap = Math.min(Math.floor(visibleIntervalMs * 0.25), MAX_VISIBLE_INTERVAL_MS - visibleIntervalMs);
    return visibleIntervalMs + Math.floor(jitterCap * boundedRandom(random));
  }

  function failureDelay() {
    const exponential = Math.min(
      maximumIntervalMs,
      visibleIntervalMs * (2 ** failureCount),
    );
    const jitterCap = Math.min(Math.floor(exponential * 0.2), maximumIntervalMs - exponential);
    return exponential + Math.floor(jitterCap * boundedRandom(random));
  }

  function reconciliationTimeoutDelay() {
    const exponent = Math.max(0, consecutiveReconciliationTimeouts - timeoutBackoffThreshold);
    const base = Math.min(timeoutBackoffMaxMs, timeoutBackoffBaseMs * (2 ** exponent));
    const jitter = base * timeoutBackoffJitterRatio;
    const lowerBound = base - jitter;
    const upperBound = Math.min(timeoutBackoffMaxMs, base + jitter);
    return Math.round(lowerBound + ((upperBound - lowerBound) * boundedRandom(random)));
  }

  function schedule() {
    if (stopped || visibilityState(visibility, getVisibility) === 'hidden') return;
    clearTimer();
    const delay = consecutiveReconciliationTimeouts >= timeoutBackoffThreshold
      ? reconciliationTimeoutDelay()
      : failureCount > 0 ? failureDelay() : visibleDelay();
    timer = scheduler.setTimeout(() => {
      timer = null;
      return pollNow();
    }, delay);
  }

  function reportError(error) {
    try {
      onError?.(error);
    } catch {
      // Diagnostics must never interrupt a background recovery loop.
    }
  }

  function abortedError() {
    const error = new Error('Revision reconciliation aborted');
    error.name = 'AbortError';
    error.code = 'ABORTED_RECONCILIATION';
    return error;
  }

  function reconciliationTimeoutError() {
    const error = new Error(`Revision reconciliation timed out after ${reconciliationDeadlineMs}ms`);
    error.code = 'RECONCILIATION_TIMEOUT';
    return error;
  }

  function awaitReconciliation(work, signal, controller) {
    let deadline = null;
    let removeAbortListener = () => {};
    let settled = false;

    return new Promise((resolve, reject) => {
      const finish = (callback, value) => {
        if (settled) return;
        settled = true;
        if (deadline !== null) reconciliationScheduler.clearTimeout(deadline);
        removeAbortListener();
        callback(value);
      };
      const abort = () => finish(reject, abortedError());

      if (signal?.aborted) {
        abort();
        return;
      }
      if (typeof signal?.addEventListener === 'function') {
        signal.addEventListener('abort', abort, { once: true });
        removeAbortListener = () => signal.removeEventListener?.('abort', abort);
      }
      deadline = reconciliationScheduler.setTimeout(() => {
        finish(reject, reconciliationTimeoutError());
        controller?.abort();
      }, reconciliationDeadlineMs);
      try {
        Promise.resolve(work()).then(
          (value) => finish(resolve, value),
          (error) => finish(reject, error),
        );
      } catch (error) {
        finish(reject, error);
      }
    });
  }

  function pollNow() {
    if (stopped || visibilityState(visibility, getVisibility) === 'hidden') return Promise.resolve();
    if (inFlight) return inFlight;

    clearTimer();
    const requestGeneration = generation;
    const requestController = typeof AbortController === 'undefined' ? null : new AbortController();
    abortController = requestController;
    let request;
    request = (async () => {
      try {
        const nextSnapshot = await fetchSnapshot({ signal: requestController?.signal });
        if (!isActive(requestGeneration)) return;

        const changed = !hasBaseline
          ? notifyOnBaseline
          : fingerprint(previousSnapshot) !== fingerprint(nextSnapshot);
        if (changed) {
          await awaitReconciliation(
            () => onChange(
              nextSnapshot,
              hasBaseline ? previousSnapshot : undefined,
              { signal: requestController?.signal },
            ),
            requestController?.signal,
            requestController,
          );
          if (!isActive(requestGeneration)) return;
        }

        previousSnapshot = nextSnapshot;
        hasBaseline = true;
        failureCount = 0;
        consecutiveReconciliationTimeouts = 0;
      } catch (error) {
        if (!isActive(requestGeneration)) return;
        if (error?.code === 'STALE_RECONCILIATION' || error?.code === 'ABORTED_RECONCILIATION') {
          failureCount = 0;
          consecutiveReconciliationTimeouts = 0;
        } else {
          if (error?.code === 'RECONCILIATION_TIMEOUT') {
            failureCount = 1;
            consecutiveReconciliationTimeouts += 1;
          } else {
            failureCount = consecutiveReconciliationTimeouts > 0 ? 1 : failureCount + 1;
            consecutiveReconciliationTimeouts = 0;
          }
          reportError(error);
        }
      } finally {
        if (!isActive(requestGeneration) || inFlight !== request) return;
        inFlight = null;
        abortController = null;
        schedule();
      }
    })();
    inFlight = request;
    return request;
  }

  function start() {
    if (!stopped) return inFlight || Promise.resolve();
    stopped = false;
    generation += 1;
    unsubscribe = subscribeToVisibility(visibility, (state) => {
      if (stopped) return;
      if (state === 'hidden') {
        clearTimer();
        abortController?.abort();
        return;
      }
      void pollNow();
    });
    return pollNow();
  }

  function stop() {
    stopped = true;
    generation += 1;
    clearTimer();
    unsubscribe?.();
    unsubscribe = null;
    abortController?.abort();
    abortController = null;
    inFlight = null;
  }

  return { start, stop, pollNow };
}

module.exports = { createReconciliationGuard, createRevisionPoller, fingerprint };
