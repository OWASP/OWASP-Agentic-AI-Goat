'use strict';

// Bounded local-model capacity gate.  This is intentionally a small cohort:
// it proves the real PostgreSQL lease/run path and the local scheduler's
// queue/reset behaviour, not a 200-user inference SLA.
const test = require('node:test');
const assert = require('node:assert/strict');
const { performance } = require('node:perf_hooks');
const { AsyncLocalStorage } = require('node:async_hooks');
const diagnosticsChannel = require('node:diagnostics_channel');
const http = require('node:http');
const { createPool } = require('../../server/database/postgres');
const { initializeIdentityRepository } = require('../../server/database/postgres/identityRepository');
const { createPostgresRunLedger } = require('../../server/agent-runtime/postgresRunLedger');
const { createRunCoordinator } = require('../../server/agent-runtime/runCoordinator');
const { sharedModelScheduler } = require('../../server/agent-runtime/providers/modelScheduler');
const { createMultiProviderAIService } = require('../../server/services/multiProviderAIService');

const MODEL = 'llama3.1:8b';
const ENDPOINT = 'http://127.0.0.1:11434';
const MAX_PROVIDER_CALLS = 10; // one warmup + eight successes + one reset abort
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes'
  && process.env.DVAIA_CAPACITY_ACTUAL8B === 'yes'
  && Boolean(process.env.PG_CAPACITY_ACTUAL8B_IDENTITY_MIGRATION_URL)
  && Boolean(process.env.PG_CAPACITY_ACTUAL8B_IDENTITY_RUNTIME_URL);

function sleep(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }
async function eventually(predicate, timeoutMs = 10000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const value = await predicate();
    if (value) return value;
    await sleep(10);
  }
  throw new Error('Timed out waiting for capacity gate condition');
}
function abortWait(signal) {
  if (signal.aborted) return Promise.resolve();
  return new Promise(resolve => signal.addEventListener('abort', resolve, { once: true }));
}

function createUndiciTransportObserver({ endpoint, ownerContext, onCreate, onHeaders, onSettled }) {
  const pending = new Map();
  const matches = request => request?.origin === endpoint && request?.path === '/api/generate';
  const create = message => {
    const request = message?.request;
    if (!matches(request)) return;
    const entry = { owner: ownerContext?.getStore(), headers: false, settled: false };
    pending.set(request, entry);
    onCreate?.(entry, request);
  };
  const headers = message => {
    const request = message?.request;
    const entry = pending.get(request);
    if (!entry || entry.headers) return;
    entry.headers = true;
    onHeaders?.(entry, request);
  };
  const settle = (request, outcome) => {
    const entry = pending.get(request);
    if (!entry || entry.settled) return;
    entry.settled = true;
    pending.delete(request);
    onSettled?.(entry, request, outcome);
  };
  const error = message => settle(message?.request, { type: 'error', error: message.error });
  const trailers = message => settle(message?.request, { type: 'trailers' });
  const subscriptions = [
    ['undici:request:create', create], ['undici:request:headers', headers],
    ['undici:request:error', error], ['undici:request:trailers', trailers],
  ];
  for (const [name, handler] of subscriptions) diagnosticsChannel.channel(name).subscribe(handler);
  return () => {
    for (const [name, handler] of subscriptions) diagnosticsChannel.channel(name).unsubscribe(handler);
    pending.clear();
  };
}

test('capacity gate wire probe exercises the production multi-provider scheduler against a local Ollama-shaped stream',
  { timeout: 15000 }, async () => {
    const previousConcurrency = process.env.AI_OLLAMA_CONCURRENCY;
    const previousQueueLimit = process.env.AI_OLLAMA_QUEUE_LIMIT;
    let server;
    let release;
    const gate = new Promise(resolve => { release = resolve; });
    let requests = 0;
    let active = 0;
    let maxActive = 0;
    try {
      server = http.createServer(async (request, response) => {
        if (request.method !== 'POST' || request.url !== '/api/generate') {
          response.writeHead(404).end();
          return;
        }
        requests += 1;
        active += 1;
        maxActive = Math.max(maxActive, active);
        if (requests <= 2) await gate;
        response.writeHead(200, { 'content-type': 'application/x-ndjson' });
        response.end(`${JSON.stringify({ model: MODEL, response: 'OK', done: false })}\n${JSON.stringify({ model: MODEL, done: true })}\n`);
        active -= 1;
      });
      await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
      const endpoint = `http://127.0.0.1:${server.address().port}`;
      process.env.AI_OLLAMA_CONCURRENCY = '2';
      process.env.AI_OLLAMA_QUEUE_LIMIT = '1';
      const service = createMultiProviderAIService({
        env: { AI_PROVIDER: 'ollama', OLLAMA_MODEL: MODEL, OLLAMA_BASE_URL: endpoint },
        logger: { log() {}, warn() {}, error() {} },
      });
      const first = service.generateResponse('Return only OK.', { ownerId: 'wire-a', num_predict: 8, timeout: 5000 });
      const second = service.generateResponse('Return only OK.', { ownerId: 'wire-b', num_predict: 8, timeout: 5000 });
      const thirdController = new AbortController();
      const third = service.generateResponse('Return only OK.', { ownerId: 'wire-c', signal: thirdController.signal, num_predict: 8, timeout: 5000 });
      await eventually(() => requests === 2);
      thirdController.abort();
      await assert.rejects(third, { name: 'AbortError' });
      assert.equal(requests, 2, 'queued cancellation must not reach the provider wire');
      release();
      const results = await Promise.all([first, second]);
      assert.deepEqual(results.map(result => [result.provider, result.model, result.fallback]),
        [['ollama', MODEL, false], ['ollama', MODEL, false]]);
      assert.equal(maxActive, 2);
      assert.equal(active, 0);
    } finally {
      if (server) await new Promise(resolve => server.close(resolve));
      if (previousConcurrency === undefined) delete process.env.AI_OLLAMA_CONCURRENCY;
      else process.env.AI_OLLAMA_CONCURRENCY = previousConcurrency;
      if (previousQueueLimit === undefined) delete process.env.AI_OLLAMA_QUEUE_LIMIT;
      else process.env.AI_OLLAMA_QUEUE_LIMIT = previousQueueLimit;
    }
  });

test('capacity transport diagnostics observe headers and actual undici abort without replacing response bodies', async () => {
  let headers = 0;
  let errors = 0;
  let server;
  let connectionClosed = false;
  let stop;
  try {
    server = http.createServer((request, response) => {
      response.writeHead(200, { 'content-type': 'application/x-ndjson' });
      response.flushHeaders();
      const timer = setTimeout(() => response.write('{"response":"late"}\n'), 5000);
      response.once('close', () => { connectionClosed = true; clearTimeout(timer); });
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const controller = new AbortController();
    const endpoint = `http://127.0.0.1:${server.address().port}`;
    stop = createUndiciTransportObserver({ endpoint,
      onHeaders: () => { headers += 1; },
      onSettled: (_entry, _request, outcome) => { if (outcome.type === 'error') errors += 1; },
    });
    const raw = await fetch(`${endpoint}/api/generate`, { signal: controller.signal });
    const pending = raw.body.getReader().read();
    controller.abort(new Error('controlled reset'));
    await assert.rejects(pending);
    await eventually(() => headers === 1 && errors === 1 && connectionClosed);
  } finally {
    stop?.();
    if (server) await new Promise(resolve => server.close(resolve));
  }
});

test('bounded actual local-8B cohort exercises PostgreSQL leases, queue cancellation, and reset fencing',
  { skip: !enabled, timeout: 300000 }, async () => {
    for (const key of ['PG_CAPACITY_ACTUAL8B_IDENTITY_MIGRATION_URL', 'PG_CAPACITY_ACTUAL8B_IDENTITY_RUNTIME_URL']) {
      const url = new URL(process.env[key]);
      assert.equal(url.hostname, '127.0.0.1');
      assert.match(url.pathname, /^\/dvaia_test_capacity_actual_8b_[a-z0-9_]+$/);
    }
    const env = {
      ...process.env,
      AI_PROVIDER: 'ollama',
      OLLAMA_MODEL: MODEL,
      OLLAMA_BASE_URL: ENDPOINT,
      AI_OLLAMA_CONCURRENCY: '2',
      AI_OLLAMA_QUEUE_LIMIT: '256',
      PG_POOL_MAX_LEASE: '6',
      DISABLE_OLLAMA: 'false',
    };
    const migration = createPool(env, 'PG_CAPACITY_ACTUAL8B_IDENTITY_MIGRATION_URL', { purpose: 'migration' });
    const pool = createPool(env, 'PG_CAPACITY_ACTUAL8B_IDENTITY_RUNTIME_URL', { purpose: 'control' });
    const leasePool = createPool(env, 'PG_CAPACITY_ACTUAL8B_IDENTITY_RUNTIME_URL', { purpose: 'lease' });
    const model = createMultiProviderAIService({ env, logger: { log() {}, warn() {}, error() {} } });
    const ledger = createPostgresRunLedger(pool, { leasePool });
    const coordinator = createRunCoordinator({ family: 'CAPACITY_ACTUAL8B', ledger, defaultTimeoutMs: 30000 });
    const secondaryCoordinator = createRunCoordinator({ family: 'CAPACITY_ACTUAL8B_SECONDARY', ledger, defaultTimeoutMs: 30000 });
    const previousConcurrency = process.env.AI_OLLAMA_CONCURRENCY;
    const previousQueueLimit = process.env.AI_OLLAMA_QUEUE_LIMIT;
    process.env.AI_OLLAMA_CONCURRENCY = '2';
    process.env.AI_OLLAMA_QUEUE_LIMIT = '256';
    const scheduler = sharedModelScheduler('ollama', ENDPOINT);
    const ownerContext = new AsyncLocalStorage();
    const calls = [];
    const timings = [];
    const transportEvents = [];
    let providerCalls = 0;
    let activeTransports = 0;
    let maxActiveTransports = 0;
    let transportAborts = 0;
    let heldTransports = 0;
    let releaseHeldTransports;
    const heldTransportGate = new Promise(resolve => { releaseHeldTransports = resolve; });
    let resetDispatchResolve;
    const resetDispatchStarted = new Promise(resolve => { resetDispatchResolve = resolve; });
    const activeSignals = new Map();
    const stopTransportObserver = createUndiciTransportObserver({ endpoint: ENDPOINT, ownerContext,
      onCreate: entry => {
        providerCalls += 1;
        assert.ok(providerCalls <= MAX_PROVIDER_CALLS, 'physical provider-call budget exceeded');
        activeTransports += 1;
        transportEvents.push({ event: 'created', owner: entry.owner ?? 'warmup', active: activeTransports, atMs: Math.round(performance.now()) });
        maxActiveTransports = Math.max(maxActiveTransports, activeTransports);
        calls.push({ owner: entry.owner, transportStart: performance.now(), physical: providerCalls });
      },
      onHeaders: entry => {
        if (entry.owner === 'owner-reset') resetDispatchResolve();
      },
      onSettled: (entry, _request, outcome) => {
        activeTransports -= 1;
        transportEvents.push({ event: outcome.type, owner: entry.owner ?? 'warmup', active: activeTransports, atMs: Math.round(performance.now()) });
        const signal = activeSignals.get(entry.owner);
        const error = outcome.type === 'error' ? outcome.error : null;
        if (entry.owner === 'owner-reset' && signal?.aborted && error?.name === 'AbortError') transportAborts += 1;
      },
    });
    const originalFetch = global.fetch;
    global.fetch = async (input, init = {}) => {
      const url = new URL(typeof input === 'string' ? input : input.url);
      if (url.origin !== ENDPOINT || url.pathname !== '/api/generate') return originalFetch(input, init);
      if (heldTransports > 0) {
        heldTransports -= 1;
        await heldTransportGate;
      }
      return originalFetch(input, init);
    };
    let sampler;
    let maxSchedulerActive = 0;
    let maxPoolConnections = 0;
    let maxPoolWaiting = 0;
    try {
      await initializeIdentityRepository(pool, migration);
      // One real warmup call is intentionally excluded from latency statistics.
      const warmup = await model.generateResponse('Return only the word OK.', {
        ownerId: 'capacity-warmup', temperature: 0, num_predict: 8, timeout: 30000,
      });
      assert.equal(warmup.provider, 'ollama');
      assert.equal(warmup.model, MODEL);
      assert.equal(warmup.mocked, false);
      assert.equal(warmup.fallback, false);
      assert.ok(String(warmup.response || '').trim());
      // Warmup consumes the first provider call but is excluded from measured
      // dispatch/latency/fairness arrays.
      calls.length = 0;
      heldTransports = 2;
      async function operation(owner, ordinal, { reset = false } = {}) {
        const ownerCoordinator = owner === 'owner-c' || owner === 'owner-d' ? secondaryCoordinator : coordinator;
        return ownerCoordinator.run(owner, { timeoutMs: 30000, idempotencyKey: `capacity-${owner}-${ordinal}` }, async execution => {
          const submitted = performance.now();
          activeSignals.set(owner, execution.signal);
          let result;
          try {
            result = await ownerContext.run(owner, () => model.generateResponse(
              reset ? 'Provide a bounded operational status explanation with no secrets.' : 'Return only the word OK.', {
                ownerId: owner, signal: execution.signal, temperature: 0,
                num_predict: reset ? 256 : 8, timeout: 20000,
              }));
          } finally {
            activeSignals.delete(owner);
          }
          const responseEnd = performance.now();
          assert.equal(result.provider, 'ollama');
          assert.equal(result.model, MODEL);
          assert.equal(result.mocked, false);
          assert.equal(result.fallback, false);
          assert.ok(String(result.response || '').trim());
          const dispatch = calls.findLast(call => call.owner === owner && !call.ordinal);
          if (dispatch) {
            dispatch.ordinal = ordinal;
            timings.push({ owner, ordinal, queueWaitMs: dispatch.transportStart - submitted,
              modelMs: responseEnd - dispatch.transportStart });
          }
          await execution.check();
          await execution.trace({ node: 'capacity_model', type: 'node_end', data: {
            provider: 'ollama', model: MODEL, decisionSource: 'local_capacity_gate',
          } });
          const effect = await execution.effectWithReceipt('capacity_probe', async () => ({ category: 'completed' }));
          return { runId: execution.runId, generation: String(execution.durableGeneration), effect };
        });
      }

      sampler = setInterval(() => {
        maxPoolConnections = Math.max(maxPoolConnections, pool.totalCount);
        maxPoolWaiting = Math.max(maxPoolWaiting, pool.waitingCount);
        maxSchedulerActive = Math.max(maxSchedulerActive, scheduler.snapshot().active);
      }, 10);

      // Occupy both scheduler slots, then enqueue the other first-dispatch
      // owners before exercising queued cancellation.
      const firstA = operation('owner-a', 1);
      const firstB = operation('owner-b', 1);
      await eventually(() => scheduler.snapshot().active === 2);
      const firstC = operation('owner-c', 1);
      const firstD = operation('owner-d', 1);
      // Submit second operations while first operations are still active. The
      // coordinator intentionally serializes each owner; their admission
      // timing is retained as a measured result rather than treated as a
      // scheduler fairness guarantee.
      const secondCohort = Promise.all(['owner-a', 'owner-b', 'owner-c', 'owner-d']
        .map(owner => operation(owner, 2)));
      const queued = operation('owner-queued', 1);
      await eventually(() => scheduler.snapshot().queued === 3);
      coordinator.cancel('owner-queued');
      await assert.rejects(queued, { name: 'AbortError' });
      assert.equal(scheduler.snapshot().queued, 2);
      assert.equal(calls.length, 0, 'queued cancellation must not dispatch a provider call');
      releaseHeldTransports();
      // Start a sixth-owner model request while the first cohort and the
      // second-operation promises are still draining; reset must observe its
      // real physical dispatch and abort it through the production signal.
      const resetRun = operation('owner-reset', 1, { reset: true });
      // Keep a rejection handler attached while waiting for physical dispatch;
      // the original promise is still asserted below.
      resetRun.catch(() => {});
      await Promise.race([resetDispatchStarted, resetRun.then(() => { throw new Error('Reset run completed before dispatch observation'); })]);
      const resetGeneration = await coordinator.reset('owner-reset', async execution => {
        await execution.check();
      });
      void resetGeneration;
      await Promise.all([firstA, firstB, firstC, firstD]);
      await assert.rejects(resetRun, { name: 'AbortError' });
      assert.equal(transportAborts, 1, 'reset must abort the in-flight production transport');
      await secondCohort;

      assert.equal(providerCalls, 10, 'warmup + eight successes + one reset call');
      assert.equal(calls.filter(call => call.owner === 'owner-queued').length, 0);
      assert.equal(calls.filter(call => call.owner === 'owner-reset').length, 1);
      assert.equal(calls.filter(call => call.owner === 'owner-a').length, 2);
      assert.equal(calls.filter(call => call.owner === 'owner-b').length, 2);
      assert.equal(calls.filter(call => call.owner === 'owner-c').length, 2);
      assert.equal(calls.filter(call => call.owner === 'owner-d').length, 2);
      const resetOwnerKey = JSON.stringify(['CAPACITY_ACTUAL8B', 'owner-reset']);
      const resetOwner = (await pool.query('SELECT generation FROM graph_runtime.owners WHERE owner_key=$1', [resetOwnerKey])).rows[0];
      assert.ok(Number(resetOwner?.generation) >= 1);
      assert.equal((await pool.query("SELECT count(*)::int AS n FROM graph_runtime.effects WHERE owner_key=$1 AND status='completed'", [resetOwnerKey])).rows[0].n, 0);
      assert.equal((await pool.query("SELECT count(*)::int AS n FROM graph_runtime.runs WHERE owner_key=$1 AND status='running'", [resetOwnerKey])).rows[0].n, 0);
      const snapshot = scheduler.snapshot();
      assert.deepEqual({ active: snapshot.active, queued: snapshot.queued, owners: snapshot.owners }, { active: 0, queued: 0, owners: 0 });
      assert.ok(maxSchedulerActive <= 2);
      assert.ok(maxActiveTransports <= 2);
      assert.equal(activeTransports, 0);
      assert.equal((await pool.query("SELECT count(*)::int AS n FROM graph_runtime.runs WHERE status='running'")).rows[0].n, 0);
      assert.equal(pool.waitingCount, 0);
      const ordered = calls.filter(call => call.owner !== 'owner-reset');
      for (const owner of ['owner-a', 'owner-b', 'owner-c', 'owner-d']) {
        const rows = ordered.filter(call => call.owner === owner);
        assert.ok(rows[0].transportStart <= rows[1].transportStart, `${owner} dispatch order`);
      }
      const firstDispatches = ordered.filter(call => call.ordinal === 1).map(call => call.transportStart);
      const secondDispatches = ordered.filter(call => call.ordinal === 2).map(call => call.transportStart);
      assert.equal(firstDispatches.length, 4);
      assert.equal(secondDispatches.length, 4);
      assert.ok(Math.max(...firstDispatches) <= Math.min(...secondDispatches),
        'all owners must receive their first dispatch before any second dispatch');
      const sortedQueue = timings.map(row => row.queueWaitMs).sort((a, b) => a - b);
      const sortedModel = timings.map(row => row.modelMs).sort((a, b) => a - b);
      console.log(JSON.stringify({ qualification: 'postgres-local-8b-capacity', model: MODEL,
        providerCalls, successfulOwners: 4, successfulCalls: 8, queueMax: 256,
        scheduler: { configuredConcurrency: 2, observedMaxActive: maxSchedulerActive, final: scheduler.snapshot() },
        transport: { configuredConcurrency: 2, observedMaxActive: maxActiveTransports, finalActive: activeTransports, aborts: transportAborts },
        maxPoolConnections, maxPoolWaiting,
        queueWaitP50Ms: Math.round(sortedQueue[Math.floor(sortedQueue.length * 0.5)] || 0),
        queueWaitP95Ms: Math.round(sortedQueue[Math.min(sortedQueue.length - 1, Math.floor(sortedQueue.length * 0.95))] || 0),
        modelP50Ms: Math.round(sortedModel[Math.floor(sortedModel.length * 0.5)] || 0),
        modelP95Ms: Math.round(sortedModel[Math.min(sortedModel.length - 1, Math.floor(sortedModel.length * 0.95))] || 0),
        evidence: 'correlation ids and categorical trace only; prompt/response bodies omitted' }));
    } finally {
      if (sampler) clearInterval(sampler);
      stopTransportObserver();
      console.log(JSON.stringify({ diagnostic: 'capacity_transport_lifecycle', providerCalls, maxActiveTransports, activeTransports, transportAborts, events: transportEvents }));
      global.fetch = originalFetch;
      if (previousConcurrency === undefined) delete process.env.AI_OLLAMA_CONCURRENCY;
      else process.env.AI_OLLAMA_CONCURRENCY = previousConcurrency;
      if (previousQueueLimit === undefined) delete process.env.AI_OLLAMA_QUEUE_LIMIT;
      else process.env.AI_OLLAMA_QUEUE_LIMIT = previousQueueLimit;
      await Promise.allSettled([pool.end(), leasePool.end(), migration.end()]);
    }
  });
