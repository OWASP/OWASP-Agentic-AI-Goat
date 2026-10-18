'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { verifyRunInspector, renderedQualificationFailureDiagnostic }
  = require('./fixtures/fullBackendRenderedSecureShop');

const RUN_IDS = Object.freeze(['11111111-1111-4111-8111-111111111111',
  '22222222-2222-4222-8222-222222222222']);

function harness({ detailStatus = 200, listStatus = 200, filterStatus = 200,
  wrongRun = false, malformedDetail = false, cacheError = null, navigationError = null,
  pendingDetailJson = false, autoSelectedRunId = RUN_IDS[0] } = {}) {
  const origin = 'http://127.0.0.1:35001';
  const events = [], verified = [], clicks = [], detailRequests = [], waiterStates = [];
  const pendingDetailReads = [];
  function session(projection) {
    const prefix = projection === 'admin' ? '/api/admin/agent-runs' : '/api/agent-runs';
    const waiters = [];
    let fresh = false, selectedRunId = autoSelectedRunId;
    const response = (path, status, body, malformed = false) => ({
      url: () => origin + path, status: () => status,
      request: () => ({ method: () => 'GET' }),
      json: async () => {
        if (malformed) throw new SyntaxError('invalid JSON');
        if (pendingDetailJson && path.startsWith(`${prefix}/`)) return new Promise((resolve, reject) => {
          pendingDetailReads.push({ resolve, reject });
        });
        return body;
      },
    });
    const emit = (path, status, body, malformed = false) => {
      if (path.startsWith(`${prefix}/`)) detailRequests.push(`${projection}:${path.slice(prefix.length + 1)}`);
      const value = response(path, status, body, malformed);
      for (const waiter of [...waiters]) {
        if (!waiter.settled && waiter.predicate(value)) {
          waiter.settled = true;waiter.resolve(value);break;
        }
      }
    };
    const emitDetail = runId => emit(`${prefix}/${runId}`, detailStatus,
      { run: { runId: wrongRun ? 'foreign-run' : runId,
        ...(projection === 'admin' ? { ownerId: 11 } : {}) } }, malformedDetail);
    return { token: 'owned-test-token', page: {
      async setCacheEnabled(value) {
        events.push(`${projection}:cache:${value}`);
        if (cacheError) throw cacheError;
        assert.equal(value, false);fresh = true;
      },
      waitForResponse(predicate, options = {}) {
        assert.equal(fresh, true, 'Cache setup must finish before observing responses');
        let resolve, reject;
        const promise = new Promise((yes, no) => { resolve = yes;reject = no; });
        const waiter = { predicate, resolve, reject, settled: false, timeout: options.timeout };
        waiters.push(waiter);
        waiterStates.push(waiter);
        options.signal?.addEventListener('abort', () => {
          if (!waiter.settled) {
            waiter.settled = true;reject(Object.assign(new Error('Aborted'), { name: 'AbortError' }));
          }
        }, { once: true });
        return promise;
      },
      async goto() {
        assert.equal(fresh, true);events.push(`${projection}:navigate`);
        if (navigationError) throw navigationError;
        emit(prefix, listStatus, { runs: RUN_IDS.map(runId => ({ runId })) });
        selectedRunId = autoSelectedRunId;emitDetail(selectedRunId);
      },
      async waitForSelector() {},
      async type() {
        emit(`${prefix}?ownerId=11`, filterStatus, { runs: RUN_IDS.map(runId => ({ runId })) });
      },
      async waitForFunction() {},
      async evaluate(_fn, input) {
        if (typeof input === 'string') {
          if (selectedRunId !== input) {
            clicks.push(`${projection}:${input}`);selectedRunId = input;emitDetail(input);
          }
          return;
        }
        assert.equal(input.pathname, '/api/admin/agent-runs');return { status: 403 };
      },
    } };
  }
  const owner = session('student'), administrator = session('admin');
  const sibling = { token: 'sibling-test-token', page: { async evaluate(_fn, input) {
    return input.pathname === '/api/agent-runs'
      ? { status: 200, body: { runs: [] } } : { status: 404 };
  } } };
  const nativeEvidence = {
    async verifyRunDetail({ ownerId, runId, body, projection }) {
      assert.equal(ownerId, 11);assert.equal(body.run.runId, runId);
      verified.push(`${projection}:${runId}`);return { verified: true };
    },
    async verifyForeignRunIsolation() { return { persistedOwnerVerified: true }; },
  };
  return { args: { owner, sibling, administrator, ownerId: 11, siblingId: 12,
    runIds: RUN_IDS, nativeEvidence, origin, timeoutMs: 420_000,
    inspectorResponseTimeoutMs: 25 }, events, verified, clicks,
  detailRequests, waiterStates, pendingDetailReads };
}

test('inspector captures auto-selected detail before navigation and clicks only manually selected targets', async () => {
  const h = harness();
  assert.deepEqual(await verifyRunInspector(h.args), { persistedOwnerVerified: true });
  assert.deepEqual(h.events, ['student:cache:false', 'student:navigate', 'student:navigate',
    'admin:cache:false', 'admin:navigate', 'admin:navigate']);
  assert.deepEqual(h.clicks, [`student:${RUN_IDS[1]}`, `admin:${RUN_IDS[1]}`]);
  assert.equal(h.detailRequests.filter(value => value.endsWith(RUN_IDS[0])).length, 4);
  assert.equal(h.verified.length, 4);
  assert.ok(h.waiterStates.every(waiter => waiter.settled), 'Every response waiter must drain');
  assert.ok(h.waiterStates.every(waiter => waiter.timeout === 25),
    'Full-flow timeout must not widen the inspector response deadline');
});

test('manually selected first target triggers its exact detail capture', async () => {
  const h = harness({ autoSelectedRunId: RUN_IDS[1] });
  await verifyRunInspector(h.args);
  assert.deepEqual(h.clicks, [`student:${RUN_IDS[0]}`, `admin:${RUN_IDS[0]}`]);
  assert.equal(h.verified.length, 4);
});

test('cache configuration failure stops before navigation and preserves bounded stage metadata', async () => {
  const error = new Error('Cache setup failed');const h = harness({ cacheError: error });
  await assert.rejects(verifyRunInspector(h.args), value => value === error
    && value.runInspectorFailure?.projection === 'student'
    && value.runInspectorFailure?.phase === 'cache'
    && value.runInspectorFailure?.runOrdinal === 1);
  assert.deepEqual(h.events, ['student:cache:false']);assert.deepEqual(h.verified, []);
  assert.deepEqual(renderedQualificationFailureDiagnostic(error, 'run_inspector').runInspector,
    { projection: 'student', phase: 'cache', runOrdinal: 1 });
});

test('navigation failure aborts and drains both pre-registered response captures', async () => {
  const error = new Error('Navigation failed');const h = harness({ navigationError: error });
  await assert.rejects(verifyRunInspector(h.args), value => value === error
    && value.runInspectorFailure?.phase === 'list_wait');
  assert.ok(h.waiterStates.length === 2 && h.waiterStates.every(waiter => waiter.settled));
  assert.deepEqual(h.verified, []);
});

test('a primary list failure aborts an already-started detail JSON capture without masking identity', async () => {
  const h = harness({ listStatus: 304, pendingDetailJson: true });
  let received;
  await assert.rejects(verifyRunInspector(h.args), error => {
    received = error;return error.name === 'AssertionError'
      && error.runInspectorFailure?.phase === 'list_status';
  });
  assert.equal(received.runInspectorFailure.projection, 'student');
  assert.ok(h.waiterStates.every(waiter => waiter.settled));
  assert.deepEqual(h.verified, []);
});

test('late raw detail resolution or rejection after wrapper cancellation has no evidence effects', async t => {
  for (const outcome of ['resolve', 'reject']) await t.test(outcome, async () => {
    const h = harness({ listStatus: 304, pendingDetailJson: true });
    const unhandled = [];
    const onUnhandled = reason => unhandled.push(reason);process.on('unhandledRejection', onUnhandled);
    try {
      await assert.rejects(verifyRunInspector(h.args), error => error.name === 'AssertionError'
        && error.runInspectorFailure?.phase === 'list_status');
      assert.equal(h.pendingDetailReads.length, 1);
      if (outcome === 'resolve') h.pendingDetailReads[0].resolve({ run: { runId: RUN_IDS[0] } });
      else h.pendingDetailReads[0].reject(new Error('late raw CDP read rejection'));
      await new Promise(resolve => setImmediate(resolve));
      assert.deepEqual(unhandled, []);assert.deepEqual(h.verified, []);
    } finally { process.off('unhandledRejection', onUnhandled); }
  });
});

test('hung detail JSON is bounded independently of the full-flow timeout', async () => {
  const h = harness({ pendingDetailJson: true });
  h.args.inspectorResponseTimeoutMs = 10;
  await assert.rejects(verifyRunInspector(h.args), error => error.name === 'TimeoutError'
    && error.runInspectorFailure?.phase === 'detail_body');
  assert.deepEqual(h.verified, []);
});

test('fresh inspector rejects cached statuses, malformed detail and wrong run bodies', async t => {
  for (const options of [{ detailStatus: 304 }, { detailStatus: 403 }, { wrongRun: true },
    { malformedDetail: true }]) {
    await t.test(JSON.stringify(options), async () => {
      const h = harness(options);await assert.rejects(verifyRunInspector(h.args));
      assert.deepEqual(h.verified, []);
      assert.ok(h.waiterStates.every(waiter => waiter.settled));
    });
  }
});

test('fresh inspector rejects cached list and admin-filter responses before consuming their bodies', async t => {
  for (const options of [{ listStatus: 304 }, { filterStatus: 304 }]) {
    await t.test(JSON.stringify(options), async () => {
      const h = harness(options);await assert.rejects(verifyRunInspector(h.args));
      assert.equal(h.verified.length, options.filterStatus ? 2 : 0);
      assert.ok(h.waiterStates.every(waiter => waiter.settled));
    });
  }
});

test('public inspector diagnostics reject unbounded or unknown attached metadata', () => {
  for (const value of [{ projection: 'student', phase: 'detail_wait', runOrdinal: 0 },
    { projection: 'foreign', phase: 'detail_wait', runOrdinal: 1 },
    { projection: 'student', phase: 'raw-private-body', runOrdinal: 1 },
    { projection: 'student', phase: 'detail_wait', runOrdinal: 1, raw: 'secret' }]) {
    const error = Object.assign(new Error('failure'), { runInspectorFailure: value });
    assert.equal(renderedQualificationFailureDiagnostic(error, 'run_inspector').runInspector, undefined);
  }
});
