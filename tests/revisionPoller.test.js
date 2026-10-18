const test = require('node:test');
const assert = require('node:assert/strict');

const {
  createRevisionPoller,
  createReconciliationGuard,
  fingerprint,
} = require('../client/src/services/revisionPoller');

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

function createScheduler() {
  const tasks = [];
  return {
    tasks,
    setTimeout(callback, delay) {
      assert.equal(this.tasks, tasks, 'scheduler methods must retain their receiver');
      const task = { callback, delay, cancelled: false };
      tasks.push(task);
      return task;
    },
    clearTimeout(task) {
      assert.equal(this.tasks, tasks, 'scheduler methods must retain their receiver');
      if (task) task.cancelled = true;
    },
    lastDelay() {
      const active = tasks.filter((task) => !task.cancelled);
      return active.at(-1)?.delay;
    },
    async runNext() {
      let task;
      do {
        task = tasks.shift();
        assert.ok(task, 'expected a scheduled polling task');
      } while (task.cancelled);
      await task.callback();
      return task;
    },
  };
}

function createVisibility(initial = 'visible') {
  let state = initial;
  const listeners = new Set();
  return {
    get state() {
      return state;
    },
    subscribe(listener) {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    set(next) {
      state = next;
      listeners.forEach((listener) => listener(next));
    },
  };
}

function createFixture({ snapshots = [], random = () => 0, visibility = createVisibility() } = {}) {
  const scheduler = createScheduler();
  const changes = [];
  const diagnostics = [];
  const userMessages = [];
  const poller = createRevisionPoller({
    fetchSnapshot: async () => {
      const next = snapshots.shift();
      if (next instanceof Error) throw next;
      return next;
    },
    onChange: async (next, previous) => changes.push({ next, previous }),
    onError: (error) => diagnostics.push(error.message),
    notifyOnBaseline: true,
    scheduler,
    visibility,
    random,
  });
  return { poller, scheduler, visibility, changes, diagnostics, userMessages };
}

test('visible scheduling stays inside the twelve-to-fifteen-second active-tab window', async () => {
  const fixture = createFixture({ snapshots: [{ revision: 1 }], random: () => 0.9999 });

  await fixture.poller.start();

  assert.ok(fixture.scheduler.lastDelay() >= 12000);
  assert.ok(fixture.scheduler.lastDelay() <= 15000);
  fixture.poller.stop();
});

test('canonical fingerprints ignore object key order while preserving snapshot content', async () => {
  assert.equal(
    fingerprint({ workshops: { b: 2, a: 1 }, global: { revision: 1 } }),
    fingerprint({ global: { revision: 1 }, workshops: { a: 1, b: 2 } }),
  );

  const fixture = createFixture({
    snapshots: [
      { workshops: { b: 2, a: 1 }, global: { revision: 1 } },
      { global: { revision: 1 }, workshops: { a: 1, b: 2 } },
    ],
  });
  await fixture.poller.start();
  await fixture.scheduler.runNext();

  assert.equal(fixture.changes.length, 1, 'reordered keys must not trigger a second reconciliation');
  fixture.poller.stop();
});

test('failed poll retains the last baseline, remains user-silent, and later reconciles the changed snapshot', async () => {
  const fixture = createFixture({
    snapshots: [{ revision: 1 }, new Error('offline'), { revision: 2 }],
  });

  await fixture.poller.start();
  await fixture.scheduler.runNext();
  await fixture.scheduler.runNext();

  assert.deepEqual(fixture.changes, [
    { next: { revision: 1 }, previous: undefined },
    { next: { revision: 2 }, previous: { revision: 1 } },
  ]);
  assert.deepEqual(fixture.userMessages, []);
  assert.deepEqual(fixture.diagnostics, ['offline']);
  fixture.poller.stop();
});

test('repeated visible failures retry within fifteen seconds and recover on the next retry', async () => {
  const scheduler = createScheduler();
  const snapshots = [
    new Error('offline-one'),
    new Error('offline-two'),
    new Error('offline-three'),
    { revision: 2 },
  ];
  const changes = [];
  const diagnostics = [];
  const poller = createRevisionPoller({
    fetchSnapshot: async () => {
      const next = snapshots.shift();
      if (next instanceof Error) throw next;
      return next;
    },
    onChange: async (next) => changes.push(next),
    onError: (error) => diagnostics.push(error.message),
    notifyOnBaseline: true,
    maxIntervalMs: 120000,
    scheduler,
    visibility: createVisibility(),
    random: () => 0.9999,
  });

  await poller.start();
  for (let failure = 0; failure < 3; failure += 1) {
    assert.ok(scheduler.lastDelay() >= 12000);
    assert.ok(scheduler.lastDelay() <= 15000, `failure ${failure + 1} exceeded visible-tab recovery bound`);
    await scheduler.runNext();
  }

  assert.deepEqual(diagnostics, ['offline-one', 'offline-two', 'offline-three']);
  assert.deepEqual(changes, [{ revision: 2 }], 'first successful retry must reconcile canonical state');
  assert.ok(scheduler.lastDelay() >= 12000);
  assert.ok(scheduler.lastDelay() <= 15000, 'success must restore normal visible cadence');
  poller.stop();
});

test('failed reconciliation does not absorb a changed baseline and retries it', async () => {
  const scheduler = createScheduler();
  let attempts = 0;
  const poller = createRevisionPoller({
    fetchSnapshot: async () => ({ revision: 2 }),
    onChange: async () => {
      if (attempts++ === 0) throw new Error('refresh failed');
    },
    notifyOnBaseline: true,
    scheduler,
    visibility: createVisibility(),
    random: () => 0,
  });

  await poller.start();
  await poller.pollNow();

  assert.equal(attempts, 2);
  poller.stop();
});

test('concurrent manual and scheduled checks share one in-flight snapshot request', async () => {
  const scheduler = createScheduler();
  const request = deferred();
  let fetches = 0;
  const poller = createRevisionPoller({
    fetchSnapshot: async () => {
      fetches += 1;
      return request.promise;
    },
    onChange: async () => {},
    scheduler,
    visibility: createVisibility(),
  });

  const start = poller.start();
  const manual = poller.pollNow();
  assert.equal(fetches, 1);
  request.resolve({ revision: 1 });
  await Promise.all([start, manual]);

  assert.equal(fetches, 1);
  poller.stop();
});

test('stop cancels pending work and ignores a late snapshot completion', async () => {
  const scheduler = createScheduler();
  const request = deferred();
  let reconciliations = 0;
  const poller = createRevisionPoller({
    fetchSnapshot: async () => request.promise,
    onChange: async () => { reconciliations += 1; },
    notifyOnBaseline: true,
    scheduler,
    visibility: createVisibility(),
  });

  const start = poller.start();
  poller.stop();
  request.resolve({ revision: 1 });
  await start;

  assert.equal(reconciliations, 0);
  assert.equal(scheduler.tasks.filter((task) => !task.cancelled).length, 0);
});

test('reconciliation receives the active abort signal so page refreshes stop on unmount', async () => {
  const scheduler = createScheduler();
  let reconciliationSignal;
  const poller = createRevisionPoller({
    fetchSnapshot: async () => ({ revision: 1 }),
    onChange: async (_next, _previous, { signal }) => {
      reconciliationSignal = signal;
      await new Promise(() => {});
    },
    notifyOnBaseline: true,
    scheduler,
    visibility: createVisibility(),
  });

  void poller.start();
  await Promise.resolve();
  assert.equal(reconciliationSignal?.aborted, false);

  poller.stop();
  assert.equal(reconciliationSignal.aborted, true);
});

test('a reconciliation timeout aborts its work, releases the poller, and retries inside the visible cadence', async () => {
  const scheduler = createScheduler();
  let reconciliationSignal;
  const poller = createRevisionPoller({
    fetchSnapshot: async () => ({ revision: 1 }),
    onChange: async (_next, _previous, { signal }) => {
      reconciliationSignal = signal;
      await new Promise(() => {});
    },
    notifyOnBaseline: true,
    reconciliationTimeoutMs: 100,
    scheduler,
    reconciliationScheduler: scheduler,
    visibility: createVisibility(),
    random: () => 0,
  });

  const start = poller.start();
  await Promise.resolve();
  const deadline = scheduler.tasks.find((task) => task.delay === 100 && !task.cancelled);
  assert.ok(deadline, 'reconciliation must own a bounded deadline');

  await deadline.callback();
  await start;

  assert.equal(reconciliationSignal.aborted, true);
  assert.ok(scheduler.lastDelay() >= 12000);
  assert.ok(scheduler.lastDelay() <= 15000);
  poller.stop();
});

test('repeated reconciliation timeouts use a longer deterministic backoff after the first retry', async () => {
  const scheduler = createScheduler();
  const poller = createRevisionPoller({
    fetchSnapshot: async () => ({ revision: 1 }),
    onChange: async () => new Promise(() => {}),
    notifyOnBaseline: true,
    reconciliationTimeoutMs: 100,
    reconciliationTimeoutBackoffThreshold: 2,
    reconciliationTimeoutBackoffBaseMs: 30000,
    reconciliationTimeoutBackoffMaxMs: 120000,
    reconciliationTimeoutBackoffJitterRatio: 0.2,
    scheduler,
    reconciliationScheduler: scheduler,
    visibility: createVisibility(),
    random: () => 0,
  });

  const start = poller.start();
  await Promise.resolve();
  await scheduler.tasks.find((task) => task.delay === 100 && !task.cancelled).callback();
  await start;
  const firstRetryDelay = scheduler.lastDelay();
  assert.ok(firstRetryDelay >= 12000 && firstRetryDelay <= 15000,
    'the first timeout must retain healthy recovery cadence');

  const firstRetry = scheduler.tasks.find((task) => task.delay === firstRetryDelay && !task.cancelled);
  const retryWork = firstRetry.callback();
  await Promise.resolve();
  await scheduler.tasks.find((task) => task.delay === 100 && !task.cancelled).callback();
  await retryWork;

  assert.equal(scheduler.lastDelay(), 24000, 'second timeout uses 30s base with deterministic -20% jitter');
  poller.stop();
});

test('a non-timeout failure resets the reconciliation-timeout streak and keeps network cadence unchanged', async () => {
  const scheduler = createScheduler();
  let attempt = 0;
  const poller = createRevisionPoller({
    fetchSnapshot: async () => ({ revision: 1 }),
    onChange: async () => {
      attempt += 1;
      if (attempt === 1) return new Promise(() => {});
      throw new Error('ordinary reconciliation failure');
    },
    notifyOnBaseline: true,
    reconciliationTimeoutMs: 100,
    reconciliationTimeoutBackoffThreshold: 2,
    reconciliationTimeoutBackoffBaseMs: 30000,
    intervalMs: 1000,
    maxIntervalMs: 8000,
    scheduler,
    reconciliationScheduler: scheduler,
    visibility: createVisibility(),
    random: () => 0,
  });

  const start = poller.start();
  await Promise.resolve();
  await scheduler.tasks.find((task) => task.delay === 100 && !task.cancelled).callback();
  await start;
  assert.equal(scheduler.lastDelay(), 2000);

  await scheduler.runNext();
  assert.equal(attempt, 2);
  assert.equal(scheduler.lastDelay(), 2000, 'ordinary failures restart their unchanged backoff sequence');
  poller.stop();
});

test('a timed-out baseline remains pending until a later reconciliation succeeds', async () => {
  const scheduler = createScheduler();
  let attempts = 0;
  const previousSnapshots = [];
  const poller = createRevisionPoller({
    fetchSnapshot: async () => ({ revision: 1 }),
    onChange: async (_next, previous) => {
      attempts += 1;
      previousSnapshots.push(previous);
      if (attempts === 1) await new Promise(() => {});
    },
    notifyOnBaseline: true,
    reconciliationTimeoutMs: 100,
    scheduler,
    reconciliationScheduler: scheduler,
    visibility: createVisibility(),
    random: () => 0,
  });

  const start = poller.start();
  await Promise.resolve();
  await scheduler.tasks.find((task) => task.delay === 100 && !task.cancelled).callback();
  await start;
  await scheduler.runNext();

  assert.equal(attempts, 2);
  assert.deepEqual(previousSnapshots, [undefined, undefined]);
  poller.stop();
});

test('a late timed-out reconciliation cannot accept a stale baseline', async () => {
  const scheduler = createScheduler();
  const firstReconciliation = deferred();
  let attempts = 0;
  const previousSnapshots = [];
  const poller = createRevisionPoller({
    fetchSnapshot: async () => ({ revision: 1 }),
    onChange: async (_next, previous) => {
      attempts += 1;
      previousSnapshots.push(previous);
      if (attempts === 1) await firstReconciliation.promise;
    },
    notifyOnBaseline: true,
    reconciliationTimeoutMs: 100,
    scheduler,
    reconciliationScheduler: scheduler,
    visibility: createVisibility(),
    random: () => 0,
  });

  const start = poller.start();
  await Promise.resolve();
  await scheduler.tasks.find((task) => task.delay === 100 && !task.cancelled).callback();
  await start;
  firstReconciliation.resolve();
  await Promise.resolve();
  await scheduler.runNext();

  assert.equal(attempts, 2);
  assert.deepEqual(previousSnapshots, [undefined, undefined]);
  poller.stop();
});

test('a reconciliation completing before its deadline preserves normal successful polling', async () => {
  const scheduler = createScheduler();
  const reconciliation = deferred();
  const changes = [];
  const poller = createRevisionPoller({
    fetchSnapshot: async () => ({ revision: 1 }),
    onChange: async (next) => {
      changes.push(next);
      await reconciliation.promise;
    },
    notifyOnBaseline: true,
    reconciliationTimeoutMs: 100,
    scheduler,
    reconciliationScheduler: scheduler,
    visibility: createVisibility(),
    random: () => 0,
  });

  const start = poller.start();
  await Promise.resolve();
  reconciliation.resolve();
  await start;

  assert.deepEqual(changes, [{ revision: 1 }]);
  assert.ok(scheduler.lastDelay() >= 12000);
  assert.ok(scheduler.lastDelay() <= 15000);
  assert.equal(scheduler.tasks.some((task) => task.delay === 100 && !task.cancelled), false);
  poller.stop();
});

test('hiding a tab aborts an active reconciliation without leaving a retry timer', async () => {
  const scheduler = createScheduler();
  const visibility = createVisibility();
  let reconciliationSignal;
  const poller = createRevisionPoller({
    fetchSnapshot: async () => ({ revision: 1 }),
    onChange: async (_next, _previous, { signal }) => {
      reconciliationSignal = signal;
      await new Promise(() => {});
    },
    notifyOnBaseline: true,
    reconciliationTimeoutMs: 100,
    scheduler,
    reconciliationScheduler: scheduler,
    visibility,
  });

  const start = poller.start();
  await Promise.resolve();
  visibility.set('hidden');
  await start;

  assert.equal(reconciliationSignal.aborted, true);
  assert.equal(scheduler.tasks.filter((task) => !task.cancelled).length, 0);
  poller.stop();
});

test('hidden tabs make no periodic request and returning to visible polls immediately', async () => {
  const visibility = createVisibility('hidden');
  const fixture = createFixture({ snapshots: [{ revision: 1 }], visibility });

  await fixture.poller.start();
  assert.equal(fixture.changes.length, 0);
  assert.equal(fixture.scheduler.tasks.filter((task) => !task.cancelled).length, 0);

  visibility.set('visible');
  await Promise.resolve();
  await Promise.resolve();
  await Promise.resolve();

  assert.deepEqual(fixture.changes, [{ next: { revision: 1 }, previous: undefined }]);
  assert.ok(fixture.scheduler.lastDelay() <= 15000);
  fixture.poller.stop();
});

test('failures use bounded exponential backoff and a successful retry restores visible cadence', async () => {
  const scheduler = createScheduler();
  const snapshots = [new Error('one'), new Error('two'), new Error('three'), { revision: 1 }];
  const poller = createRevisionPoller({
    fetchSnapshot: async () => {
      const next = snapshots.shift();
      if (next instanceof Error) throw next;
      return next;
    },
    onChange: async () => {},
    intervalMs: 1000,
    maxIntervalMs: 8000,
    scheduler,
    visibility: createVisibility(),
    random: () => 0,
  });

  await poller.start();
  assert.equal(scheduler.lastDelay(), 2000);
  await scheduler.runNext();
  assert.equal(scheduler.lastDelay(), 4000);
  await scheduler.runNext();
  assert.equal(scheduler.lastDelay(), 8000);
  await scheduler.runNext();
  assert.equal(scheduler.lastDelay(), 1000);
  poller.stop();
});

test('reconciliation guard rejects a poll made stale by newer foreground progress', () => {
  assert.equal(typeof createReconciliationGuard, 'function');
  const guard = createReconciliationGuard();
  const token = guard.capture('progress');
  let applied = false;

  guard.mark('progress');

  assert.throws(
    () => guard.commit('progress', token, () => { applied = true; }),
    (error) => error.code === 'STALE_RECONCILIATION'
  );
  assert.equal(applied, false);
  const current = guard.capture('progress');
  guard.commit('progress', current, () => { applied = true; });
  assert.equal(applied, true);
});

test('request-start sequencing rejects delayed mount and poll responses in both directions', () => {
  const guard = createReconciliationGuard();
  let value = 'initial';

  const mount = guard.begin('progress');
  const newerPoll = guard.begin('progress');
  guard.commit('progress', newerPoll, () => { value = 'poll'; });
  assert.throws(
    () => guard.commit('progress', mount, () => { value = 'stale mount'; }),
    (error) => error.code === 'STALE_RECONCILIATION'
  );

  const oldPoll = guard.begin('progress');
  const newerMount = guard.begin('progress');
  guard.commit('progress', newerMount, () => { value = 'mount'; });
  assert.throws(
    () => guard.commit('progress', oldPoll, () => { value = 'stale poll'; }),
    (error) => error.code === 'STALE_RECONCILIATION'
  );
  assert.equal(value, 'mount');
});

test('foreground mode mutation owns the domain until it settles', () => {
  const guard = createReconciliationGuard();
  const state = { mode: 'fixed', userErrors: [] };

  const olderPoll = guard.beginBackground('mode');
  const toggle = guard.beginForeground('mode');
  assert.equal(guard.beginBackground('mode'), null);

  assert.throws(
    () => guard.commit('mode', olderPoll, () => { state.mode = 'fixed'; }),
    (error) => error.code === 'STALE_RECONCILIATION'
  );
  guard.commit('mode', toggle, () => { state.mode = 'vuln'; });
  guard.endForeground('mode', toggle);

  const laterPoll = guard.beginBackground('mode');
  guard.commit('mode', laterPoll, () => { state.mode = 'vuln'; });
  assert.deepEqual(state, { mode: 'vuln', userErrors: [] });
});

test('overlapping foreground mutations release only their own ownership', () => {
  const guard = createReconciliationGuard();
  const first = guard.beginForeground('mode');
  const second = guard.beginForeground('mode');

  guard.endForeground('mode', first);
  assert.equal(guard.beginBackground('mode'), null);
  guard.endForeground('mode', second);
  assert.notEqual(guard.beginBackground('mode'), null);
});

test('foreground completion invalidates delayed mount and poll requests', () => {
  const guard = createReconciliationGuard();
  let value = 'initial';
  const mount = guard.begin('progress');
  const poll = guard.begin('progress');

  guard.mark('progress');
  value = 'foreground';

  for (const token of [mount, poll]) {
    assert.throws(
      () => guard.commit('progress', token, () => { value = 'stale'; }),
      (error) => error.code === 'STALE_RECONCILIATION'
    );
  }
  assert.equal(value, 'foreground');
});

test('multi-slice reconciliation validates every token before applying atomically', () => {
  const guard = createReconciliationGuard();
  const tokens = {
    progress: guard.begin('progress'),
    gates: guard.begin('gates'),
  };
  let applied = false;
  guard.mark('gates');
  assert.throws(
    () => guard.commitAll(tokens, () => { applied = true; }),
    (error) => error.code === 'STALE_RECONCILIATION'
  );
  assert.equal(applied, false);
});

test('stale reconciliation is a neutral conflict that keeps the baseline and normal cadence', async () => {
  const scheduler = createScheduler();
  const diagnostics = [];
  let attempts = 0;
  const poller = createRevisionPoller({
    fetchSnapshot: async () => ({ revision: 2 }),
    onChange: async () => {
      attempts += 1;
      if (attempts === 1) {
        const error = new Error('foreground won');
        error.code = 'STALE_RECONCILIATION';
        throw error;
      }
    },
    onError: (error) => diagnostics.push(error.message),
    notifyOnBaseline: true,
    intervalMs: 12000,
    maxIntervalMs: 120000,
    scheduler,
    visibility: createVisibility(),
    random: () => 0.9999,
  });

  await poller.start();
  assert.ok(scheduler.lastDelay() <= 15000, 'stale conflict must retry at normal visible cadence');
  assert.deepEqual(diagnostics, [], 'stale conflict must stay out of failure diagnostics');

  await scheduler.runNext();
  assert.equal(attempts, 2, 'unchanged baseline must be retried after the stale conflict');
  assert.ok(scheduler.lastDelay() <= 15000);
  poller.stop();
});

test('mode revision skipped during a failed foreground mutation is retried after release', async () => {
  const scheduler = createScheduler();
  const guard = createReconciliationGuard();
  const foreground = guard.beginForeground('mode');
  let reconciliations = 0;
  let appliedMode = 'fixed';
  const poller = createRevisionPoller({
    fetchSnapshot: async () => ({ user: { workshop_mode: 2 } }),
    onChange: async () => {
      reconciliations += 1;
      const token = guard.beginRequiredBackground('mode');
      guard.commit('mode', token, () => { appliedMode = 'vuln'; });
    },
    notifyOnBaseline: true,
    intervalMs: 12000,
    scheduler,
    visibility: createVisibility(),
    random: () => 0.9999,
  });

  await poller.start();
  assert.equal(reconciliations, 1);
  assert.equal(appliedMode, 'fixed');

  guard.endForeground('mode', foreground);
  await scheduler.runNext();
  assert.equal(reconciliations, 2, 'the rejected revision must remain pending');
  assert.equal(appliedMode, 'vuln');
  poller.stop();
});

test('poll-owned disclosure refresh replaces a pending request while close still wins', () => {
  const guard = createReconciliationGuard();
  let pendingId = 'objective-1';
  let rendered = null;

  const manual = guard.begin('solutionModal');
  const disclosureId = rendered?.id || pendingId;
  const poll = guard.begin('solutionModal');
  guard.commit('solutionModal', poll, () => {
    pendingId = null;
    rendered = { id: disclosureId, content: 'edited canonical content' };
  });
  assert.throws(
    () => guard.commit('solutionModal', manual, () => { rendered = { id: disclosureId, content: 'old content' }; }),
    (error) => error.code === 'STALE_RECONCILIATION'
  );
  assert.equal(rendered.content, 'edited canonical content');

  const laterPoll = guard.begin('solutionModal');
  guard.mark('solutionModal');
  rendered = null;
  assert.throws(
    () => guard.commit('solutionModal', laterPoll, () => { rendered = { id: disclosureId }; }),
    (error) => error.code === 'STALE_RECONCILIATION'
  );
  assert.equal(rendered, null);
});

test('MCP solution and hint disclosures reconcile independently', () => {
  const guard = createReconciliationGuard();
  const content = { solution: 'old solution', hint: 'old hint' };
  const solutionToken = guard.begin('solutionModal');
  const hintToken = guard.begin('hintModal');

  guard.commit('solutionModal', solutionToken, () => { content.solution = 'new solution'; });
  guard.commit('hintModal', hintToken, () => { content.hint = 'new hint'; });

  assert.deepEqual(content, { solution: 'new solution', hint: 'new hint' });
});
