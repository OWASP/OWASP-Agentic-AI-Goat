const test = require('node:test');
const assert = require('node:assert/strict');

const {
  createLeaderboardRefreshCoordinator,
} = require('../server/services/ctfLeaderboardRefreshCoordinator');

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
  const timeouts = [];
  const intervals = [];
  return {
    timeouts,
    intervals,
    setTimeout(callback, delay) {
      const task = { callback, delay, cancelled: false, unref() {} };
      timeouts.push(task);
      return task;
    },
    clearTimeout(task) {
      if (task) task.cancelled = true;
    },
    setInterval(callback, delay) {
      const task = { callback, delay, cancelled: false, unref() {} };
      intervals.push(task);
      return task;
    },
    clearInterval(task) {
      if (task) task.cancelled = true;
    },
    async runNextTimeout() {
      const index = timeouts.findIndex((task) => !task.cancelled);
      assert.notEqual(index, -1, 'expected a scheduled leaderboard refresh');
      const [task] = timeouts.splice(index, 1);
      await task.callback();
      return task;
    },
    async fireInterval(index = 0) {
      const task = intervals[index];
      assert.ok(task && !task.cancelled, 'expected an active reconciliation interval');
      await task.callback();
    },
    activeTimeouts() {
      return timeouts.filter((task) => !task.cancelled);
    },
    activeIntervals() {
      return intervals.filter((task) => !task.cancelled);
    },
  };
}

test('mutation bursts coalesce into one leaderboard recomputation', async () => {
  const scheduler = createScheduler();
  let updates = 0;
  const coordinator = createLeaderboardRefreshCoordinator({
    updateLeaderboard: async () => { updates += 1; },
    scheduler,
    debounceMs: 250,
  });

  coordinator.start();
  await scheduler.runNextTimeout();
  updates = 0;

  coordinator.requestRefresh();
  coordinator.requestRefresh();
  coordinator.requestRefresh();

  assert.equal(scheduler.activeTimeouts().length, 1);
  await scheduler.runNextTimeout();
  assert.equal(updates, 1);
  coordinator.stop();
});

test('mutation during recomputation produces exactly one follow-up', async () => {
  const scheduler = createScheduler();
  const firstRun = deferred();
  let updates = 0;
  const coordinator = createLeaderboardRefreshCoordinator({
    updateLeaderboard: async () => {
      updates += 1;
      if (updates === 1) await firstRun.promise;
    },
    scheduler,
  });

  coordinator.start();
  const runningFlush = scheduler.runNextTimeout();
  await new Promise((resolve) => setImmediate(resolve));
  coordinator.requestRefresh();
  coordinator.requestRefresh();
  assert.equal(scheduler.activeTimeouts().length, 0);

  firstRun.resolve();
  await runningFlush;
  assert.equal(scheduler.activeTimeouts().length, 1);
  await scheduler.runNextTimeout();
  assert.equal(updates, 2);
  coordinator.stop();
});

test('failed recomputation stays dirty and retries after bounded delay', async () => {
  const scheduler = createScheduler();
  let updates = 0;
  const errors = [];
  const coordinator = createLeaderboardRefreshCoordinator({
    updateLeaderboard: async () => {
      updates += 1;
      if (updates === 1) throw new Error('temporary sqlite contention');
    },
    scheduler,
    retryMs: 5000,
    logger: { error: (...args) => errors.push(args) },
  });

  coordinator.start();
  await scheduler.runNextTimeout();

  assert.equal(errors.length, 1);
  assert.equal(coordinator.getState().dirty, true);
  assert.equal(scheduler.activeTimeouts().length, 1);
  assert.equal(scheduler.activeTimeouts()[0].delay, 5000);

  await scheduler.runNextTimeout();
  assert.equal(updates, 2);
  assert.deepEqual(coordinator.getState(), {
    started: true,
    dirty: false,
    running: false,
  });
  coordinator.stop();
});

test('foreground flush can require recomputation success while retaining background retry', async () => {
  const scheduler = createScheduler();
  const failure = new Error('sqlite write failed');
  const coordinator = createLeaderboardRefreshCoordinator({
    updateLeaderboard: async () => { throw failure; },
    scheduler,
    retryMs: 5000,
    logger: { error() {} },
  });

  coordinator.start();
  await assert.rejects(
    coordinator.flush({ throwOnError: true }),
    (error) => error === failure,
  );

  assert.equal(coordinator.getState().dirty, true);
  assert.equal(scheduler.activeTimeouts().length, 1);
  assert.equal(scheduler.activeTimeouts()[0].delay, 5000);
  coordinator.stop();
});

test('start performs one initial refresh and owns one periodic reconciliation', async () => {
  const scheduler = createScheduler();
  let updates = 0;
  const coordinator = createLeaderboardRefreshCoordinator({
    updateLeaderboard: async () => { updates += 1; },
    scheduler,
    reconcileMs: 60000,
  });

  coordinator.start();
  coordinator.start();
  assert.equal(scheduler.activeIntervals().length, 1);
  assert.equal(scheduler.activeIntervals()[0].delay, 60000);
  assert.equal(scheduler.activeTimeouts().length, 1);

  await scheduler.runNextTimeout();
  assert.equal(updates, 1);

  await scheduler.fireInterval();
  assert.equal(scheduler.activeTimeouts().length, 1);
  await scheduler.runNextTimeout();
  assert.equal(updates, 2);

  coordinator.stop();
  assert.equal(scheduler.activeIntervals().length, 0);
  assert.equal(scheduler.activeTimeouts().length, 0);
});

test('explicit flush consumes a scheduled refresh without duplicate work', async () => {
  const scheduler = createScheduler();
  let updates = 0;
  const coordinator = createLeaderboardRefreshCoordinator({
    updateLeaderboard: async () => { updates += 1; },
    scheduler,
  });

  coordinator.start();
  await coordinator.flush();

  assert.equal(updates, 1);
  assert.equal(scheduler.activeTimeouts().length, 0);
  coordinator.stop();
});

test('explicit flush during a run drains the current run and one dirty follow-up', async () => {
  const scheduler = createScheduler();
  const firstRun = deferred();
  let updates = 0;
  const coordinator = createLeaderboardRefreshCoordinator({
    updateLeaderboard: async () => {
      updates += 1;
      if (updates === 1) await firstRun.promise;
    },
    scheduler,
  });

  coordinator.start();
  const periodicFlush = scheduler.runNextTimeout();
  await new Promise((resolve) => setImmediate(resolve));
  coordinator.requestRefresh();
  const synchronousFlush = coordinator.flush();

  firstRun.resolve();
  await Promise.all([periodicFlush, synchronousFlush]);

  assert.equal(updates, 2);
  assert.equal(scheduler.activeTimeouts().length, 0);
  assert.equal(coordinator.getState().dirty, false);
  coordinator.stop();
});

test('concurrent required flush callers both await the same dirty follow-up', async () => {
  const scheduler = createScheduler();
  const firstRun = deferred();
  const secondRun = deferred();
  let updates = 0;
  let settled = 0;
  const coordinator = createLeaderboardRefreshCoordinator({
    updateLeaderboard: async () => {
      updates += 1;
      if (updates === 1) await firstRun.promise;
      if (updates === 2) await secondRun.promise;
    },
    scheduler,
  });

  coordinator.start();
  const background = scheduler.runNextTimeout();
  await new Promise((resolve) => setImmediate(resolve));
  coordinator.requestRefresh();
  const foregroundOne = coordinator.flush({ throwOnError: true }).then(() => { settled += 1; });
  const foregroundTwo = coordinator.flush({ throwOnError: true }).then(() => { settled += 1; });

  firstRun.resolve();
  while (updates < 2) await new Promise((resolve) => setImmediate(resolve));
  assert.equal(settled, 0, 'neither required caller may resolve before follow-up finishes');

  secondRun.resolve();
  await Promise.all([background, foregroundOne, foregroundTwo]);
  assert.equal(settled, 2);
  assert.equal(updates, 2);
  coordinator.stop();
});

test('concurrent required flush callers share a follow-up failure and retain background retry', async () => {
  const scheduler = createScheduler();
  const firstRun = deferred();
  const failure = new Error('follow-up sqlite write failed');
  let updates = 0;
  const coordinator = createLeaderboardRefreshCoordinator({
    updateLeaderboard: async () => {
      updates += 1;
      if (updates === 1) await firstRun.promise;
      if (updates === 2) throw failure;
    },
    scheduler,
    retryMs: 5000,
    logger: { error() {} },
  });

  coordinator.start();
  const background = scheduler.runNextTimeout();
  await new Promise((resolve) => setImmediate(resolve));
  coordinator.requestRefresh();
  const foregroundOne = coordinator.flush({ throwOnError: true });
  const foregroundTwo = coordinator.flush({ throwOnError: true });

  firstRun.resolve();
  const results = await Promise.allSettled([foregroundOne, foregroundTwo]);
  await background;

  assert.deepEqual(results.map((result) => result.status), ['rejected', 'rejected']);
  assert.equal(results[0].reason, failure);
  assert.equal(results[1].reason, failure);
  assert.equal(updates, 2);
  assert.equal(coordinator.getState().dirty, true);
  assert.equal(scheduler.activeTimeouts().length, 1);
  assert.equal(scheduler.activeTimeouts()[0].delay, 5000);
  coordinator.stop();
});

test('stop during recomputation prevents follow-up scheduling and restart is clean', async () => {
  const scheduler = createScheduler();
  const firstRun = deferred();
  let updates = 0;
  const coordinator = createLeaderboardRefreshCoordinator({
    updateLeaderboard: async () => {
      updates += 1;
      if (updates === 1) await firstRun.promise;
    },
    scheduler,
  });

  coordinator.start();
  const runningFlush = scheduler.runNextTimeout();
  await new Promise((resolve) => setImmediate(resolve));
  coordinator.requestRefresh();
  coordinator.stop();
  firstRun.resolve();
  await runningFlush;

  assert.deepEqual(coordinator.getState(), {
    started: false,
    dirty: false,
    running: false,
  });
  assert.equal(scheduler.activeTimeouts().length, 0);
  assert.equal(scheduler.activeIntervals().length, 0);

  coordinator.start();
  assert.equal(scheduler.activeTimeouts().length, 1);
  assert.equal(scheduler.activeIntervals().length, 1);
  await scheduler.runNextTimeout();
  assert.equal(updates, 2);
  coordinator.stop();
});
