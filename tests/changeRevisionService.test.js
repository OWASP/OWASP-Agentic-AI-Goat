const test = require('node:test');
const assert = require('node:assert/strict');

const { createChangeRevisionService } = require('../server/services/changeRevisionServiceFactory');

function createScheduler(tasks) {
  return {
    setTimeout(callback, delay) {
      const task = { callback, delay, unref() {} };
      tasks.push(task);
      return task;
    },
  };
}

test('service records a persisted global restart revision before serving snapshots', async () => {
  const calls = [];
  const service = createChangeRevisionService({
    async initialize() { calls.push('initialize'); },
    async bump(change) { calls.push(['bump', change]); },
    async getSnapshot() { calls.push('snapshot'); return { global: {} }; },
  });

  await service.getSnapshot({ userId: 101, workshopKeys: [] });
  assert.deepEqual(calls, [
    'initialize',
    ['bump', { scopeType: 'global', scopeKey: '*', category: 'server_restart' }],
    'snapshot',
  ]);
});

test('failed restart signals retry with bounded backoff without blocking revision reads', async () => {
  const tasks = [];
  let attempts = 0;
  const service = createChangeRevisionService({
    async initialize() {},
    async bump() {
      attempts += 1;
      if (attempts < 3) throw new Error('database busy');
    },
    async getSnapshot() { return { global: {} }; },
  }, { error() {} }, createScheduler(tasks));

  assert.deepEqual(await service.getSnapshot({ userId: 101, workshopKeys: [] }), { global: {} });
  const firstRetry = tasks.shift();
  assert.equal(firstRetry.delay, 1000);
  await firstRetry.callback();
  assert.equal(tasks.length, 1);
  const secondRetry = tasks.shift();
  assert.equal(secondRetry.delay, 2000);
  await secondRetry.callback();
  assert.equal(attempts, 3);
  assert.equal(tasks.length, 0);
});

test('a transient initialization failure retries once for concurrent later callers and preserves revision behavior', async () => {
  let initializeAttempts = 0;
  let releaseRetry;
  let beginRetry;
  const retryStarted = new Promise((resolve) => { beginRetry = resolve; });
  const retryRelease = new Promise((resolve) => { releaseRetry = resolve; });
  const bumps = [];
  let snapshotCalls = 0;
  const service = createChangeRevisionService({
    async initialize() {
      initializeAttempts += 1;
      if (initializeAttempts === 1) throw new Error('temporary database contention');
      beginRetry();
      await retryRelease;
    },
    async bump(change) { bumps.push(change); },
    async getSnapshot() {
      snapshotCalls += 1;
      return { global: { server_restart: 1 }, workshops: {}, user: {} };
    },
  });

  await assert.rejects(
    service.getSnapshot({ userId: 101, workshopKeys: [] }),
    /temporary database contention/
  );
  assert.equal(initializeAttempts, 1);
  assert.equal(snapshotCalls, 0);

  const snapshot = service.getSnapshot({ userId: 101, workshopKeys: [] });
  await retryStarted;
  const change = { scopeType: 'global', scopeKey: '*', category: 'admin_visibility' };
  const bumped = service.bump(change);
  releaseRetry();

  assert.deepEqual(await snapshot, { global: { server_restart: 1 }, workshops: {}, user: {} });
  await bumped;
  await service.getSnapshot({ userId: 101, workshopKeys: [] });

  assert.equal(initializeAttempts, 2, 'successful initialization must not rerun');
  assert.equal(snapshotCalls, 2);
  assert.deepEqual(bumps, [
    { scopeType: 'global', scopeKey: '*', category: 'server_restart' },
    change,
  ]);
});

test('repeated initialization failures are returned to callers without background retry or unhandled rejections', async (t) => {
  const errors = [];
  const onUnhandledRejection = (reason) => errors.push(reason);
  process.on('unhandledRejection', onUnhandledRejection);
  t.after(() => process.off('unhandledRejection', onUnhandledRejection));

  let initializeAttempts = 0;
  const service = createChangeRevisionService({
    async initialize() {
      initializeAttempts += 1;
      throw new Error(`database unavailable (${initializeAttempts})`);
    },
    async bump() { throw new Error('must not bump before initialization'); },
    async getSnapshot() { throw new Error('must not read before initialization'); },
  });

  await assert.rejects(
    service.getSnapshot({ userId: 101, workshopKeys: [] }),
    /database unavailable \(1\)/
  );
  await assert.rejects(
    service.bump({ scopeType: 'global', scopeKey: '*', category: 'admin_visibility' }),
    /database unavailable \(2\)/
  );
  await new Promise((resolve) => setImmediate(resolve));

  assert.equal(initializeAttempts, 2);
  assert.deepEqual(errors, []);
});
