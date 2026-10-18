'use strict';

// Controlled finite pools only: no PostgreSQL, model, browser or application.
const test = require('node:test');
const assert = require('node:assert/strict');
const { createSecureShopSceneRepository } = require('../server/database/postgres/secureshopSceneRepository');
const SCOPE = Object.freeze({ launchId: '11111111-1111-4111-8111-111111111111',
  scenarioId: '22222222-2222-4222-8222-222222222222', generation: 1,
  platformOwnerId: 31, platformSessionId: 41 });
const deferred = () => { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; };
const tick = () => new Promise(resolve => setImmediate(resolve));

function finitePool(max, execute = async () => ({ rows: [], rowCount: 1 })) {
  const waiting = [], calls = [];
  let active = 0, peak = 0, acquired = 0;
  function checkout(resolve) {
    active++; acquired++; peak = Math.max(peak, active);
    assert.ok(active <= max);
    let released = false;
    resolve({ async query(sql, args) {
      assert.equal(released, false);
      calls.push({ sql, args });
      return execute(sql, args);
    }, release() {
      assert.equal(released, false, 'client must be released exactly once');
      released = true; active--;
      if (waiting.length) checkout(waiting.shift());
    } });
  }
  const pool = { options: { max }, connect: () => new Promise(resolve => {
    if (active < max) checkout(resolve); else waiting.push(resolve);
  }), async query(sql, args) {
    const client = await pool.connect();
    try { return await client.query(sql, args); } finally { client.release(); }
  } };
  return { pool, calls, get active() { return active; }, get queued() { return waiting.length; },
    get peak() { return peak; }, get acquired() { return acquired; } };
}

test('provision holder completes with control capacity available while provisioning waiters and graph leases are occupied',
  { timeout: 2000 }, async () => {
    const control = finitePool(1), provision = finitePool(1), graph = finitePool(2);
    const graphClients = await Promise.all([graph.pool.connect(), graph.pool.connect()]);
    const repository = createSecureShopSceneRepository({ pool: control.pool,
      provisionPool: provision.pool, launches: { assertCurrent: async () => {} } });
    const entered = deferred(), continueHolder = deferred(), order = [];
    const first = repository.withProvisionLease(SCOPE, async () => {
      entered.resolve(); await continueHolder.promise;
      await control.pool.query('holder owned scene query');
      await repository.withProvisionLease(SCOPE, async () => {
        await control.pool.query('nested owned scene query'); order.push('nested');
      });
      await assert.rejects(repository.withProvisionLease({ ...SCOPE, platformOwnerId: 32 },
        async () => { throw Error('foreign nested work must not execute'); }), { code: 'SHOP_SCENE_STALE' });
      order.push('holder'); return 'first';
    });
    await entered.promise;
    const second = repository.withProvisionLease(SCOPE, async () => {
      await control.pool.query('waiter owned scene query'); order.push('waiter'); return 'second';
    });
    await tick();
    assert.equal(provision.active, 1); assert.equal(provision.queued, 1);
    assert.equal(control.active, 0); assert.equal(control.queued, 0);
    assert.equal(graph.active, 2); assert.equal(graph.acquired, 2);
    continueHolder.resolve();
    assert.deepEqual(await Promise.all([first, second]), ['first', 'second']);
    assert.deepEqual(order, ['nested', 'holder', 'waiter']);
    assert.equal(provision.acquired, 2, 'nested same-owner lease must reuse ALS');
    assert.equal(provision.peak, 1); assert.equal(provision.active, 0);
    assert.equal(control.peak, 1); assert.equal(control.active, 0);
    assert.equal(graph.active, 2, 'progress must not depend on releasing graph lease clients');
    const locks = provision.calls.filter(call => call.sql.includes('pg_advisory_xact_lock'));
    assert.equal(locks.length, 2);
    for (const lock of locks) {
      assert.equal(lock.sql, "SELECT pg_advisory_xact_lock(hashtextextended('secureshop-store-provision:'||$1::text,0))");
      assert.deepEqual(lock.args, [SCOPE.platformOwnerId]);
    }
    assert.equal(provision.calls.filter(call => call.sql === "SET LOCAL lock_timeout='10s'").length, 2);
    const checks = provision.calls.filter(call => call.sql.includes('SELECT l.launch_id'));
    assert.equal(checks.length, 4, 'both holders retain pre- and post-work authority checks');
    for (const check of checks) assert.deepEqual(check.args,
      [SCOPE.launchId, SCOPE.scenarioId, SCOPE.generation, SCOPE.platformOwnerId, SCOPE.platformSessionId]);
    assert.equal(control.calls.some(call => call.sql.includes('pg_advisory')), false);
    graphClients.forEach(client => client.release());
  });

test('provision authority revocation rolls back on the dedicated pool before or after work', async () => {
  for (const deniedCheck of [1, 2]) {
    let checks = 0, worked = false;
    const control = finitePool(1), provision = finitePool(1, async sql => {
      if (sql.includes('SELECT l.launch_id')) return { rows: [], rowCount: ++checks === deniedCheck ? 0 : 1 };
      return { rows: [], rowCount: 1 };
    });
    const repository = createSecureShopSceneRepository({ pool: control.pool,
      provisionPool: provision.pool, launches: { assertCurrent: async () => {} } });
    await assert.rejects(repository.withProvisionLease(SCOPE, async () => { worked = true; }),
      { code: 'SHOP_SCENE_STALE' });
    assert.equal(worked, deniedCheck === 2);
    assert.equal(provision.active, 0); assert.equal(control.acquired, 0);
    assert.equal(provision.calls.at(-1).sql, 'ROLLBACK');
    assert.equal(provision.calls.some(call => call.sql === 'COMMIT'), false);
  }
});

test('omitted provision pool preserves the legacy authority transaction', async () => {
  const control = finitePool(1);
  const repository = createSecureShopSceneRepository({ pool: control.pool,
    launches: { assertCurrent: async () => {} } });
  assert.equal(await repository.withProvisionLease(SCOPE, async () => 'retained'), 'retained');
  assert.equal(control.acquired, 1); assert.equal(control.active, 0);
  assert.equal(control.calls.at(-1).sql, 'COMMIT');
});

test('escaped provisioning ALS cannot authorize work after its transaction finishes', async () => {
  const control = finitePool(1), provision = finitePool(1), resume = deferred();
  const repository = createSecureShopSceneRepository({ pool: control.pool,
    provisionPool: provision.pool, launches: { assertCurrent: async () => {} } });
  let late, performed = false;
  await repository.withProvisionLease(SCOPE, async () => {
    late = resume.promise.then(() => repository.withProvisionLease(SCOPE, async () => { performed = true; }));
  });
  const denied = assert.rejects(late, { code: 'SHOP_SCENE_STALE' });
  resume.resolve(); await denied;
  assert.equal(performed, false); assert.equal(provision.acquired, 1);
  assert.equal(provision.active, 0);
});

test('dedicated provisioning allocation remains one slot and invalid pool admission fails closed', () => {
  const { poolBudget } = require('../server/database/postgres/poolBudget');
  assert.deepEqual(poolBudget({}, 'IDENTITY_DATABASE_URL', 'provision'),
    { purpose: 'provision', max: 1, budget: 78 });
  for (const value of ['0', '2', '99', 'unbounded']) assert.throws(() =>
    poolBudget({ PG_POOL_MAX_PROVISION: value }, 'IDENTITY_DATABASE_URL', 'provision'),
  /PG_POOL_MAX_PROVISION must be an integer from 1 to 1/);
  assert.throws(() => createSecureShopSceneRepository({ pool: finitePool(1).pool,
    provisionPool: {}, launches: { assertCurrent: async () => {} } }), /Scene authority required/);
  const reused = finitePool(1);
  assert.throws(() => createSecureShopSceneRepository({ pool: reused.pool,
    provisionPool: reused.pool, launches: { assertCurrent: async () => {} } }), /pool|authority/i);
});

test('supported production factory denies missing or reused provisioning pools before any checkout', async () => {
  const { createSecureShopProductionSceneRepository } = require('../server/database/postgres/secureshopSceneRepository');
  const control = finitePool(1), provision = finitePool(1), graph = finitePool(2);
  const input = { pool: control.pool, provisionPool: provision.pool, leasePool: graph.pool,
    launches: { assertCurrent: async () => {} } };
  for (const change of [{ provisionPool: undefined }, { provisionPool: control.pool },
    { provisionPool: graph.pool }, { provisionPool: {} }, { leasePool: undefined }, { pool: undefined }]) {
    assert.throws(() => createSecureShopProductionSceneRepository({ ...input, ...change }),
      /pool|authority/i);
  }
  assert.equal(control.acquired + provision.acquired + graph.acquired, 0);
  const repository = createSecureShopProductionSceneRepository(input);
  assert.equal(await repository.withProvisionLease(SCOPE, async () => {
    await control.pool.query('owned production work'); return 'completed';
  }), 'completed');
  assert.equal(provision.acquired, 1); assert.equal(control.acquired, 1);
  assert.equal(graph.acquired, 0); assert.equal(provision.active + control.active, 0);
});

test('owned provisioning pool uses runtime configuration and releases its budget exactly once', async t => {
  const { EventEmitter } = require('node:events');
  const pg = require('pg');
  const { createPool, getPoolBudgetSnapshot } = require('../server/database/postgres');
  let configured, ends = 0;
  const close = deferred();
  // Replace only the physical driver; the real allocator/idempotent owner runs.
  t.mock.method(pg, 'Pool', function ControlledPool(config) {
    configured = config;
    const pool = new EventEmitter();
    pool.end = () => { ends++; return close.promise; };
    pool.connect = () => { throw Error('No physical connections allowed'); };
    return pool;
  });
  const before = getPoolBudgetSnapshot().reserved;
  const runtime = 'postgresql://owned_runtime:controlled_only@127.0.0.1/owned_controlled';
  const pool = createPool({ IDENTITY_DATABASE_URL: runtime }, 'IDENTITY_DATABASE_URL', { purpose: 'provision' });
  assert.equal(configured.connectionString, runtime); assert.equal(configured.max, 1);
  assert.equal(getPoolBudgetSnapshot().reserved, before + 1);
  const first = pool.end(), second = pool.end();
  assert.equal(first, second); await tick(); assert.equal(ends, 1);
  assert.equal(getPoolBudgetSnapshot().reserved, before + 1, 'budget remains owned until shutdown settles');
  close.resolve(); await Promise.all([first, second]); await pool.end();
  assert.equal(ends, 1); assert.equal(getPoolBudgetSnapshot().reserved, before);
});
