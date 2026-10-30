'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { Pool } = require('pg');
const { initializeIdentityRepository } = require('../../server/database/postgres/identityRepository');
const { createPostgresRunLedger } = require('../../server/agent-runtime/postgresRunLedger');
const { createRunCoordinator } = require('../../server/agent-runtime/runCoordinator');

const enabled = process.env.PG_TEST_DISPOSABLE === 'yes'
  && process.env.PG_LEDGER_CONCURRENCY_MIGRATION_URL && process.env.PG_LEDGER_CONCURRENCY_RUNTIME_URL;
const defer = () => { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; };

test('native lease lane supports parallel effects and drains finish, failure and reset without concurrent-query warnings', {
  skip: !enabled, timeout: 120000,
}, async () => {
  for (const key of ['PG_LEDGER_CONCURRENCY_MIGRATION_URL', 'PG_LEDGER_CONCURRENCY_RUNTIME_URL']) {
    const url = new URL(process.env[key]);
    assert.ok(['127.0.0.1', 'localhost'].includes(url.hostname));
    assert.match(url.pathname, /^\/owasp_ai_goat_test_[a-z0-9_]+$/);
  }
  const migration = new Pool({ connectionString: process.env.PG_LEDGER_CONCURRENCY_MIGRATION_URL, max: 2 });
  const runtime = new Pool({ connectionString: process.env.PG_LEDGER_CONCURRENCY_RUNTIME_URL, max: 6 });
  const leases = new Pool({ connectionString: process.env.PG_LEDGER_CONCURRENCY_RUNTIME_URL, max: 3,
    application_name: 'ledger-concurrency-native' });
  const warnings = [];
  const onWarning = warning => warnings.push(String(warning?.message || warning));
  process.on('warning', onWarning);
  try {
    await initializeIdentityRepository(runtime, migration);
    const family = 'LedgerConcurrencyNative';
    const ledger = createPostgresRunLedger(runtime, { leasePool: leases });
    const coordinator = createRunCoordinator({ family, ledger });

    let activeBusiness = 0, maxBusiness = 0;
    await coordinator.run('success', { idempotencyKey: 'parallel-success' }, async execution => {
      const entered = [], release = defer();
      const values = await Promise.all(Array.from({ length: 3 }, (_, index) =>
        execution.effect(`tool-${index}`, async () => {
          activeBusiness += 1; maxBusiness = Math.max(maxBusiness, activeBusiness); entered.push(index);
          if (entered.length === 3) release.resolve();
          await release.promise; await new Promise(resolve => setTimeout(resolve, 5));
          activeBusiness -= 1; return index;
        })));
      assert.deepEqual(values.sort(), [0, 1, 2]);
      await Promise.all([
        execution.checkpoint('parallel-complete'),
        execution.trace({ node: 'parallel', type: 'decision', data: { provider: 'fixture' } }),
      ]);
    });
    assert.equal(maxBusiness, 3, 'only ledger SQL is serialized; business effects remain parallel');

    await assert.rejects(coordinator.run('failure', { idempotencyKey: 'parallel-failure' }, async execution => {
      const results = await Promise.allSettled(Array.from({ length: 3 }, (_, index) =>
        execution.effect(`tool-${index}`, async () => {
          await new Promise(resolve => setTimeout(resolve, index + 1));
          if (index === 1) throw new Error('owned native effect failure');
          return index;
        })));
      assert.deepEqual(results.map(result => result.status), ['fulfilled', 'rejected', 'fulfilled']);
      throw results[1].reason;
    }), /owned native effect failure/);

    const held = defer(), allEntered = defer(); let entered = 0, cleanupRan = false;
    const running = coordinator.run('reset', { idempotencyKey: 'parallel-reset' }, async execution => {
      await Promise.all(Array.from({ length: 3 }, (_, index) => execution.effect(`tool-${index}`, async () => {
        entered += 1; if (entered === 3) allEntered.resolve();
        await held.promise; return index;
      })));
    });
    await allEntered.promise;
    const resetCoordinator = createRunCoordinator({ family,
      ledger: createPostgresRunLedger(runtime, { leasePool: leases }) });
    const resetting = resetCoordinator.reset('reset', async () => { cleanupRan = true; });
    for (let attempt = 0; attempt < 100; attempt += 1) {
      const row = (await runtime.query('SELECT generation FROM graph_runtime.owners WHERE owner_key=$1',
        ['["LedgerConcurrencyNative","reset"]'])).rows[0];
      if (Number(row?.generation) === 1) break;
      await new Promise(resolve => setTimeout(resolve, 5));
    }
    assert.equal(cleanupRan, false, 'reset waits for admitted parallel effects and lease release');
    held.resolve();
    await Promise.all([assert.rejects(running, { name: 'AbortError' }), resetting]);
    assert.equal(cleanupRan, true);

    await new Promise(resolve => setImmediate(resolve));
    assert.equal(warnings.some(message => /already executing a query|concurrent.*query/i.test(message)), false);
    const states = (await runtime.query(`SELECT status,count(*)::int AS count FROM graph_runtime.runs
      GROUP BY status ORDER BY status`)).rows;
    assert.ok(states.some(row => row.status === 'completed'));
    assert.ok(states.some(row => row.status === 'failed'));
    assert.ok(states.some(row => row.status === 'cancelled'));
    assert.equal(Number((await runtime.query("SELECT count(*)::int AS count FROM graph_runtime.effects WHERE status='started'"))
      .rows[0].count), 0);
  } finally {
    process.off('warning', onWarning);
    await Promise.all([leases.end(), runtime.end(), migration.end()]);
  }
});
