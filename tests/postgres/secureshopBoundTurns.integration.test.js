'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const { randomUUID } = require('node:crypto');
const { Pool } = require('pg');
const { createBoundTurns } = require('../../server/services/secureshopBoundTurns');
const { createRunCoordinator } = require('../../server/agent-runtime/runCoordinator');
const { createPostgresRunLedger } = require('../../server/agent-runtime/postgresRunLedger');

const PREFIX = 'PG_SECURESHOP_BOUND_TURNS_TEST';
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes'
  && Boolean(process.env[`${PREFIX}_MIGRATION_URL`])
  && Boolean(process.env[`${PREFIX}_RUNTIME_URL`]);

function deferred() {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return { promise, resolve };
}

async function until(predicate, message) {
  for (let attempt = 0; attempt < 200; attempt++) {
    if (await predicate()) return;
    await new Promise(resolve => setTimeout(resolve, 5));
  }
  assert.fail(message);
}

test('native bound turns use durable leases for serialization, cancellation, and effect fencing', {
  skip: !enabled,
  timeout: 30000,
}, async (t) => {
  const migrationUrl = new URL(process.env[`${PREFIX}_MIGRATION_URL`]);
  const runtimeUrl = new URL(process.env[`${PREFIX}_RUNTIME_URL`]);
  for (const url of [migrationUrl, runtimeUrl]) {
    assert.ok(['127.0.0.1', 'localhost'].includes(url.hostname));
    assert.match(url.pathname, /^\/dvaia_test_[a-z0-9_]+$/);
  }
  assert.equal(migrationUrl.pathname, runtimeUrl.pathname);

  const migration = new Pool({ connectionString: migrationUrl.href, max: 1 });
  const control = new Pool({ connectionString: runtimeUrl.href, max: 1,
    application_name: 'secureshop-bound-turn-control' });
  const leases = new Pool({ connectionString: runtimeUrl.href, max: 2,
    application_name: 'secureshop-bound-turn-lease' });
  t.after(async () => Promise.all([migration.end(), control.end(), leases.end()]));

  assert.equal((await migration.query("SELECT to_regnamespace('graph_runtime') AS present")).rows[0].present, null);
  const schema = await fs.readFile(path.join(
    __dirname, '../../db/postgres/identity-migrations/0004_graph_runtime.sql',
  ), 'utf8');
  await migration.query(schema);

  const conversations = {
    async assertOwned(sessionId, binding, persona) {
      assert.equal(typeof sessionId, 'string');
      assert.equal(binding.shopUserId, persona.id);
      assert.equal(binding.role, persona.role);
    },
  };
  const family = `SecureShopBoundTurn:${randomUUID()}`;
  const coordinator = () => createRunCoordinator({
    family,
    ledger: createPostgresRunLedger(control, { leasePool: leases }),
    defaultTimeoutMs: 10000,
  });
  const turnsA = createBoundTurns({ conversations, coordinator: coordinator() });
  const turnsB = createBoundTurns({ conversations, coordinator: coordinator() });
  const scope = {
    launchId: randomUUID(), scenarioId: randomUUID(), generation: 1,
    platformOwnerId: 41, platformSessionId: 51,
  };
  const persona = { id: 61, role: 'customer' };

  await t.test('separate coordinator instances serialize one conversation while control queries remain available', async () => {
    const sessionId = randomUUID();
    const firstEntered = deferred();
    const releaseFirst = deferred();
    const order = [];
    const first = turnsA.run(sessionId, scope, persona, {}, async () => {
      order.push('first-start');
      firstEntered.resolve();
      await releaseFirst.promise;
      order.push('first-end');
      return 'first';
    });
    await firstEntered.promise;
    const second = turnsB.run(sessionId, scope, persona, {}, async () => {
      order.push('second-start');
      return 'second';
    });
    await until(() => leases.totalCount === 2 && leases.idleCount === 0,
      'second coordinator never reached the dedicated lease pool');
    assert.deepEqual(order, ['first-start']);
    assert.equal(Number((await control.query('SELECT 1 AS alive')).rows[0].alive), 1);
    releaseFirst.resolve();
    assert.deepEqual(await Promise.all([first, second]), ['first', 'second']);
    assert.deepEqual(order, ['first-start', 'first-end', 'second-start']);
    const ownerKey = JSON.stringify([family, sessionId]);
    assert.equal(Number((await control.query(
      'SELECT count(*)::int AS count FROM graph_runtime.runs WHERE owner_key=$1', [ownerKey],
    )).rows[0].count), 2);
  });

  await t.test('distinct conversations overlap on separate durable leases', async () => {
    const enteredA = deferred();
    const enteredB = deferred();
    const release = deferred();
    const first = turnsA.run(randomUUID(), scope, persona, {}, async () => {
      enteredA.resolve();
      await release.promise;
      return 'A';
    });
    const second = turnsB.run(randomUUID(), scope, persona, {}, async () => {
      enteredB.resolve();
      await release.promise;
      return 'B';
    });
    await Promise.all([enteredA.promise, enteredB.promise]);
    assert.equal(leases.idleCount, 0);
    release.resolve();
    assert.deepEqual(await Promise.all([first, second]), ['A', 'B']);
  });

  await t.test('an aborted queued turn never starts its operation', async () => {
    const sessionId = randomUUID();
    const holderEntered = deferred();
    const releaseHolder = deferred();
    const holder = turnsA.run(sessionId, scope, persona, {}, async () => {
      holderEntered.resolve();
      await releaseHolder.promise;
    });
    await holderEntered.promise;
    let queuedStarts = 0;
    const abort = new AbortController();
    const queued = turnsB.run(sessionId, scope, persona, { signal: abort.signal }, async () => {
      queuedStarts++;
    });
    const rejected = assert.rejects(queued, { name: 'AbortError' });
    await until(() => leases.totalCount === 2 && leases.idleCount === 0,
      'queued turn never reached the dedicated lease pool');
    abort.abort();
    await rejected;
    assert.equal(queuedStarts, 0);
    releaseHolder.resolve();
    await holder;
  });

  await t.test('losing the owned lease fences a later effect before its callback', async () => {
    const sessionId = randomUUID();
    const operationEntered = deferred();
    const attemptEffect = deferred();
    let callbacks = 0;
    const pending = turnsA.run(sessionId, scope, persona, {}, async boundary => {
      operationEntered.resolve();
      await attemptEffect.promise;
      return boundary.effect('tool-call', async () => { callbacks++; });
    });
    const rejected = assert.rejects(pending);
    await operationEntered.promise;
    let pid;
    await until(async () => {
      const rows = (await control.query(`SELECT a.pid
        FROM pg_stat_activity a
        JOIN pg_locks l ON l.pid=a.pid
        WHERE a.application_name='secureshop-bound-turn-lease'
          AND a.datname=current_database()
          AND l.locktype='advisory' AND l.granted`)).rows;
      if (rows.length === 1) pid = rows[0].pid;
      return rows.length === 1;
    }, 'owned advisory lease was not observable');
    assert.equal((await control.query('SELECT pg_terminate_backend($1) AS terminated', [pid])).rows[0].terminated, true);
    attemptEffect.resolve();
    await rejected;
    assert.equal(callbacks, 0);
    assert.equal(Number((await control.query('SELECT 1 AS alive')).rows[0].alive), 1);
  });
});
