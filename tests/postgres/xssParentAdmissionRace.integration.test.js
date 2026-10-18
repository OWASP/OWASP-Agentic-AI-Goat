'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { createPool } = require('../../server/database/postgres');
const { initializeIdentityRepository } = require('../../server/database/postgres/identityRepository');
const { seedWorkshopPlatform } = require('../../server/database/postgres/workshopPlatformSeed');

const RUNTIME = 'PG_XSS_PARENT_ADMISSION_RUNTIME_URL';
const MIGRATION = 'PG_XSS_PARENT_ADMISSION_MIGRATION_URL';
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes'
  && Boolean(process.env[RUNTIME]) && Boolean(process.env[MIGRATION]);
const password = '$2b$12$000000000000000000000uG3W0Jp6IPhhD1TRqN8Yc2zJQG3vVnSA';

function assertOwnedUrl(value, role) {
  const url = new URL(value);
  assert.equal(url.hostname, '127.0.0.1');
  assert.equal(url.pathname, '/dvaia_test_xss_parent_admission_identity');
  assert.equal(decodeURIComponent(url.username), role);
}

async function waitForBlocked(observer, blockedPid, blockerPid) {
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) {
    await observer.query('SELECT pg_stat_clear_snapshot()');
    const row = (await observer.query(`SELECT state,wait_event_type,wait_event,
        pg_blocking_pids(pid) AS blockers
      FROM pg_stat_activity WHERE pid=$1`, [blockedPid])).rows[0];
    if (row?.state === 'active' && row.wait_event_type === 'Lock'
      && row.blockers.includes(blockerPid)) return row;
    await new Promise(resolve => setImmediate(resolve));
  }
  assert.fail(`Backend ${blockedPid} did not wait for owner admission authority`);
}

async function createOwner(migration, suffix) {
  const owner = (await migration.query(`INSERT INTO identity.users(username,email,password)
    VALUES($1,$2,$3) RETURNING id`, [
    `xss-parent-race-${suffix}`, `xss-parent-race-${suffix}@fixture.invalid`, password,
  ])).rows[0].id;
  const ownerKey = JSON.stringify(['XSS', String(owner)]);
  await migration.query('INSERT INTO graph_runtime.owners(owner_key,generation) VALUES($1,0)', [ownerKey]);
  await migration.query(`INSERT INTO workshop_platform.user_state(user_id,workshop_key,generation)
    VALUES($1,'xss_workshop',0)`, [owner]);
  return { owner, ownerKey };
}

async function boundClient(client) {
  await client.query("SET statement_timeout='15s'");
  await client.query("SET lock_timeout='10s'");
  await client.query("SET idle_in_transaction_session_timeout='15s'");
}

function admission(kind, client, fixture) {
  if (kind === 'judgment') {
    return client.query(`INSERT INTO workshop_platform.objective_judgments
      (user_id,evaluation_id,workshop_key,objective_id,family,scenario,rubric_version,
       evidence_digest,generation)
      VALUES($1,$2,'xss_workshop','xss_r1','XSS','parent-race','fixture',$3,0)`,
    [fixture.owner, randomUUID(), 'a'.repeat(64)]);
  }
  if (kind === 'completion') {
    return client.query(`INSERT INTO workshop_platform.completions(user_id,workshop_key,objective_id)
      VALUES($1,'xss_workshop','xss_r1')`, [fixture.owner]);
  }
  if (kind === 'run') {
    return client.query(`INSERT INTO graph_runtime.runs(run_id,owner_key,generation,status)
      VALUES($1,$2,0,'running')`, [randomUUID(), fixture.ownerKey]);
  }
  throw new TypeError('Unsupported admission kind');
}

async function admissionFirst(runtime, observer, migration, kind) {
  const fixture = await createOwner(migration, `${kind}-first`);
  const admissionClient = await runtime.connect();
  const resetClient = await runtime.connect();
  let admissionOpen = false;
  let resetOpen = false;
  let pendingReset;
  let primary;
  try {
    await Promise.all([boundClient(admissionClient), boundClient(resetClient)]);
    await admissionClient.query('BEGIN'); admissionOpen = true;
    await resetClient.query('BEGIN'); resetOpen = true;
    await admission(kind, admissionClient, fixture);
    const admissionPid = admissionClient.processID;
    const resetPid = resetClient.processID;
    const operationId = randomUUID();
    pendingReset = resetClient.query(
      'SELECT operation_id FROM identity.begin_xss_parent_reset($1,$2)',
      [operationId, fixture.owner],
    ).then(value => ({ value }), error => ({ error }));
    await waitForBlocked(observer, resetPid, admissionPid);
    await admissionClient.query('COMMIT'); admissionOpen = false;
    const outcome = await pendingReset;
    assert.equal(outcome.error, undefined);
    assert.equal(outcome.value.rowCount, 1);
    await resetClient.query('COMMIT'); resetOpen = false;
    assert.equal((await migration.query(`SELECT count(*)::integer AS count
      FROM identity.xss_parent_reset_operations WHERE operation_id=$1 AND owner_id=$2`,
    [operationId, fixture.owner])).rows[0].count, 1);
  } catch (error) {
    primary = error;
  } finally {
    const cleanup = await Promise.allSettled([
      ...(admissionOpen ? [admissionClient.query('ROLLBACK')] : []),
      ...(resetOpen ? [resetClient.query('ROLLBACK')] : []),
      ...(pendingReset ? [pendingReset] : []),
    ]);
    admissionClient.release();
    resetClient.release();
    const errors = cleanup.filter(result => result.status === 'rejected').map(result => result.reason);
    if (primary) {
      if (errors.length) primary.cleanupErrors = errors;
      throw primary;
    }
    if (errors.length) throw new AggregateError(errors, 'Admission-first cleanup failed');
  }
}

async function resetFirst(runtime, observer, migration, kind) {
  const fixture = await createOwner(migration, `${kind}-reset`);
  const resetClient = await runtime.connect();
  const admissionClient = await runtime.connect();
  let resetOpen = false;
  let admissionOpen = false;
  let pendingAdmission;
  let primary;
  try {
    await Promise.all([boundClient(resetClient), boundClient(admissionClient)]);
    await resetClient.query('BEGIN'); resetOpen = true;
    await admissionClient.query('BEGIN'); admissionOpen = true;
    const resetPid = resetClient.processID;
    const admissionPid = admissionClient.processID;
    const operationId = randomUUID();
    assert.equal((await resetClient.query(
      'SELECT operation_id FROM identity.begin_xss_parent_reset($1,$2)',
      [operationId, fixture.owner],
    )).rowCount, 1);
    pendingAdmission = admission(kind, admissionClient, fixture)
      .then(value => ({ value }), error => ({ error }));
    await waitForBlocked(observer, admissionPid, resetPid);
    await resetClient.query('COMMIT'); resetOpen = false;
    const outcome = await pendingAdmission;
    assert.equal(outcome.error?.code, '55000');
    await admissionClient.query('ROLLBACK'); admissionOpen = false;
    assert.equal((await migration.query(`SELECT count(*)::integer AS count
      FROM identity.xss_parent_reset_operations WHERE operation_id=$1 AND owner_id=$2`,
    [operationId, fixture.owner])).rows[0].count, 1);
  } catch (error) {
    primary = error;
  } finally {
    const cleanup = await Promise.allSettled([
      ...(resetOpen ? [resetClient.query('ROLLBACK')] : []),
      ...(admissionOpen ? [admissionClient.query('ROLLBACK')] : []),
      ...(pendingAdmission ? [pendingAdmission] : []),
    ]);
    resetClient.release();
    admissionClient.release();
    const errors = cleanup.filter(result => result.status === 'rejected').map(result => result.reason);
    if (primary) {
      if (errors.length) primary.cleanupErrors = errors;
      throw primary;
    }
    if (errors.length) throw new AggregateError(errors, 'Reset-first cleanup failed');
  }
}

async function coordinateChangeDenied(runtime, migration) {
  const fixture = await createOwner(migration, 'coordinate-old');
  const sibling = await createOwner(migration, 'coordinate-new');
  const foreign = (await migration.query(`SELECT workshop_key,objective_id
    FROM workshop_platform.objectives
    WHERE workshop_key<>'xss_workshop' AND is_enabled=true
    ORDER BY workshop_key,objective_id LIMIT 1`)).rows[0];
  assert.ok(foreign, 'a seeded non-XSS objective is required');
  const moveWorkshop = randomUUID();
  const moveOwner = randomUUID();
  for (const evaluationId of [moveWorkshop, moveOwner]) {
    await runtime.query(`INSERT INTO workshop_platform.objective_judgments
      (user_id,evaluation_id,workshop_key,objective_id,family,scenario,rubric_version,
       evidence_digest,generation)
      VALUES($1,$2,'xss_workshop','xss_r1','XSS','parent-coordinate','fixture',$3,0)`,
    [fixture.owner, evaluationId, 'b'.repeat(64)]);
  }
  assert.equal((await runtime.query(
    'SELECT identity.assert_xss_mutation_admitted($1) AS admitted', [fixture.owner]
  )).rows[0].admitted, true);
  const operationId = randomUUID();
  assert.equal((await runtime.query(
    'SELECT operation_id FROM identity.begin_xss_parent_reset($1,$2)',
    [operationId, fixture.owner],
  )).rowCount, 1);
  await assert.rejects(runtime.query(
    'SELECT identity.assert_xss_mutation_admitted($1)', [fixture.owner]
  ), { code: '55000' });
  await assert.rejects(runtime.query(`UPDATE workshop_platform.objective_judgments
    SET workshop_key=$1,objective_id=$2 WHERE user_id=$3 AND evaluation_id=$4`,
  [foreign.workshop_key, foreign.objective_id, fixture.owner, moveWorkshop]), { code: '55000' });
  await assert.rejects(runtime.query(`UPDATE workshop_platform.objective_judgments
    SET user_id=$1 WHERE user_id=$2 AND evaluation_id=$3`,
  [sibling.owner, fixture.owner, moveOwner]), { code: '55000' });
  assert.deepEqual((await migration.query(`SELECT user_id,workshop_key,objective_id
    FROM workshop_platform.objective_judgments
    WHERE evaluation_id=ANY($1::uuid[]) ORDER BY evaluation_id`,
  [[moveWorkshop, moveOwner]])).rows.map(row => ({
    userId: Number(row.user_id), workshopKey: row.workshop_key, objectiveId: row.objective_id,
  })), [
    { userId: fixture.owner, workshopKey: 'xss_workshop', objectiveId: 'xss_r1' },
    { userId: fixture.owner, workshopKey: 'xss_workshop', objectiveId: 'xss_r1' },
  ]);
}

test('0078 serializes XSS parent reset publication with every durable admission path',
  { skip: !enabled }, async () => {
    assertOwnedUrl(process.env[RUNTIME], 'dvaia_identity_runtime');
    assertOwnedUrl(process.env[MIGRATION], 'dvaia_identity_migration');
    const runtime = createPool(process.env, RUNTIME);
    const migration = createPool(process.env, MIGRATION);
    const observer = createPool(process.env, RUNTIME);
    try {
      const applied = await initializeIdentityRepository(runtime, migration);
      assert.ok(applied.includes('0078_xss_parent_reset_admission_fence.sql'));
      assert.ok(applied.includes('0079_xss_deletion_redaction_recovery_filter.sql'));
      assert.ok(applied.includes('0080_legacy_ai_private_history.sql'));
      const expected = fs.readdirSync(path.join(__dirname, '../../db/postgres/identity-migrations'))
        .filter(name => /^[0-9]{4}_.*\.sql$/.test(name)).sort();
      assert.deepEqual(applied, expected);
      assert.deepEqual(await initializeIdentityRepository(runtime, migration), []);
      await seedWorkshopPlatform(migration);
      for (const kind of ['judgment', 'completion', 'run']) {
        await admissionFirst(runtime, observer, migration, kind);
        await resetFirst(runtime, observer, migration, kind);
      }
      await coordinateChangeDenied(runtime, migration);
    } finally {
      const settled = await Promise.allSettled([runtime.end(), migration.end(), observer.end()]);
      const failures = settled.filter(result => result.status === 'rejected').map(result => result.reason);
      if (failures.length) throw new AggregateError(failures, 'XSS parent admission pool cleanup failed');
    }
  });
