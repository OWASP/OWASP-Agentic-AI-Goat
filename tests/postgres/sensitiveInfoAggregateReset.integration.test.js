'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const { createHash, randomUUID } = require('node:crypto');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const { migrate, readMigrations } = require('../../db/postgres/migrate');
const { seedWorkshopPlatform } = require('../../server/database/postgres/workshopPlatformSeed');
const { initializeIdentityRepository } = require('../../server/database/postgres/identityRepository');
const { createFinflowWorkshopDb } = require('../../server/database/postgres/sensitiveInfoWorkshopDb');
const { createSensitiveInfoResetRepository } = require('../../server/database/postgres/sensitiveInfoResetRepository');
const { createSensitiveInfoCleanupRepository } = require('../../server/database/postgres/sensitiveInfoCleanupRepository');
const { createLegacySensitiveStore } = require('../../server/database/postgres/legacySensitiveStore');
const { createSensitiveInfoAggregateReset } = require('../../server/services/sensitiveInfoAggregateReset');

const ROOT = path.resolve(__dirname, '../..');
const PREFIX = 'PG_SENSITIVE_INFO_RESET_';
const variants = ['POPULATED', 'FRESH'];
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes' && variants.every(variant =>
  ['IDENTITY_MIGRATION', 'IDENTITY_RUNTIME', 'FINFLOW_MIGRATION', 'FINFLOW_RUNTIME']
    .every(key => process.env[`${PREFIX}${variant}_${key}_URL`]));
const idDraft = path.join(ROOT, 'docs/modernization/drafts/sensitive-info-aggregate-reset.sql');
const catalogDraft = path.join(ROOT, 'docs/modernization/drafts/legacy-sensitive-canonical-catalog.sql');
const finflowDraft = path.join(ROOT, 'docs/modernization/drafts/sensitive-info-aggregate-reset-finflow.sql');
const identityHead = path.join(ROOT, 'db/postgres/identity-migrations');
const finflowHead = path.join(ROOT, 'db/postgres/workshop-migrations/finflow');

function pools(variant) {
  const make = key => new Pool({ connectionString: process.env[`${PREFIX}${variant}_${key}_URL`], max: 6 });
  return { identityMigration: make('IDENTITY_MIGRATION'), identityRuntime: make('IDENTITY_RUNTIME'),
    finflowMigration: make('FINFLOW_MIGRATION'), finflowRuntime: make('FINFLOW_RUNTIME') };
}
async function ledger(pool, directory) {
  assert.deepEqual((await pool.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows,
    (await readMigrations(directory)).map(({ name, checksum }) => ({ name, checksum })));
}
async function ledgerNames(pool) {
  const ready = (await pool.query("SELECT to_regclass('dvaia_migrations.ledger') IS NOT NULL AS ready")).rows[0].ready;
  return ready ? (await pool.query('SELECT name FROM dvaia_migrations.ledger ORDER BY name')).rows.map(row => row.name) : [];
}
async function createUser(pool, id, suffix) {
  await pool.query(`INSERT INTO identity.users(id,username,email,password)
    VALUES($1,$2,$3,$4)`, [id, `owner-${suffix}`, `${suffix}@owned.invalid`, await bcrypt.hash('owned-reset-fixture', 4)]);
}
async function seedOwner(identity, finflow, id, legacyGeneration = 2) {
  await identity.query(`INSERT INTO workshop_platform.user_state(user_id,workshop_key,generation)
    VALUES($1,'sensitive_info_disclosure',2) ON CONFLICT(user_id,workshop_key) DO UPDATE SET generation=2`, [id]);
  await identity.query(`INSERT INTO workshop_platform.completions(user_id,workshop_key,objective_id)
    VALUES($1,'sensitive_info_disclosure','tool_enum') ON CONFLICT DO NOTHING`, [id]);
  await identity.query(`INSERT INTO workshop_platform.completions(user_id,workshop_key,objective_id)
    VALUES($1,'sensitive_info_disclosure','llm_identify') ON CONFLICT DO NOTHING`, [id]);
  await identity.query(`INSERT INTO workshop_platform.activity_counters(user_id,workshop_key,activity_key,activity_count)
    VALUES($1,'sensitive_info_disclosure','attempts',3) ON CONFLICT DO NOTHING`, [id]);
  await identity.query(`INSERT INTO workshop_platform.time_tracking
    (user_id,workshop_key,session_start,last_heartbeat,duration_seconds)
    VALUES($1,'sensitive_info_disclosure',now(),now(),19)`, [id]);
  await finflow.query(`INSERT INTO legacy_sensitive.owner_state(user_id,generation) VALUES($1,$2)
    ON CONFLICT(user_id) DO UPDATE SET generation=EXCLUDED.generation`, [id, legacyGeneration]);
  await finflow.query(`INSERT INTO legacy_sensitive.access_logs(user_id,file_path,access_type,status)
    VALUES($1,'/owned/secret','read','success')`, [id]);
  await finflow.query(`INSERT INTO finflow.progress(user_id,objective_id,completed,completed_at)
    SELECT $1,objective_id,true,clock_timestamp() FROM finflow.objectives ORDER BY ordinal LIMIT 1`, [String(id)]);
  await finflow.query(`INSERT INTO finflow.tool_log(user_id,tool_name,mode) VALUES($1,'owned_reset_fixture','vulnerable')`, [String(id)]);
}
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const checkpoint = stage => console.error(`# sensitive-info-reset-stage ${stage}`);
async function openTransaction(pool) {
  const client=await pool.connect();let active=false,released=false;
  try {await client.query('BEGIN');active=true;} catch(error){client.release(error);throw error;}
  return {client,async commit(){if(active){await client.query('COMMIT');active=false;}},
    async rollback(){if(active){await client.query('ROLLBACK');active=false;}},
    async close(){if(released)return;try{if(active)await client.query('ROLLBACK');}finally{active=false;released=true;client.release();}}};
}
async function expectBlocked(promise) {
  let settled = false; promise.finally(() => { settled = true; }).catch(() => {});
  await sleep(100); assert.equal(settled, false, 'write must wait for the reset admission transaction');
}
async function waitForLock(pool, pid) {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    const row = (await pool.query('SELECT wait_event_type FROM pg_stat_activity WHERE pid=$1', [pid])).rows[0];
    if (row?.wait_event_type === 'Lock') return true;
    await sleep(10);
  }
  return false;
}
async function assertBackendVisible(pool,pid) {
  const row=(await pool.query(`SELECT usename=current_user AS same_role,state
    FROM pg_stat_activity WHERE pid=$1`,[pid])).rows[0];
  assert.ok(row,'the observed reset backend must exist');
  assert.equal(row.same_role,true,'lock observation must use the reset backend role');
  assert.ok(row.state,'the same-role observer must see backend activity metadata');
}
function coordinators() { return { legacyRuns: { reset: async (_owner, work) => work() }, finflowReset: async (_owner, work) => work() }; }

test('draft reset/catalog migration qualifies fresh and populated stores with cross-process fences', {
  skip: !enabled, timeout: 90000,
}, async () => {
  const manifest = JSON.parse(await fs.readFile(path.join(ROOT,
    'docs/modernization/drafts/sensitive-info-phase-two-manifest-2026-09-14.json'), 'utf8'));
  for (const entry of manifest.order) {
    const bytes = await fs.readFile(path.join(ROOT, 'docs/modernization/drafts', entry.file));
    assert.equal(createHash('sha256').update(bytes).digest('hex'), entry.sha256);
  }
  assert.ok(process.env.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE,
    'an explicit owned source workspace is required');
  const isolatedRoot = await fs.realpath(process.env.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE);
  const sourceRoot = await fs.realpath(ROOT);
  const ownedRelative = path.relative(isolatedRoot, sourceRoot);
  assert.ok(ownedRelative && !ownedRelative.startsWith(`..${path.sep}`)
      && ownedRelative !== '..' && !path.isAbsolute(ownedRelative),
    'candidate migration files may only be installed in the owned source snapshot');
  const baselineIdentity = await readMigrations(identityHead);
  const baselineFinflow = await readMigrations(finflowHead);
  assert.equal(baselineIdentity.at(-1).name, '0043_dpi_evidence_guidance.sql');
  assert.equal(baselineFinflow.at(-1).name, '0008_student_deletion.sql');
  let candidatesInstalled = false;
  try {
    for (const variant of variants) {
      const db = pools(variant); const populated = variant === 'POPULATED';
      try {
        if (populated) {
          assert.deepEqual(await initializeIdentityRepository(db.identityRuntime, db.identityMigration),
            baselineIdentity.map(row => row.name));
          await seedWorkshopPlatform(db.identityMigration);
          await migrate(db.finflowMigration, finflowHead);
          await createFinflowWorkshopDb(db.finflowRuntime).initialize(db.finflowMigration);
          const custom = { title: 'Instructor retained', hints: ['custom bytes'] };
          await db.identityMigration.query(`UPDATE workshop_platform.objectives SET label='Instructor label',
            hint_content=$1::jsonb,is_enabled=false,hint_enabled=true WHERE workshop_key='sensitive_info_disclosure' AND objective_id='tool_enum'`, [JSON.stringify(custom)]);
        }
        if (!candidatesInstalled) {
          await fs.copyFile(idDraft, path.join(identityHead, '0044_sensitive_info_aggregate_reset.sql'));
          await fs.copyFile(catalogDraft, path.join(identityHead, '0045_legacy_sensitive_canonical_catalog.sql'));
          await fs.copyFile(finflowDraft, path.join(finflowHead, '0009_sensitive_info_aggregate_reset.sql'));
          candidatesInstalled = true;
        }
        const expectedIdentity = (await readMigrations(identityHead)).map(row => row.name);
        const expectedFinflow = (await readMigrations(finflowHead)).map(row => row.name);
        assert.deepEqual(await ledgerNames(db.identityMigration),
          populated ? baselineIdentity.map(row => row.name) : [], 'identity pre-initializer ledger is exact');
        assert.deepEqual(await ledgerNames(db.finflowMigration),
          populated ? baselineFinflow.map(row => row.name) : [], 'FinFlow pre-initializer ledger is exact');
        assert.deepEqual(await initializeIdentityRepository(db.identityRuntime, db.identityMigration),
          populated ? expectedIdentity.slice(baselineIdentity.length) : expectedIdentity);
        // This is the normal production workshop initializer, now pointed at
        // the snapshot's complete candidate migration directory.
        await createFinflowWorkshopDb(db.finflowRuntime).initialize(db.finflowMigration);
        assert.deepEqual((await db.finflowMigration.query('SELECT name FROM dvaia_migrations.ledger ORDER BY name')).rows.map(row => row.name), expectedFinflow);
        if (populated) {
          assert.deepEqual((await db.identityMigration.query(`SELECT label,hint_content,is_enabled,hint_enabled
            FROM workshop_platform.objectives WHERE workshop_key='sensitive_info_disclosure' AND objective_id='tool_enum'`)).rows[0],
          { label: 'Instructor label', hint_content: { title: 'Instructor retained', hints: ['custom bytes'] }, is_enabled: false, hint_enabled: true },
          'the additive draft itself preserves every populated instructor byte and toggle');
        }
        assert.deepEqual(await initializeIdentityRepository(db.identityRuntime, db.identityMigration), []);
        assert.deepEqual(await migrate(db.finflowMigration, finflowHead), []);
        await ledger(db.identityMigration, identityHead); await ledger(db.finflowMigration, finflowHead);
        await seedWorkshopPlatform(db.identityMigration);
        await createFinflowWorkshopDb(db.finflowRuntime).initialize(db.finflowMigration);
        const phase = await db.identityRuntime.query(`SELECT objective_id,is_enabled,catalog_active
          FROM workshop_platform.objectives WHERE workshop_key='sensitive_info_disclosure'
          AND objective_id=ANY($1::text[]) ORDER BY objective_id`, [[
          'path_traversal','ssi_injection','combined_traversal_ssi','ai_assisted_path_traversal','ai_assisted_ssi']]);
        assert.equal(phase.rowCount, 5); assert.ok(phase.rows.every(row => !row.is_enabled && !row.catalog_active));
        const parent = (await db.identityRuntime.query(`SELECT is_visible,catalog_active
          FROM workshop_platform.exercises WHERE workshop_key='sensitive_info_disclosure'`)).rows[0];
        assert.deepEqual(parent, { is_visible: true, catalog_active: true },
          'adding the inactive phase does not hide the existing FinFlow workshop');
        if (populated) {
          assert.deepEqual((await db.identityRuntime.query(`SELECT label,hint_content,is_enabled,hint_enabled
            FROM workshop_platform.objectives WHERE workshop_key='sensitive_info_disclosure' AND objective_id='tool_enum'`)).rows[0],
          { label: 'Tool Enumeration — list all tools including admin tools', hint_content: { title: 'Instructor retained', hints: ['custom bytes'] }, is_enabled: false, hint_enabled: true });
          const owner=7201,sibling=7202;
          await createUser(db.identityRuntime,owner,'populated-reset-a');
          await createUser(db.identityRuntime,sibling,'populated-reset-b');
          await seedOwner(db.identityRuntime,db.finflowRuntime,owner,7);
          await seedOwner(db.identityRuntime,db.finflowRuntime,sibling,4);
          const journal=createSensitiveInfoResetRepository(db.identityRuntime);
          const cleanup=createSensitiveInfoCleanupRepository(db.finflowRuntime);
          await journal.assertReady();await cleanup.assertReady();
          const operation=await journal.begin({ownerId:owner,operationId:randomUUID()});
          assert.equal(operation.fromGeneration,2);assert.equal(operation.toGeneration,3);
          const lease=await journal.claim(operation.operationId);
          await cleanup.apply({...lease,stepKey:'legacy_store'});
          await cleanup.apply({...lease,stepKey:'legacy_store'});
          assert.equal((await db.finflowRuntime.query(
            'SELECT generation FROM legacy_sensitive.owner_state WHERE user_id=$1',[owner])).rows[0].generation,8);
          await journal.acknowledge({...lease,stepKey:'legacy_store'});
          await cleanup.apply({...lease,stepKey:'finflow_store'});
          await journal.acknowledge({...lease,stepKey:'finflow_store'});await journal.complete(lease);
          const replay=await journal.begin({ownerId:owner,operationId:operation.operationId});
          assert.equal(replay.status,'completed');assert.equal(replay.toGeneration,3);
          await cleanup.apply({...lease,stepKey:'legacy_store'});
          assert.equal((await db.finflowRuntime.query(
            'SELECT generation FROM legacy_sensitive.owner_state WHERE user_id=$1',[owner])).rows[0].generation,8);
          assert.equal((await db.identityRuntime.query(`SELECT generation FROM workshop_platform.user_state
            WHERE user_id=$1 AND workshop_key='sensitive_info_disclosure'`,[owner])).rows[0].generation,3);
          await assert.rejects(createLegacySensitiveStore(db.finflowRuntime).recordJudgment({userId:owner,
            objectiveId:'path_traversal',runId:randomUUID(),flagFound:null,exploitUsed:'owned stale fixture',
            completed:false,generation:7,judgment:{verdict:'fail'}}),error=>error.code==='STALE_GENERATION');
          assert.equal((await db.finflowRuntime.query(
            'SELECT generation FROM legacy_sensitive.owner_state WHERE user_id=$1',[sibling])).rows[0].generation,4);
          assert.equal((await db.finflowRuntime.query(
            'SELECT count(*)::int n FROM legacy_sensitive.access_logs WHERE user_id=$1',[sibling])).rows[0].n,1);
          assert.equal((await db.identityRuntime.query(`SELECT generation FROM workshop_platform.user_state
            WHERE user_id=$1 AND workshop_key='sensitive_info_disclosure'`,[sibling])).rows[0].generation,2);
          assert.equal((await db.identityRuntime.query(`SELECT count(*)::int n FROM workshop_platform.completions
            WHERE user_id=$1 AND workshop_key='sensitive_info_disclosure'`,[sibling])).rows[0].n,2);
          assert.deepEqual((await db.identityMigration.query(`SELECT label,hint_content,is_enabled,hint_enabled
            FROM workshop_platform.objectives WHERE workshop_key='sensitive_info_disclosure'
              AND objective_id='tool_enum'`)).rows[0],
          {label:'Tool Enumeration — list all tools including admin tools',
            hint_content:{title:'Instructor retained',hints:['custom bytes']},is_enabled:false,hint_enabled:true});
          continue;
        }

        const owner = 7101, sibling = 7102;
        await createUser(db.identityRuntime, owner, 'reset-a'); await createUser(db.identityRuntime, sibling, 'reset-b');
        await seedOwner(db.identityRuntime, db.finflowRuntime, owner);
        await seedOwner(db.identityRuntime, db.finflowRuntime, sibling);
        const journalA = createSensitiveInfoResetRepository(db.identityRuntime);
        const cleanupA = createSensitiveInfoCleanupRepository(db.finflowRuntime);
        await journalA.assertReady(); await cleanupA.assertReady();

        // Crash after begin: canonical credit is already gone, local bytes remain,
        // and both graph families plus canonical writes are fenced.
        const first = await journalA.begin({ ownerId: owner, operationId: randomUUID() });
        assert.equal(first.toGeneration, 3);
        assert.equal((await db.identityRuntime.query(`SELECT count(*)::int n FROM workshop_platform.completions
          WHERE user_id=$1 AND workshop_key='sensitive_info_disclosure'`, [owner])).rows[0].n, 0);
        assert.equal((await db.finflowRuntime.query('SELECT count(*)::int n FROM legacy_sensitive.access_logs WHERE user_id=$1', [owner])).rows[0].n, 1);
        for (const family of ['LegacySensitiveInfo', 'FinFlow']) {
          const key = JSON.stringify([family, String(owner)]); await db.identityRuntime.query('INSERT INTO graph_runtime.owners(owner_key) VALUES($1) ON CONFLICT DO NOTHING', [key]);
          await assert.rejects(db.identityRuntime.query(`INSERT INTO graph_runtime.runs(run_id,owner_key,generation,status)
            VALUES($1,$2,0,'running')`, [randomUUID(), key]), error => error.code === '23514');
        }
        await assert.rejects(db.identityRuntime.query(`INSERT INTO workshop_platform.completions(user_id,workshop_key,objective_id)
          VALUES($1,'sensitive_info_disclosure','tool_enum')`, [owner]), error => error.code === '23514');
        await assert.rejects(db.identityRuntime.query(`INSERT INTO workshop_platform.completions(user_id,workshop_key,objective_id)
          VALUES($1,'sensitive_info_disclosure','path_traversal')`, [owner]), error => error.code === '23514');
        await db.identityRuntime.query(`INSERT INTO workshop_platform.completions(user_id,workshop_key,objective_id)
          VALUES($1,'sensitive_info_disclosure','tool_enum') ON CONFLICT DO NOTHING`, [sibling]);

        // A new process/repository resumes after legacy acknowledgement.
        const lease = await journalA.claim(first.operationId);
        const legacyGenerationBefore = (await db.finflowRuntime.query(
          'SELECT generation FROM legacy_sensitive.owner_state WHERE user_id=$1', [owner])).rows[0].generation;
        await cleanupA.apply({ ...lease, stepKey: 'legacy_store' });
        assert.equal((await db.finflowRuntime.query(
          'SELECT generation FROM legacy_sensitive.owner_state WHERE user_id=$1', [owner])).rows[0].generation,
        legacyGenerationBefore + 1, 'aggregate cleanup advances the independent legacy generation monotonically');
        await cleanupA.apply({ ...lease, stepKey: 'legacy_store' });
        assert.equal((await db.finflowRuntime.query(
          'SELECT generation FROM legacy_sensitive.owner_state WHERE user_id=$1', [owner])).rows[0].generation,
        legacyGenerationBefore + 1, 'exact cleanup replay cannot advance the legacy generation twice');
        await journalA.acknowledge({ ...lease, stepKey: 'legacy_store' });
        await journalA.fail({ ...lease, stepKey: 'finflow_store', code: 'PROCESS_EXIT' });
        await assert.rejects(db.identityRuntime.query(`INSERT INTO workshop_platform.completions(user_id,workshop_key,objective_id)
          VALUES($1,'sensitive_info_disclosure','tool_enum')`, [owner]), error => error.code === '23514');
        const identityB = new Pool({ connectionString: process.env[`${PREFIX}${variant}_IDENTITY_RUNTIME_URL`], max: 3 });
        const finflowB = new Pool({ connectionString: process.env[`${PREFIX}${variant}_FINFLOW_RUNTIME_URL`], max: 3 });
        const journalB = createSensitiveInfoResetRepository(identityB);
        const cleanupB = createSensitiveInfoCleanupRepository(finflowB);
        try {
          const aggregate = createSensitiveInfoAggregateReset({ ...coordinators(), journal: journalB, cleanup: cleanupB });
          assert.equal((await aggregate.recover(first.operationId)).status, 'completed');
        } finally { await Promise.all([identityB.end(), finflowB.end()]); }
        assert.equal((await db.finflowRuntime.query('SELECT count(*)::int n FROM finflow.tool_log WHERE user_id=$1', [String(owner)])).rows[0].n, 0);
        assert.equal((await db.finflowRuntime.query('SELECT count(*)::int n FROM finflow.tool_log WHERE user_id=$1', [String(sibling)])).rows[0].n, 1);
        const replay = await journalA.begin({ ownerId: owner, operationId: first.operationId });
        assert.equal(replay.status, 'completed'); assert.equal(replay.toGeneration, 3);

        // Direct writers that start after an uncommitted begin wait on the same
        // state/authority tuple, then fail once the pending journal is visible.
        const barrierOwner = 7103; await createUser(db.identityRuntime, barrierOwner, 'barrier');
        await seedOwner(db.identityRuntime, db.finflowRuntime, barrierOwner);
        checkpoint(`${variant}:insert-after-begin`);
        const tx = await openTransaction(db.identityRuntime);
        try {
          const barrierOperation = randomUUID(); await tx.client.query('SELECT * FROM identity.begin_sensitive_info_reset($1,$2)', [barrierOwner, barrierOperation]);
          const completionWrite = db.identityRuntime.query(`INSERT INTO workshop_platform.completions(user_id,workshop_key,objective_id)
            VALUES($1,'sensitive_info_disclosure','llm_identify')`, [barrierOwner]);
          await expectBlocked(completionWrite); await tx.commit();
          await assert.rejects(completionWrite, error => error.code === '23514');
        } finally {await tx.close();}

        // An existing-row updater has already locked its projection tuple when
        // its BEFORE ROW trigger locks user_state. Begin takes projection rows
        // before user_state, waits without a cycle, then removes the update.
        const updateOwner = 7105; await createUser(db.identityRuntime, updateOwner, 'update-barrier');
        await seedOwner(db.identityRuntime, db.finflowRuntime, updateOwner);
        checkpoint(`${variant}:completion-update-before-begin`);
        const updater = await openTransaction(db.identityRuntime);let updateReset;
        try {
          await updater.client.query(`UPDATE workshop_platform.completions SET updated_at=clock_timestamp()
            WHERE user_id=$1 AND workshop_key='sensitive_info_disclosure' AND objective_id='tool_enum'`, [updateOwner]);
          const concurrentBegin = journalA.begin({ ownerId: updateOwner, operationId: randomUUID() });
          await expectBlocked(concurrentBegin); await updater.commit();updateReset=await concurrentBegin;
        } finally {await updater.close();}
        assert.equal(updateReset.status, 'pending');
        assert.equal((await db.identityRuntime.query(`SELECT count(*)::int n FROM workshop_platform.completions
          WHERE user_id=$1 AND workshop_key='sensitive_info_disclosure'`, [updateOwner])).rows[0].n, 0);

        const timeOwner = 7106; await createUser(db.identityRuntime, timeOwner, 'time-barrier');
        await seedOwner(db.identityRuntime, db.finflowRuntime, timeOwner);
        checkpoint(`${variant}:time-update-before-begin`);
        const timeUpdater = await openTransaction(db.identityRuntime);
        try {
          await timeUpdater.client.query(`UPDATE workshop_platform.time_tracking SET duration_seconds=duration_seconds+1
            WHERE id=(SELECT id FROM workshop_platform.time_tracking WHERE user_id=$1
            AND workshop_key='sensitive_info_disclosure' ORDER BY id DESC LIMIT 1)`, [timeOwner]);
          const timeBegin = journalA.begin({ ownerId: timeOwner, operationId: randomUUID() });
          await expectBlocked(timeBegin);await timeUpdater.commit();await timeBegin;
        } finally {await timeUpdater.close();}
        assert.equal((await db.identityRuntime.query(`SELECT count(*)::int n FROM workshop_platform.time_tracking
          WHERE user_id=$1 AND workshop_key='sensitive_info_disclosure'`, [timeOwner])).rows[0].n, 0);

        // Arbitrary direct multi-row DML can choose the opposite tuple order.
        // PostgreSQL must abort one participant with 40P01; retrying the reset
        // then removes both rows, rather than losing a committed update.
        const deadlockOwner = 7110; await createUser(db.identityRuntime, deadlockOwner, 'deadlock');
        await seedOwner(db.identityRuntime, db.finflowRuntime, deadlockOwner);
        checkpoint(`${variant}:opposite-row-order-deadlock`);
        const opposite = await openTransaction(db.identityRuntime);let beginClient;let beginOutcome;let racingBegin;
        const deadlockOperation = randomUUID();
        try {
          await opposite.client.query(`UPDATE workshop_platform.completions SET updated_at=clock_timestamp()
            WHERE user_id=$1 AND workshop_key='sensitive_info_disclosure' AND objective_id='tool_enum'`, [deadlockOwner]);
          beginClient = await db.identityRuntime.connect();
          const beginPid = Number((await beginClient.query('SELECT pg_backend_pid() AS pid')).rows[0].pid);
          racingBegin = beginClient.query('SELECT * FROM identity.begin_sensitive_info_reset($1,$2)',
            [deadlockOwner, deadlockOperation]);
          await assertBackendVisible(db.identityRuntime,beginPid);
          const reachedBarrier=await waitForLock(db.identityRuntime, beginPid);
          if(!reachedBarrier){
            await opposite.rollback();await Promise.allSettled([racingBegin]);
            assert.fail('transaction never reached the intended row-lock barrier');
          }
          const oppositeSecond = opposite.client.query(`UPDATE workshop_platform.completions SET updated_at=clock_timestamp()
            WHERE user_id=$1 AND workshop_key='sensitive_info_disclosure' AND objective_id='llm_identify'`, [deadlockOwner]);
          let updateOutcome;[beginOutcome, updateOutcome] = await Promise.allSettled([racingBegin, oppositeSecond]);
          assert.equal([beginOutcome, updateOutcome].filter(value => value.status === 'rejected'
            && value.reason?.code === '40P01').length, 1, 'one opposing lock order is bounded by PostgreSQL deadlock detection');
          if(updateOutcome.status==='rejected')await opposite.rollback();else await opposite.commit();
        } finally {
          await opposite.close();
          if(racingBegin)await Promise.allSettled([racingBegin]);
          if(beginClient)beginClient.release();
        }
        if (beginOutcome?.status === 'rejected') await journalA.begin({ ownerId: deadlockOwner, operationId: deadlockOperation });
        assert.equal((await db.identityRuntime.query(`SELECT count(*)::int n FROM workshop_platform.completions
          WHERE user_id=$1 AND workshop_key='sensitive_info_disclosure'`, [deadlockOwner])).rows[0].n, 0);

        const runOwner = 7104; await createUser(db.identityRuntime, runOwner, 'run-barrier');
        await seedOwner(db.identityRuntime, db.finflowRuntime, runOwner);
        const runKey = JSON.stringify(['LegacySensitiveInfo', String(runOwner)]);
        await db.identityRuntime.query('INSERT INTO graph_runtime.owners(owner_key) VALUES($1)', [runKey]);
        checkpoint(`${variant}:run-after-begin`);
        const tx2 = await openTransaction(db.identityRuntime);
        try {
          await tx2.client.query('SELECT * FROM identity.begin_sensitive_info_reset($1,$2)', [runOwner, randomUUID()]);
          const runWrite = db.identityRuntime.query(`INSERT INTO graph_runtime.runs(run_id,owner_key,generation,status)
            VALUES($1,$2,0,'running')`, [randomUUID(), runKey]);
          await expectBlocked(runWrite);await tx2.commit();await assert.rejects(runWrite, error => error.code === '23514');
        } finally {await tx2.close();}

        const preRunOwner = 7109; await createUser(db.identityRuntime, preRunOwner, 'pre-run');
        await seedOwner(db.identityRuntime, db.finflowRuntime, preRunOwner);
        const preRunKey = JSON.stringify(['FinFlow', String(preRunOwner)]), preRunId = randomUUID();
        await db.identityRuntime.query('INSERT INTO graph_runtime.owners(owner_key) VALUES($1)', [preRunKey]);
        checkpoint(`${variant}:begin-after-run`);
        const runTx = await openTransaction(db.identityRuntime);
        try {
          await runTx.client.query(`INSERT INTO graph_runtime.runs(run_id,owner_key,generation,status)
            VALUES($1,$2,0,'running')`, [preRunId, preRunKey]);
          const beginAfterRun = journalA.begin({ ownerId: preRunOwner, operationId: randomUUID() });
          await expectBlocked(beginAfterRun);await runTx.commit();await beginAfterRun;
        } finally {await runTx.close();}
        assert.equal((await db.identityRuntime.query('SELECT status FROM graph_runtime.runs WHERE run_id=$1', [preRunId])).rows[0].status, 'interrupted');

        // A late worker for a completed old generation sees its immutable receipt
        // and cannot erase data created after a newer reset.
        const firstReceipt = { operationId: first.operationId, ownerId: owner, fromGeneration: 2, toGeneration: 3, stepKey: 'finflow_store' };
        const second = await journalA.begin({ ownerId: owner, operationId: randomUUID() });
        const secondLease = await journalA.claim(second.operationId);
        for (const stepKey of ['legacy_store', 'finflow_store']) {
          await cleanupA.apply({ ...secondLease, stepKey }); await journalA.acknowledge({ ...secondLease, stepKey });
        }
        await db.identityMigration.query(`UPDATE identity.sensitive_info_resets
          SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE operation_id=$1`, [second.operationId]);
        const restartedAfterEffects = createSensitiveInfoAggregateReset({ ...coordinators(), journal: journalA, cleanup: cleanupA });
        assert.equal((await restartedAfterEffects.recover(second.operationId)).status, 'completed');
        await db.finflowRuntime.query(`INSERT INTO finflow.tool_log(user_id,tool_name,mode) VALUES($1,'post_reset_marker','vulnerable')`, [String(owner)]);
        await cleanupA.apply(firstReceipt);
        assert.equal((await db.finflowRuntime.query(`SELECT count(*)::int n FROM finflow.tool_log
          WHERE user_id=$1 AND tool_name='post_reset_marker'`, [String(owner)])).rows[0].n, 1);

        // Worker A loses its one-second identity lease before entering the
        // destination. Worker B reclaims and publishes the receipt; A's late
        // exact call observes that receipt and cannot erase post-B activity.
        const stalledOwner = 7108; await createUser(db.identityRuntime, stalledOwner, 'stalled-worker');
        await seedOwner(db.identityRuntime, db.finflowRuntime, stalledOwner);
        checkpoint(`${variant}:expired-worker-destination-replay`);
        const stalledOperation = await journalA.begin({ ownerId: stalledOwner, operationId: randomUUID() });
        const leaseA = await journalA.claim(stalledOperation.operationId, 1000);
        await sleep(1100);
        const leaseB = await journalA.claim(stalledOperation.operationId, 30000);
        assert.ok(leaseB); assert.notEqual(leaseA.leaseToken, leaseB.leaseToken);
        const stalledScope = { ...leaseA, stepKey: 'legacy_store' };
        await cleanupA.apply({ ...leaseB, stepKey: 'legacy_store' });
        await db.finflowRuntime.query(`INSERT INTO legacy_sensitive.access_logs(user_id,file_path,access_type,status)
          VALUES($1,'/post-reclaim-marker','read','success')`, [stalledOwner]);
        await cleanupA.apply(stalledScope);
        assert.equal((await db.finflowRuntime.query(`SELECT count(*)::int n FROM legacy_sensitive.access_logs
          WHERE user_id=$1 AND file_path='/post-reclaim-marker'`, [stalledOwner])).rows[0].n, 1);
        await assert.rejects(journalA.acknowledge({ ...leaseA, stepKey: 'legacy_store' }),
          error => error.code === 'SENSITIVE_INFO_RESET_STEP_OUT_OF_ORDER');
        await journalA.acknowledge({ ...leaseB, stepKey: 'legacy_store' });
        await cleanupA.apply({ ...leaseB, stepKey: 'finflow_store' });
        await journalA.acknowledge({ ...leaseB, stepKey: 'finflow_store' });
        await journalA.complete(leaseB);

        // Runtime can call the exact functions but cannot rewrite their durable bindings.
        await assert.rejects(db.finflowRuntime.query(`UPDATE finflow.sensitive_info_cleanup_operations
          SET owner_id=owner_id WHERE operation_id=$1`, [first.operationId]), error => error.code === '42501');
        await assert.rejects(db.identityRuntime.query(`DELETE FROM identity.sensitive_info_resets WHERE operation_id=$1`, [first.operationId]), error => ['42501','23514'].includes(error.code));

        // Separate application/repository instances converge on the same
        // durable operation; an unexpired claimant is never double-executed.
        const concurrentOwner = 7107; await createUser(db.identityRuntime, concurrentOwner, 'concurrent');
        await seedOwner(db.identityRuntime, db.finflowRuntime, concurrentOwner);
        const identityC = new Pool({ connectionString: process.env[`${PREFIX}${variant}_IDENTITY_RUNTIME_URL`], max: 3 });
        const finflowC = new Pool({ connectionString: process.env[`${PREFIX}${variant}_FINFLOW_RUNTIME_URL`], max: 3 });
        const identityD = new Pool({ connectionString: process.env[`${PREFIX}${variant}_IDENTITY_RUNTIME_URL`], max: 3 });
        const finflowD = new Pool({ connectionString: process.env[`${PREFIX}${variant}_FINFLOW_RUNTIME_URL`], max: 3 });
        let entered, release, running; const enteredPromise = new Promise(resolve => { entered = resolve; });
        const baseCleanupC = createSensitiveInfoCleanupRepository(finflowC);
        const cleanupC = { readReceipt: value => baseCleanupC.readReceipt(value), async apply(value) {
          if (value.stepKey === 'legacy_store') { entered(); await new Promise(resolve => { release = resolve; }); }
          return baseCleanupC.apply(value);
        } };
        try {
          const appC = createSensitiveInfoAggregateReset({ ...coordinators(), journal: createSensitiveInfoResetRepository(identityC), cleanup: cleanupC });
          const appD = createSensitiveInfoAggregateReset({ ...coordinators(), journal: createSensitiveInfoResetRepository(identityD), cleanup: createSensitiveInfoCleanupRepository(finflowD) });
          checkpoint(`${variant}:two-worker-lease`);
          running = appC.reset(concurrentOwner); await enteredPromise;
          await assert.rejects(appD.reset(concurrentOwner), error => error.code === 'SENSITIVE_INFO_RESET_BUSY');
          release(); assert.equal((await running).status, 'completed');
          assert.equal((await db.identityMigration.query(`SELECT count(*)::int n FROM identity.sensitive_info_resets
            WHERE owner_id=$1`, [concurrentOwner])).rows[0].n, 1);
        } finally {
          release?.();if(running)await running.catch(()=>{});
          await Promise.allSettled([identityC.end(), finflowC.end(), identityD.end(), finflowD.end()]);
        }
      } finally { await Promise.allSettled(Object.values(db).map(pool => pool.end())); }
    }
  } catch(error) {
    checkpoint(`primary-failure:${error.code||error.name||'unknown'}:${String(error.message||'').slice(0,240)}`);
    throw error;
  } finally {
    if (candidatesInstalled) await Promise.all([
      fs.rm(path.join(identityHead, '0044_sensitive_info_aggregate_reset.sql'), { force: true }),
      fs.rm(path.join(identityHead, '0045_legacy_sensitive_canonical_catalog.sql'), { force: true }),
      fs.rm(path.join(finflowHead, '0009_sensitive_info_aggregate_reset.sql'), { force: true }),
    ]);
  }
});
