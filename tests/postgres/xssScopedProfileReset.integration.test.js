'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const { randomUUID, createHash } = require('node:crypto');
const { migrate, readMigrations } = require('../../db/postgres/migrate');
const { createPool } = require('../../server/database/postgres');
const { createXssScopedProfileResetRepository } = require(
  '../../server/database/postgres/xssScopedProfileResetRepository');

const RUNTIME = 'PG_XSS_SCOPED_PROFILE_RUNTIME_URL';
const MIGRATION = 'PG_XSS_SCOPED_PROFILE_MIGRATION_URL';
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes'
  && Boolean(process.env[RUNTIME]) && Boolean(process.env[MIGRATION]);
const digest = value => createHash('sha256').update(value, 'utf8').digest('hex');

const migrationDirectory = path.resolve(__dirname, '../../db/postgres/workshop-migrations/xss');
function prefixLoader(lastVersion) {
  assert.ok(lastVersion === 7 || lastVersion === 8);
  const { Module, createRequire } = require('node:module');
  const filename = require.resolve('../../db/postgres/migrate');
  const localRequire = createRequire(filename), loaded = new Module(filename, module);
  loaded.filename = filename;
  loaded.require = name => name === 'node:fs/promises' ? {
    async readdir(directory, ...args) {
      assert.equal(path.resolve(directory), migrationDirectory);
      return (await fs.readdir(directory, ...args)).filter(name => Number(name.slice(0, 4)) <= lastVersion);
    },
    readFile: (...args) => fs.readFile(...args),
  } : localRequire(name);
  loaded._compile(require('node:fs').readFileSync(filename, 'utf8'), filename);
  return loaded.exports;
}
test('XSS migration prefix views retain exact canonical SQL and checksums', async () => {
  const original = fs.readdir, full = await readMigrations(migrationDirectory);
  for (const version of [7, 8]) {
    assert.deepEqual(await prefixLoader(version).readMigrations(migrationDirectory),
      full.filter(row => Number(row.name.slice(0, 4)) <= version));
  }
  assert.equal(fs.readdir, original);
  assert.deepEqual(await readMigrations(migrationDirectory), full);
});

function assertOwnedUrl(value, role) {
  const url = new URL(value);
  assert.equal(url.hostname, '127.0.0.1');
  assert.equal(url.pathname, '/owasp_ai_goat_test_xss_scoped_profile_reset');
  assert.equal(decodeURIComponent(url.username), role);
}
async function insertOrigin(pool, ownerId, field, revision, value) {
  await pool.query(`INSERT INTO xss.profile_model_origins
    (user_key,field,platform_user_id,revision,value_sha256,workshop_generation,run_id,
     owner_key,durable_generation,decision_source,provider,model,raw_decision_sha256,observation_index)
    VALUES($1,$2,$3,$4,$5,2,$6,$7,4,'model','ollama','llama3.1:8b',$8,0)`,
  [String(ownerId), field, ownerId, revision, digest(value), randomUUID(),
    JSON.stringify(['XSS', String(ownerId)]), digest(`decision:${ownerId}:${field}`)]);
}
function input(operationId, ownerId = 17) {
  return { operationId, ownerId, graphParentGeneration:'4', workshopGeneration:'2',
    children:{ stored_user:{ from:'6', to:'7' }, stored_llm:{ from:'8', to:'9' } } };
}
async function waitForAdvisoryWait(pool, pid, label) {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    const result = await pool.query(`SELECT count(*)::int AS n FROM pg_locks
      WHERE pid=$1 AND locktype='advisory' AND granted=false`, [pid]);
    if (result.rows[0].n > 0) return;
    await new Promise(resolve => setImmediate(resolve));
  }
  throw new Error(`${label} did not reach an advisory-lock wait`);
}
function settled(promise) {
  return promise.then(value => ({ status:'fulfilled', value }), reason => ({ status:'rejected', reason }));
}
async function cleanupLockRace({ observer, observerClosed, promises, clients, migration, drops }) {
  const errors = [];
  if (!observerClosed) {
    try { await observer.query('ROLLBACK'); } catch (error) { errors.push(error); }
  }
  await Promise.allSettled(promises);
  for (const client of clients) {
    try { await client.release(); } catch (error) { errors.push(error); }
  }
  for (const sql of drops) {
    try { await migration.query(sql); } catch (error) { errors.push(error); }
  }
  if (errors.length) throw new AggregateError(errors, 'XSS lock-race cleanup failed');
}

test('native 0008→0013 applies reset retirement and fences deleted owners',
  { skip:!enabled }, async () => {
    assertOwnedUrl(process.env[RUNTIME], 'dvaia_xss_runtime');
    assertOwnedUrl(process.env[MIGRATION], 'dvaia_xss_migration');
    const runtime = createPool(process.env, RUNTIME);
    const migration = createPool(process.env, MIGRATION);
    const observerPool = createPool(process.env, MIGRATION);
    try {
      const canonical = await readMigrations(migrationDirectory);
      assert.deepEqual(await prefixLoader(7).migrate(migration, migrationDirectory),
        canonical.filter(row => Number(row.name.slice(0, 4)) <= 7).map(row => row.name));

      await migration.query(`INSERT INTO xss.profiles
        (user_key,name,bio,website,name_revision,bio_revision,website_revision)
        VALUES('17','owner name','<img src=x onerror=owner()>','javascript:owner()',5,6,7),
              ('18','sibling name','<svg onload=sibling()>','javascript:sibling()',3,4,5),
              ('19','rollback name','<b>rollback</b>','https://rollback.invalid',2,3,4)`);
      await insertOrigin(migration, 17, 'name', 5, 'owner name');
      await insertOrigin(migration, 17, 'bio', 6, '<img src=x onerror=owner()>');
      await insertOrigin(migration, 18, 'bio', 4, '<svg onload=sibling()>');
      await insertOrigin(migration, 19, 'bio', 3, '<b>rollback</b>');
      await migration.query(`INSERT INTO xss.progress(user_key,objective_id,completed)
        VALUES('17','xss_s1',1),('18','xss_s1',1)`);
      await migration.query(`INSERT INTO xss.emails(subject,sender,body,user_key)
        VALUES('owned','fixture@invalid','owner mail','17'),('sibling','fixture@invalid','sibling mail','18')`);
      await migration.query(`INSERT INTO xss.progress(user_key,objective_id,completed)
        VALUES('19','xss_s1',1)`);
      const beforeTail = (await migration.query(`SELECT user_key,name,bio,website,name_revision,bio_revision,website_revision
        FROM xss.profiles WHERE user_key IN ('17','18','19') ORDER BY user_key`)).rows;

      assert.deepEqual(await prefixLoader(8).migrate(migration, migrationDirectory),
        ['0008_scoped_profile_reset_receipt.sql']);
      assert.deepEqual((await migration.query(`SELECT user_key,name,bio,website,name_revision,bio_revision,website_revision
        FROM xss.profiles WHERE user_key IN ('17','18','19') ORDER BY user_key`)).rows, beforeTail,
      '0008 preserves preexisting populated profiles');
      assert.deepEqual(await prefixLoader(8).migrate(migration, migrationDirectory), []);

      const sourceTail = path.join(__dirname, '../../db/postgres/workshop-migrations/xss');
      assert.deepEqual(await migrate(migration, sourceTail), [
        '0009_student_deletion_receipt_retention.sql',
        '0010_profile_origin_child_scope.sql',
        '0011_profile_origin_child_scope_not_null.sql',
        '0012_scoped_profile_reset_retirement.sql',
        '0013_scoped_profile_reset_owner_deletion_fence.sql',
        '0014_parent_profile_reset_receipt.sql',
        '0015_owner_deletion_write_fence.sql',
        '0016_email_builder_reset_receipt.sql',
      ]);
      assert.deepEqual((await migration.query(`SELECT user_key,name,bio,website,name_revision,bio_revision,website_revision
        FROM xss.profiles WHERE user_key IN ('17','18','19') ORDER BY user_key`)).rows, beforeTail,
      'current XSS tail preserves populated profiles');
      const ledger = (await migration.query(`SELECT name,checksum,applied_at FROM dvaia_migrations.ledger
        WHERE name IN ('0008_scoped_profile_reset_receipt.sql','0009_student_deletion_receipt_retention.sql',
          '0010_profile_origin_child_scope.sql','0011_profile_origin_child_scope_not_null.sql',
          '0012_scoped_profile_reset_retirement.sql','0013_scoped_profile_reset_owner_deletion_fence.sql',
          '0014_parent_profile_reset_receipt.sql','0015_owner_deletion_write_fence.sql') ORDER BY name`)).rows;
      assert.ok(ledger);
      assert.deepEqual((await migrate(migration, sourceTail)), [], 'full-tail replay is a migration no-op');
      assert.deepEqual((await migration.query(`SELECT name,checksum,applied_at FROM dvaia_migrations.ledger
        WHERE name IN ('0008_scoped_profile_reset_receipt.sql','0009_student_deletion_receipt_retention.sql',
          '0010_profile_origin_child_scope.sql','0011_profile_origin_child_scope_not_null.sql',
          '0012_scoped_profile_reset_retirement.sql','0013_scoped_profile_reset_owner_deletion_fence.sql',
          '0014_parent_profile_reset_receipt.sql','0015_owner_deletion_write_fence.sql') ORDER BY name`)).rows, ledger,
      'full-tail replay is a migration no-op');

      const repository = createXssScopedProfileResetRepository(runtime);
      const operationId = randomUUID();
      const applied = await repository.apply(input(operationId));
      assert.equal(applied.replayed, false);
      assert.deepEqual(applied.profileRevisions, { name:'6', bio:'7', website:'8' });
      assert.equal(applied.originsRemoved, 2);
      const committedRetirement = await repository.retireOrRead(input(operationId));
      assert.equal(committedRetirement.kind, 'committed');
      assert.deepEqual(committedRetirement.receipt, applied,
        'retireOrRead returns the existing committed receipt unchanged');
      assert.deepEqual((await migration.query(`SELECT name,bio,website,name_revision::text,bio_revision::text,
        website_revision::text FROM xss.profiles WHERE user_key='17'`)).rows[0], {
        name:'Security Student', bio:'Learning about web security.', website:'https://example.com',
        name_revision:'6', bio_revision:'7', website_revision:'8',
      });
      assert.equal((await migration.query("SELECT count(*)::int n FROM xss.profile_model_origins WHERE user_key='17'"))
        .rows[0].n, 0);
      assert.deepEqual((await migration.query(`SELECT user_key,name,bio,website,name_revision,bio_revision,website_revision
        FROM xss.profiles WHERE user_key='18'`)).rows[0], beforeTail[1]);
      assert.equal((await migration.query("SELECT count(*)::int n FROM xss.profile_model_origins WHERE user_key='18'"))
        .rows[0].n, 1);
      assert.equal((await migration.query("SELECT count(*)::int n FROM xss.progress WHERE user_key IN ('17','18')"))
        .rows[0].n, 2);
      assert.equal((await migration.query("SELECT count(*)::int n FROM xss.emails WHERE user_key IN ('17','18')"))
        .rows[0].n, 2);

      await runtime.query(`UPDATE xss.profiles SET bio='later learner edit',bio_revision=bio_revision+1
        WHERE user_key='17'`);
      const replay = await repository.apply(input(operationId));
      assert.equal(replay.replayed, true);
      assert.deepEqual(replay.profileRevisions, applied.profileRevisions);
      assert.equal((await migration.query("SELECT bio FROM xss.profiles WHERE user_key='17'")).rows[0].bio,
        'later learner edit', 'replay never overwrites a later edit');
      await assert.rejects(repository.apply({ ...input(operationId), workshopGeneration:'3' }),
        { code:'XSS_PROFILE_RESET_CONFLICT' });
      await assert.rejects(repository.apply(input(operationId, 18)),
        { code:'XSS_PROFILE_RESET_CONFLICT' });
      assert.deepEqual((await migration.query(`SELECT user_key,name,bio,website,name_revision,bio_revision,website_revision
        FROM xss.profiles WHERE user_key='18'`)).rows[0], beforeTail[1],
      'owner-mismatched replay cannot change a sibling profile');

      const retiredInput = input(randomUUID(), 22);
      const retired = await repository.retireOrRead(retiredInput);
      assert.equal(retired.kind, 'retired_no_effect');
      assert.equal(retired.ownerId, 22);
      await assert.rejects(repository.apply(retiredInput), { code:'55000' });
      assert.deepEqual(await repository.retireOrRead(retiredInput), retired,
        'a retired operation remains a stable no-effect outcome');
      await assert.rejects(repository.retireOrRead({ ...retiredInput, ownerId:23 }),
        { code:'XSS_PROFILE_RESET_CONFLICT' });

      for (const sql of [
        'SELECT * FROM xss.scoped_profile_reset_receipts',
        "UPDATE xss.scoped_profile_reset_receipts SET owner_id=18 WHERE operation_id='" + operationId + "'",
        "DELETE FROM xss.scoped_profile_reset_receipts WHERE operation_id='" + operationId + "'",
        'SELECT * FROM xss.scoped_profile_reset_retirements',
        "DELETE FROM xss.scoped_profile_reset_retirements WHERE operation_id='" + retiredInput.operationId + "'",
        'SELECT * FROM xss.scoped_profile_reset_owner_deletions',
        'DELETE FROM xss.scoped_profile_reset_owner_deletions WHERE owner_id=17',
        'SELECT * FROM xss.parent_profile_reset_receipts',
      ]) await assert.rejects(runtime.query(sql), { code:'42501' });
      await assert.rejects(migration.query(`UPDATE xss.scoped_profile_reset_receipts SET owner_id=18
        WHERE operation_id=$1`, [operationId]), { code:'55000' });

      await migration.query(`CREATE FUNCTION xss.reject_scoped_profile_receipt_fixture() RETURNS trigger
        LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture receipt failure'; END $$`);
      await migration.query(`CREATE TRIGGER reject_scoped_profile_receipt_fixture
        BEFORE INSERT ON xss.scoped_profile_reset_receipts FOR EACH ROW
        EXECUTE FUNCTION xss.reject_scoped_profile_receipt_fixture()`);
      await assert.rejects(repository.apply(input(randomUUID(), 19)), /fixture receipt failure/);
      assert.deepEqual((await migration.query(`SELECT user_key,name,bio,website,name_revision,bio_revision,website_revision
        FROM xss.profiles WHERE user_key='19'`)).rows[0], beforeTail[2],
      'receipt insertion failure rolls back profile defaults and revisions');
      assert.equal((await migration.query("SELECT count(*)::int n FROM xss.profile_model_origins WHERE user_key='19'"))
        .rows[0].n, 1, 'receipt insertion failure rolls back origin removal');
      await migration.query('DROP TRIGGER reject_scoped_profile_receipt_fixture ON xss.scoped_profile_reset_receipts');
      await migration.query('DROP FUNCTION xss.reject_scoped_profile_receipt_fixture()');

      const fresh = await repository.apply(input(randomUUID(), 20));
      assert.deepEqual(fresh.profileRevisions, { name:'1', bio:'1', website:'1' });
      assert.equal(fresh.originsRemoved, 0);

      const concurrentOperation = randomUUID();
      const concurrent = await Promise.all([
        repository.apply(input(concurrentOperation, 21)),
        repository.apply(input(concurrentOperation, 21)),
      ]);
      assert.deepEqual(concurrent.map(result => result.replayed).sort(), [false, true]);
      assert.deepEqual(concurrent.map(result => result.profileRevisions), [
        { name:'1', bio:'1', website:'1' }, { name:'1', bio:'1', website:'1' },
      ]);
      assert.deepEqual((await migration.query(`SELECT name_revision::text,bio_revision::text,website_revision::text
        FROM xss.profiles WHERE user_key='21'`)).rows[0], {
        name_revision:'1', bio_revision:'1', website_revision:'1',
      }, 'same-operation concurrency applies the reset exactly once');

      const parentOperationId = randomUUID();
      const parentReceipt = await repository.clearParent({ operationId:parentOperationId, ownerId:19 });
      assert.deepEqual(parentReceipt.profileRevisions, { name:'3', bio:'4', website:'5' });
      assert.equal(parentReceipt.progressRemoved, 1);
      assert.equal(parentReceipt.originsRemoved, 1);
      await migration.query("UPDATE xss.profiles SET bio='post-parent-edit',bio_revision=bio_revision+1 WHERE user_key='19'");
      const parentReplay = await repository.clearParent({ operationId:parentOperationId, ownerId:19 });
      assert.equal(parentReplay.replayed, true);
      assert.deepEqual({ ...parentReplay, replayed:false }, parentReceipt);
      assert.equal((await migration.query("SELECT bio FROM xss.profiles WHERE user_key='19'")).rows[0].bio, 'post-parent-edit');
      assert.equal((await migration.query("SELECT count(*)::int AS n FROM xss.progress WHERE user_key='19'")).rows[0].n, 0);
      assert.equal((await migration.query("SELECT count(*)::int AS n FROM xss.profile_model_origins WHERE user_key='19'")).rows[0].n, 0);

      // Deletion acquires the owner lock before its profile delete. A fixture
      // trigger holds the delete inside the transaction so the delayed apply
      // is observed waiting on that same owner lock, then fails after the
      // deletion fence commits.
      await migration.query(`INSERT INTO xss.profiles
        (user_key,name,bio,website,name_revision,bio_revision,website_revision)
        VALUES('24','delete race','bio','https://example.com',1,1,1)`);
      await migration.query(`CREATE FUNCTION xss.block_owner_delete_fixture() RETURNS trigger
        LANGUAGE plpgsql AS $$ BEGIN
          PERFORM pg_advisory_xact_lock(hashtextextended('xss-delete-race',8013));
          RETURN OLD;
        END $$`);
      await migration.query(`CREATE TRIGGER block_owner_delete_fixture
        BEFORE DELETE ON xss.profiles FOR EACH ROW
        EXECUTE FUNCTION xss.block_owner_delete_fixture()`);
      const deleteObserver = await migration.connect();
      const deleteClient = await runtime.connect();
      const applyAfterDeleteClient = await runtime.connect();
      let deleteObserverClosed = false;
      let deletePromise;
      let applyPromise;
      try {
        await deleteObserver.query('BEGIN');
        await deleteObserver.query("SELECT pg_advisory_xact_lock(hashtextextended('xss-delete-race',8013))");
        await deleteClient.query("SET statement_timeout='3000ms'");
        await applyAfterDeleteClient.query("SET statement_timeout='3000ms'");
        const deletePid = (await deleteClient.query('SELECT pg_backend_pid()')).rows[0].pg_backend_pid;
        deletePromise = settled(deleteClient.query('SELECT xss.destroy_student_owner($1)::integer AS removed', [24]));
        await waitForAdvisoryWait(observerPool, deletePid, 'owner deletion');
        const applyPid = (await applyAfterDeleteClient.query('SELECT pg_backend_pid()')).rows[0].pg_backend_pid;
        const delayedApplyOperation = randomUUID();
        applyPromise = settled(applyAfterDeleteClient.query(`SELECT * FROM xss.apply_scoped_profile_reset($1,$2,$3,$4,$5,$6,$7,$8)`, [
          delayedApplyOperation, 24, '4', '2', '6', '7', '8', '9']));
        await waitForAdvisoryWait(observerPool, applyPid, 'late apply after deletion');
        await deleteObserver.query('COMMIT');
        deleteObserverClosed = true;
        const deleteResult = await deletePromise;
        assert.equal(deleteResult.status, 'fulfilled');
        assert.ok(deleteResult.value.rows[0].removed > 0);
        const applyResult = await applyPromise;
        assert.equal(applyResult.status, 'rejected');
        assert.equal(applyResult.reason.code, '55000');
        assert.equal((await observerPool.query("SELECT count(*)::int AS n FROM xss.profiles WHERE user_key='24'")).rows[0].n, 0);
        assert.equal((await observerPool.query("SELECT count(*)::int AS n FROM xss.scoped_profile_reset_owner_deletions WHERE owner_id=24")).rows[0].n, 1);
      } finally {
        await cleanupLockRace({ observer:deleteObserver, observerClosed:deleteObserverClosed,
          promises:[deletePromise, applyPromise], clients:[deleteClient, applyAfterDeleteClient, deleteObserver],
          migration, drops:['DROP TRIGGER block_owner_delete_fixture ON xss.profiles',
            'DROP FUNCTION xss.block_owner_delete_fixture()'] });
      }

      // Conversely, an apply can hold the owner lock while its receipt insert
      // is paused. Deletion queues behind it, then removes the newly-created
      // effect and retains the owner fence after the apply commits.
      await migration.query(`CREATE FUNCTION xss.block_reset_receipt_fixture() RETURNS trigger
        LANGUAGE plpgsql AS $$ BEGIN
          PERFORM pg_advisory_xact_lock(hashtextextended('xss-apply-race',8013));
          RETURN NEW;
        END $$`);
      await migration.query(`CREATE TRIGGER block_reset_receipt_fixture
        AFTER INSERT ON xss.scoped_profile_reset_receipts FOR EACH ROW
        EXECUTE FUNCTION xss.block_reset_receipt_fixture()`);
      const applyObserver = await migration.connect();
      const applyClient = await runtime.connect();
      const deleteAfterApplyClient = await runtime.connect();
      let applyObserverClosed = false;
      let applyRacePromise;
      let deleteAfterApplyPromise;
      try {
        await applyObserver.query('BEGIN');
        await applyObserver.query("SELECT pg_advisory_xact_lock(hashtextextended('xss-apply-race',8013))");
        await applyClient.query("SET statement_timeout='3000ms'");
        await deleteAfterApplyClient.query("SET statement_timeout='3000ms'");
        const applyPid = (await applyClient.query('SELECT pg_backend_pid()')).rows[0].pg_backend_pid;
        applyRacePromise = settled(applyClient.query(`SELECT * FROM xss.apply_scoped_profile_reset($1,$2,$3,$4,$5,$6,$7,$8)`, [
          randomUUID(), 26, '4', '2', '6', '7', '8', '9']));
        await waitForAdvisoryWait(observerPool, applyPid, 'apply receipt insertion');
        const deletePid = (await deleteAfterApplyClient.query('SELECT pg_backend_pid()')).rows[0].pg_backend_pid;
        deleteAfterApplyPromise = settled(deleteAfterApplyClient.query('SELECT xss.destroy_student_owner($1)::integer AS removed', [26]));
        await waitForAdvisoryWait(observerPool, deletePid, 'deletion behind apply');
        await applyObserver.query('COMMIT');
        applyObserverClosed = true;
        const applyResult = await applyRacePromise;
        assert.equal(applyResult.status, 'fulfilled');
        assert.equal(applyResult.value.rowCount, 1);
        const deleteResult = await deleteAfterApplyPromise;
        assert.equal(deleteResult.status, 'fulfilled');
        assert.ok(deleteResult.value.rows[0].removed > 0);
        assert.equal((await observerPool.query("SELECT count(*)::int AS n FROM xss.profiles WHERE user_key='26'")).rows[0].n, 0);
        assert.equal((await observerPool.query("SELECT count(*)::int AS n FROM xss.scoped_profile_reset_receipts WHERE owner_id=26")).rows[0].n, 0);
        assert.equal((await observerPool.query("SELECT count(*)::int AS n FROM xss.scoped_profile_reset_owner_deletions WHERE owner_id=26")).rows[0].n, 1);
      } finally {
        await cleanupLockRace({ observer:applyObserver, observerClosed:applyObserverClosed,
          promises:[applyRacePromise, deleteAfterApplyPromise], clients:[applyClient, deleteAfterApplyClient, applyObserver],
          migration, drops:['DROP TRIGGER block_reset_receipt_fixture ON xss.scoped_profile_reset_receipts',
            'DROP FUNCTION xss.block_reset_receipt_fixture()'] });
      }

      const siblingBeforeDeletion = (await migration.query(`SELECT user_key,name,bio,website,name_revision,bio_revision,website_revision
        FROM xss.profiles WHERE user_key='18'`)).rows[0];
      const deleted = (await runtime.query('SELECT xss.destroy_student_owner($1)::integer AS removed', [17])).rows[0].removed;
      assert.ok(deleted > 0, 'runtime cleanup must remove the target owner rows and receipt');
      assert.equal((await migration.query("SELECT count(*)::int AS n FROM xss.scoped_profile_reset_receipts WHERE owner_id=17")).rows[0].n, 0);
      const retiredBeforeCleanup = (await migration.query(
        'SELECT operation_id::text,owner_id FROM xss.scoped_profile_reset_retirements WHERE operation_id=$1',
        [retiredInput.operationId])).rows[0];
      await runtime.query('SELECT xss.destroy_student_owner($1)::integer AS removed', [22]);
      assert.deepEqual((await migration.query(
        'SELECT operation_id::text,owner_id FROM xss.scoped_profile_reset_retirements WHERE operation_id=$1',
        [retiredInput.operationId])).rows[0], retiredBeforeCleanup,
      'student cleanup retains retirement tombstones so late replay remains fenced');
      assert.equal((await migration.query("SELECT count(*)::int AS n FROM xss.profiles WHERE user_key='17'")).rows[0].n, 0);
      assert.equal((await migration.query("SELECT count(*)::int AS n FROM xss.profile_model_origins WHERE user_key='17'")).rows[0].n, 0);
      assert.equal((await migration.query("SELECT count(*)::int AS n FROM xss.scoped_profile_reset_owner_deletions WHERE owner_id=17")).rows[0].n, 1,
        'owner deletion fence is retained after student cleanup');
      await assert.rejects(migration.query(
        'UPDATE xss.scoped_profile_reset_owner_deletions SET owner_id=17 WHERE owner_id=17'),
      { code:'55000' });
      await assert.rejects(migration.query(
        'DELETE FROM xss.scoped_profile_reset_owner_deletions WHERE owner_id=17'),
      { code:'55000' });
      await assert.rejects(repository.apply(input(randomUUID(), 17)), { code:'55000' },
        'a delayed unknown operation cannot recreate a deleted owner profile');
      await assert.rejects(repository.retireOrRead(input(randomUUID(), 17)), { code:'55000' },
        'retire/read cannot create a post-deletion operation tombstone');
      // 0015 fences ordinary runtime writes as well as the reset functions.
      // The trigger checks both old and new canonical owner IDs, so a delayed
      // update cannot move a sibling row onto a deleted owner either.
      const deletedOwnerWrites = [
        `INSERT INTO xss.profiles(user_key,name,bio,website) VALUES('17','late','late','https://late.invalid')`,
        `INSERT INTO xss.progress(user_key,objective_id,completed) VALUES('17','late',1)`,
        `INSERT INTO xss.emails(subject,sender,body,user_key) VALUES('late','late@invalid','late','17')`,
        `INSERT INTO xss.email_profiles(user_id,full_name,email_address) VALUES(17,'late','late@invalid')`,
        `INSERT INTO xss.email_templates(user_id,profile_id,template_name,html_content) VALUES(17,999,'late','<p>late</p>')`,
        `INSERT INTO xss.template_previews(template_id,user_id) VALUES(999,17)`,
        `INSERT INTO xss.xss_challenge_progress(user_id,challenge_level,challenge_name) VALUES(17,1,'late')`,
        `INSERT INTO xss.xss_email_judge_receipts(user_id,challenge_level,template_id,verdict,rubric_version,browser_executed) VALUES(17,1,999,'fail','late',0)`,
        `INSERT INTO xss.profile_model_origins
          (user_key,field,platform_user_id,revision,value_sha256,workshop_generation,run_id,owner_key,
           durable_generation,decision_source,provider,model,raw_decision_sha256,observation_index)
          VALUES('17','name',17,1,repeat('a',64),1,'00000000-0000-4000-8000-000000000017','["XSS","17"]',
                 1,'model','ollama','llama3.1:8b',repeat('b',64),0)`,
      ];
      for (const sql of deletedOwnerWrites) await assert.rejects(runtime.query(sql), { code:'55000' });
      await assert.rejects(migration.query("UPDATE xss.profiles SET user_key='17' WHERE user_key='18'"), { code:'55000' });
      assert.deepEqual((await migration.query(`SELECT user_key,name,bio,website,name_revision,bio_revision,website_revision
        FROM xss.profiles WHERE user_key='18'`)).rows[0], siblingBeforeDeletion,
      'owner cleanup must preserve sibling profile state');
      await runtime.query("UPDATE xss.profiles SET bio='sibling-after-delete' WHERE user_key='18'");
      await runtime.query(`INSERT INTO xss.profiles(user_key,name,bio,website)
        VALUES('anon_1234567890123456','anonymous','anonymous','https://anon.invalid')`);
      await runtime.query(`INSERT INTO xss.emails(subject,sender,body,user_key)
        VALUES('public','public@invalid','public',NULL),('anonymous','anon@invalid','anonymous','anon_1234567890123456')`);
      await runtime.query("DELETE FROM xss.emails WHERE user_key='anon_1234567890123456'");
      await runtime.query("DELETE FROM xss.profiles WHERE user_key='anon_1234567890123456'");
      const deletedParent = (await runtime.query('SELECT xss.destroy_student_owner($1)::integer AS removed', [19])).rows[0].removed;
      assert.ok(deletedParent > 0);
      assert.equal((await migration.query('SELECT count(*)::int AS n FROM xss.parent_profile_reset_receipts WHERE owner_id=19')).rows[0].n, 0,
        'owner cleanup removes parent receipts after fencing deletion');
      assert.equal((await migration.query('SELECT count(*)::int AS n FROM xss.scoped_profile_reset_owner_deletions WHERE owner_id=19')).rows[0].n, 1);
      const replayDelete = (await runtime.query('SELECT xss.destroy_student_owner($1)::integer AS removed', [17])).rows[0].removed;
      assert.equal(replayDelete, 0, 'owner cleanup is idempotent after deletion');
      for (const value of [null, 0, 2147483648]) {
        await assert.rejects(runtime.query('SELECT xss.destroy_student_owner($1)', [value]), { code:'22023' });
      }
    } finally {
      const closed = await Promise.allSettled([runtime.end(), migration.end(), observerPool.end()]);
      const failures = closed.filter(result => result.status === 'rejected').map(result => result.reason);
      if (failures.length) throw new AggregateError(failures, 'XSS scoped profile reset cleanup failed');
    }
  });
