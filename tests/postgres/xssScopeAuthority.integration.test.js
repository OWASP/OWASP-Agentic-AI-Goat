'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const path = require('node:path');
const { createXssBoundedMigrationView } = require('../helpers/xssBoundedMigrationView');
const { createPool } = require('../../server/database/postgres');
const { createPostgresRunLedger } = require('../../server/agent-runtime/postgresRunLedger');
const { createRunCoordinator } = require('../../server/agent-runtime/runCoordinator');
const { createXssScopeAuthorityRepository } = require(
  '../../server/database/postgres/xssScopeAuthorityRepository');

const RUNTIME = 'PG_XSS_SCOPE_RUNTIME_URL';
const MIGRATION = 'PG_XSS_SCOPE_MIGRATION_URL';
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes'
  && Boolean(process.env[RUNTIME]) && Boolean(process.env[MIGRATION]);
const password = '$2b$12$000000000000000000000uG3W0Jp6IPhhD1TRqN8Yc2zJQG3vVnSA';

function assertOwnedUrl(value, role) {
  const url = new URL(value);
  assert.equal(url.hostname, '127.0.0.1');
  assert.equal(url.pathname, '/owasp_ai_goat_test_xss_scope_authority_identity');
  assert.equal(decodeURIComponent(url.username), role);
}

async function createUser(migration, suffix) {
  return (await migration.query(`INSERT INTO identity.users(username,email,password)
    VALUES($1,$2,$3) RETURNING id`,
  [`xss-scope-${suffix}`, `xss-scope-${suffix}@fixture.invalid`, password])).rows[0];
}

test('native 0070 binds exact XSS child authority and fails closed across child, parent and deletion fences',
  { skip:!enabled }, async () => {
    assertOwnedUrl(process.env[RUNTIME], 'dvaia_identity_runtime');
    assertOwnedUrl(process.env[MIGRATION], 'dvaia_identity_migration');
    const runtime = createPool(process.env, RUNTIME);
    const migration = createPool(process.env, MIGRATION);
    const lease = createPool(process.env, RUNTIME);
    lease.options.max = 2;
    // Historical 0070→0071 qualification, not current full-tail readiness.
    const view = createXssBoundedMigrationView({ identity:70 });
    const { migrate, initializeIdentityRepository } = view;
    try {
      assert.equal((await migrate(migration, view.directories.identity)).at(-1), '0070_xss_scope_authority.sql');
      const [owner, deletionOwner, parentOwner, requester] = await Promise.all([
        createUser(migration, 'owner'), createUser(migration, 'deleted'),
        createUser(migration, 'parent'), createUser(migration, 'requester'),
      ]);
      const historicalRun = randomUUID();
      const historicalOwnerKey = JSON.stringify(['XSS', String(owner.id)]);
      await migration.query('INSERT INTO graph_runtime.owners(owner_key) VALUES($1)', [historicalOwnerKey]);
      await migration.query(`INSERT INTO graph_runtime.runs(run_id,owner_key,generation,status)
        VALUES($1,$2,0,'running')`, [historicalRun, historicalOwnerKey]);
      await migration.query(`INSERT INTO identity.xss_scope_state(owner_id,owner_key,scope_key)
        VALUES($1,$2,'email'),($3,$4,'stored_llm')`,
      [owner.id, historicalOwnerKey, requester.id, JSON.stringify(['XSS', String(requester.id)])]);
      await migration.query(`INSERT INTO identity.xss_run_bindings
        (run_id,owner_id,owner_key,scope_key,parent_generation,child_generation)
        VALUES($1,$2,$3,'email',0,0)`, [historicalRun, owner.id, historicalOwnerKey]);
      await migration.query("UPDATE graph_runtime.runs SET status='completed',finished_at=clock_timestamp() WHERE run_id=$1",
        [historicalRun]);
      const beforeCorrection = (await migration.query(`SELECT owner_id,owner_key,scope_key,
        child_generation::text child_generation,state FROM identity.xss_scope_state ORDER BY owner_id,scope_key`)).rows;
      const bindingBeforeCorrection = (await migration.query(`SELECT run_id,owner_id,owner_key,scope_key,
        parent_generation::text parent_generation,child_generation::text child_generation
        FROM identity.xss_run_bindings ORDER BY run_id`)).rows;
      view.setCeiling('identity', 71);
      assert.deepEqual(await initializeIdentityRepository(runtime, migration),
        ['0071_xss_scope_bind_conflict_fix.sql']);
      assert.deepEqual((await migration.query(`SELECT owner_id,owner_key,scope_key,
        child_generation::text child_generation,state FROM identity.xss_scope_state ORDER BY owner_id,scope_key`)).rows,
      beforeCorrection);
      assert.deepEqual((await migration.query(`SELECT run_id,owner_id,owner_key,scope_key,
        parent_generation::text parent_generation,child_generation::text child_generation
        FROM identity.xss_run_bindings ORDER BY run_id`)).rows, bindingBeforeCorrection);
      assert.deepEqual(await initializeIdentityRepository(runtime, migration), [], 'the corrected bounded tail replays as a no-op');
      const authority = createXssScopeAuthorityRepository();
      const coordinator = createRunCoordinator({ family:'XSS',
        ledger:createPostgresRunLedger(runtime, { leasePool:lease, scopeAuthority:authority }) });

      let emailBinding;
      await coordinator.run(owner.id, { scope:{ userId:owner.id, scopeKey:'email' } }, async execution => {
        emailBinding = execution.scopeBinding;
        assert.deepEqual(emailBinding, {
          runId:execution.runId, ownerId:owner.id, ownerKey:JSON.stringify(['XSS', String(owner.id)]),
          scopeKey:'email', parentGeneration:'0', childGeneration:'0',
        });
        await execution.check();
      });
      assert.equal((await migration.query(`SELECT count(*)::int n FROM identity.xss_run_bindings
        WHERE run_id=$1`, [emailBinding.runId])).rows[0].n, 1);

      await assert.rejects(runtime.query(`UPDATE identity.xss_scope_state
        SET child_generation=child_generation+1 WHERE owner_id=$1 AND scope_key='email'`, [owner.id]),
      { code:'42501' });
      await assert.rejects(runtime.query(`DELETE FROM identity.xss_scope_state
        WHERE owner_id=$1 AND scope_key='email'`, [owner.id]), { code:'42501' });
      await assert.rejects(runtime.query(`UPDATE identity.xss_run_bindings
        SET child_generation=child_generation+1 WHERE run_id=$1`, [emailBinding.runId]),
      { code:'42501' });
      await assert.rejects(runtime.query('DELETE FROM identity.xss_run_bindings WHERE run_id=$1',
        [emailBinding.runId]), { code:'42501' });
      await assert.rejects(runtime.query('SELECT * FROM identity.xss_run_bindings WHERE run_id=$1',
        [emailBinding.runId]), { code:'42501' });

      let staleBinding;
      await assert.rejects(coordinator.run(owner.id,
        { scope:{ userId:owner.id, scopeKey:'stored_user' } }, async execution => {
          staleBinding = execution.scopeBinding;
          await migration.query(`UPDATE identity.xss_scope_state SET child_generation=child_generation+1,
            updated_at=clock_timestamp() WHERE owner_id=$1 AND scope_key='stored_user'`, [owner.id]);
          await execution.check();
        }), { name:'AbortError' });
      assert.equal(staleBinding.childGeneration, '0');
      const children = (await migration.query(`SELECT scope_key,child_generation::text generation
        FROM identity.xss_scope_state WHERE owner_id=$1 ORDER BY scope_key`, [owner.id])).rows;
      assert.deepEqual(children, [
        { scope_key:'email', generation:'0' },
        { scope_key:'stored_user', generation:'1' },
      ]);
      await coordinator.run(owner.id, { scope:{ userId:owner.id, scopeKey:'email' } },
        async execution => { assert.equal(execution.scopeBinding.childGeneration, '0'); await execution.check(); });

      const deletionKey = JSON.stringify(['XSS', String(deletionOwner.id)]);
      const beforeDeletion = Number((await migration.query(
        'SELECT count(*) n FROM graph_runtime.runs WHERE owner_key=$1', [deletionKey])).rows[0].n);
      await migration.query(`INSERT INTO identity.student_deletion_jobs
        (job_id,subject_user_id,requested_by) VALUES($1,$2,$3)`,
      [randomUUID(), deletionOwner.id, requester.id]);
      await assert.rejects(coordinator.run(deletionOwner.id,
        { scope:{ userId:deletionOwner.id, scopeKey:'reflected' } }, async () => {}),
      { name:'AbortError', code:'XSS_SCOPE_STALE' });
      assert.equal(Number((await migration.query(
        'SELECT count(*) n FROM graph_runtime.runs WHERE owner_key=$1', [deletionKey])).rows[0].n),
      beforeDeletion, 'the deletion rejection rolls back the graph run inserted in the same transaction');

      await assert.rejects(coordinator.run(parentOwner.id,
        { scope:{ userId:parentOwner.id, scopeKey:'stored_llm' } }, async execution => {
          await migration.query(`UPDATE graph_runtime.owners SET generation=generation+1,
            updated_at=clock_timestamp() WHERE owner_key=$1`, [execution.ownerKey]);
          await execution.check();
        }), { name:'AbortError' });
    } finally {
      const closed = await Promise.allSettled([runtime.end(), migration.end(), lease.end()]);
      const failures = closed.filter(result => result.status === 'rejected').map(result => result.reason);
      if (failures.length) throw new AggregateError(failures, 'XSS scope authority pool cleanup failed');
    }
  });
