'use strict';
const assert = require('node:assert/strict');
const WORKSHOP = 'sensitive_info_disclosure';
async function createResetLeasePools({ env = process.env,
  createPool = require('../../server/database/postgres').createPool } = {}) {
  const owned = [];
  const close = async () => {
    const results = await Promise.allSettled(owned.map(pool => pool.end()));
    const errors = results.filter(result => result.status === 'rejected').map(result => result.reason);
    if (errors.length) throw new AggregateError(errors, 'Reset fixture lease pool cleanup failed');
  };
  try {
    const graphLease = createPool(env, 'PG_ADMIN_BROWSER_TEST_RUNTIME_URL', { purpose: 'lease' }); owned.push(graphLease);
    const lifecycleLease = createPool(env, 'PG_ADMIN_BROWSER_TEST_RUNTIME_URL', { purpose: 'lease' }); owned.push(lifecycleLease);
    return { graphLease, lifecycleLease, close };
  } catch (error) {
    try { await close(); } catch (cleanupError) { error.cleanupError = cleanupError; }
    throw error;
  }
}

async function createResetSupport({ runtime, migration, progress, appDataRoot }) {
  const { createPool } = require('../../server/database/postgres');
  const runtimeUrl = new URL(process.env.FINFLOW_WORKSHOP_DATABASE_URL);
  const migrationUrl = new URL(process.env.FINFLOW_WORKSHOP_MIGRATION_DATABASE_URL);
  const identityUrl = new URL(process.env.PG_ADMIN_BROWSER_TEST_RUNTIME_URL);
  assert.equal(runtimeUrl.hostname, '127.0.0.1');
  assert.match(runtimeUrl.pathname, /^\/owasp_ai_goat_test_student_reset_finflow_[a-f0-9]{12}$/);
  assert.equal(runtimeUrl.pathname, migrationUrl.pathname);
  assert.notEqual(runtimeUrl.pathname, identityUrl.pathname);
  assert.equal(runtimeUrl.username, 'dvaia_finflow_runtime');
  assert.equal(migrationUrl.username, 'dvaia_finflow_migration');
  const finflow = createPool(process.env, 'FINFLOW_WORKSHOP_DATABASE_URL');
  const finflowMigration = createPool(process.env, 'FINFLOW_WORKSHOP_MIGRATION_DATABASE_URL');
  let leasePools;
  try {
    leasePools = await createResetLeasePools();
    const store = require('../../server/database/postgres/sensitiveInfoWorkshopDb').createFinflowWorkshopDb(finflow);
    await store.initialize(finflowMigration);
    const { createPostgresRunLedger } = require('../../server/agent-runtime/postgresRunLedger');
    const ledger = createPostgresRunLedger(runtime, { leasePool: leasePools.graphLease });
    const { SensitiveInfoWorkshopAgent, createSensitiveInfoWorkshopStateStore } = require('../../server/services/sensitiveInfoWorkshopAgent');
    const stateStore = createSensitiveInfoWorkshopStateStore();
    const agent = new SensitiveInfoWorkshopAgent({ stateStore, runLedger: ledger });
    const runs = require('../../server/agent-runtime/runCoordinator').createRunCoordinator({ family: 'LegacySensitiveInfo', ledger });
    const composition = await require('../../server/services/sensitiveInfoResetComposition').createSensitiveInfoResetComposition({
      identityPool: runtime, finflowPool: finflow, migrationPools: { identity: migration, finflow: finflowMigration },
      appDataRoot, runs,
      finflowReset: (owner, work) => agent.resetUserExclusive(String(owner), async () => {
        await work(); stateStore.resetUser(String(owner));
      }),
    });
    assert.ok(composition?.reset);
    const { createPostgresWorkshopResetService, withPostgresStudentResetAdmission } = require('../../server/services/postgresWorkshopResetService');
    const resetService = createPostgresWorkshopResetService({ progress,
      adapters: { [WORKSHOP]: { resetOwner: (owner, options) => composition.reset.reset(owner, options) } },
      withStudentResetAdmission: (owner, work) => withPostgresStudentResetAdmission(leasePools.lifecycleLease, owner, work),
    });
    async function resume(owner, marker) {
      await progress.syncWorkshopStarted(owner, WORKSHOP);
      await progress.recordHeartbeat({ userId: owner, workshopKey: WORKSHOP });
      await store.logToolCall(String(owner), { name: marker, result: 'controlled non-credit activity', mode: 'vulnerable' });
    }
    async function seedControlledCompletion(owner) {
      // Projection/reset fixture only: no agent run, model, evidence adapter or Judge is invoked.
      const objectiveId = 'tool_enum';
      const available = (await migration.query(`SELECT is_enabled FROM workshop_platform.objectives
        WHERE workshop_key=$1 AND objective_id=$2 AND catalog_active=true`, [WORKSHOP, objectiveId])).rows[0];
      assert.equal(available?.is_enabled, true, 'controlled reset completion objective must be enabled');
      const result = await progress.syncObjectiveComplete(owner, WORKSHOP, objectiveId);
      assert.equal(result.changed, true, 'controlled completion fixture must be newly seeded');
      return objectiveId;
    }
    async function snapshot(owner) {
      const query = async (pool, sql, args=[owner]) => (await pool.query(sql, args)).rows;
      return {
        state: await query(migration, 'SELECT * FROM workshop_platform.user_state WHERE user_id=$1 AND workshop_key=$2', [owner, WORKSHOP]),
        time: await query(migration, 'SELECT * FROM workshop_platform.time_tracking WHERE user_id=$1 AND workshop_key=$2 ORDER BY id', [owner, WORKSHOP]),
        completions: await query(migration, 'SELECT * FROM workshop_platform.completions WHERE user_id=$1 AND workshop_key=$2 ORDER BY objective_id', [owner, WORKSHOP]),
        resets: await query(migration, 'SELECT * FROM identity.sensitive_info_resets WHERE owner_id=$1 ORDER BY operation_id'),
        steps: await query(migration, 'SELECT s.* FROM identity.sensitive_info_reset_steps s JOIN identity.sensitive_info_resets r USING(operation_id) WHERE r.owner_id=$1 ORDER BY operation_id,ordinal'),
        tools: await query(finflowMigration, 'SELECT * FROM finflow.tool_log WHERE user_id=$1 ORDER BY id', [String(owner)]),
        receipts: await query(finflowMigration, 'SELECT * FROM finflow.sensitive_info_cleanup_receipts WHERE owner_id=$1 ORDER BY operation_id,step_key'),
      };
    }
    return { resetService, resume, seedControlledCompletion, snapshot,
      close: async () => { await Promise.all([finflow.end(), finflowMigration.end(), leasePools.close()]); } };
  } catch (error) {
    await Promise.allSettled([finflow.end(), finflowMigration.end(), leasePools?.close()]); throw error;
  }
}
module.exports = { createResetSupport, createResetLeasePools };
