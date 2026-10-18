'use strict';

const { withTransaction } = require('./index');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const WORKSHOP_KEY = 'secureshop_agent_security';
function failure(code, message = 'Canonical SecureShop progress retirement unavailable') {
  return Object.assign(new Error(message), { code });
}
function uuid(value) {
  if (typeof value !== 'string' || !UUID.test(value)) throw failure('INVALID_ARGUMENT', 'resetId is invalid');
  return value.toLowerCase();
}
function project(row) {
  return Object.freeze({ resetId: row.reset_id, launchId: row.launch_id,
    scenarioId: row.scenario_id, fromLaunchGeneration: Number(row.from_launch_generation),
    platformOwnerId: Number(row.original_platform_owner_id),
    platformSessionId: Number(row.original_platform_session_id), workshopKey: row.workshop_key,
    workshopGeneration: Number(row.workshop_generation),
    retiredObjectiveContributionCount: Number(row.retired_objective_contribution_count),
    retiredActivityContributionCount: Number(row.retired_activity_contribution_count),
    retiredTimeEntryCount: Number(row.retired_time_entry_count),
    retiredTimeSeconds: String(row.retired_time_seconds),
    projectedCompletionCount: Number(row.projected_completion_count),
    projectedActivityCount: Number(row.projected_activity_count),
    projectedTimeEntryCount: Number(row.projected_time_entry_count),
    projectedTimeSeconds: String(row.projected_time_seconds), completedAt: row.completed_at });
}
const notRetired = (alias, current = false) => `NOT EXISTS (
  SELECT 1 FROM identity.secureshop_progress_cleanup_history h
  WHERE h.launch_id=${alias}.platform_launch_id
    AND h.from_launch_generation=${alias}.platform_launch_generation)
  ${current ? `AND NOT (${alias}.platform_launch_id=$3 AND ${alias}.platform_launch_generation=$4)` : ''}`;

async function validateProjection(client, row) {
  const args = [row.original_platform_owner_id, WORKSHOP_KEY, row.workshop_generation];
  const objectiveMismatch = (await client.query(`SELECT EXISTS(
      (SELECT c.objective_id FROM workshop_platform.completions c WHERE c.user_id=$1 AND c.workshop_key=$2
       EXCEPT SELECT DISTINCT s.objective_id FROM workshop_platform.objective_contributions s
         WHERE s.user_id=$1 AND s.workshop_key=$2 AND s.workshop_generation=$3 AND ${notRetired('s')})
      UNION ALL
      (SELECT DISTINCT s.objective_id FROM workshop_platform.objective_contributions s
         WHERE s.user_id=$1 AND s.workshop_key=$2 AND s.workshop_generation=$3 AND ${notRetired('s')}
       EXCEPT SELECT c.objective_id FROM workshop_platform.completions c WHERE c.user_id=$1 AND c.workshop_key=$2)
    ) AS mismatch`, args)).rows[0].mismatch;
  const activityMismatch = (await client.query(`SELECT EXISTS(
    SELECT 1 FROM (
      SELECT actual.activity_key,actual.activity_count,expected.expected_count
      FROM (SELECT activity_key,activity_count FROM workshop_platform.activity_counters
        WHERE user_id=$1 AND workshop_key=$2) actual
      FULL JOIN (
        SELECT a.activity_key,sum(a.activity_delta)::integer AS expected_count
        FROM workshop_platform.instance_activity_contributions a
        WHERE a.user_id=$1 AND a.workshop_key=$2 AND a.workshop_generation=$3 AND ${notRetired('a')}
        GROUP BY a.activity_key) expected USING(activity_key)
      WHERE activity_count IS DISTINCT FROM expected_count) differences) AS mismatch`, args)).rows[0].mismatch;
  const unscopedTime = (await client.query(`SELECT EXISTS(SELECT 1 FROM workshop_platform.time_tracking
    WHERE user_id=$1 AND workshop_key=$2 AND (platform_launch_id IS NULL OR workshop_generation IS NULL)) AS invalid`,
  args.slice(0, 2))).rows[0].invalid;
  if (objectiveMismatch || activityMismatch || unscopedTime) throw failure('PROGRESS_CHECKPOINT_MISMATCH');
}

function createSecureShopProgressCleanupCheckpointRepository(pool) {
  if (typeof pool?.connect !== 'function' || typeof pool?.query !== 'function') throw failure('INVALID_CONFIGURATION');
  return Object.freeze({
    async finalize(value) {
      const resetId = uuid(value);
      return withTransaction(pool, async client => {
        const located = (await client.query(
          'SELECT launch_id FROM identity.secureshop_launch_resets WHERE reset_id=$1', [resetId])).rows[0];
        if (!located) throw failure('RESET_CLEANUP_AUTHORITY_REQUIRED');
        // Match identity teardown and grading admission: owner, retained
        // session (when it still exists), then launch. Cleanup remains possible
        // after session revocation/deletion, but never takes launch->owner locks.
        const coordinates=(await client.query(`SELECT original_platform_owner_id,
          original_platform_session_id FROM identity.secureshop_launches WHERE launch_id=$1`,
        [located.launch_id])).rows[0];
        if(!coordinates)throw failure('RESET_CLEANUP_AUTHORITY_REQUIRED');
        await client.query('SELECT id FROM identity.users WHERE id=$1 FOR SHARE',
          [coordinates.original_platform_owner_id]);
        await client.query('SELECT id FROM identity.user_sessions WHERE id=$1 FOR SHARE',
          [coordinates.original_platform_session_id]);
        const launch = (await client.query(`SELECT launch_id,scenario_id,generation,
            original_platform_owner_id,original_platform_session_id
          FROM identity.secureshop_launches WHERE launch_id=$1 FOR UPDATE`, [located.launch_id])).rows[0];
        const reset = (await client.query(`SELECT * FROM identity.secureshop_launch_resets
          WHERE reset_id=$1 AND launch_id=$2 FOR UPDATE`, [resetId, located.launch_id])).rows[0];
        if (!launch || !reset || !['fenced','committed','aborted'].includes(reset.status)) {
          throw failure('RESET_CLEANUP_AUTHORITY_REQUIRED');
        }
        const prior = (await client.query(`SELECT * FROM identity.secureshop_progress_cleanup_history
          WHERE reset_id=$1 OR (launch_id=$2 AND from_launch_generation=$3)`,
        [resetId,launch.launch_id,reset.from_generation])).rows;
        if (prior.length) {
          const row = prior[0];
          if (prior.length!==1 || row.reset_id!==resetId || row.launch_id!==launch.launch_id
            || row.scenario_id!==launch.scenario_id
            || Number(row.from_launch_generation)!==Number(reset.from_generation)
            || Number(row.original_platform_owner_id)!==Number(launch.original_platform_owner_id)
            || Number(row.original_platform_session_id)!==Number(launch.original_platform_session_id)
            || row.workshop_key!==WORKSHOP_KEY || reset.progress_reconciliation_required) {
            throw failure('PROGRESS_CHECKPOINT_MISMATCH');
          }
          await validateProjection(client,row);
          return Object.freeze({resetId,replayed:true,checkpoint:project(row)});
        }
        if (Number(launch.generation)!==Number(reset.to_generation)) throw failure('STALE_GENERATION');
        await client.query('SELECT revision FROM workshop_platform.config_revision WHERE id=1 FOR SHARE');
        // Cleanup is lifecycle authority, not learner admission. An instructor
        // hiding the exercise must not strand a fenced launch or account
        // deletion; the canonical catalog row still supplies the FK identity.
        const workshop=(await client.query(`SELECT workshop_key FROM workshop_platform.exercises
          WHERE workshop_key=$1 FOR SHARE`,[WORKSHOP_KEY])).rows[0];
        if(!workshop)throw failure('CATALOG_UNAVAILABLE');
        await client.query(`INSERT INTO workshop_platform.user_state(user_id,workshop_key)
          VALUES($1,$2) ON CONFLICT DO NOTHING`,[launch.original_platform_owner_id,WORKSHOP_KEY]);
        const state=(await client.query(`SELECT generation FROM workshop_platform.user_state
          WHERE user_id=$1 AND workshop_key=$2 FOR UPDATE`,[launch.original_platform_owner_id,WORKSHOP_KEY])).rows[0];
        if(!state||!Number.isInteger(state.generation)||state.generation<0)throw failure('STALE_GENERATION');
        const row=(await client.query(
          'SELECT * FROM identity.finalize_secureshop_progress_cleanup($1)',[resetId])).rows[0];
        if(!row||Number(row.workshop_generation)!==state.generation)throw failure('PROGRESS_CHECKPOINT_MISMATCH');
        return Object.freeze({resetId,replayed:false,checkpoint:project(row)});
      });
    },
  });
}
module.exports={createSecureShopProgressCleanupCheckpointRepository,WORKSHOP_KEY};
