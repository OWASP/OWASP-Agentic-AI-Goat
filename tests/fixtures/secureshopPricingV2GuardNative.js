'use strict';

// Invoked by the detached Pricing native fixture after its real registered
// merchant has committed a v2 experiment admission. Every probe uses the
// migration role only inside a rolled-back transaction; no learner row changes.
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');

const TABLE = 'secureshop_agents.bound_pricing_admissions';
const COLUMNS = Object.freeze([
  'platform_launch_id', 'platform_scenario_id', 'platform_launch_generation',
  'original_platform_owner_id', 'original_platform_session_id', 'operation_id',
  'run_id', 'target_id', 'target_snapshot_json', 'persona_id',
  'persona_session_id', 'persona_role', 'authority_version', 'request_sha256',
  'binding_sha256', 'request_json',
]);

async function assertPricingV2GuardNative({ agentsRuntime, agentsMigration, ownedAdmissionRow } = {}) {
  assert.equal(typeof agentsRuntime?.query, 'function');
  assert.equal(typeof agentsMigration?.connect, 'function');
  const original = ownedAdmissionRow;
  assert.ok(original && COLUMNS.every(key => Object.hasOwn(original, key)));
  assert.equal(original.persona_role, 'merchant');
  assert.equal(original.request_json?.task, 'pricing-strategy');
  assert.equal(Object.keys(original.request_json).length, 5);
  assert.deepEqual(Object.keys(original.request_json.experiment).sort(), ['durationDays', 'strategy']);
  assert.equal(typeof original.request_json.experiment.durationDays, 'number');
  const existing = await agentsRuntime.query(`SELECT request_json,request_sha256,target_id FROM ${TABLE}
    WHERE platform_launch_id=$1 AND platform_scenario_id=$2 AND platform_launch_generation=$3
      AND original_platform_owner_id=$4 AND original_platform_session_id=$5 AND operation_id=$6`,
  [original.platform_launch_id, original.platform_scenario_id, original.platform_launch_generation,
    original.original_platform_owner_id, original.original_platform_session_id, original.operation_id]);
  assert.equal(existing.rows.length, 1, 'genuine v2 admission must already be durable');
  assert.deepEqual(existing.rows[0].request_json, original.request_json);

  const noExperiment = { ...original.request_json };
  delete noExperiment.experiment;
  const probes = [
    ['v1Accepted', true, noExperiment],
    ['v2Accepted', true, original.request_json],
    ['unknownFifthDenied', false, { ...noExperiment, unknown: true }],
    ['missingStrategyDenied', false, { ...noExperiment,
      experiment: { durationDays: 7, unknown: true } }],
    ['missingDurationDenied', false, { ...noExperiment,
      experiment: { strategy: 'undercut', unknown: true } }],
    ['nullStrategyDenied', false, { ...noExperiment,
      experiment: { strategy: null, durationDays: 7 } }],
    ['nullDurationDenied', false, { ...noExperiment,
      experiment: { strategy: 'undercut', durationDays: null } }],
    ['extraNestedDenied', false, { ...noExperiment,
      experiment: { strategy: 'undercut', durationDays: 7, unknown: true } }],
    ['stringDurationDenied', false, { ...noExperiment,
      experiment: { strategy: 'undercut', durationDays: '7' } }],
    ['customerModeDenied', false, { ...noExperiment,
      task: 'price-advisor', experiment: { strategy: 'undercut', durationDays: 7 } },
    { persona_role: 'customer' }],
  ];
  const foreign = await agentsRuntime.query('SELECT COALESCE(max(shop_user_id),0)+1 AS id FROM secureshop_agents.bound_actor_identities');
  probes.push(['foreignActorDenied', false, original.request_json,
    { persona_id: Number(foreign.rows[0].id) }]);

  const checks = {};
  for (const [name, accepted, request, overrides = {}] of probes) {
    const client = await agentsMigration.connect();
    const operationId = randomUUID();
    const targetId = randomUUID();
    const value = { ...original, ...overrides, operation_id: operationId, target_id: targetId,
      request_json: { ...request, operationId } };
    try {
      await client.query('BEGIN');
      const result = client.query(`INSERT INTO ${TABLE} (${COLUMNS.join(',')})
        VALUES (${COLUMNS.map((_, index) => `$${index + 1}`).join(',')}) RETURNING request_json`,
      COLUMNS.map(key => key === 'request_json' || key === 'target_snapshot_json'
        ? JSON.stringify(value[key]) : value[key]));
      if (accepted) {
        const inserted = await result;
        assert.equal(inserted.rows.length, 1, `${name}: exact registered actor should be admitted`);
        assert.deepEqual(inserted.rows[0].request_json, value.request_json);
      } else {
        await assert.rejects(result, { code: '55000' }, `${name}: guard must deny the request`);
      }
      checks[name] = true;
    } finally {
      await client.query('ROLLBACK');
      client.release();
    }
    const leaked = await agentsRuntime.query(`SELECT count(*)::int AS n FROM ${TABLE} WHERE operation_id=$1`,
      [operationId]);
    assert.equal(leaked.rows[0].n, 0, `${name}: rolled-back probe must leave no admission`);
  }
  const after = await agentsRuntime.query(`SELECT request_json,request_sha256,target_id FROM ${TABLE}
    WHERE platform_launch_id=$1 AND platform_scenario_id=$2 AND platform_launch_generation=$3
      AND original_platform_owner_id=$4 AND original_platform_session_id=$5 AND operation_id=$6`,
  [original.platform_launch_id, original.platform_scenario_id, original.platform_launch_generation,
    original.original_platform_owner_id, original.original_platform_session_id, original.operation_id]);
  assert.deepEqual(after.rows, existing.rows, 'genuine v2 admission must remain unchanged');
  return Object.freeze(checks);
}

module.exports = { assertPricingV2GuardNative };
