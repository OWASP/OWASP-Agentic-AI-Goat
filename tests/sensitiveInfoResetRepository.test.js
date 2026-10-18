'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createSensitiveInfoResetRepository } = require('../server/database/postgres/sensitiveInfoResetRepository');

const OPERATION = '11111111-1111-4111-8111-111111111111';
const LEASE = '22222222-2222-4222-8222-222222222222';

test('begin binds the authenticated owner to the database admission function and identifies replay', async () => {
  const calls = [];
  const pool = { connect: async () => {}, query: async (sql, params) => {
    calls.push({ sql, params });
    return { rows: [{ operation_id: OPERATION, owner_id: 41, from_generation: 8,
      to_generation: 9, status: 'pending', plan_version: 1 }] };
  } };
  const repository = createSensitiveInfoResetRepository(pool);
  const result = await repository.begin({ ownerId: 41, operationId: OPERATION });
  assert.match(calls[0].sql, /identity\.begin_sensitive_info_reset/);
  assert.deepEqual(calls[0].params, [41, OPERATION]);
  assert.deepEqual(result, { operationId: OPERATION, ownerId: 41, fromGeneration: 8,
    toGeneration: 9, status: 'pending', planVersion: 1, replayed: false });
});

test('claim and nextStep require an exact durable lease and canonical step order', async () => {
  let phase = 0;
  const pool = { connect: async () => {}, query: async (sql, params) => {
    if (/UPDATE identity\.sensitive_info_resets/.test(sql)) return { rows: [{ owner_id: 9, from_generation: 2, to_generation: 3 }] };
    if (/SELECT s\.step_key/.test(sql)) {
      assert.deepEqual(params, [OPERATION, LEASE]);
      return { rows: phase++ ? [
        { step_key: 'legacy_store', status: 'completed' }, { step_key: 'finflow_store', status: 'completed' },
      ] : [
        { step_key: 'legacy_store', status: 'completed' }, { step_key: 'finflow_store', status: 'pending' },
      ] };
    }
    throw new Error(`Unexpected query: ${sql}`);
  } };
  const repository = createSensitiveInfoResetRepository(pool);
  const lease = await repository.claim(OPERATION);
  // claim generates the private token; use the known lease only to exercise a
  // separately recovered worker's exact next-step predicate.
  assert.equal(lease.ownerId, 9);
  assert.equal(await repository.nextStep({ operationId: OPERATION, leaseToken: LEASE }), 'finflow_store');
  assert.equal(await repository.nextStep({ operationId: OPERATION, leaseToken: LEASE }), null);
});

test('draft atomically fences canonical credit and keeps journal/catalog private and inactive', () => {
  const reset = fs.readFileSync(path.resolve(__dirname,
    '../docs/modernization/drafts/sensitive-info-aggregate-reset.sql'), 'utf8');
  const catalog = fs.readFileSync(path.resolve(__dirname,
    '../docs/modernization/drafts/legacy-sensitive-canonical-catalog.sql'), 'utf8');
  assert.match(reset, /UPDATE workshop_platform\.user_state SET generation=generation\+1/);
  assert.match(reset, /sensitive_info_reset_judgment_guard/);
  assert.match(reset, /sensitive_info_reset_completion_guard/);
  assert.match(reset, /sensitive_info_reset_run_guard/);
  assert.match(reset, /UPDATE graph_runtime\.runs run SET status='interrupted'/);
  assert.match(reset, /run\.status='running'/);
  assert.match(reset, /effect\.status='started'/);
  assert.match(reset, /authority\.owner_id=p_owner_id/);
  assert.match(reset, /BEFORE INSERT OR UPDATE OF owner_key,status ON graph_runtime\.runs/);
  assert.match(reset, /guard_sensitive_info_reset_admission\(\)[\s\S]*SECURITY DEFINER SET search_path=pg_catalog/);
  assert.match(reset, /guard_sensitive_info_reset_run\(\)[\s\S]*SECURITY DEFINER SET search_path=pg_catalog/);
  assert.doesNotMatch(reset, /GRANT\s+(?:SELECT,)?INSERT ON identity\.sensitive_info_reset_authority/i);
  assert.match(reset, /LegacySensitiveInfo\|FinFlow/);
  assert.match(reset, /FROM workshop_platform\.completions[\s\S]*FOR UPDATE;[\s\S]*FROM workshop_platform\.activity_counters[\s\S]*FOR UPDATE;[\s\S]*FROM workshop_platform\.time_tracking[\s\S]*FOR UPDATE;[\s\S]*FROM workshop_platform\.user_state/);
  assert.match(reset, /status <> 'completed'/);
  assert.match(reset, /REVOKE ALL ON FUNCTION identity\.begin_sensitive_info_reset/);
  assert.doesNotMatch(reset, /GRANT\s+(?:INSERT|DELETE)\s+ON identity\.sensitive_info_resets/i);
  assert.equal((catalog.match(/'sensitive_info_disclosure','(?:path_traversal|ssi_injection|combined_traversal_ssi|ai_assisted_path_traversal|ai_assisted_ssi)'/g) || []).length, 5);
  assert.equal((catalog.match(/false,false,false,false,NULL,NULL/g) || []).length, 5);
  assert.match(catalog, /seed reconciler deactivates objectives absent/i);
});

test('repository rejects invalid owners, operations, steps, and lease bounds before SQL', async () => {
  const repository = createSensitiveInfoResetRepository({ connect: async () => {},
    query: async () => { throw new Error('SQL must not run'); } });
  await assert.rejects(repository.begin({ ownerId: 'other', operationId: OPERATION }), TypeError);
  await assert.rejects(repository.read('not-a-uuid'), TypeError);
  await assert.rejects(repository.claim(OPERATION, 999), TypeError);
  await assert.rejects(repository.nextStep({ operationId: OPERATION, leaseToken: 'bad' }), TypeError);
});

test('readiness uses valid lateral ACL syntax and requires authority plus non-public execution', async () => {
  let inspected;
  const repository = createSensitiveInfoResetRepository({ connect: async () => {}, query: async sql => {
    inspected = sql;
    return { rows: [{ operations:true,steps:true,authority:true,begin:true,judgment_guard:true,
      completion_guard:true,run_guard:true,runtime_begin:true,no_public_execute:true }] };
  } });
  assert.equal(await repository.assertReady(), true);
  assert.match(inspected, /FROM pg_proc p CROSS JOIN LATERAL aclexplode/);
  assert.doesNotMatch(inspected, /p,CROSS JOIN/);
});
