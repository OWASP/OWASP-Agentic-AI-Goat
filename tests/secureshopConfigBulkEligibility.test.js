'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createWorkshopConfigRepository } = require('../server/database/postgres/workshopConfigRepository');
const { QUALIFIED_OBJECTIVE_IDS, WORKSHOP_KEY } = require('../server/config/secureshopCurriculum');

function fixture() {
  const calls = [];
  const exercise = { workshop_key: WORKSHOP_KEY, challenge_name: 'SecureShop', category: 'ai', difficulty: 'advanced',
    is_visible: false, show_solutions: false, challenge_description: 'desc', route: '/workshop/secureshop' };
  const client = { async query(sql, params = []) {
    calls.push({ sql, params });
    if (sql === 'SELECT * FROM workshop_platform.exercises WHERE (workshop_key=$1 OR challenge_key=$1) AND catalog_active=true') return { rows: [exercise] };
    if (/SELECT revision FROM workshop_platform\.config_revision/.test(sql)) return { rows: [{ revision: 0 }] };
    if (/SELECT w\.\*,o\.objective_id/.test(sql)) return { rows: [] };
    if (sql === 'SELECT * FROM workshop_platform.objectives WHERE workshop_key=$1 AND objective_id=$2 AND catalog_active=true')
      return { rows: [{ objective_id: params[1], workshop_key: WORKSHOP_KEY }] };
    if (/SELECT count\(\*\)::integer AS count/.test(sql)) return { rows: [{ count: params.length === 2 ? QUALIFIED_OBJECTIVE_IDS.length : QUALIFIED_OBJECTIVE_IDS.length + 1 }] };
    if (/UPDATE workshop_platform\.config_revision/.test(sql)) return { rowCount: 1, rows: [] };
    if (/INSERT INTO workshop_platform\.revisions/.test(sql)) return { rowCount: 1, rows: [{ revision: 1 }] };
    if (/UPDATE/.test(sql)) return { rowCount: 1, rows: [] };
    return { rowCount: 0, rows: [] };
  }, release() {} };
  const pool = { async connect() { return client; }, async query(sql, params) { return client.query(sql, params); } };
  return { service: createWorkshopConfigRepository(pool, { isSecureShopReady: () => true }), calls };
}

function objectiveUpdate(calls, field) {
  return calls.find(call => call.sql.includes(`SET ${field}=`) && call.sql.includes('workshop_platform.objectives'));
}

test('master hint and solution enable only qualified SecureShop objectives', async () => {
  for (const [method, field] of [['setMasterHintVisibility', 'hint_enabled'], ['setMasterSolutionVisibility', 'solution_enabled']]) {
    const f = fixture(); await f.service[method](WORKSHOP_KEY, true, 9);
    const update = objectiveUpdate(f.calls, field);
    assert.match(update.sql, /objective_id = ANY\(\$4::text\[\]\)/);
    assert.deepEqual(update.params[3], QUALIFIED_OBJECTIVE_IDS);
  }
});

test('master disable clears all active objectives without a qualification filter', async () => {
  for (const [method, field] of [['setMasterHintVisibility', 'hint_enabled'], ['setMasterSolutionVisibility', 'solution_enabled']]) {
    const f = fixture(); await f.service[method](WORKSHOP_KEY, false, 9);
    const update = objectiveUpdate(f.calls, field);
    assert.doesNotMatch(update.sql, /objective_id = ANY/);
    assert.deepEqual(update.params, [false, 9, WORKSHOP_KEY]);
  }
});

test('global help enable keeps unqualified SecureShop objectives disabled', async () => {
  const enabled = fixture();
  await enabled.service.setAllHintAndSolutionVisibility(true, 9);
  for (const field of ['hint_enabled', 'solution_enabled']) {
    const update = objectiveUpdate(enabled.calls, field);
    assert.match(update.sql, /workshop_key<>\$3 OR objective_id=ANY\(\$4::text\[\]\)/);
    assert.deepEqual(update.params, [true, 9, WORKSHOP_KEY, QUALIFIED_OBJECTIVE_IDS]);
  }
  const disabled = fixture();
  await disabled.service.setAllHintAndSolutionVisibility(false, 9);
  for (const field of ['hint_enabled', 'solution_enabled']) {
    const update = objectiveUpdate(disabled.calls, field);
    assert.doesNotMatch(update.sql, /objective_id=ANY/);
    assert.deepEqual(update.params, [false, 9]);
  }
});

test('exercise showSolutions enable updates only qualified objectives', async () => {
  const f = fixture();
  await f.service.updateExercise({ key: WORKSHOP_KEY, challengeName: 'SecureShop', category: 'ai', difficulty: 'advanced',
    isVisible: false, showSolutions: true, description: 'desc', route: '/workshop/secureshop', userId: 9 });
  const update = objectiveUpdate(f.calls, 'solution_enabled');
  assert.match(update.sql, /objective_id = ANY\(\$4::text\[\]\)/);
  assert.deepEqual(update.params[3], QUALIFIED_OBJECTIVE_IDS);
});

test('bulk objective enable reports and updates the qualified count; disable counts all', async () => {
  const enabled = fixture();
  const enabledResult = await enabled.service.setAllObjectiveVisibility(WORKSHOP_KEY, true, 9);
  assert.equal(enabledResult.affectedCount, QUALIFIED_OBJECTIVE_IDS.length);
  const enabledUpdate = enabled.calls.find(call => call.sql.includes('SET is_enabled='));
  assert.match(enabledUpdate.sql, /objective_id = ANY\(\$4::text\[\]\)/);
  assert.deepEqual(enabledUpdate.params[3], QUALIFIED_OBJECTIVE_IDS);

  const disabled = fixture();
  const disabledResult = await disabled.service.setAllObjectiveVisibility(WORKSHOP_KEY, false, 9);
  assert.equal(disabledResult.affectedCount, QUALIFIED_OBJECTIVE_IDS.length + 1);
  const disabledUpdate = disabled.calls.find(call => call.sql.includes('SET is_enabled='));
  assert.doesNotMatch(disabledUpdate.sql, /objective_id = ANY/);
  assert.deepEqual(disabledUpdate.params, [false, 9, WORKSHOP_KEY]);
});

test('instructor can enable qualified UNION and order-error while deferred IDOR stays blocked', async () => {
  for (const objectiveId of ['ss_sqli_union', 'ss_sqli_error_based']) {
    assert.equal(QUALIFIED_OBJECTIVE_IDS.includes(objectiveId), true);
    const admitted = fixture();
    await admitted.service.setObjectiveVisibility(WORKSHOP_KEY, objectiveId, true, 9);
    assert.deepEqual(admitted.calls.find(call => call.sql.includes('SET is_enabled='))?.params,
      [true, 9, WORKSHOP_KEY, objectiveId]);
  }
  const excluded = 'ss_idor_order_status_disclosure';
  assert.equal(QUALIFIED_OBJECTIVE_IDS.includes(excluded), false);
  const pending = fixture();
  await assert.rejects(pending.service.setObjectiveVisibility(WORKSHOP_KEY,
    excluded, true, 9), { code: 'OBJECTIVE_UNQUALIFIED' });
  assert.equal(pending.calls.some(call => call.sql.includes('SET is_enabled=')), false);
});
