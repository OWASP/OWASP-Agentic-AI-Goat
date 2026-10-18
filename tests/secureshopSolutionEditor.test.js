'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createWorkshopConfigRepository } = require('../server/database/postgres/workshopConfigRepository');
const { WORKSHOP_KEY, isQualifiedObjective } = require('../server/config/secureshopCurriculum');

function fixture({ secureShop = false, failMaster = false, objectiveId } = {}) {
  const calls = [];
  const key = secureShop ? WORKSHOP_KEY : 'direct_prompt_injection';
  const exercise = { workshop_key: key, challenge_name: 'Workshop', category: 'ai', difficulty: 'advanced',
    is_visible: true, show_solutions: false, challenge_description: 'desc', route: '/workshop/test' };
  const objective = { workshop_key: key, objective_id: objectiveId ?? (secureShop ? 'ss_audit_instruction_followed' : 'jailbreak'),
    catalog_active: true, solution_content: { title: 'Existing', hints: ['old'], examples: [{ prompt: 'old', explanation: 'old' }] },
    solution_enabled: false };
  const client = { async query(sql, params = []) {
    calls.push({ sql, params });
    if (failMaster && sql.includes('SET show_solutions=')) throw new Error('controlled master update outage');
    if (sql === 'SELECT * FROM workshop_platform.exercises WHERE (workshop_key=$1 OR challenge_key=$1) AND catalog_active=true') return { rows: [exercise] };
    if (sql === 'SELECT * FROM workshop_platform.objectives WHERE workshop_key=$1 AND objective_id=$2 AND catalog_active=true') return { rows: [objective] };
    if (/SELECT revision FROM workshop_platform\.config_revision/.test(sql)) return { rows: [{ revision: 0 }] };
    if (/SELECT w\.\*,o\.objective_id/.test(sql)) return { rows: [] };
    if (/SELECT EXISTS\(SELECT 1 FROM workshop_platform\.objectives/.test(sql)) return { rows: [{ enabled: params[0] !== 'never' }] };
    if (/INSERT INTO workshop_platform\.revisions/.test(sql)) return { rows: [{ revision: 1 }], rowCount: 1 };
    if (/UPDATE/.test(sql)) return { rows: [], rowCount: 1 };
    return { rows: [], rowCount: 1 };
  }, release() {} };
  const pool = { async connect() { return client; }, async query(sql, params) { return client.query(sql, params); } };
  return { service: createWorkshopConfigRepository(pool, { isSecureShopReady: () => true }), calls };
}

test('solution editor accepts optional fields and derives the master gate atomically', async () => {
  const f = fixture();
  const result = await f.service.saveSolutionEditor('direct_prompt_injection', 'jailbreak', {
    description: '', code: 'const x = 1;', references: ['https://example.test/advisory', '../docs/runbook.md'],
    estimatedTime: '5 minutes', prerequisites: ['Read the challenge guide'],
  }, { isPublic: true, userId: 7 });
  assert.equal(result.changed, true);
  assert.ok(f.calls.some(call => call.sql.includes('SET solution_content=')));
  assert.ok(f.calls.some(call => call.sql.includes('SET show_solutions=')));
  assert.ok(f.calls.some(call => call.sql.includes('catalog_field_defaults')));
});

test('invalid optional fields reject before opening a transaction', async () => {
  const f = fixture();
  assert.throws(() => f.service.saveSolutionEditor('direct_prompt_injection', 'jailbreak', {
    references: ['javascript:alert(1)'], prerequisites: [''],
  }), { code: 'BAD_REQUEST' });
  assert.equal(f.calls.length, 0);
});

test('qualified SecureShop audit objective can be published through the canonical editor', async () => {
  const f = fixture({ secureShop: true });
  const result = await f.service.saveSolutionEditor(WORKSHOP_KEY, 'ss_audit_instruction_followed', {
    description: 'pending',
  }, { isPublic: true, userId: 7 });
  assert.equal(result.changed, true);
  assert.equal(f.calls.some(call => /^UPDATE/.test(call.sql)), true);
});

test('active database objective outside the qualified catalog cannot publish or perform DML', async () => {
  // Controlled active database row models catalog drift, not a change to real eligibility.
  const objectiveId = 'ss_controlled_unqualified_objective';
  assert.equal(isQualifiedObjective(objectiveId), false);
  const f = fixture({ secureShop: true, objectiveId });
  await assert.rejects(f.service.saveSolutionEditor(WORKSHOP_KEY, objectiveId,
    { description: 'must remain unpublished' }, { isPublic: true, userId: 7 }),
  { code: 'OBJECTIVE_UNQUALIFIED' });
  assert.ok(f.calls.some(call => call.sql.includes('SELECT * FROM workshop_platform.objectives')
    && call.params[1] === objectiveId), 'the active database row was found before qualification denial');
  assert.equal(f.calls.some(call => /^\s*(UPDATE|INSERT|DELETE)\b/.test(call.sql)), false);
  assert.ok(f.calls.some(call => call.sql === 'ROLLBACK'));
  assert.equal(f.calls.some(call => call.sql === 'COMMIT'), false);
});

test('editor preserves the existing provenance path for custom solution content', async () => {
  const f = fixture();
  await f.service.saveSolutionEditor('direct_prompt_injection', 'jailbreak', { code: '' }, { userId: 9 });
  const provenance = f.calls.find(call => call.sql.includes("provenance_state='custom'"));
  assert.ok(provenance);
  assert.deepEqual(provenance.params, ['objective', 'direct_prompt_injection', 'jailbreak', 'solution_content']);
});

test('a master update outage rolls back the content and visibility transaction', async () => {
  const f = fixture({ failMaster: true });
  await assert.rejects(f.service.saveSolutionEditor('direct_prompt_injection', 'jailbreak',
    { description: 'must roll back' }, { isPublic: true, userId: 7 }), /controlled master update outage/);
  assert.ok(f.calls.some(call => call.sql.includes('SET solution_content=')));
  assert.ok(f.calls.some(call => call.sql === 'ROLLBACK'));
  assert.equal(f.calls.some(call => call.sql === 'COMMIT'), false);
});
