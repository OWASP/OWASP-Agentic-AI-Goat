'use strict';

// Called only by the paired, disposable CTF authority application fixture.
const assert = require('node:assert/strict');
const prior = require('../fixtures/ctfStage6PriorDefaults');
const current = require('../../server/data/ctfDefaults').stages.find(stage => stage.stage_number === 6);
const { hashValue } = require('../../server/database/postgres/ctfStageDefaultProvenance');
const changed = Object.freeze(['stage_description', 'hints', 'system_prompt', 'defense_style']);
const customDescription = 'Instructor-owned Stage 6 description; leave this lesson text intact.';
const customPersonality = 'Instructor-owned IronClad personality; preserve sibling teaching content.';

async function stage(pool, number = 6) {
  return (await pool.query('SELECT * FROM ctf.ctf_stages WHERE stage_number=$1', [number])).rows[0];
}
async function provenance(pool) {
  return (await pool.query('SELECT field_name,provenance_state,applied_default_sha256,source_default_sha256,updated_at FROM ctf.stage_default_fields WHERE stage_number=6 ORDER BY field_name')).rows;
}
async function snapshot(pool, table) {
  return (await pool.query(`SELECT to_jsonb(t)::text AS row FROM ctf.${table} t ORDER BY 1`)).rows.map(row => row.row);
}

async function preparePriorStage6({ state, ctfPool }) {
  assert.equal(current.success_criteria, 'FORTRESS_OMEGA_X1');
  assert.equal(current.level_score, 500);
  const original = await stage(ctfPool);
  assert(original, 'Stage 6 seeded before authority bootstrap');
  for (const field of changed) {
    assert.equal(original[field], current[field], `${field} must begin at the reviewed current default`);
    const record = (await provenance(ctfPool)).find(row => row.field_name === field);
    assert.equal(record?.provenance_state, 'managed', `${field} must begin managed`);
    assert.equal(record.applied_default_sha256, hashValue(current[field]));
    await ctfPool.query(`UPDATE ctf.ctf_stages SET ${field}=$1 WHERE stage_number=6`, [prior[field]]);
    await ctfPool.query(`UPDATE ctf.stage_default_fields SET applied_default_sha256=$1,source_default_sha256=$1 WHERE stage_number=6 AND field_name=$2`, [hashValue(prior[field]), field]);
  }
  await ctfPool.query('UPDATE ctf.ctf_stages SET ai_guardian_personality=$1 WHERE stage_number=6', [customPersonality]);
  await ctfPool.query("UPDATE ctf.stage_default_fields SET provenance_state='custom',applied_default_sha256=NULL WHERE stage_number=6 AND field_name='ai_guardian_personality'");
  if (state === 'POPULATED') {
    // Active authority must omit both instructor content and imported unknown content.
    await ctfPool.query('UPDATE ctf.ctf_stages SET stage_description=$1 WHERE stage_number=6', [customDescription]);
    await ctfPool.query("UPDATE ctf.stage_default_fields SET provenance_state='custom',applied_default_sha256=NULL WHERE stage_number=6 AND field_name='stage_description'");
    await ctfPool.query("UPDATE ctf.stage_default_fields SET provenance_state='legacy_unknown',applied_default_sha256=NULL WHERE stage_number=6 AND field_name='hints'");
  }
}

async function verifyActiveAdoption({ state, ctfPool, migrationPrefix, mutate, admin, siblingBefore, siblingAttempts, ledger, migrate, fs, path }) {
  const control = (await ctfPool.query('SELECT state FROM ctf.bootstrap_control')).rows[0];
  const delivery = (await ctfPool.query('SELECT activation_id FROM ctf.delivery_control')).rows[0];
  assert.equal(control.state, 'prepared');
  assert(delivery.activation_id, 'CTF delivery must be active before migration 0014');
  const before = await stage(ctfPool);
  const beforeProvenance = await provenance(ctfPool);
  const otherStage = await stage(ctfPool, 5);
  const siblingJudgments = await snapshot(ctfPool, 'ctf_judgments');
  const migrationName = '0014_stage6_rotation_handoff_default.sql';
  fs.copyFileSync(path.resolve(__dirname, '../../db/postgres/workshop-migrations/ctf', migrationName), path.join(migrationPrefix, migrationName));
  await migrate(ctfPool, migrationPrefix);
  assert.deepEqual(await migrate(ctfPool, migrationPrefix), [], 'second migration application must be a no-op');
  assert.deepEqual(await stage(ctfPool), before, 'active migration must not alter Stage 6');
  assert.deepEqual(await provenance(ctfPool), beforeProvenance, 'active migration must not alter field provenance');

  const selected = {};
  for (const field of changed) {
    const record = beforeProvenance.find(row => row.field_name === field);
    if (record?.provenance_state === 'managed' &&
        record.applied_default_sha256 === hashValue(prior[field]) && before[field] === prior[field]) {
      selected[field] = current[field];
    }
  }
  assert.deepEqual(Object.keys(selected), state === 'FRESH' ? changed : ['system_prompt', 'defense_style']);
  const outcome = await mutate(admin, 'catalog_mutation', { action: 'update', stageId: String(before.id), fields: selected });
  assert.equal(outcome.status, 200, 'canonical instructor catalog mutation must apply');
  const after = await stage(ctfPool);
  for (const field of changed) assert.equal(after[field], Object.hasOwn(selected, field) ? current[field] : before[field], field);
  assert.equal(after.ai_guardian_personality, customPersonality);
  assert.equal(after.success_criteria, 'FORTRESS_OMEGA_X1');
  assert.equal(after.level_score, 500);
  assert.deepEqual(await stage(ctfPool, 5), otherStage, 'sibling catalog stage preserved');
  const afterProvenance = await provenance(ctfPool);
  for (const field of Object.keys(selected)) {
    const record = afterProvenance.find(row => row.field_name === field);
    assert.equal(record.provenance_state, 'custom', `${field} is now an instructor mutation`);
    assert.equal(record.applied_default_sha256, null);
  }
  for (const field of ['ai_guardian_personality', ...changed.filter(name => !Object.hasOwn(selected, name))]) {
    assert.deepEqual(afterProvenance.find(row => row.field_name === field), beforeProvenance.find(row => row.field_name === field), `${field} provenance preserved`);
  }
  assert.deepEqual((await ctfPool.query('SELECT * FROM ctf.ctf_progress WHERE participant_id=1001 ORDER BY id')).rows, siblingBefore);
  assert.deepEqual((await ctfPool.query('SELECT * FROM ctf.ctf_attempts WHERE participant_id=1001 ORDER BY id')).rows, siblingAttempts);
  assert.deepEqual(await snapshot(ctfPool, 'ctf_judgments'), siblingJudgments, 'immutable judgment evidence preserved');
  assert.equal(ledger.length, 0, 'adoption makes no model call');
}

module.exports = { preparePriorStage6, verifyActiveAdoption };
