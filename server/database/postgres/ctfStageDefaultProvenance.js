'use strict';
const { createHash } = require('node:crypto');
const { withTransaction } = require('./index');

const MANAGED_FIELDS = Object.freeze([
  'stage_description', 'ai_guardian_personality', 'hints', 'system_prompt', 'defense_style',
]);
const FIELD_SET = new Set(MANAGED_FIELDS);
function hashValue(value) {
  if (value !== null && typeof value !== 'string') throw new TypeError('CTF managed value must be text or null');
  const tag = Buffer.from([value === null ? 0 : 1]);
  const bytes = value === null ? Buffer.alloc(0) : Buffer.from(value, 'utf8');
  return createHash('sha256').update(tag).update(bytes).digest('hex');
}

function decide({ provenance, currentValue, sourceValue }) {
  const sourceHash = hashValue(sourceValue);
  if (!provenance || provenance.provenance_state === 'legacy_unknown') {
    return { action: 'preserve_unknown', sourceHash };
  }
  if (provenance.provenance_state === 'custom') return { action: 'preserve', sourceHash };
  if (provenance.provenance_state !== 'managed') throw new Error('Unknown CTF provenance state');
  if (hashValue(currentValue) !== provenance.applied_default_sha256) {
    return { action: 'mark_custom', sourceHash };
  }
  return provenance.applied_default_sha256 === sourceHash
    ? { action: 'unchanged', sourceHash }
    : { action: 'upgrade', sourceHash };
}

async function reconcileStageField(client, { stageNumber, fieldName, currentValue, sourceValue, inserted }) {
  if (!FIELD_SET.has(fieldName)) throw new TypeError('Unsupported CTF managed field');
  const sourceHash = hashValue(sourceValue);
  if (inserted) {
    await client.query(`INSERT INTO ctf.stage_default_fields
      (stage_number,field_name,provenance_state,applied_default_sha256,source_default_sha256)
      VALUES($1,$2,'managed',$3,$3)`, [stageNumber, fieldName, sourceHash]);
    return 'managed';
  }
  const provenance = (await client.query(`SELECT provenance_state,applied_default_sha256,source_default_sha256
    FROM ctf.stage_default_fields WHERE stage_number=$1 AND field_name=$2 FOR UPDATE`,
  [stageNumber, fieldName])).rows[0];
  if (!provenance) {
    await client.query(`INSERT INTO ctf.stage_default_fields
      (stage_number,field_name,provenance_state,source_default_sha256)
      VALUES($1,$2,'legacy_unknown',$3)`, [stageNumber, fieldName, sourceHash]);
    return 'preserve_unknown';
  }
  const decision = decide({ provenance, currentValue, sourceValue });
  if (decision.action === 'mark_custom') {
    await client.query(`UPDATE ctf.stage_default_fields SET provenance_state='custom',
      applied_default_sha256=NULL,source_default_sha256=$3,updated_at=now()
      WHERE stage_number=$1 AND field_name=$2`, [stageNumber, fieldName, sourceHash]);
  } else if (decision.action === 'upgrade') {
    await client.query(`UPDATE ctf.ctf_stages SET ${fieldName}=$1 WHERE stage_number=$2`,
      [sourceValue, stageNumber]);
    await client.query(`UPDATE ctf.stage_default_fields SET applied_default_sha256=$3,
      source_default_sha256=$3,updated_at=now() WHERE stage_number=$1 AND field_name=$2`,
    [stageNumber, fieldName, sourceHash]);
  } else if (provenance.source_default_sha256 !== sourceHash) {
    await client.query(`UPDATE ctf.stage_default_fields SET source_default_sha256=$3,updated_at=now()
      WHERE stage_number=$1 AND field_name=$2`, [stageNumber, fieldName, sourceHash]);
  }
  return decision.action;
}

async function markStageFieldsCustom(client, stageNumber, fields) {
  const managed = [...new Set(fields)].filter(field => FIELD_SET.has(field));
  if (!managed.length) return;
  await client.query('SELECT ctf.mark_stage_default_fields_custom($1,$2::text[])', [stageNumber, managed]);
}

async function adoptExactPriorDefaultInTransaction(client, { stageNumber, fieldName, priorValue }) {
  if (!FIELD_SET.has(fieldName)) throw new TypeError('Unsupported CTF managed field');
  // Match ordinary CTF writers before taking rows; bootstrap triggers use this lock too.
  await client.query('SELECT pg_advisory_xact_lock(1886610804, 44)');
  const stage = (await client.query(`SELECT ${fieldName} AS value FROM ctf.ctf_stages
    WHERE stage_number=$1 FOR UPDATE`, [stageNumber])).rows[0];
  const provenance = (await client.query(`SELECT provenance_state FROM ctf.stage_default_fields
    WHERE stage_number=$1 AND field_name=$2 FOR UPDATE`, [stageNumber, fieldName])).rows[0];
  if (!stage || provenance?.provenance_state !== 'legacy_unknown') {
    throw new Error('Only a legacy_unknown CTF field can be adopted');
  }
  if (stage.value !== priorValue) throw new Error('CTF field does not equal the reviewed prior default');
  const priorHash = hashValue(priorValue);
  await client.query(`UPDATE ctf.stage_default_fields SET provenance_state='managed',
    applied_default_sha256=$3,updated_at=now() WHERE stage_number=$1 AND field_name=$2`,
  [stageNumber, fieldName, priorHash]);
  return { stageNumber, fieldName, appliedDefaultSha256: priorHash };
}

async function adoptExactPriorDefault(pool, input) {
  if (!pool || typeof pool.connect !== 'function') throw new TypeError('PostgreSQL pool required for CTF default adoption');
  return withTransaction(pool, client => adoptExactPriorDefaultInTransaction(client, input));
}

async function adoptStage8SystemPromptDefault(pool, { priorValue }) {
  if (!pool || typeof pool.connect !== 'function') throw new TypeError('PostgreSQL pool required for CTF default adoption');
  const sourceValue = require('../../data/ctfDefaults').stages.find(stage => stage.stage_number === 8)?.system_prompt;
  if (typeof sourceValue !== 'string') throw new Error('Stage 8 source system prompt is unavailable');
  return withTransaction(pool, async client => {
    const adoption = await adoptExactPriorDefaultInTransaction(client,
      { stageNumber: 8, fieldName: 'system_prompt', priorValue });
    const action = await reconcileStageField(client, { stageNumber: 8, fieldName: 'system_prompt',
      currentValue: priorValue, sourceValue, inserted: false });
    if (action !== 'upgrade' && action !== 'unchanged') throw new Error('Adopted system prompt was not reconciled');
    return Object.freeze({ ...adoption, action, sourceDefaultSha256: hashValue(sourceValue) });
  });
}

module.exports = { MANAGED_FIELDS, hashValue, decide, reconcileStageField, markStageFieldsCustom,
  adoptExactPriorDefault, adoptStage8SystemPromptDefault };
