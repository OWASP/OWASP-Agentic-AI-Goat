'use strict';

// Native qualification harness for reserved identity 0067. This test is
// intentionally gated and never targets an application or learner database.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { Pool } = require('pg');
const provenance = require('../../server/database/postgres/catalogDefaultProvenance');
const catalog = require('../../server/config/workshopCatalog').WORKSHOP_OBJECTIVES;
const hints = require('../../server/data/workshopHints').sensitive_info_disclosure;
const solutions = require('../../server/data/sensitiveInfoSolutions').solutions;

const enabled = process.env.PG_TEST_DISPOSABLE === 'yes'
  && process.env.PG_FINFLOW_RECON_MIGRATION_URL
  && process.env.PG_FINFLOW_RECON_RUNTIME_URL;
const WORKSHOP = 'sensitive_info_disclosure';
const DRAFT = path.join(__dirname, '../../docs/modernization/drafts/finflow-recon-scope-managed-defaults.candidate.sql');
const SOURCE_VERSION = 'finflow-recon-scope-2026-09-15-draft';
const OWNED_PATH = /^\/owasp_ai_goat_test_[a-z0-9_]+$/;

function ownedUrl(key) {
  const url = new URL(process.env[key]);
  assert.ok(['127.0.0.1', 'localhost'].includes(url.hostname), `${key} must be local disposable PostgreSQL`);
  assert.match(url.pathname, OWNED_PATH, `${key} must target a owasp_ai_goat_test database`);
  return url.href;
}

function draftRows() {
  const source = fs.readFileSync(DRAFT, 'utf8');
  const rows = [];
  const pattern = /\('([^']+)','(label|hint_content|solution_content)',\$document\$([\s\S]*?)\$document\$::jsonb,'([0-9a-f]+)',\$document\$([\s\S]*?)\$document\$::jsonb,'([0-9a-f]+)'\)\s*,?\s*\n?/g;
  for (const match of source.matchAll(pattern)) {
    rows.push({ objectiveId: match[1], fieldName: match[2], oldDocument: JSON.parse(match[3]),
      oldHash: match[4], newDocument: JSON.parse(match[5]), newHash: match[6] });
  }
  assert.equal(rows.length, 6, 'draft must contain exactly six FinFlow reconciliation rows');
  assert.deepEqual(rows.map(row => `${row.objectiveId}:${row.fieldName}`).sort(), [
    'admin_enum:hint_content', 'admin_enum:label', 'admin_enum:solution_content',
    'tool_enum:hint_content', 'tool_enum:label', 'tool_enum:solution_content',
  ]);
  return rows;
}

function canonicalRows() {
  const values = new Map();
  for (const id of ['tool_enum', 'admin_enum']) {
    values.set(`${id}:label`, catalog.sensitive_info_disclosure.find(row => row.id === id).text);
    values.set(`${id}:hint_content`, hints[id]);
    values.set(`${id}:solution_content`, solutions[id]);
  }
  return values;
}

function document(value) { return provenance.document(value); }
function hash(value) { return provenance.hashDocument(document(value)); }

async function createSchema(pool, { fresh = false } = {}) {
  if (fresh) {
    const existing = (await pool.query(`SELECT to_regclass('workshop_platform.objectives') AS objectives,
      to_regclass('workshop_platform.catalog_field_defaults') AS provenance,
      to_regclass('workshop_platform.config_revision') AS revisions`)).rows[0];
    assert.deepEqual(existing, { objectives: null, provenance: null, revisions: null },
      'fresh qualification database must not contain the minimal test schema');
  }
  await pool.query(`CREATE SCHEMA IF NOT EXISTS workshop_platform;
    CREATE TABLE IF NOT EXISTS workshop_platform.config_revision
      (id integer PRIMARY KEY, revision integer NOT NULL, updated_at timestamptz NOT NULL DEFAULT now());
    CREATE TABLE IF NOT EXISTS workshop_platform.objectives
      (workshop_key text NOT NULL, objective_id text NOT NULL, label text,
       hint_content jsonb, solution_content jsonb, updated_at timestamptz NOT NULL DEFAULT now(),
       PRIMARY KEY(workshop_key, objective_id));
    CREATE TABLE IF NOT EXISTS workshop_platform.catalog_field_defaults
      (entity_kind text NOT NULL, workshop_key text NOT NULL, objective_id text NOT NULL,
       field_name text NOT NULL, provenance_state text NOT NULL, source_version text,
       source_hash text, source_document jsonb, applied_default_version text,
       applied_default_hash text, applied_default_document jsonb, observed_document jsonb,
       updated_at timestamptz NOT NULL DEFAULT now(),
       PRIMARY KEY(entity_kind, workshop_key, objective_id, field_name));
    INSERT INTO workshop_platform.config_revision(id, revision) VALUES(1, 0)
      ON CONFLICT (id) DO UPDATE SET revision=0;
    TRUNCATE workshop_platform.catalog_field_defaults, workshop_platform.objectives;
  `);
}

async function seed(pool, rows, mode = 'old') {
  const canonical = canonicalRows();
  for (const row of rows) {
    const value = mode === 'old' ? row.oldDocument.value : canonical.get(`${row.objectiveId}:${row.fieldName}`);
    const current = document(value);
    const source = mode === 'old' ? row.oldDocument : current;
    const sourceHash = mode === 'old' ? row.oldHash : hash(value);
    const applied = mode === 'old' ? row.oldDocument : current;
    const appliedHash = mode === 'old' ? row.oldHash : hash(value);
    const column = row.fieldName;
    const valueParam = column === 'label' ? value : JSON.stringify(value);
    await pool.query(`INSERT INTO workshop_platform.objectives(workshop_key,objective_id,${column})
      VALUES($1,$2,$3${column === 'label' ? '' : '::jsonb'})
      ON CONFLICT(workshop_key,objective_id) DO UPDATE SET ${column}=EXCLUDED.${column}`,
    [WORKSHOP, row.objectiveId, valueParam]);
    await pool.query(`INSERT INTO workshop_platform.catalog_field_defaults
      (entity_kind,workshop_key,objective_id,field_name,provenance_state,source_version,source_hash,
       source_document,applied_default_version,applied_default_hash,applied_default_document,observed_document)
      VALUES('objective',$1,$2,$3,'managed',$4,$5,$6::jsonb,$4,$7,$8::jsonb,$9::jsonb)
      ON CONFLICT(entity_kind,workshop_key,objective_id,field_name) DO UPDATE SET
       provenance_state=EXCLUDED.provenance_state,source_version=EXCLUDED.source_version,
       source_hash=EXCLUDED.source_hash,source_document=EXCLUDED.source_document,
       applied_default_version=EXCLUDED.applied_default_version,applied_default_hash=EXCLUDED.applied_default_hash,
       applied_default_document=EXCLUDED.applied_default_document,observed_document=EXCLUDED.observed_document`,
    [WORKSHOP, row.objectiveId, row.fieldName, SOURCE_VERSION, sourceHash, JSON.stringify(source),
      appliedHash, JSON.stringify(applied), JSON.stringify(current)]);
  }
}

async function values(pool) {
  return (await pool.query(`SELECT objective_id, label, hint_content, solution_content
    FROM workshop_platform.objectives WHERE workshop_key=$1 ORDER BY objective_id`, [WORKSHOP])).rows;
}
async function revision(pool) {
  return Number((await pool.query('SELECT revision FROM workshop_platform.config_revision WHERE id=1')).rows[0].revision);
}
async function fieldState(pool, objectiveId, fieldName) {
  return (await pool.query(`SELECT o.${fieldName} AS value,p.provenance_state,p.applied_default_hash,
      p.applied_default_document FROM workshop_platform.objectives o
      JOIN workshop_platform.catalog_field_defaults p ON p.entity_kind='objective'
       AND p.workshop_key=o.workshop_key AND p.objective_id=o.objective_id AND p.field_name=$2
      WHERE o.workshop_key=$1 AND o.objective_id=$3`, [WORKSHOP, fieldName, objectiveId])).rows[0];
}

test('FinFlow 0067 draft has six canonical public5/admin8 JSON defaults and hashes', () => {
  const rows = draftRows();
  const canonical = canonicalRows();
  const draftText = fs.readFileSync(DRAFT, 'utf8');
  for (const row of rows) {
    const value = canonical.get(`${row.objectiveId}:${row.fieldName}`);
    assert.deepEqual(row.newDocument, document(value), `${row.objectiveId}/${row.fieldName} JSON default`);
    assert.equal(row.newHash, hash(value), `${row.objectiveId}/${row.fieldName} default hash`);
    assert.equal(draftText.split(row.newHash).length - 1, 1, `${row.objectiveId}/${row.fieldName} hash is singular`);
  }
});

test('reserved FinFlow 0067 draft preserves managed/custom/unknown/null/drifted catalog state', {
  skip: !enabled, timeout: 60000,
}, async t => {
  const migrationUrl = new URL(ownedUrl('PG_FINFLOW_RECON_MIGRATION_URL'));
  const runtimeUrl = new URL(ownedUrl('PG_FINFLOW_RECON_RUNTIME_URL'));
  assert.equal(runtimeUrl.hostname, migrationUrl.hostname, 'migration/runtime host must match');
  assert.equal(runtimeUrl.port, migrationUrl.port, 'migration/runtime port must match');
  assert.equal(runtimeUrl.pathname, migrationUrl.pathname, 'migration/runtime database must match');
  const migration = new Pool({ connectionString: migrationUrl.href, max: 4 });
  const runtime = new Pool({ connectionString: runtimeUrl.href, max: 4 });
  t.after(async () => Promise.allSettled([runtime.end(), migration.end()]));
  const rows = draftRows();
  const canonical = canonicalRows();

  await createSchema(migration, { fresh: true });
  await seed(migration, rows);
  const before = await values(runtime);
  await migration.query(fs.readFileSync(DRAFT, 'utf8'));
  const after = await values(runtime);
  assert.deepEqual(after, [
    { objective_id: 'admin_enum', label: canonical.get('admin_enum:label'), hint_content: canonical.get('admin_enum:hint_content'), solution_content: canonical.get('admin_enum:solution_content') },
    { objective_id: 'tool_enum', label: canonical.get('tool_enum:label'), hint_content: canonical.get('tool_enum:hint_content'), solution_content: canonical.get('tool_enum:solution_content') },
  ]);
  assert.notDeepEqual(after, before);
  assert.equal(await revision(runtime), 1);

  await migration.query(fs.readFileSync(DRAFT, 'utf8'));
  assert.equal(await revision(runtime), 1, 'idempotent replay does not bump config_revision');
  assert.deepEqual(await values(runtime), after);

  await createSchema(migration);
  await seed(migration, rows);
  await migration.query(`UPDATE workshop_platform.objectives SET label='Instructor custom'
    WHERE workshop_key=$1 AND objective_id='tool_enum'`, [WORKSHOP]);
  await migration.query(`UPDATE workshop_platform.catalog_field_defaults SET provenance_state='custom'
    WHERE workshop_key=$1 AND objective_id='tool_enum' AND field_name='label'`, [WORKSHOP]);
  const custom = await fieldState(migration, 'tool_enum', 'label');
  await migration.query(`UPDATE workshop_platform.catalog_field_defaults SET provenance_state='legacy_unknown'
    WHERE workshop_key=$1 AND objective_id='tool_enum' AND field_name='hint_content'`, [WORKSHOP]);
  const unknown = await fieldState(migration, 'tool_enum', 'hint_content');
  await migration.query(`UPDATE workshop_platform.objectives SET solution_content=NULL
    WHERE workshop_key=$1 AND objective_id='tool_enum'`, [WORKSHOP]);
  const nullManaged = await fieldState(migration, 'tool_enum', 'solution_content');
  await migration.query(`UPDATE workshop_platform.catalog_field_defaults SET applied_default_hash=$4
    WHERE workshop_key=$1 AND objective_id=$2 AND field_name=$3`, [WORKSHOP, 'admin_enum', 'label', 'a'.repeat(64)]);
  const drifted = await fieldState(migration, 'admin_enum', 'label');
  const missing = await fieldState(migration, 'admin_enum', 'hint_content');
  await migration.query(`DELETE FROM workshop_platform.catalog_field_defaults
    WHERE workshop_key=$1 AND objective_id='admin_enum' AND field_name='hint_content'`, [WORKSHOP]);
  const preserved = await values(runtime);
  await migration.query(fs.readFileSync(DRAFT, 'utf8'));
  assert.equal(await revision(runtime), 1);
  const reconciled = await values(runtime);
  assert.deepEqual(reconciled.find(row => row.objective_id === 'admin_enum').solution_content,
    canonical.get('admin_enum:solution_content'), 'the sole unprotected field upgrades');
  assert.equal(reconciled.find(row => row.objective_id === 'tool_enum').label, 'Instructor custom');
  assert.equal((await fieldState(runtime, 'tool_enum', 'label')).provenance_state, custom.provenance_state);
  assert.deepEqual(await fieldState(runtime, 'tool_enum', 'label'), custom);
  assert.equal((await fieldState(runtime, 'tool_enum', 'hint_content')).provenance_state, unknown.provenance_state);
  assert.deepEqual(await fieldState(runtime, 'tool_enum', 'hint_content'), unknown);
  assert.equal((await fieldState(runtime, 'tool_enum', 'solution_content')).value, null);
  assert.deepEqual(await fieldState(runtime, 'tool_enum', 'solution_content'), nullManaged,
    'managed NULL remains separate from unknown provenance');
  assert.equal((await fieldState(runtime, 'admin_enum', 'label')).value, drifted.value);
  assert.equal((await fieldState(runtime, 'admin_enum', 'label')).applied_default_hash, drifted.applied_default_hash);
  assert.equal(missing.provenance_state, 'managed');
  assert.equal((await fieldState(runtime, 'admin_enum', 'hint_content')), undefined);
  assert.deepEqual(preserved.find(row => row.objective_id === 'tool_enum').label,
    'Instructor custom');
  await migration.query(fs.readFileSync(DRAFT, 'utf8'));
  assert.equal(await revision(runtime), 1, 'preservation replay remains stable');

  await createSchema(migration);
  await seed(migration, rows, 'current');
  const fresh = await values(runtime);
  await migration.query(fs.readFileSync(DRAFT, 'utf8'));
  assert.equal(await revision(runtime), 0);
  assert.deepEqual(await values(runtime), fresh, 'fresh current defaults are unchanged');

  await createSchema(migration);
  await seed(migration, rows);
  const rollbackBefore = await values(runtime);
  const client = await migration.connect();
  try {
    await client.query('BEGIN');
    await client.query(fs.readFileSync(DRAFT, 'utf8'));
    await client.query('ROLLBACK');
  } finally { client.release(); }
  assert.equal(await revision(runtime), 0);
  assert.deepEqual(await values(runtime), rollbackBefore, 'transaction rollback restores all six fields');
});
