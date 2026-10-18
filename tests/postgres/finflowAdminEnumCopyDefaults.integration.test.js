'use strict';

// Root-only qualification for the unregistered identity0068 draft. The gated
// branch accepts only newly created local dvaia_test PostgreSQL databases.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { Pool } = require('pg');

const sourceRoot = path.resolve(process.env.FINFLOW_0068_SOURCE_ROOT || path.join(__dirname, '../..'));
const provenance = require(path.join(sourceRoot, 'server/database/postgres/catalogDefaultProvenance'));
const generator = require(path.join(sourceRoot, 'scripts/generate-finflow-admin-enum-copy-defaults'));
const draftPath = path.join(sourceRoot, 'docs/modernization/drafts/0068_finflow_admin_enum_copy_defaults.sql');
const draft = fs.readFileSync(draftPath, 'utf8');
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes'
  && process.env.FINFLOW_0068_ISOLATED === '1'
  && process.env.PG_FINFLOW_0068_MIGRATION_URL
  && process.env.PG_FINFLOW_0068_RUNTIME_URL;
const WORKSHOP = 'sensitive_info_disclosure';
const DATABASE = 'dvaia_test_finflow_0068';
const OWNED_PATH = new RegExp(`^/${DATABASE}$`);

function ownedUrl(key) {
  const url = new URL(process.env[key]);
  assert.equal(url.protocol, 'postgresql:');
  assert.ok(['127.0.0.1', 'localhost'].includes(url.hostname));
  assert.match(url.pathname, OWNED_PATH);
  return url.href;
}
function pool(connectionString, applicationName) {
  return new Pool({ connectionString, max: 2, connectionTimeoutMillis: 5000,
    statement_timeout: 30000, lock_timeout: 5000, application_name: applicationName });
}
function clone(value) { return JSON.parse(JSON.stringify(value)); }
function encode(value) { return provenance.encode(value); }

async function createSchema(client) {
  await client.query(`DROP SCHEMA IF EXISTS workshop_platform CASCADE;
    CREATE SCHEMA workshop_platform;
    CREATE TABLE workshop_platform.config_revision(
      id integer PRIMARY KEY CHECK(id=1), revision integer NOT NULL,
      updated_at timestamptz NOT NULL DEFAULT now());
    INSERT INTO workshop_platform.config_revision VALUES(1,11,now());
    CREATE TABLE workshop_platform.objectives(
      workshop_key text NOT NULL, objective_id text NOT NULL, label text NOT NULL,
      category text NOT NULL, ordinal integer NOT NULL, hint_content jsonb,
      solution_content jsonb, is_enabled boolean NOT NULL, catalog_active boolean NOT NULL,
      hint_enabled boolean NOT NULL, solution_enabled boolean NOT NULL, updated_by integer,
      updated_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(workshop_key,objective_id));
    CREATE TABLE workshop_platform.catalog_field_defaults(
      entity_kind text NOT NULL, workshop_key text NOT NULL, objective_id text NOT NULL,
      field_name text NOT NULL, provenance_state text NOT NULL
        CHECK(provenance_state IN ('managed','custom','legacy_unknown')),
      source_version text, source_hash text, source_document jsonb,
      applied_default_version text, applied_default_hash text, applied_default_document jsonb,
      observed_document jsonb NOT NULL, updated_at timestamptz NOT NULL DEFAULT now(),
      PRIMARY KEY(entity_kind,workshop_key,objective_id,field_name),
      CHECK ((provenance_state='managed' AND applied_default_hash IS NOT NULL
        AND applied_default_document IS NOT NULL AND applied_default_version IS NOT NULL)
        OR provenance_state<>'managed'));
    CREATE TABLE workshop_platform.user_state(
      user_id integer, workshop_key text, generation integer, started_at timestamptz);
    CREATE TABLE workshop_platform.completions(
      user_id integer, workshop_key text, objective_id text, completed_at timestamptz);
  `);
}

async function seedFields(client, rows, { state = 'managed', currentDocument,
  appliedDocument, observedDocument, provenanceRow = true } = {}) {
  const objectiveIds = [...new Set(rows.map(row => row.objectiveId))];
  for (const [index, objectiveId] of objectiveIds.entries()) {
    await client.query(`INSERT INTO workshop_platform.objectives(
      workshop_key,objective_id,label,category,ordinal,hint_content,solution_content,
      is_enabled,catalog_active,hint_enabled,solution_enabled,updated_by)
      VALUES($1,$2,$3,'recon',$4,$5::jsonb,$6::jsonb,false,true,false,true,908)`,
    [WORKSHOP, objectiveId, `Preserved ${objectiveId}`, index,
      JSON.stringify({ untouched: `hint-${objectiveId}` }),
      JSON.stringify({ untouched: `solution-${objectiveId}` })]);
  }
  for (const row of rows) {
    const live = currentDocument || row.oldDocument;
    await client.query(`UPDATE workshop_platform.objectives SET ${row.fieldName}=$3::jsonb
      WHERE workshop_key=$1 AND objective_id=$2`, [WORKSHOP, row.objectiveId,
      live.value === null ? null : JSON.stringify(live.value)]);
    if (!provenanceRow) continue;
    const applied = appliedDocument || row.oldDocument;
    const observed = observedDocument || row.oldDocument;
    await client.query(`INSERT INTO workshop_platform.catalog_field_defaults(
      entity_kind,workshop_key,objective_id,field_name,provenance_state,
      source_version,source_hash,source_document,applied_default_version,applied_default_hash,
      applied_default_document,observed_document)
      VALUES('objective',$1,$2,$3,$4,'pre-0068',$5,$6::jsonb,
        CASE WHEN $4='managed' THEN 'pre-0068' ELSE NULL END,
        CASE WHEN $4='managed' THEN $7 ELSE NULL END,
        CASE WHEN $4='managed' THEN $8::jsonb ELSE NULL END,$9::jsonb)`,
    [WORKSHOP, row.objectiveId, row.fieldName, state, row.oldHash, encode(row.oldDocument),
      provenance.hashDocument(applied), encode(applied), encode(observed)]);
  }
  await client.query('INSERT INTO workshop_platform.user_state VALUES(701,$1,19,now())', [WORKSHOP]);
  await client.query(
    "INSERT INTO workshop_platform.completions VALUES(701,$1,'admin_backup',now())", [WORKSHOP]);
}

async function snapshot(client) {
  const [objectives, defaults, revision, userState, completions] = await Promise.all([
    client.query(`SELECT workshop_key,objective_id,label,category,ordinal,hint_content,solution_content,
      is_enabled,catalog_active,hint_enabled,solution_enabled,updated_by
      FROM workshop_platform.objectives ORDER BY objective_id`),
    client.query(`SELECT entity_kind,workshop_key,objective_id,field_name,provenance_state,
      source_version,source_hash,source_document,applied_default_version,applied_default_hash,
      applied_default_document,observed_document
      FROM workshop_platform.catalog_field_defaults ORDER BY objective_id,field_name`),
    client.query('SELECT revision FROM workshop_platform.config_revision WHERE id=1'),
    client.query('SELECT user_id,workshop_key,generation FROM workshop_platform.user_state ORDER BY user_id'),
    client.query('SELECT user_id,workshop_key,objective_id FROM workshop_platform.completions ORDER BY user_id'),
  ]);
  return { objectives: objectives.rows, defaults: defaults.rows,
    revision: Number(revision.rows[0].revision), userState: userState.rows, completions: completions.rows };
}
function withoutTarget(before, after, row) {
  const oldObjective = before.objectives.find(value => value.objective_id === row.objectiveId);
  const newObjective = after.objectives.find(value => value.objective_id === row.objectiveId);
  assert.deepEqual({ ...newObjective, [row.fieldName]: undefined },
    { ...oldObjective, [row.fieldName]: undefined });
  assert.deepEqual(after.userState, before.userState);
  assert.deepEqual(after.completions, before.completions);
}
function assertCanonicalDefault(state, row) {
  assert.equal(state.provenance_state, 'managed');
  assert.equal(state.source_version, generator.sourceVersion);
  assert.equal(state.applied_default_version, generator.sourceVersion);
  assert.equal(state.source_hash, row.newHash);
  assert.equal(state.applied_default_hash, row.newHash);
  assert.deepEqual(state.source_document, row.newDocument);
  assert.deepEqual(state.applied_default_document, row.newDocument);
  assert.deepEqual(state.observed_document, row.newDocument);
}

test('identity0068 package binds three source defaults and five 0041/0067 predecessors', () => {
  assert.equal(draft, generator.buildSql());
  assert.doesNotMatch(fs.readFileSync(__filename, 'utf8'),
    /query\(\s*`[^`]*;[^`]*`\s*,\s*\[/s,
    'parameterized fixture queries must contain one statement');
  assert.equal(fs.existsSync(path.join(sourceRoot,
    'db/postgres/identity-migrations/0068_finflow_admin_enum_copy_defaults.sql')), false);
  const rows = generator.buildRows();
  assert.equal(rows.length, 5);
  assert.deepEqual(rows.map(row => row.oldHash), [
    '77c500931a70b1ec9530da96a08efe93817454cda78d4fb78c82bd34d32df974',
    '7fadc62e31d6ec553830d9f4ad12a31791699e8a456ff5ff4381e024709c5127',
    '592fc334d732e376bb7216a5be1b1ce3bbfd83d382ddce560ad11b29c4c5d106',
    'e94ef5ca26ef2a1e5b1056bfa87dd12d3753524352257d2acd0dcd0356be48ac',
    'acbc7a6208209683897d454a2e60f0a7159841cbb0a56f0a591e351dba61515c',
  ]);
  assert.deepEqual([...new Set(rows.map(row => `${row.objectiveId}:${row.fieldName}`))].sort(), [
    'admin_enum:hint_content', 'admin_enum:solution_content', 'tool_version:solution_content',
  ]);
});

test('identity0068 PostgreSQL qualification preserves catalog and learner state', {
  skip: !enabled ? 'requires root-owned disposable PostgreSQL URLs' : false,
  timeout: 120000,
}, async t => {
  const migrationUrl = new URL(ownedUrl('PG_FINFLOW_0068_MIGRATION_URL'));
  const runtimeUrl = new URL(ownedUrl('PG_FINFLOW_0068_RUNTIME_URL'));
  assert.equal(runtimeUrl.host, migrationUrl.host);
  assert.equal(runtimeUrl.pathname, migrationUrl.pathname);
  const migration = pool(migrationUrl.href, 'dvaia-finflow-0068-migration');
  const runtime = pool(runtimeUrl.href, 'dvaia-finflow-0068-runtime');
  t.after(async () => Promise.allSettled([runtime.end(), migration.end()]));
  const rows = generator.buildRows();

  for (const state of ['managed', 'legacy_unknown']) {
    for (const row of rows) {
      await createSchema(migration); await seedFields(migration, [row], { state });
      const before = await snapshot(runtime); await migration.query(draft); const after = await snapshot(runtime);
      const objective = after.objectives.find(value => value.objective_id === row.objectiveId);
      assert.deepEqual(objective[row.fieldName], row.newDocument.value, `${state}/${row.oldLineage} upgraded`);
      withoutTarget(before, after, row);
      assert.equal(after.revision, before.revision + 1);
      assertCanonicalDefault(after.defaults[0], row);
    }
  }

  const selected = rows.filter(row => row.oldLineage === 'reserved-identity0067'
    || row.oldLineage === 'canonical-before-0068');
  await createSchema(migration); await seedFields(migration, selected, { state: 'managed' });
  const combinedBefore = await snapshot(runtime); await migration.query(draft); const combined = await snapshot(runtime);
  assert.equal(combined.revision, combinedBefore.revision + 1, 'three changed fields cause one revision bump');
  assert.deepEqual(combined.userState, combinedBefore.userState);
  assert.deepEqual(combined.completions, combinedBefore.completions);
  for (const row of selected) {
    const objective = combined.objectives.find(value => value.objective_id === row.objectiveId);
    assert.deepEqual(objective[row.fieldName], row.newDocument.value);
    assertCanonicalDefault(combined.defaults.find(value => value.objective_id === row.objectiveId
      && value.field_name === row.fieldName), row);
  }
  await migration.query(draft);
  assert.deepEqual(await snapshot(runtime), combined, 'direct replay is a complete no-op');
  for (const row of selected) {
    assert.deepEqual(await provenance.reconcileField(migration, { entityKind: 'objective',
      workshopKey: WORKSHOP, objectiveId: row.objectiveId, fieldName: row.fieldName,
      sourceValue: row.newDocument.value, sourceVersion: generator.sourceVersion }),
    { changed: false, decision: 'record' });
  }
  assert.deepEqual(await snapshot(runtime), combined,
    'canonical seed reconciliation records the same version and hash without a revision change');

  const targets = selected;
  const drift = provenance.document({ instructor: 'preserved field' });
  const preserve = [
    ['custom', row => ({ state: 'custom' })],
    ['missing', row => ({ provenanceRow: false })],
    ['NULL', row => ({ currentDocument: provenance.document(null) })],
    ['live drift', row => ({ currentDocument: drift })],
    ['applied drift', row => ({ appliedDocument: drift })],
    ['observed drift', row => ({ state: 'legacy_unknown', observedDocument: drift })],
  ];
  for (const [label, options] of preserve) {
    for (const row of targets) {
      await createSchema(migration); await seedFields(migration, [row], options(row));
      const before = await snapshot(runtime); await migration.query(draft);
      assert.deepEqual(await snapshot(runtime), before, `${label}/${row.objectiveId}/${row.fieldName} preserved`);
    }
  }

  await createSchema(migration); await seedFields(migration, selected, { state: 'legacy_unknown' });
  const rollbackBefore = await snapshot(runtime);
  const client = await migration.connect();
  try {
    await client.query('BEGIN'); await client.query(draft);
    assert.equal((await client.query('SELECT revision FROM workshop_platform.config_revision WHERE id=1')).rows[0].revision,
      rollbackBefore.revision + 1);
    await client.query('ROLLBACK');
  } finally { client.release(); }
  assert.deepEqual(await snapshot(runtime), rollbackBefore, 'transaction rollback restores all fields and provenance');
});
