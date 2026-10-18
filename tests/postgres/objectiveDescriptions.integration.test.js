'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { randomUUID } = require('node:crypto');
const { Pool } = require('pg');
const { migrate } = require('../../db/postgres/migrate');
const { seedWorkshopPlatform } = require('../../server/database/postgres/workshopPlatformSeed');
const { createWorkshopConfigRepository } = require('../../server/database/postgres/workshopConfigRepository');

const root = path.join(__dirname, '../..');
const migrations = path.join(root, 'db/postgres/identity-migrations');
const workshop = 'objective_description_lab';
const prefix = 'PG_OBJECTIVE_DESCRIPTIONS_';
const enabled = kind => process.env.PG_TEST_DISPOSABLE === 'yes'
  && ['MIGRATION', 'RUNTIME'].every(role => process.env[`${prefix}${kind}_${role}_URL`]);

function ownedUrl(kind, role) {
  const url = new URL(process.env[`${prefix}${kind}_${role}_URL`]);
  assert.equal(url.protocol, 'postgresql:');
  assert.equal(url.hostname, '127.0.0.1');
  assert.match(url.pathname, /^\/dvaia_test_[a-z0-9_]+$/);
  assert.equal(url.username, role === 'MIGRATION'
    ? 'dvaia_identity_migration' : 'dvaia_identity_runtime');
  assert.equal(url.password, '');
  assert.match(url.port, /^\d+$/);
  assert.equal(url.search, '');
  assert.equal(url.hash, '');
  return url;
}

function pools(kind) {
  const migrationUrl = ownedUrl(kind, 'MIGRATION');
  const runtimeUrl = ownedUrl(kind, 'RUNTIME');
  assert.equal(runtimeUrl.pathname, migrationUrl.pathname);
  assert.equal(runtimeUrl.port, migrationUrl.port);
  assert.notEqual(runtimeUrl.username, migrationUrl.username);
  const options = { max: 3, statement_timeout: 30000, lock_timeout: 5000,
    idle_in_transaction_session_timeout: 30000 };
  return {
    migration: new Pool({ ...options, connectionString: migrationUrl.href,
      application_name: 'objective-descriptions-migration' }),
    runtime: new Pool({ ...options, connectionString: runtimeUrl.href,
      application_name: 'objective-descriptions-runtime' }),
  };
}

function boundedMigrations(t, lastName) {
  const workspace = process.env.DVAIA_ISOLATED_TEST_WORKSPACE;
  assert.equal(typeof workspace, 'string');
  assert.ok(fs.realpathSync(workspace).startsWith('/'));
  const directory = fs.mkdtempSync(path.join(workspace, 'objective-description-migrations-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  for (const name of fs.readdirSync(migrations).sort()) {
    if (/^[0-9]{4}_.*\.sql$/.test(name) && name <= lastName) {
      fs.symlinkSync(path.join(migrations, name), path.join(directory, name));
    }
  }
  assert.equal(fs.readdirSync(directory).sort().at(-1), lastName);
  return directory;
}

function catalog(version, primaryDescription, siblingDescription = 'Sibling source description') {
  return {
    catalogVersion: version,
    catalog: { [workshop]: [
      { id: 'primary', text: `Source label ${version}`, description: primaryDescription,
        category: 'training', defaultEnabled: true },
      { id: 'sibling', text: `Sibling source label ${version}`,
        description: siblingDescription, category: 'training', defaultEnabled: true },
    ] },
    hints: { [workshop]: {
      primary: { title: `Source hint ${version}`, hints: ['Source teaching hint'] },
      sibling: { title: `Sibling source hint ${version}`, hints: ['Sibling teaching hint'] },
    } },
    solutions: { [workshop]: {
      primary: { title: `Source solution ${version}`, approach: 'Source teaching approach' },
      sibling: { title: `Sibling source solution ${version}`, approach: 'Sibling teaching approach' },
    } },
    challenges: [{ key: workshop, name: `Source exercise ${version}`,
      description: 'Source exercise description', category: 'ai', difficulty: 'intermediate',
      route: '/workshop/objective-description-lab', defaultVisible: true }],
  };
}

async function objective(pool, id = 'primary') {
  return (await pool.query(`SELECT label,description,category,hint_content,solution_content
    FROM workshop_platform.objectives WHERE workshop_key=$1 AND objective_id=$2`,
  [workshop, id])).rows[0];
}

async function revision(pool) {
  return Number((await pool.query(
    'SELECT revision FROM workshop_platform.config_revision WHERE id=1')).rows[0].revision);
}

async function assertCapabilities(migration, runtime) {
  const identity = await migration.query(`SELECT current_user AS role,
    pg_get_userbyid(c.relowner) AS owner
    FROM pg_class c WHERE c.oid='workshop_platform.objectives'::regclass`);
  assert.equal(identity.rows[0].role, identity.rows[0].owner);
  const grants = (await runtime.query(`SELECT
    has_table_privilege(current_user,'workshop_platform.objectives','SELECT') AS read_objectives,
    has_table_privilege(current_user,'workshop_platform.objectives','UPDATE') AS edit_objectives,
    has_table_privilege(current_user,'workshop_platform.catalog_field_defaults','SELECT') AS read_provenance,
    has_table_privilege(current_user,'workshop_platform.catalog_field_defaults','UPDATE') AS edit_provenance,
    has_schema_privilege(current_user,'workshop_platform','CREATE') AS schema_create,
    has_table_privilege(current_user,'workshop_platform.objectives','TRUNCATE') AS truncate_objectives`)).rows[0];
  assert.deepEqual(grants, { read_objectives: true, edit_objectives: true,
    read_provenance: true, edit_provenance: true, schema_create: false,
    truncate_objectives: false });
}

test('fresh 0132 identity install seeds objective descriptions and admin readback', {
  skip: !enabled('FRESH'), timeout: 90000,
}, async t => {
  const { migration, runtime } = pools('FRESH');
  t.after(async () => Promise.allSettled([runtime.end(), migration.end()]));
  const current = boundedMigrations(t, '0132_objective_descriptions.sql');
  const applied = await migrate(migration, current);
  assert.ok(applied.includes('0132_objective_descriptions.sql'));
  await assertCapabilities(migration, runtime);
  assert.equal((await seedWorkshopPlatform(runtime, catalog('fresh-v1',
    'Fresh source description'))).changed, true);
  const repo = createWorkshopConfigRepository(runtime);
  assert.equal((await repo.getObjectiveMetadata(workshop, 'primary')).description,
    'Fresh source description');
  assert.equal((await repo.getSnapshot()).exercises[workshop].objectives.primary.description,
    'Fresh source description');
  const provenance = (await migration.query(`SELECT provenance_state,source_document,
    applied_default_document FROM workshop_platform.catalog_field_defaults
    WHERE entity_kind='objective' AND workshop_key=$1 AND objective_id='primary'
      AND field_name='description'`, [workshop])).rows[0];
  assert.deepEqual(provenance, { provenance_state: 'managed',
    source_document: { present: true, value: 'Fresh source description' },
    applied_default_document: { present: true, value: 'Fresh source description' } });
  const before = await revision(migration);
  assert.equal((await seedWorkshopPlatform(runtime, catalog('fresh-v1',
    'Fresh source description'))).changed, false);
  assert.equal(await revision(migration), before);
  assert.deepEqual(await migrate(migration, current), []);
});

test('populated 0131 to 0132 preserves learner evidence and instructor catalog edits', {
  skip: !enabled('POPULATED'), timeout: 90000,
}, async t => {
  const { migration, runtime } = pools('POPULATED');
  t.after(async () => Promise.allSettled([runtime.end(), migration.end()]));
  const prior = boundedMigrations(t, '0131_ctf_current_decision_pending.sql');
  const current = boundedMigrations(t, '0132_objective_descriptions.sql');
  assert.equal((await migrate(migration, prior)).at(-1),
    '0131_ctf_current_decision_pending.sql');
  const userId = Number((await migration.query(`INSERT INTO identity.users
    (username,email,password,role) VALUES('description-learner','description@example.test',$1,'student')
    RETURNING id`, [`$2b$10$${'a'.repeat(53)}`])).rows[0].id);
  const adminId = Number((await migration.query(`INSERT INTO identity.users
    (username,email,password,role,admin_level)
    VALUES('description-admin','description-admin@example.test',$1,'admin',1)
    RETURNING id`, [`$2b$10$${'b'.repeat(53)}`])).rows[0].id);
  await migration.query(`INSERT INTO identity.admin_permissions (admin_id,permission_name)
    VALUES($1,'challenge_management')`, [adminId]);
  await migration.query(`INSERT INTO workshop_platform.exercises
    (workshop_key,challenge_key,challenge_name,challenge_description,category,difficulty,route,ordinal)
    VALUES($1,$1,'Instructor exercise','Instructor exercise description','ai','advanced',
      '/workshop/objective-description-lab',11)`, [workshop]);
  await migration.query(`INSERT INTO workshop_platform.objectives
    (workshop_key,objective_id,label,category,ordinal,hint_content,solution_content)
    VALUES($1,'primary','Prior instructor label','training',0,
      '{"title":"Prior instructor hint","hints":["Retain this hint"]}'::jsonb,
      '{"title":"Prior instructor solution","approach":"Retain this approach"}'::jsonb),
      ($1,'sibling','Unrelated instructor label','training',1,
      '{"title":"Unrelated hint","hints":["Preserve sibling content"]}'::jsonb,
      '{"title":"Unrelated solution","approach":"Preserve sibling content"}'::jsonb)`, [workshop]);
  await migration.query(`INSERT INTO workshop_platform.completions
    (user_id,workshop_key,objective_id) VALUES($1,$2,'primary')`, [userId, workshop]);
  await migration.query(`INSERT INTO workshop_platform.objective_evidence
    (user_id,workshop_key,scenario,generation,run_id,evidence_id,evidence_json,evidence_digest,expires_at)
    VALUES($1,$2,'objective-description',0,$3,'immutable-evidence',
      '{"effect":"owned"}'::jsonb,$4,now()+interval '1 day')`,
  [userId, workshop, randomUUID(), 'e'.repeat(64)]);
  const durableQueries = {
    user: 'SELECT id,username,email,role FROM identity.users ORDER BY id',
    exercise: `SELECT workshop_key,challenge_name,challenge_description,route
      FROM workshop_platform.exercises ORDER BY workshop_key`,
    objectives: `SELECT workshop_key,objective_id,label,hint_content,solution_content
      FROM workshop_platform.objectives ORDER BY workshop_key,objective_id`,
    completions: `SELECT user_id,workshop_key,objective_id,completed_at
      FROM workshop_platform.completions ORDER BY user_id,workshop_key,objective_id`,
    evidence: `SELECT user_id,workshop_key,scenario,generation,run_id,evidence_id,
      evidence_json,evidence_digest,created_at,expires_at
      FROM workshop_platform.objective_evidence ORDER BY id`,
  };
  const snapshot = async () => Object.fromEntries(await Promise.all(
    Object.entries(durableQueries).map(async ([name, sql]) => [name, (await migration.query(sql)).rows])));
  const before = await snapshot();
  const applied = await migrate(migration, current);
  assert.ok(applied.includes('0132_objective_descriptions.sql'));
  assert.deepEqual(await snapshot(), before);
  await assertCapabilities(migration, runtime);
  assert.equal((await objective(migration)).description, '');
  const backfill = (await migration.query(`SELECT objective_id,provenance_state,
    source_document,applied_default_document,observed_document
    FROM workshop_platform.catalog_field_defaults
    WHERE entity_kind='objective' AND workshop_key=$1 AND field_name='description'
    ORDER BY objective_id`, [workshop])).rows;
  assert.deepEqual(backfill.map(row => row.objective_id), ['primary', 'sibling']);
  for (const row of backfill) {
    assert.equal(row.provenance_state, 'managed');
    for (const field of ['source_document', 'applied_default_document', 'observed_document']) {
      assert.deepEqual(row[field], { present: true, value: '' });
    }
  }

  const repo = createWorkshopConfigRepository(runtime);
  await seedWorkshopPlatform(runtime, catalog('populated-v1', 'First source description'));
  assert.equal((await objective(migration)).description, 'First source description');
  const primaryBeforeAdmin = await objective(migration);
  assert.equal(primaryBeforeAdmin.label, 'Prior instructor label');
  assert.deepEqual(primaryBeforeAdmin.hint_content,
    { title: 'Prior instructor hint', hints: ['Retain this hint'] });
  await repo.updateObjectiveMetadata(workshop, 'primary',
    { label: 'Instructor edited label', description: 'Instructor edited description' }, adminId);
  await repo.updateHintContent(workshop, 'primary',
    { title: 'Instructor edited hint', hints: ['Retain this hint'] }, adminId);
  await repo.updateSolutionContent(workshop, 'primary',
    { title: 'Instructor edited solution', approach: 'Retain this approach' }, adminId);
  assert.deepEqual(await repo.getObjectiveMetadata(workshop, 'primary'), {
    workshopKey: workshop, objectiveId: 'primary', label: 'Instructor edited label',
    description: 'Instructor edited description', category: 'training',
  });
  assert.deepEqual(await repo.getHintContent(workshop, 'primary'), {
    workshopKey: workshop, objectiveId: 'primary', authored: true,
    title: 'Instructor edited hint', hints: ['Retain this hint'],
  });
  assert.deepEqual(await repo.getSolutionContent(workshop, 'primary'), {
    workshopKey: workshop, objectiveId: 'primary', authored: true,
    title: 'Instructor edited solution', approach: 'Retain this approach',
  });
  assert.equal((await repo.getSnapshot()).exercises[workshop].objectives.primary.description,
    'Instructor edited description');
  const primaryAfterAdmin = await objective(migration);
  const siblingAfterAdmin = await objective(migration, 'sibling');
  const custom = (await migration.query(`SELECT field_name FROM workshop_platform.catalog_field_defaults
    WHERE entity_kind='objective' AND workshop_key=$1 AND objective_id='primary'
      AND provenance_state='custom' ORDER BY field_name`, [workshop])).rows.map(row => row.field_name);
  assert.deepEqual(custom, ['description', 'hint_content', 'label', 'solution_content']);
  const learnerBeforeReseed = (await snapshot());
  await seedWorkshopPlatform(runtime, catalog('populated-v2', 'Changed source description',
    'Changed sibling source description'));
  assert.deepEqual(await objective(migration), primaryAfterAdmin);
  assert.equal((await objective(migration, 'sibling')).description,
    'Changed sibling source description');
  assert.deepEqual({ ...await objective(migration, 'sibling'),
    description: siblingAfterAdmin.description }, siblingAfterAdmin);
  const learnerAfterReseed = await snapshot();
  assert.deepEqual(learnerAfterReseed.user, learnerBeforeReseed.user);
  assert.deepEqual(learnerAfterReseed.completions, learnerBeforeReseed.completions);
  assert.deepEqual(learnerAfterReseed.evidence, learnerBeforeReseed.evidence);
  assert.deepEqual(learnerAfterReseed.exercise, learnerBeforeReseed.exercise);
  const secondRevision = await revision(migration);
  assert.equal((await seedWorkshopPlatform(runtime, catalog('populated-v2',
    'Changed source description', 'Changed sibling source description'))).changed, false);
  assert.equal(await revision(migration), secondRevision);
  assert.deepEqual(await migrate(migration, current), []);
  assert.deepEqual((await snapshot()).completions, learnerBeforeReseed.completions);
  assert.deepEqual((await snapshot()).evidence, learnerBeforeReseed.evidence);
});
