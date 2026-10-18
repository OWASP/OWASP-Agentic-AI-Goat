'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');
const { Pool } = require('pg');

const enabled = process.env.PG_TEST_DISPOSABLE === 'yes'
  && process.env.FINFLOW_TRAVERSAL_ISOLATED === '1';
const MIGRATION_NAME = '0054_finflow_log_policy_defaults.sql';
const LATER_MIGRATION_NAME = '0055_finflow_admin_artifact_defaults.sql';
const MIGRATION_SHA256 = '91db77530d1632518dedc4403d455c0b5be632309a8c607c07576f2027b7fa21';
const migrationDirectory = path.resolve(__dirname, '../../db/postgres/identity-migrations');
const migrationPath = path.join(migrationDirectory, MIGRATION_NAME);
const migrationSql = fs.readFileSync(migrationPath, 'utf8');
const snapshots = JSON.parse(fs.readFileSync(path.resolve(__dirname,
  'fixtures/finflow-v7-default-snapshots.json'), 'utf8')).records;
const snapshot = (objectiveId, column) => snapshots.find(value =>
  value.objectiveId === objectiveId && value.column === column);

function ownedUrl(name, database, role) {
  const value = new URL(process.env[name]);
  assert.equal(value.hostname, '127.0.0.1');
  assert.equal(value.protocol, 'postgresql:');
  assert.equal(decodeURIComponent(value.username), `dvaia_identity_${role}`);
  assert.equal(value.password, '');
  assert.equal(value.search, '');
  assert.equal(value.hash, '');
  assert.ok(Number(value.port) > 0 && Number(value.port) <= 65535);
  assert.equal(value.pathname, `/${database}`);
  return value.href;
}
function pool(url) {
  return new Pool({ connectionString: url, max: 2, connectionTimeoutMillis: 5000,
    statement_timeout: 30000, lock_timeout: 5000,
    application_name: 'dvaia-finflow-integrated-migrations' });
}
async function objective(poolValue, id) {
  return (await poolValue.query(`SELECT workshop_key,objective_id,label,category,ordinal,
    is_enabled,catalog_active,hint_enabled,solution_enabled,hint_content,solution_content,
    updated_by FROM workshop_platform.objectives
    WHERE workshop_key='sensitive_info_disclosure' AND objective_id=$1`, [id])).rows[0];
}
function withoutManaged(row) {
  const value = { ...row };
  delete value.solution_content;
  delete value.hint_content;
  return value;
}
test('identity 0054 uses the real loader for fresh, populated, no-op, and rollback paths',
  { skip: !enabled, timeout: 120000 }, async t => {
    assert.equal(fs.realpathSync(process.cwd()), fs.realpathSync(path.resolve(__dirname, '../..')));
    assert.equal(process.env.PG_TEST_DISPOSABLE, 'yes');
    const urls = ['IDENTITY_DATABASE_URL', 'IDENTITY_MIGRATION_DATABASE_URL',
      'FINFLOW_IDENTITY_POPULATED_DATABASE_URL', 'FINFLOW_IDENTITY_POPULATED_MIGRATION_DATABASE_URL']
      .map(name => new URL(process.env[name]));
    for (const url of urls) assert.equal(url.port, urls[0].port);
    assert.equal(urls[0].pathname, urls[1].pathname);
    assert.equal(urls[2].pathname, urls[3].pathname);
    assert.notEqual(urls[0].pathname, urls[2].pathname);
    assert.equal(createHash('sha256').update(migrationSql).digest('hex'), MIGRATION_SHA256);
    const mainRuntime = pool(ownedUrl('IDENTITY_DATABASE_URL',
      'dvaia_test_finflow_traversal_identity', 'runtime'));
    const mainMigration = pool(ownedUrl('IDENTITY_MIGRATION_DATABASE_URL',
      'dvaia_test_finflow_traversal_identity', 'migration'));
    const populatedRuntime = pool(ownedUrl('FINFLOW_IDENTITY_POPULATED_DATABASE_URL',
      'dvaia_test_finflow_traversal_identity_populated', 'runtime'));
    const populatedMigration = pool(ownedUrl('FINFLOW_IDENTITY_POPULATED_MIGRATION_DATABASE_URL',
      'dvaia_test_finflow_traversal_identity_populated', 'migration'));
    const pools = [mainRuntime, mainMigration, populatedRuntime, populatedMigration];
    t.after(async () => Promise.allSettled(pools.map(value => value.end())));

    const { createXssBoundedMigrationView } = require('../helpers/xssBoundedMigrationView');
    const identityApi = createXssBoundedMigrationView({ identity: 55 });
    await identityApi.initializeIdentityRepository(mainRuntime, mainMigration);
    await require('../../server/database/postgres/workshopPlatformSeed')
      .seedWorkshopPlatform(mainMigration);
    assert.equal((await mainMigration.query(`SELECT count(*)::integer AS count
      FROM dvaia_migrations.ledger WHERE name=$1`, [MIGRATION_NAME])).rows[0].count, 1);
    for (const id of ['admin_read_logs', 'admin_llm_logs']) {
      const row = await objective(mainRuntime, id);
      assert.deepEqual(row.solution_content, snapshot(id, 'solution_content').replacement);
      assert.deepEqual(row.hint_content, snapshot(id, 'hint_content').replacement);
    }

    const baseline = createXssBoundedMigrationView({ identity: 53 });
    await baseline.initializeIdentityRepository(populatedRuntime, populatedMigration);
    await require('../../server/database/postgres/workshopPlatformSeed')
      .seedWorkshopPlatform(populatedMigration);

    const readSolution = snapshot('admin_read_logs', 'solution_content');
    const readHint = snapshot('admin_read_logs', 'hint_content');
    const llmSolution = snapshot('admin_llm_logs', 'solution_content');
    const llmHint = snapshot('admin_llm_logs', 'hint_content');
    const customHint = { title: 'Instructor custom hint', hints: ['Preserve exactly.'] };
    await populatedMigration.query(`UPDATE workshop_platform.objectives SET
      solution_content=$1::jsonb,hint_content=$2::jsonb,is_enabled=false,
      hint_enabled=true,solution_enabled=false
      WHERE workshop_key='sensitive_info_disclosure' AND objective_id='admin_read_logs'`,
    [JSON.stringify(readSolution.accepted[0]), JSON.stringify(customHint)]);
    await populatedMigration.query(`UPDATE workshop_platform.objectives SET
      solution_content=NULL,hint_content=$1::jsonb,is_enabled=true,
      hint_enabled=false,solution_enabled=true
      WHERE workshop_key='sensitive_info_disclosure' AND objective_id='admin_llm_logs'`,
    [JSON.stringify(llmHint.accepted[0])]);
    const beforeRead = await objective(populatedRuntime, 'admin_read_logs');
    const beforeLlm = await objective(populatedRuntime, 'admin_llm_logs');
    const unrelatedBefore = await objective(populatedRuntime, 'traversal_secrets');
    const revisionBefore = Number((await populatedRuntime.query(
      'SELECT revision FROM workshop_platform.config_revision WHERE id=1')).rows[0].revision);

    identityApi.setCeiling('identity', 54);
    const applied = await identityApi.initializeIdentityRepository(populatedRuntime,
      populatedMigration);
    assert.deepEqual(applied, [MIGRATION_NAME]);
    const afterRead = await objective(populatedRuntime, 'admin_read_logs');
    const afterLlm = await objective(populatedRuntime, 'admin_llm_logs');
    assert.deepEqual(afterRead.solution_content, readSolution.replacement);
    assert.deepEqual(afterRead.hint_content, customHint);
    assert.equal(afterLlm.solution_content, null);
    assert.deepEqual(afterLlm.hint_content, llmHint.replacement);
    assert.deepEqual(withoutManaged(afterRead), withoutManaged(beforeRead));
    assert.deepEqual(withoutManaged(afterLlm), withoutManaged(beforeLlm));
    assert.deepEqual(await objective(populatedRuntime, 'traversal_secrets'), unrelatedBefore);
    assert.equal(Number((await populatedRuntime.query(
      'SELECT revision FROM workshop_platform.config_revision WHERE id=1')).rows[0].revision),
    revisionBefore + 1);

    const rowsAfter = [afterRead, afterLlm];
    const revisionAfter = revisionBefore + 1;
    const ledgerAfter = (await populatedMigration.query(
      'SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows;
    assert.deepEqual(await identityApi.initializeIdentityRepository(populatedRuntime,
      populatedMigration), []);
    assert.deepEqual([await objective(populatedRuntime, 'admin_read_logs'),
      await objective(populatedRuntime, 'admin_llm_logs')], rowsAfter);
    assert.equal(Number((await populatedRuntime.query(
      'SELECT revision FROM workshop_platform.config_revision WHERE id=1')).rows[0].revision),
    revisionAfter);
    assert.deepEqual((await populatedMigration.query(
      'SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows, ledgerAfter);

    const client = await populatedMigration.connect();
    try {
      for (const record of snapshots) {
        assert.ok(['solution_content', 'hint_content'].includes(record.column));
        for (const accepted of record.accepted) {
          await client.query('BEGIN');
          await client.query(`UPDATE workshop_platform.objectives SET ${record.column}=$1::jsonb
            WHERE workshop_key='sensitive_info_disclosure' AND objective_id=$2`,
          [JSON.stringify(accepted), record.objectiveId]);
          const revision = Number((await client.query(
            'SELECT revision FROM workshop_platform.config_revision WHERE id=1')).rows[0].revision);
          await client.query(migrationSql);
          const row = (await client.query(`SELECT ${record.column} AS content
            FROM workshop_platform.objectives WHERE workshop_key='sensitive_info_disclosure'
            AND objective_id=$1`, [record.objectiveId])).rows[0];
          assert.deepEqual(row.content, record.replacement,
            `${record.objectiveId}.${record.column} accepted legacy value`);
          assert.equal(Number((await client.query(
            'SELECT revision FROM workshop_platform.config_revision WHERE id=1')).rows[0].revision),
          revision + 1);
          await client.query('ROLLBACK');
        }
      }
      assert.deepEqual(await objective(populatedRuntime, 'admin_read_logs'), afterRead);
      assert.deepEqual(await objective(populatedRuntime, 'admin_llm_logs'), afterLlm);

      await client.query('BEGIN');
      await client.query(`UPDATE workshop_platform.objectives SET
        solution_content=$1::jsonb,hint_content=$2::jsonb
        WHERE workshop_key='sensitive_info_disclosure' AND objective_id='admin_read_logs'`,
      [JSON.stringify(readSolution.replacement), JSON.stringify(readHint.replacement)]);
      await client.query(`UPDATE workshop_platform.objectives SET
        solution_content=$1::jsonb,hint_content=$2::jsonb
        WHERE workshop_key='sensitive_info_disclosure' AND objective_id='admin_llm_logs'`,
      [JSON.stringify(llmSolution.replacement), JSON.stringify(llmHint.replacement)]);
      const noOpRevision = Number((await client.query(
        'SELECT revision FROM workshop_platform.config_revision WHERE id=1')).rows[0].revision);
      await client.query(migrationSql);
      assert.equal(Number((await client.query(
        'SELECT revision FROM workshop_platform.config_revision WHERE id=1')).rows[0].revision),
      noOpRevision);
      await client.query('ROLLBACK');
    } finally {
      client.release();
    }

    await populatedMigration.query(`UPDATE workshop_platform.objectives SET solution_content=$1::jsonb
      WHERE workshop_key='sensitive_info_disclosure' AND objective_id='admin_read_logs'`,
    [JSON.stringify(readSolution.accepted[0])]);
    async function assertOwnedRollback(ceiling) {
      const failureMigrationName = `${String(ceiling + 1).padStart(4, '0')}_qualification_failure.sql`;
      const failing = createXssBoundedMigrationView({ identity: ceiling,
        identityFailureSql: `${migrationSql}\nDO $$ BEGIN RAISE EXCEPTION 'owned qualification rollback'; END $$;\n` });
    const failureBefore = await objective(populatedRuntime, 'admin_read_logs');
    const failureRevision = Number((await populatedRuntime.query(
      'SELECT revision FROM workshop_platform.config_revision WHERE id=1')).rows[0].revision);
    const failureLedger = (await populatedMigration.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows;
    await assert.rejects(failing.migrate(populatedMigration, migrationDirectory),
      /owned qualification rollback/);
    assert.deepEqual(await objective(populatedRuntime, 'admin_read_logs'), failureBefore);
    assert.equal(Number((await populatedRuntime.query(
      'SELECT revision FROM workshop_platform.config_revision WHERE id=1')).rows[0].revision),
    failureRevision);
    assert.equal((await populatedMigration.query(`SELECT count(*)::integer AS count
      FROM dvaia_migrations.ledger WHERE name=$1`, [failureMigrationName])).rows[0].count, 0);
    assert.deepEqual((await populatedMigration.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows, failureLedger);
    }
    await assertOwnedRollback(54);
    identityApi.setCeiling('identity', 55);
    assert.deepEqual(await identityApi.initializeIdentityRepository(populatedRuntime, populatedMigration), [LATER_MIGRATION_NAME]);
    assert.deepEqual(await identityApi.initializeIdentityRepository(populatedRuntime, populatedMigration), []);
    await assertOwnedRollback(55);
  });
