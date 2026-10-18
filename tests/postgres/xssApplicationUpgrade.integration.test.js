'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash, randomUUID } = require('node:crypto');
const path = require('node:path');
const { createXssBoundedMigrationView } = require('../helpers/xssBoundedMigrationView');
const { createPool } = require('../../server/database/postgres');
const { seedWorkshopPlatform } = require('../../server/database/postgres/workshopPlatformSeed');

const URLS = Object.freeze({
  identityRuntime: 'PG_XSS_UPGRADE_IDENTITY_RUNTIME_URL',
  identityMigration: 'PG_XSS_UPGRADE_IDENTITY_MIGRATION_URL',
  xssRuntime: 'PG_XSS_UPGRADE_STORE_RUNTIME_URL',
  xssMigration: 'PG_XSS_UPGRADE_STORE_MIGRATION_URL',
});
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes'
  && Object.values(URLS).every(key => Boolean(process.env[key]));
const password = '$2b$12$000000000000000000000uG3W0Jp6IPhhD1TRqN8Yc2zJQG3vVnSA';
const sha256 = value => createHash('sha256').update(value).digest('hex');

function assertOwnedUrl(value, database, role) {
  const url = new URL(value);
  assert.equal(url.hostname, '127.0.0.1');
  assert.equal(url.pathname, `/${database}`);
  assert.equal(decodeURIComponent(url.username), role);
}

async function jsonRows(pool, sql, values = []) {
  return (await pool.query(sql, values)).rows;
}

async function ledger(pool) {
  return jsonRows(pool, 'SELECT name,checksum,applied_at FROM dvaia_migrations.ledger ORDER BY name');
}

function quoteIdentifier(value) {
  assert.match(value, /^[a-z_][a-z0-9_]*$/);
  return `"${value}"`;
}

async function capturePreexistingTables(pool, schemas, inventory = null) {
  if (!inventory) {
    const rows = await jsonRows(pool, `SELECT table_schema,table_name,column_name
      FROM information_schema.columns
      WHERE table_schema=ANY($1::text[]) ORDER BY table_schema,table_name,ordinal_position`, [schemas]);
    inventory = {};
    for (const row of rows) {
      const key = `${row.table_schema}.${row.table_name}`;
      (inventory[key] ||= []).push(row.column_name);
    }
  }
  const tables = {};
  for (const [key, columns] of Object.entries(inventory)) {
    const [schema, table] = key.split('.');
    const projection = columns.map(quoteIdentifier).join(',');
    const result = await pool.query(`SELECT ${projection} FROM ${quoteIdentifier(schema)}.${quoteIdentifier(table)}
      ORDER BY to_jsonb(ROW(${projection}))::text COLLATE "C"`);
    tables[key] = { rows: result.rowCount, sha256: sha256(JSON.stringify(result.rows)) };
  }
  return { inventory, tables };
}

test('application upgrade preserves populated identity0069 and XSS0007 state through current tails',
  { skip: !enabled, timeout: 60000 }, async () => {
    assertOwnedUrl(process.env[URLS.identityRuntime], 'dvaia_test_xss_upgrade_identity', 'dvaia_identity_runtime');
    assertOwnedUrl(process.env[URLS.identityMigration], 'dvaia_test_xss_upgrade_identity', 'dvaia_identity_migration');
    assertOwnedUrl(process.env[URLS.xssRuntime], 'dvaia_test_xss_upgrade_store', 'dvaia_xss_runtime');
    assertOwnedUrl(process.env[URLS.xssMigration], 'dvaia_test_xss_upgrade_store', 'dvaia_xss_migration');

    const identityRuntime = createPool(process.env, URLS.identityRuntime);
    const identityMigration = createPool(process.env, URLS.identityMigration);
    const xssRuntime = createPool(process.env, URLS.xssRuntime);
    const xssMigration = createPool(process.env, URLS.xssMigration);
    const pools = [identityRuntime, identityMigration, xssRuntime, xssMigration];
    const identitySource = path.resolve(__dirname, '../../db/postgres/identity-migrations');
    const xssSource = path.resolve(__dirname, '../../db/postgres/workshop-migrations/xss');
    // Historical identity 0069→0080 and XSS 0007→0015 qualification only.
    const view = createXssBoundedMigrationView({ identity:69, xss:7 });
    const { migrate, readMigrations, initializeIdentityRepository, createXssWorkshopDb } = view;
    let primaryError;
    try {
      assert.equal((await migrate(identityMigration, identitySource)).at(-1),
        '0069_sql_injection_postgres_copy_defaults.sql');
      assert.equal((await migrate(xssMigration, xssSource)).at(-1), '0007_student_deletion.sql');
      await seedWorkshopPlatform(identityMigration);

      const users = [];
      for (const suffix of ['owner', 'sibling']) {
        users.push((await identityMigration.query(`INSERT INTO identity.users(username,email,password)
          VALUES($1,$2,$3) RETURNING id`,
        [`upgrade-${suffix}`, `upgrade-${suffix}@fixture.invalid`, password])).rows[0]);
      }
      const [owner, sibling] = users;
      const ownerKeys = users.map(user => JSON.stringify(['XSS', String(user.id)]));
      const runs = [randomUUID(), randomUUID()];
      for (let index = 0; index < users.length; index += 1) {
        const user = users[index];
        await identityMigration.query('INSERT INTO graph_runtime.owners(owner_key,generation) VALUES($1,$2)',
          [ownerKeys[index], index + 3]);
        await identityMigration.query(`INSERT INTO graph_runtime.runs
          (run_id,owner_key,generation,status,last_node,provider,model,decision_source,finished_at)
          VALUES($1,$2,$3,'completed','fixture','ollama','llama3.1:8b','model',clock_timestamp())`,
        [runs[index], ownerKeys[index], index + 3]);
        await identityMigration.query(`INSERT INTO workshop_platform.user_state
          (user_id,workshop_key,generation,started_at) VALUES($1,'xss_workshop',$2,clock_timestamp())`,
        [user.id, index + 1]);
        await identityMigration.query(`INSERT INTO workshop_platform.completions
          (user_id,workshop_key,objective_id) VALUES($1,'xss_workshop','xss_s1')`, [user.id]);
        await identityMigration.query(`INSERT INTO workshop_platform.time_tracking
          (user_id,workshop_key,session_start,last_heartbeat,duration_seconds)
          VALUES($1,'xss_workshop',clock_timestamp(),clock_timestamp(),$2)`, [user.id, 60 + index]);
        await identityMigration.query(`INSERT INTO workshop_platform.objective_judgments
          (user_id,evaluation_id,workshop_key,objective_id,family,scenario,rubric_version,
           evidence_digest,run_id,generation,verdict,result_json,result_digest,disposition,evaluated_at)
          VALUES($1,$2,'xss_workshop','xss_s1','XSS','upgrade-preservation','xss-v3',$3,
           $4,$5,'pass',$6::jsonb,$7,'awarded',clock_timestamp())`,
        [user.id, randomUUID(), sha256(`evidence:${user.id}`), runs[index], index + 3,
          JSON.stringify({ qualified: true, owner: index === 0 ? 'owner' : 'sibling' }),
          sha256(`result:${user.id}`)]);
      }
      await identityMigration.query(`INSERT INTO identity.student_deletion_jobs
        (job_id,subject_user_id,requested_by,state)
        VALUES($1,$2,$3,'pending')`, [randomUUID(), sibling.id, owner.id]);

      for (let index = 0; index < users.length; index += 1) {
        const user = users[index];
        const value = `<strong>owned-${user.id}</strong>`;
        await xssMigration.query(`INSERT INTO xss.profiles
          (user_key,name,bio,website,name_revision,bio_revision,website_revision)
          VALUES($1,$2,$3,$4,5,6,7)`,
        [String(user.id), `name-${user.id}`, value, `https://owner-${user.id}.invalid`]);
        await xssMigration.query(`INSERT INTO xss.profile_model_origins
          (user_key,field,platform_user_id,revision,value_sha256,workshop_generation,run_id,
           owner_key,durable_generation,decision_source,provider,model,raw_decision_sha256,observation_index)
          VALUES($1,'bio',$2,6,$3,$4,$5,$6,$7,'model','ollama','llama3.1:8b',$8,0)`,
        [String(user.id), user.id, sha256(value), index + 1, runs[index], ownerKeys[index],
          index + 3, sha256(`decision:${user.id}`)]);
        await xssMigration.query(`INSERT INTO xss.progress(user_key,objective_id,completed,completed_at)
          VALUES($1,'stored_xss',1,clock_timestamp())`, [String(user.id)]);
        await xssMigration.query(`INSERT INTO xss.emails(subject,sender,body,user_key)
          VALUES($1,'fixture@invalid',$2,$3)`,
        [`mail-${user.id}`, `private-body-${user.id}`, String(user.id)]);
      }

      const identityBefore = await capturePreexistingTables(identityMigration,
        ['identity', 'graph_runtime', 'workshop_platform']);
      const xssBefore = await capturePreexistingTables(xssMigration, ['xss']);
      const identityPrefixLedger = await ledger(identityMigration);
      const xssPrefixLedger = await ledger(xssMigration);
      assert.equal(identityPrefixLedger.at(-1).name, '0069_sql_injection_postgres_copy_defaults.sql');
      assert.equal(xssPrefixLedger.at(-1).name, '0007_student_deletion.sql');

      view.setCeiling('identity', 80);
      view.setCeiling('xss', 15);
      const expectedIdentityTail = (await readMigrations(identitySource))
        .filter(row => Number(row.name.slice(0, 4)) >= 70);
      const expectedXssTail = (await readMigrations(xssSource))
        .filter(row => Number(row.name.slice(0, 4)) >= 8);
      assert.equal(expectedIdentityTail.at(-1).name, '0080_legacy_ai_private_history.sql');
      assert.equal(expectedXssTail.at(-1).name, '0015_owner_deletion_write_fence.sql');
      assert.deepEqual(await initializeIdentityRepository(identityRuntime, identityMigration), [
        '0070_xss_scope_authority.sql',
        '0071_xss_scope_bind_conflict_fix.sql',
        '0072_xss_profile_reset_journal.sql',
        '0073_xss_judgment_child_binding.sql',
        '0074_xss_profile_reset_parent_supersession.sql',
        '0075_xss_profile_reset_constraint_repair.sql',
        '0076_xss_profile_reset_owner_lookup.sql',
        '0077_xss_parent_reset_journal.sql',
        '0078_xss_parent_reset_admission_fence.sql',
        '0079_xss_deletion_redaction_recovery_filter.sql',
        '0080_legacy_ai_private_history.sql',
      ]);
      const xssDb = createXssWorkshopDb(xssRuntime);
      await xssDb.initializeXssWorkshopDb(xssMigration);
      await seedWorkshopPlatform(identityMigration);

      assert.deepEqual((await capturePreexistingTables(identityMigration,
        ['identity', 'graph_runtime', 'workshop_platform'], identityBefore.inventory)).tables,
      identityBefore.tables, 'identity tail and canonical seed preserve every preexisting table row');
      assert.deepEqual((await capturePreexistingTables(xssMigration, ['xss'], xssBefore.inventory)).tables,
        xssBefore.tables, 'XSS tail preserves every preexisting table row');

      const identityTailLedger = await ledger(identityMigration);
      const xssTailLedger = await ledger(xssMigration);
      assert.deepEqual(identityTailLedger.slice(0, identityPrefixLedger.length), identityPrefixLedger);
      assert.deepEqual(xssTailLedger.slice(0, xssPrefixLedger.length), xssPrefixLedger);
      assert.deepEqual(identityTailLedger.slice(identityPrefixLedger.length)
        .map(({ name, checksum }) => ({ name, checksum })),
      expectedIdentityTail.map(({ name, checksum }) => ({ name, checksum })));
      assert.deepEqual(identityTailLedger.slice(identityPrefixLedger.length).map(row => row.name), [
        '0070_xss_scope_authority.sql', '0071_xss_scope_bind_conflict_fix.sql',
        '0072_xss_profile_reset_journal.sql', '0073_xss_judgment_child_binding.sql',
        '0074_xss_profile_reset_parent_supersession.sql', '0075_xss_profile_reset_constraint_repair.sql',
        '0076_xss_profile_reset_owner_lookup.sql', '0077_xss_parent_reset_journal.sql',
        '0078_xss_parent_reset_admission_fence.sql', '0079_xss_deletion_redaction_recovery_filter.sql',
        '0080_legacy_ai_private_history.sql',
      ]);
      assert.deepEqual(xssTailLedger.slice(xssPrefixLedger.length)
        .map(({ name, checksum }) => ({ name, checksum })),
      expectedXssTail.map(({ name, checksum }) => ({ name, checksum })));
      assert.deepEqual(xssTailLedger.slice(xssPrefixLedger.length).map(row => row.name), [
        '0008_scoped_profile_reset_receipt.sql', '0009_student_deletion_receipt_retention.sql',
        '0010_profile_origin_child_scope.sql', '0011_profile_origin_child_scope_not_null.sql',
        '0012_scoped_profile_reset_retirement.sql', '0013_scoped_profile_reset_owner_deletion_fence.sql',
        '0014_parent_profile_reset_receipt.sql', '0015_owner_deletion_write_fence.sql',
      ]);

      assert.deepEqual(await initializeIdentityRepository(identityRuntime, identityMigration), []);
      await xssDb.initializeXssWorkshopDb(xssMigration);
      await seedWorkshopPlatform(identityMigration);
      assert.deepEqual(await ledger(identityMigration), identityTailLedger,
        'identity second run is a ledger no-op');
      assert.deepEqual(await ledger(xssMigration), xssTailLedger,
        'XSS second run is a ledger no-op');
      assert.deepEqual((await capturePreexistingTables(identityMigration,
        ['identity', 'graph_runtime', 'workshop_platform'], identityBefore.inventory)).tables,
      identityBefore.tables, 'identity replay preserves every preexisting table row');
      assert.deepEqual((await capturePreexistingTables(xssMigration, ['xss'], xssBefore.inventory)).tables,
        xssBefore.tables, 'XSS replay preserves every preexisting table row');
    } catch (error) {
      primaryError = error;
    } finally {
      const cleanup = await Promise.allSettled([
        ...pools.map(pool => pool.end()),
      ]);
      const failures = cleanup.filter(result => result.status === 'rejected').map(result => result.reason);
      if (failures.length) primaryError = new AggregateError(
        primaryError ? [primaryError, ...failures] : failures, 'XSS application upgrade fixture cleanup failed');
    }
    if (primaryError) throw primaryError;
  });
