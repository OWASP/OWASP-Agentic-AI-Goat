'use strict';

// Database-only upgrade qualification. No agent, Judge or objective award is created.
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { createHash, randomUUID } = require('node:crypto');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const { migrate, readMigrations } = require('../../db/postgres/migrate');
const { seedSecureShopAssessmentDefaults } = require('../../server/database/postgres/secureshopAssessmentSeed');
const { seedWorkshopPlatform } = require('../../server/database/postgres/workshopPlatformSeed');
const { seedSecureShopStandaloneDefaults } = require('../../server/database/postgres/secureshopStandaloneSeed');
const { createSecureShopStandaloneAuthRepository } = require('../../server/database/postgres/secureshopStandaloneAuthRepository');
const { createSecureShopStandaloneAuthService } = require('../../server/services/secureshopStandaloneAuth');
const { createSecureShopAssessmentCatalog } = require('../../server/services/secureshopAssessmentCatalog');
const curriculum = require('../../server/config/secureshopCurriculum');
const { OBJECTIVES } = curriculum;

const PREFIX = 'PG_SECURESHOP_V03_LISTING_OPTIMIZE_SEED_';
const ID = 'ss_listing_image_command_execution';
const DIRECTORY = path.resolve(__dirname, '../../db/postgres/identity-migrations');
const PREDECESSOR = JSON.stringify({ version: 1, id: ID,
  label: 'Cause an owned listing image task to run an additional command inside its isolated target',
  defaultEnabled: false, qualification: 'pending' });
// Original checked-in source bytes, independent of the seed implementation.
const OLD_SHA = 'a2ee10715a26bb7e272ac208cc7913725aecf6ac9c605b24258cf83dc4ed30e7';
const sha = text => createHash('sha256').update(text).digest('hex');
const expected = OBJECTIVES.find(row => row.id === ID);
const CURRENT = JSON.stringify({ version: 1, id: ID, label: expected.text,
  defaultEnabled: expected.defaultEnabled, qualification: expected.qualification });
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes'
  && ['FRESH', 'POPULATED'].every(store => ['MIGRATION', 'RUNTIME']
    .every(role => process.env[`${PREFIX}${store}_${role}_URL`]));

function checkedUrls(store) {
  const urls = ['MIGRATION', 'RUNTIME'].map(role => {
    const url = new URL(process.env[`${PREFIX}${store}_${role}_URL`]);
    assert.equal(url.protocol, 'postgresql:');
    assert.equal(url.hostname, '127.0.0.1');
    assert.equal(url.username, `dvaia_identity_${role.toLowerCase()}`);
    assert.equal(url.password, ''); assert.equal(url.search, ''); assert.equal(url.hash, '');
    assert.match(url.pathname, new RegExp(`^/dvaia_test_persona_${store.toLowerCase()}_[a-f0-9]{12}$`));
    assert.ok(Number(url.port) > 0 && Number(url.port) <= 65535);
    return url;
  });
  assert.equal(urls[0].host, urls[1].host);
  assert.equal(urls[0].pathname, urls[1].pathname);
  const other = checkedOther(store);
  assert.equal(urls[0].host, other.host);
  assert.notEqual(urls[0].pathname, other.pathname);
  assert.equal(urls[0].pathname.split('_').at(-1), other.pathname.split('_').at(-1));
  return urls;
}
function checkedOther(store) {
  return new URL(process.env[`${PREFIX}${store === 'FRESH' ? 'POPULATED' : 'FRESH'}_MIGRATION_URL`]);
}
async function open(store, t) {
  const [migrationUrl, runtimeUrl] = checkedUrls(store);
  const migration = new Pool({ connectionString: migrationUrl.href, max: 2,
    statement_timeout: 15000, lock_timeout: 3000 });
  const runtime = new Pool({ connectionString: runtimeUrl.href, max: 2,
    statement_timeout: 15000, lock_timeout: 3000 });
  t.after(async () => {
    const closed = await Promise.allSettled([migration.end(), runtime.end()]);
    assert.equal(closed.filter(row => row.status === 'rejected').length, 0);
  });
  const manifest = (await readMigrations(DIRECTORY)).map(({ name, checksum }) => ({ name, checksum }));
  assert.deepEqual(await migrate(migration, DIRECTORY), manifest.map(row => row.name));
  assert.deepEqual(await migrate(migration, DIRECTORY), []);
  assert.deepEqual((await migration.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows, manifest);
  assert.equal((await runtime.query("SELECT has_table_privilege(current_user,'secureshop_auth.assessment_objectives','UPDATE') AS allowed")).rows[0].allowed, false);
  return { migration, runtime, manifest };
}
async function row(pool) {
  return (await pool.query('SELECT * FROM secureshop_auth.assessment_objectives WHERE objective_id=$1', [ID])).rows[0];
}
async function content(pool, id = ID) {
  return (await pool.query(`SELECT * FROM workshop_platform.objectives
    WHERE workshop_key=$1 AND objective_id=$2`, [curriculum.WORKSHOP_KEY, id])).rows[0];
}
async function defaults(pool, id = ID) {
  return (await pool.query(`SELECT * FROM workshop_platform.catalog_field_defaults
    WHERE entity_kind='objective' AND workshop_key=$1 AND objective_id=$2 ORDER BY field_name`,
  [curriculum.WORKSHOP_KEY, id])).rows;
}
async function snapshot(pool) {
  const tables = ['secureshop_auth.assessment_objectives', 'secureshop_auth.assessment_configuration',
    'secureshop_auth.assessment_configuration_history', 'secureshop_auth.assessment_judgments',
    'secureshop_auth.assessment_completions', 'secureshop_auth.assessment_contributions',
    'secureshop_auth.assessment_retries', 'workshop_platform.objectives',
    'workshop_platform.catalog_field_defaults', 'workshop_platform.config_revision'];
  return Object.fromEntries(await Promise.all(tables.map(async table => [table.split('.').at(-1),
    (await pool.query(`SELECT to_jsonb(t) AS row FROM ${table} t ORDER BY to_jsonb(t)::text`)).rows])));
}
async function seedOwner(migration, runtime) {
  await seedSecureShopStandaloneDefaults(migration, { hashPassword: value => bcrypt.hash(value, 4) });
  const auth = createSecureShopStandaloneAuthService({ repository:
    createSecureShopStandaloneAuthRepository({ pool: runtime }) });
  const admin = await auth.login({ username: 'student_admin', password: 'student123' });
  return { admin, auth, catalog: createSecureShopAssessmentCatalog({ pool: runtime, authService: auth }) };
}

test('native fresh V03 listing image optimize seed is qualified but disabled and exact second seed is a no-op',
  { skip: !enabled, timeout: 120000 }, async t => {
    assert.equal(sha(PREDECESSOR), OLD_SHA);
    assert.equal(expected.qualification, 'native-browser-judge');
    assert.equal(expected.defaultEnabled, false);
    const { migration, runtime, manifest } = await open('FRESH', t);
    assert.deepEqual(await seedSecureShopAssessmentDefaults(migration), { inserted: OBJECTIVES.length });
    assert.equal((await seedWorkshopPlatform(migration)).changed, true);
    const actual = await row(runtime), lesson = await content(runtime);
    assert.equal(actual.qualification, 'native-browser-judge'); assert.equal(actual.is_enabled, false);
    assert.equal(actual.catalog_active, true); assert.equal(actual.configuration_source, 'checked_in_default');
    assert.equal(actual.source_sha256, sha(CURRENT));
    assert.deepEqual(actual.source_document, JSON.parse(CURRENT));
    assert.equal(lesson.is_enabled, false); assert.equal(lesson.catalog_active, true);
    assert.deepEqual(lesson.hint_content, curriculum.HINTS[ID]);
    assert.deepEqual(lesson.solution_content, curriculum.SOLUTIONS[ID]);
    assert.ok((await defaults(runtime)).every(value => value.provenance_state === 'managed'));
    const before = await snapshot(migration);
    assert.deepEqual(await seedSecureShopAssessmentDefaults(migration), { inserted: 0 });
    assert.equal((await seedWorkshopPlatform(migration)).changed, false);
    assert.deepEqual(await snapshot(migration), before);
    assert.deepEqual(await migrate(migration, DIRECTORY), []);
    assert.deepEqual((await migration.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows, manifest);
  });

test('native populated V03 listing image optimize seed preserves instructor and sibling configuration and admits only exact old provenance',
  { skip: !enabled, timeout: 120000 }, async t => {
    const { migration, runtime, manifest } = await open('POPULATED', t);
    await migration.query(`INSERT INTO secureshop_auth.assessment_objectives
      (objective_id,label,is_enabled,catalog_active,qualification,source_sha256,source_document,updated_at)
      VALUES($1,'Retained instructor label',true,false,'pending',$2,$3::jsonb,'2026-01-01T00:00:00Z')`,
    [ID, OLD_SHA, PREDECESSOR]);
    const siblingSource = JSON.stringify({ version: 1, id: 'ss_v03_seed_sibling', label: 'Retained sibling source' });
    await migration.query(`INSERT INTO secureshop_auth.assessment_objectives
      (objective_id,label,is_enabled,catalog_active,qualification,source_sha256,source_document,configuration_source)
      VALUES('ss_v03_seed_sibling','Retained sibling label',true,false,'pending',$1,$2::jsonb,'instructor')`,
    [sha(siblingSource), siblingSource]);
    assert.equal((await seedWorkshopPlatform(migration)).changed, true);
    await migration.query(`UPDATE workshop_platform.objectives SET label=$3,hint_content=$4::jsonb,
      solution_content=$5::jsonb,hint_enabled=false,solution_enabled=true
      WHERE workshop_key=$1 AND objective_id=$2`, [curriculum.WORKSHOP_KEY, ID,
      'Instructor-owned V03 lesson', JSON.stringify({ title: 'Custom V03 hints', hints: ['Retain this content'] }),
      JSON.stringify({ title: 'Custom V03 solution', examples: [] })]);
    const contentSibling = OBJECTIVES.find(value => value.id !== ID).id;
    await migration.query(`UPDATE workshop_platform.objectives SET label=$3 WHERE workshop_key=$1
      AND objective_id=$2`, [curriculum.WORKSHOP_KEY, contentSibling, 'Retained sibling lesson']);
    const originalContent = await content(migration);
    const originalContentSibling = await content(migration, contentSibling);
    const { admin, auth, catalog } = await seedOwner(migration, runtime);
    const context = await auth.establishTenantContext(admin.context);
    const siblingTenant = randomUUID();
    await migration.query('INSERT INTO secureshop_auth.tenants(tenant_id,slug) VALUES($1,$2)',
      [siblingTenant, `v03-peer-${siblingTenant}`]);
    // Synthetic database-only preservation fixtures. These do not claim a model, Judge, effect or credit run.
    for (const [tenant, enabledValue, revision] of [[context.tenantId, false, 7], [siblingTenant, true, 11]]) {
      await migration.query(`INSERT INTO secureshop_auth.assessment_configuration
        (tenant_id,objective_id,is_enabled,revision,updated_by) VALUES($1,$2,$3,$4,$5)`,
      [tenant, ID, enabledValue, revision, context.principalId]);
      await migration.query(`INSERT INTO secureshop_auth.assessment_configuration_history
        (tenant_id,objective_id,revision,is_enabled,principal_id,execution_session_id)
        VALUES($1,$2,$3,$4,$5,$6)`, [tenant, ID, revision, enabledValue, context.principalId, context.sessionId]);
    }
    const shopUserId = (await migration.query(
      'SELECT shop_user_id FROM secureshop_auth.principals WHERE principal_id=$1',
      [context.principalId])).rows[0].shop_user_id;
    const parentEvaluation = randomUUID(), childEvaluation = randomUUID();
    const judgments = [
      { evaluationId: parentEvaluation, verdict: 'pass', disposition: 'awarded' },
      { evaluationId: childEvaluation, verdict: 'fail', disposition: 'denied' },
    ];
    for (const judgment of judgments) {
      const result = JSON.stringify({ verdict: judgment.verdict,
        fixture: 'v03-catalog-seed-preservation', actualModel: false, actualJudge: false });
      await migration.query(`INSERT INTO secureshop_auth.assessment_judgments
        (tenant_id,principal_id,evaluation_id,shop_user_id,execution_json,objective_id,family,scenario,
         rubric_version,evidence_digest,run_id,generation,mode,mode_stamp,owner_key,owner_generation,
         verdict,disposition,result_json,result_digest,evaluated_at)
        VALUES($1,$2,$3,$4,$5::jsonb,$6,'SecureShop','v03-catalog-seed-preservation','fixture-only-v1',
         $7,$8,0,'vuln','v03-catalog-seed-preservation',$9,0,$10,$11,$12::jsonb,$13,clock_timestamp())`,
      [context.tenantId, context.principalId, judgment.evaluationId, shopUserId,
        JSON.stringify({ fixture: 'database-only-catalog-seed-preservation' }), ID,
        sha(`evidence:${judgment.evaluationId}`), randomUUID(), `fixture:${judgment.evaluationId}`,
        judgment.verdict, judgment.disposition, result, sha(result)]);
    }
    await migration.query(`INSERT INTO secureshop_auth.assessment_completions
      (tenant_id,principal_id,objective_id,generation,evaluation_id) VALUES($1,$2,$3,0,$4)`,
    [context.tenantId, context.principalId, ID, parentEvaluation]);
    await migration.query(`INSERT INTO secureshop_auth.assessment_contributions
      (tenant_id,principal_id,evaluation_id) VALUES($1,$2,$3)`,
    [context.tenantId, context.principalId, parentEvaluation]);
    await migration.query(`INSERT INTO secureshop_auth.assessment_retries
      (tenant_id,principal_id,parent_id,child_id) VALUES($1,$2,$3,$4)`,
    [context.tenantId, context.principalId, parentEvaluation, childEvaluation]);
    const original = await row(migration);
    const retained = await snapshot(migration);
    assert.equal(retained.assessment_judgments.length, 2);
    assert.equal(retained.assessment_completions.length, 1);
    assert.equal(retained.assessment_contributions.length, 1);
    assert.equal(retained.assessment_retries.length, 1);
    await seedSecureShopAssessmentDefaults(migration);
    assert.equal((await seedWorkshopPlatform(migration)).changed, false);
    assert.deepEqual(await row(runtime), { ...original, qualification: 'native-browser-judge',
      source_sha256: sha(CURRENT), source_document: JSON.parse(CURRENT) });
    const preservedContent = await content(runtime);
    assert.equal(preservedContent.label, originalContent.label);
    assert.deepEqual(preservedContent.hint_content, originalContent.hint_content);
    assert.deepEqual(preservedContent.solution_content, originalContent.solution_content);
    assert.equal(preservedContent.hint_enabled, false); assert.equal(preservedContent.solution_enabled, true);
    assert.deepEqual(await content(runtime, contentSibling), originalContentSibling);
    for (const field of ['label', 'hint_content', 'solution_content'])
      assert.equal((await defaults(runtime)).find(value => value.field_name === field)?.provenance_state, 'custom');
    const after = await snapshot(migration);
    for (const table of Object.keys(retained)
      .filter(key => !['assessment_objectives', 'catalog_field_defaults'].includes(key))) {
      assert.deepEqual(after[table], retained[table], table);
    }
    const expectedCustomTransitions = [
      { objectiveId: ID, field: 'label', observed: { present: true, value: 'Instructor-owned V03 lesson' } },
      { objectiveId: ID, field: 'hint_content', observed:
        { present: true, value: { hints: ['Retain this content'], title: 'Custom V03 hints' } } },
      { objectiveId: ID, field: 'solution_content', observed:
        { present: true, value: { examples: [], title: 'Custom V03 solution' } } },
      { objectiveId: contentSibling, field: 'label', observed:
        { present: true, value: 'Retained sibling lesson' } },
    ];
    const defaultKey = item => `${item.row.workshop_key}:${item.row.objective_id}:${item.row.field_name}`;
    const changedKeys = new Set(expectedCustomTransitions.map(item =>
      `${curriculum.WORKSHOP_KEY}:${item.objectiveId}:${item.field}`));
    assert.deepEqual(after.catalog_field_defaults.filter(item => !changedKeys.has(defaultKey(item))),
      retained.catalog_field_defaults.filter(item => !changedKeys.has(defaultKey(item))));
    for (const expectedTransition of expectedCustomTransitions) {
      const beforeDefault = retained.catalog_field_defaults.find(item =>
        item.row.objective_id === expectedTransition.objectiveId
          && item.row.field_name === expectedTransition.field)?.row;
      const afterDefault = after.catalog_field_defaults.find(item =>
        item.row.objective_id === expectedTransition.objectiveId
          && item.row.field_name === expectedTransition.field)?.row;
      assert.ok(beforeDefault); assert.ok(afterDefault);
      assert.deepEqual(afterDefault.observed_document, expectedTransition.observed);
      assert.deepEqual({ ...afterDefault, provenance_state: beforeDefault.provenance_state,
        observed_document: beforeDefault.observed_document, updated_at: beforeDefault.updated_at }, beforeDefault);
      assert.equal(beforeDefault.provenance_state, 'managed');
      assert.equal(afterDefault.provenance_state, 'custom');
    }
    assert.equal(after.assessment_configuration.length, 2);
    assert.equal(after.assessment_configuration_history.length, 2);
    for (const table of ['assessment_judgments', 'assessment_completions',
      'assessment_contributions', 'assessment_retries']) assert.deepEqual(after[table], retained[table], table);
    const siblings = after.assessment_objectives.filter(item => item.row.objective_id !== ID);
    assert.equal(siblings.length, OBJECTIVES.length);
    assert.deepEqual(siblings.filter(item => item.row.objective_id === 'ss_v03_seed_sibling'),
      retained.assessment_objectives.filter(item => item.row.objective_id === 'ss_v03_seed_sibling'));
    assert.deepEqual(await seedSecureShopAssessmentDefaults(migration), { inserted: 0 });
    assert.deepEqual(await snapshot(migration), after);

    // Each variant is a representative populated installation, not a fallback
    // match. Both original digest and original JSONB must agree.
    const variants = [
      { configuration_source: 'instructor' },
      { source_sha256: 'f'.repeat(64) },
      { source_document: { ...JSON.parse(PREDECESSOR), label: 'Custom default' } },
      { qualification: 'native-model' },
      { source_document: { ...JSON.parse(PREDECESSOR), extra: true } },
    ];
    for (const override of variants) {
      const fixture = { qualification: 'pending', configuration_source: 'checked_in_default',
        source_sha256: OLD_SHA, source_document: JSON.parse(PREDECESSOR), ...override };
      await migration.query(`UPDATE secureshop_auth.assessment_objectives SET qualification=$2,
        configuration_source=$3,source_sha256=$4,source_document=$5::jsonb WHERE objective_id=$1`,
      [ID, fixture.qualification, fixture.configuration_source, fixture.source_sha256, JSON.stringify(fixture.source_document)]);
      const before = await snapshot(migration);
      await seedSecureShopAssessmentDefaults(migration);
      await seedSecureShopAssessmentDefaults(migration);
      assert.deepEqual(await snapshot(migration), before, JSON.stringify(override));
    }

    // Exercise the actual current administrator path: old pending cannot be
    // enabled, the recognized transition permits it, and sibling state stays put.
    await migration.query(`UPDATE secureshop_auth.assessment_objectives SET qualification='pending',
      configuration_source='checked_in_default',source_sha256=$2,source_document=$3::jsonb,
      catalog_active=true WHERE objective_id=$1`, [ID, OLD_SHA, PREDECESSOR]);
    const beforeAdmin = await snapshot(migration);
    await assert.rejects(catalog.set(admin.context,
      { objectiveId: ID, enabled: true, expectedRevision: '7' }), { code: 'SHOP_OBJECTIVE_UNQUALIFIED' });
    assert.deepEqual(await snapshot(migration), beforeAdmin);
    await seedSecureShopAssessmentDefaults(migration);
    assert.deepEqual(await catalog.set(admin.context,
      { objectiveId: ID, enabled: true, expectedRevision: '7' }),
    { objectiveId: ID, enabled: true, qualification: 'native-browser-judge', revision: '8' });
    const completed = await snapshot(migration);
    assert.deepEqual(completed.assessment_configuration.filter(item => item.row.tenant_id === siblingTenant),
      retained.assessment_configuration.filter(item => item.row.tenant_id === siblingTenant));
    assert.deepEqual(completed.assessment_configuration_history.filter(item => item.row.tenant_id === siblingTenant),
      retained.assessment_configuration_history.filter(item => item.row.tenant_id === siblingTenant));
    for (const table of ['assessment_judgments', 'assessment_completions', 'assessment_contributions', 'assessment_retries']) {
      assert.deepEqual(completed[table], retained[table], table);
    }
    assert.deepEqual(completed.assessment_objectives.filter(item => item.row.objective_id !== ID), siblings);
    assert.deepEqual(await seedSecureShopAssessmentDefaults(migration), { inserted: 0 });
    assert.equal((await seedWorkshopPlatform(migration)).changed, false);
    assert.deepEqual(await snapshot(migration), completed);
    assert.deepEqual(await migrate(migration, DIRECTORY), []);
    assert.deepEqual((await migration.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows, manifest);
  });
