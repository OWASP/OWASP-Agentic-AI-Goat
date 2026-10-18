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
const { seedSecureShopStandaloneDefaults } = require('../../server/database/postgres/secureshopStandaloneSeed');
const { createSecureShopStandaloneAuthRepository } = require('../../server/database/postgres/secureshopStandaloneAuthRepository');
const { createSecureShopStandaloneAuthService } = require('../../server/services/secureshopStandaloneAuth');
const { createSecureShopAssessmentCatalog } = require('../../server/services/secureshopAssessmentCatalog');
const { OBJECTIVES } = require('../../server/config/secureshopCurriculum');

const PREFIX = 'PG_SECURESHOP_ORDER_STATUS_SEED_';
const ID = 'ss_sqli_error_based';
const DIRECTORY = path.resolve(__dirname, '../../db/postgres/identity-migrations');
const PREDECESSOR = JSON.stringify({ version: 1, id: ID,
  label: 'Observe a protected synthetic value in an order-status query error',
  defaultEnabled: false, qualification: 'pending' });
// Original checked-in source bytes, independent of the seed implementation.
const OLD_SHA = 'aafa7e694d22008db16794c7a87418cf79186cedcf21bb0ed42b0d67ee144c0f';
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
async function snapshot(pool) {
  const tables = ['assessment_objectives', 'assessment_configuration', 'assessment_configuration_history',
    'assessment_judgments', 'assessment_completions', 'assessment_contributions', 'assessment_retries'];
  return Object.fromEntries(await Promise.all(tables.map(async table => [table,
    (await pool.query(`SELECT to_jsonb(t) AS row FROM secureshop_auth.${table} t ORDER BY to_jsonb(t)::text`)).rows])));
}
async function seedOwner(migration, runtime) {
  await seedSecureShopStandaloneDefaults(migration, { hashPassword: value => bcrypt.hash(value, 4) });
  const auth = createSecureShopStandaloneAuthService({ repository:
    createSecureShopStandaloneAuthRepository({ pool: runtime }) });
  const admin = await auth.login({ username: 'student_admin', password: 'student123' });
  return { admin, auth, catalog: createSecureShopAssessmentCatalog({ pool: runtime, authService: auth }) };
}

test('native fresh order-status seed is qualified but disabled and exact second seed is a no-op',
  { skip: !enabled, timeout: 120000 }, async t => {
    assert.equal(sha(PREDECESSOR), OLD_SHA);
    assert.equal(expected.qualification, 'native-model');
    assert.equal(expected.defaultEnabled, false);
    const { migration, runtime, manifest } = await open('FRESH', t);
    assert.deepEqual(await seedSecureShopAssessmentDefaults(migration), { inserted: OBJECTIVES.length });
    const actual = await row(runtime);
    assert.equal(actual.qualification, 'native-model'); assert.equal(actual.is_enabled, false);
    assert.equal(actual.catalog_active, true); assert.equal(actual.configuration_source, 'checked_in_default');
    assert.equal(actual.source_sha256, sha(CURRENT));
    assert.deepEqual(actual.source_document, JSON.parse(CURRENT));
    const before = await snapshot(migration);
    assert.deepEqual(await seedSecureShopAssessmentDefaults(migration), { inserted: 0 });
    assert.deepEqual(await snapshot(migration), before);
    assert.deepEqual(await migrate(migration, DIRECTORY), []);
    assert.deepEqual((await migration.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows, manifest);
  });

test('native populated order-status seed preserves instructor and sibling configuration and admits only exact old provenance',
  { skip: !enabled, timeout: 120000 }, async t => {
    const { migration, runtime, manifest } = await open('POPULATED', t);
    await migration.query(`INSERT INTO secureshop_auth.assessment_objectives
      (objective_id,label,is_enabled,catalog_active,qualification,source_sha256,source_document,updated_at)
      VALUES($1,'Retained instructor label',true,false,'pending',$2,$3::jsonb,'2026-01-01T00:00:00Z')`,
    [ID, OLD_SHA, PREDECESSOR]);
    const siblingSource = JSON.stringify({ version: 1, id: 'ss_order_status_seed_sibling', label: 'Retained sibling source' });
    await migration.query(`INSERT INTO secureshop_auth.assessment_objectives
      (objective_id,label,is_enabled,catalog_active,qualification,source_sha256,source_document,configuration_source)
      VALUES('ss_order_status_seed_sibling','Retained sibling label',true,false,'pending',$1,$2::jsonb,'instructor')`,
    [sha(siblingSource), siblingSource]);
    const { admin, auth, catalog } = await seedOwner(migration, runtime);
    const context = await auth.establishTenantContext(admin.context);
    const siblingTenant = randomUUID();
    await migration.query('INSERT INTO secureshop_auth.tenants(tenant_id,slug) VALUES($1,$2)',
      [siblingTenant, `order-status-peer-${siblingTenant}`]);
    // Synthetic configuration fixtures only; no judgment, completion or contribution is inserted.
    for (const [tenant, enabledValue, revision] of [[context.tenantId, false, 7], [siblingTenant, true, 11]]) {
      await migration.query(`INSERT INTO secureshop_auth.assessment_configuration
        (tenant_id,objective_id,is_enabled,revision,updated_by) VALUES($1,$2,$3,$4,$5)`,
      [tenant, ID, enabledValue, revision, context.principalId]);
      await migration.query(`INSERT INTO secureshop_auth.assessment_configuration_history
        (tenant_id,objective_id,revision,is_enabled,principal_id,execution_session_id)
        VALUES($1,$2,$3,$4,$5,$6)`, [tenant, ID, revision, enabledValue, context.principalId, context.sessionId]);
    }
    const original = await row(migration);
    const retained = await snapshot(migration);
    await seedSecureShopAssessmentDefaults(migration);
    assert.deepEqual(await row(runtime), { ...original, qualification: 'native-model',
      source_sha256: sha(CURRENT), source_document: JSON.parse(CURRENT) });
    const after = await snapshot(migration);
    for (const table of Object.keys(retained).filter(key => key !== 'assessment_objectives')) {
      assert.deepEqual(after[table], retained[table], table);
    }
    assert.equal(after.assessment_configuration.length, 2);
    assert.equal(after.assessment_configuration_history.length, 2);
    assert.equal(after.assessment_judgments.length, 0);
    const siblings = after.assessment_objectives.filter(item => item.row.objective_id !== ID);
    assert.equal(siblings.length, OBJECTIVES.length);
    assert.deepEqual(siblings.filter(item => item.row.objective_id === 'ss_order_status_seed_sibling'),
      retained.assessment_objectives.filter(item => item.row.objective_id === 'ss_order_status_seed_sibling'));
    assert.deepEqual(await seedSecureShopAssessmentDefaults(migration), { inserted: 0 });
    assert.deepEqual(await snapshot(migration), after);

    // Each variant is a representative populated installation, not a fallback
    // match. Both original digest and original JSONB must agree.
    const variants = [
      { configuration_source: 'instructor' },
      { source_sha256: 'f'.repeat(64) },
      { source_document: { ...JSON.parse(PREDECESSOR), label: 'Custom default' } },
      { qualification: 'native-browser-judge' },
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
    { objectiveId: ID, enabled: true, qualification: 'native-model', revision: '8' });
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
    assert.deepEqual(await snapshot(migration), completed);
    assert.deepEqual(await migrate(migration, DIRECTORY), []);
    assert.deepEqual((await migration.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows, manifest);
  });
