'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const { Module, createRequire } = require('node:module');
const { randomUUID } = require('node:crypto');
const { Pool } = require('pg');
const { migrate } = require('../../db/postgres/migrate');
const { seedSecureShop } = require('../../server/database/postgres/secureshopSeed');
const { seedSecureShopStandaloneDefaults } = require('../../server/database/postgres/secureshopStandaloneSeed');
const { createSecureShopStandaloneAuthRepository } = require('../../server/database/postgres/secureshopStandaloneAuthRepository');
const { createSecureShopStandaloneAuthService } = require('../../server/services/secureshopStandaloneAuth');
const { createSecureShopLaunchRepository } = require('../../server/database/postgres/secureshopLaunchRepository');
const { createSecureShopSceneRepository } = require('../../server/database/postgres/secureshopSceneRepository');
const { createSecureShopScenes } = require('../../server/services/secureshopScenes');
const { createSecureShopBoundProductRepository } = require('../../server/database/postgres/secureshopBoundProductRepository');
const { createSecureShopBoundCatalog } = require('../../server/services/secureshopBoundCatalog');
const { createSecureShopPracticeAdmissionRepository } = require('../../server/database/postgres/secureshopPracticeAdmissionRepository');
const { createSecureShopPracticeAdmission } = require('../../server/services/secureshopPracticeAdmission');

const ROOT = path.resolve(__dirname, '../..');
const PREFIX = 'PG_SECURESHOP_PRACTICE_';
const STORES = { IDENTITY: 'identity', REVIEW: 'secureshop_review',
  AGENTS: 'secureshop_agents', COMMERCE: 'secureshop' };
const SCOPE = 'Disposable four-store explicit shop practice admission, historical migration and exact recovery; controlled PostgreSQL only';
const FLAGS = ['freshMigration', 'populatedMigrationPreserved', 'secondRunNoop',
  'freshPreferenceInitialized', 'realCatalogPublication', 'immutableHistory',
  'exactRecovery', 'crossStoreDebtRecovered', 'preferenceCasRetainsDebt',
  'revokedExecutionDenied', 'siblingIsolation', 'capacityPreclaimRollback'];
const enabled = process.env.SECURESHOP_PRACTICE_ADMISSION_NATIVE === '1'
  && process.env.PG_TEST_DISPOSABLE === 'yes'
  && Object.keys(STORES).every(store => ['RUNTIME', 'MIGRATION'].every(role =>
    process.env[`${PREFIX}${store}_${role}_URL`]));
const dir = store => path.join(ROOT, 'db/postgres', store === 'IDENTITY'
  ? 'identity-migrations' : `workshop-migrations/${STORES[store]}`);

function url(store, role) {
  const value = new URL(process.env[`${PREFIX}${store}_${role}_URL`]);
  assert.equal(value.protocol, 'postgresql:');
  assert.equal(value.hostname, '127.0.0.1');
  assert.match(value.pathname, /^\/owasp_ai_goat_test_[a-z0-9_]+$/);
  assert.equal(value.username, `dvaia_${STORES[store]}_${role.toLowerCase()}`);
  assert.equal(value.password, ''); assert.equal(value.search, ''); assert.equal(value.hash, '');
  return value.href;
}

// Read an exact historical migration prefix without changing tracked SQL or the loader.
function historical(directory, ceiling) {
  const filename = require.resolve('../../db/postgres/migrate');
  const local = createRequire(filename), loaded = new Module(filename, module);
  loaded.filename = filename;
  const original = require('node:fs/promises');
  loaded.require = name => name === 'node:fs/promises' ? {
    ...original, async readdir(selected, ...args) {
      const names = await original.readdir(selected, ...args);
      return path.resolve(selected) === directory
        ? names.filter(name => !/^\d{4}_.*\.sql$/.test(name) || Number(name.slice(0, 4)) <= ceiling) : names;
    },
  } : local(name);
  loaded._compile(require('node:fs').readFileSync(filename, 'utf8'), filename);
  return loaded.exports.migrate;
}

async function count(pool, sql, args = []) {
  return Number((await pool.query(sql, args)).rows[0].n);
}

test('explicit shop practice admission preserves current authority, immutable history and recoverable debt',
  { skip: !enabled, timeout: 240000 }, async t => {
    assert.equal(process.cwd(), ROOT);
    assert.equal(path.resolve(process.env.OWASP_AI_GOAT_CURRENT_MAIN_WORKSPACE || '/'), ROOT);
    const evidence = process.env.SECURESHOP_PRACTICE_ADMISSION_EVIDENCE_PATH || '';
    assert.ok(path.isAbsolute(evidence));
    assert.ok(!path.resolve(evidence).startsWith(`${ROOT}${path.sep}`));
    const status = Object.fromEntries(FLAGS.map(flag => [flag, false]));
    const pools = Object.fromEntries(Object.keys(STORES).flatMap(store =>
      ['RUNTIME', 'MIGRATION'].map(role => [`${store}_${role}`, new Pool({
        connectionString: url(store, role), max: role === 'RUNTIME' ? 8 : 2,
        statement_timeout: 20000, lock_timeout: 5000,
      })])));
    let phase = 'admission', failure, cleanupComplete = false;
    try {
      for (const store of Object.keys(STORES)) {
        const runtime = new URL(url(store, 'RUNTIME')), migration = new URL(url(store, 'MIGRATION'));
        assert.equal(runtime.pathname, migration.pathname); assert.equal(runtime.port, migration.port);
      }
      assert.equal(new Set(Object.keys(STORES).map(store => new URL(url(store, 'RUNTIME')).pathname)).size, 4);
      assert.equal(new Set(Object.keys(STORES).map(store => new URL(url(store, 'RUNTIME')).port)).size, 1);
      const identity = pools.IDENTITY_RUNTIME, identityMigration = pools.IDENTITY_MIGRATION;
      const review = pools.REVIEW_RUNTIME, commerce = pools.COMMERCE_RUNTIME;
      phase = 'historical-prefix';
      await historical(dir('IDENTITY'), 149)(identityMigration, dir('IDENTITY'));
      for (const store of ['REVIEW', 'AGENTS', 'COMMERCE']) await migrate(pools[`${store}_MIGRATION`], dir(store));
      const preview = await identityMigration.connect();
      try {
        await preview.query('BEGIN');
        await preview.query(await fs.readFile(path.join(dir('IDENTITY'), '0150_secureshop_practice_admission.sql'), 'utf8'));
        for (const table of ['practice_preferences', 'practice_selections', 'practice_operations', 'practice_publications']) {
          assert.equal(await count(preview, `SELECT count(*)::int n FROM secureshop_auth.${table}`), 0);
        }
        await preview.query('ROLLBACK');
      } catch (error) { await preview.query('ROLLBACK').catch(() => {}); throw error; }
      finally { preview.release(); }
      assert.equal((await identityMigration.query("SELECT to_regclass('secureshop_auth.practice_operations') AS name")).rows[0].name, null);
      status.freshMigration = true;

      phase = 'historical-population';
      const seedClient = await pools.COMMERCE_MIGRATION.connect();
      try { await seedClient.query('BEGIN'); await seedSecureShop(seedClient); await seedClient.query('COMMIT'); }
      catch (error) { await seedClient.query('ROLLBACK').catch(() => {}); throw error; }
      finally { seedClient.release(); }
      await seedSecureShopStandaloneDefaults(identityMigration, { hashPassword: value => require('bcryptjs').hash(value, 4) });
      const authRepository = createSecureShopStandaloneAuthRepository({ pool: identity });
      const auth = createSecureShopStandaloneAuthService({ repository: authRepository,
        hashPassword: value => require('bcryptjs').hash(value, 4) });
      const suffix = randomUUID().slice(0, 8), password = 'disposable practice admission';
      const first = await auth.register({ username: `practice_${suffix}`, email: `practice_${suffix}@example.invalid`,
        password, role: 'customer' });
      const tenant = (await identity.query("SELECT tenant_id,owner_id,seed_merchant_id FROM secureshop_auth.tenants WHERE slug='default'")).rows[0];
      assert.ok(tenant.seed_merchant_id);
      const member = (await identity.query(`SELECT membership_version FROM secureshop_auth.tenant_memberships
        WHERE tenant_id=$1 AND principal_id=$2`, [tenant.tenant_id, first.context.principalId])).rows[0];
      const historicalExecution = (await identityMigration.query(`INSERT INTO secureshop_auth.execution_sessions
        (auth_session_id,tenant_id,principal_id,membership_version,expires_at)
        VALUES($1,$2,$3,$4,$5) RETURNING session_id`, [first.context.sessionId, tenant.tenant_id,
        first.context.principalId, member.membership_version, first.context.expiresAt])).rows[0].session_id;
      const launches = createSecureShopLaunchRepository(identity);
      const historicalLaunch = (await launches.issueOrRenew({ platformOwnerId: Number(tenant.owner_id),
        platformSessionId: historicalExecution, expiresAt: first.context.expiresAt })).binding;
      const products = createSecureShopBoundProductRepository(review, {
        checkCurrent: scope => launches.assertCurrent(scope),
        checkCleanup: async () => { throw Error('Canonical reset authority required'); },
      });
      const catalog = createSecureShopBoundCatalog({ sourcePool: commerce, repository: products,
        checkCurrent: scope => launches.assertCurrent(scope),
        resolveTarget: scope => launches.reserveProductsTarget({ ...scope, expectedGeneration: scope.generation }),
        ownMerchantId: Number(tenant.seed_merchant_id) });
      const birth = await catalog.prepareTarget({ scope: historicalLaunch, persona: { id: 11, role: 'customer' } });
      assert.ok(await products.open(birth));
      const originalScene = randomUUID();
      await identityMigration.query(`INSERT INTO identity.secureshop_scenes
        (scene_id,original_platform_owner_id,product_target_id,birth_launch_id,birth_scenario_id,
         birth_generation,birth_platform_session_id,is_default)
        VALUES($1,$2,$3,$4,$5,$6,$7,true)`, [originalScene, historicalLaunch.platformOwnerId,
        birth.targetId, birth.launchId, birth.scenarioId, birth.generation, birth.platformSessionId]);
      const second = await auth.login({ username: `practice_${suffix}`, password });
      await identityMigration.query(`INSERT INTO secureshop_auth.execution_sessions
        (auth_session_id,tenant_id,principal_id,membership_version,expires_at)
        VALUES($1,$2,$3,$4,$5)`, [second.context.sessionId, tenant.tenant_id,
        second.context.principalId, member.membership_version, second.context.expiresAt]);
      const oldScene = (await identity.query('SELECT * FROM identity.secureshop_scenes WHERE scene_id=$1', [originalScene])).rows[0];
      const oldProductCount = await count(review, 'SELECT count(*)::int n FROM secureshop_review.product_targets WHERE target_id=$1', [birth.targetId]);
      phase = 'populated-migration';
      assert.ok((await migrate(identityMigration, dir('IDENTITY'))).includes('0150_secureshop_practice_admission.sql'));
      const selections = (await identity.query(`SELECT auth_session_id,scene_id FROM secureshop_auth.practice_selections
        WHERE principal_id=$1 ORDER BY auth_session_id`, [first.context.principalId])).rows;
      assert.equal(selections.length, 2);
      assert.ok(selections.every(row => row.scene_id === originalScene));
      assert.equal((await identity.query(`SELECT scene_id FROM secureshop_auth.practice_preferences
        WHERE tenant_id=$1 AND principal_id=$2`, [tenant.tenant_id, first.context.principalId])).rows[0].scene_id, originalScene);
      assert.deepEqual((await identity.query('SELECT * FROM identity.secureshop_scenes WHERE scene_id=$1', [originalScene])).rows[0], oldScene);
      assert.equal(await count(review, 'SELECT count(*)::int n FROM secureshop_review.product_targets WHERE target_id=$1', [birth.targetId]), oldProductCount);
      status.populatedMigrationPreserved = true;
      assert.deepEqual(await migrate(identityMigration, dir('IDENTITY')), []);
      assert.equal((await identityMigration.query(`SELECT count(*)::int n FROM dvaia_migrations.ledger
        WHERE name='0150_secureshop_practice_admission.sql'`)).rows[0].n, 1);
      status.secondRunNoop = true;

      // This account did not exist at migration time: bootstrap must create its
      // caller preference and selected execution in the first auth transaction.
      const fresh = await auth.register({ username: `fresh_${suffix}`,
        email: `fresh_${suffix}@example.invalid`, password, role: 'customer' });
      assert.equal(await count(identity, `SELECT count(*)::int n FROM secureshop_auth.practice_preferences
        WHERE tenant_id=$1 AND principal_id=$2`, [tenant.tenant_id, fresh.context.principalId]), 0);
      const freshExecution = await auth.establishTenantContext(fresh.context);
      const freshPreference = (await identity.query(`SELECT scene_id,revision FROM secureshop_auth.practice_preferences
        WHERE tenant_id=$1 AND principal_id=$2`, [tenant.tenant_id, fresh.context.principalId])).rows[0];
      const freshSelection = (await identity.query(`SELECT scene_id,execution_session_id,revision
        FROM secureshop_auth.practice_selections WHERE auth_session_id=$1 AND tenant_id=$2`,
      [fresh.context.sessionId, tenant.tenant_id])).rows[0];
      assert.equal(freshPreference.scene_id, originalScene);
      assert.equal(freshSelection.scene_id, originalScene);
      assert.equal(Number(freshSelection.execution_session_id), freshExecution.sessionId);
      assert.equal(Number(freshPreference.revision), 1);
      assert.equal(Number(freshSelection.revision), 1);
      status.freshPreferenceInitialized = true;

      phase = 'current-auth-and-publication';
      const current = await auth.login({ username: `practice_${suffix}`, password });
      const execution = await auth.establishTenantContext(current.context);
      const issued = await launches.issueOrRenew({ platformOwnerId: execution.ownerId,
        platformSessionId: execution.sessionId, expiresAt: execution.expiresAt, shopPrincipal: execution });
      const scenes = createSecureShopScenes({ repository: createSecureShopSceneRepository({ pool: identity, launches }),
        reviewPool: review, launches });
      const available = await scenes.list(issued.binding);
      assert.equal(available.find(scene => scene.isDefault)?.id, originalScene);
      const selected = await scenes.resolve(issued.binding);
      assert.equal(selected.scene.sceneId, originalScene);
      assert.equal(await count(review, `SELECT count(*)::int n FROM secureshop_review.scene_execution_grants
        WHERE scene_id=$1 AND launch_id=$2`, [originalScene, issued.binding.launchId]), 1);
      assert.equal((await identity.query(`SELECT scene_id FROM secureshop_auth.practice_preferences
        WHERE tenant_id=$1 AND principal_id=$2`, [execution.tenantId, execution.principalId])).rows[0].scene_id, originalScene);
      const repository = createSecureShopPracticeAdmissionRepository({ pool: identity });
      const practice = createSecureShopPracticeAdmission({ repository, catalog });
      const publishedId = randomUUID();
      assert.deepEqual(await practice.read(current.context, publishedId),
        { operationId: publishedId, status: 'unconfirmed', sceneId: null, canResume: false });
      const published = await practice.create(current.context, publishedId);
      assert.equal(published.status, 'published'); assert.ok(published.sceneId);
      assert.notEqual(published.sceneId, originalScene);
      const operation = (await identity.query('SELECT * FROM secureshop_auth.practice_operations WHERE operation_id=$1', [publishedId])).rows[0];
      const publication = (await identity.query('SELECT * FROM secureshop_auth.practice_publications WHERE operation_id=$1', [publishedId])).rows[0];
      assert.equal(operation.scene_id, published.sceneId);
      assert.equal(publication.scene_id, published.sceneId);
      assert.equal((await identity.query('SELECT product_target_id FROM identity.secureshop_scenes WHERE scene_id=$1', [published.sceneId])).rows[0].product_target_id, operation.target_id);
      assert.equal((await products.open({ targetId: operation.target_id, launchId: operation.launch_id,
        scenarioId: operation.scenario_id, generation: Number(operation.generation),
        platformOwnerId: Number(operation.owner_id), platformSessionId: Number(operation.execution_session_id) })).targetId,
      operation.target_id);
      status.realCatalogPublication = true;
      assert.deepEqual(await practice.create(current.context, publishedId), published);
      assert.deepEqual(await practice.read(current.context, publishedId), published);
      status.exactRecovery = true;
      for (const sql of [
        'UPDATE secureshop_auth.practice_operations SET scene_id=scene_id WHERE operation_id=$1',
        'DELETE FROM secureshop_auth.practice_operations WHERE operation_id=$1',
        'UPDATE secureshop_auth.practice_publications SET scene_id=scene_id WHERE operation_id=$1',
        'DELETE FROM secureshop_auth.practice_publications WHERE operation_id=$1',
      ]) await assert.rejects(identityMigration.query(sql, [publishedId]), error => error?.code === '55000');
      assert.deepEqual((await identity.query('SELECT * FROM secureshop_auth.practice_operations WHERE operation_id=$1', [publishedId])).rows[0], operation);
      assert.deepEqual((await identity.query('SELECT * FROM secureshop_auth.practice_publications WHERE operation_id=$1', [publishedId])).rows[0], publication);
      status.immutableHistory = true;

      phase = 'cross-store-debt';
      // This failure is injected after the real review-store write, before identity publication.
      const nextExecution = await auth.establishTenantContext(current.context);
      const nextLaunch = (await launches.issueOrRenew({ platformOwnerId: nextExecution.ownerId,
        platformSessionId: nextExecution.sessionId, expiresAt: nextExecution.expiresAt,
        shopPrincipal: nextExecution })).binding;
      const debtId = randomUUID();
      assert.equal((await repository.admit(current.context, debtId)).status, 'pending');
      await assert.rejects(repository.publish(current.context, debtId, async claim => {
        await catalog.provisionPracticeTarget(claim);
        throw Error('simulated lost cross-store publication response');
      }), /simulated lost cross-store publication response/);
      const debt = (await identity.query('SELECT * FROM secureshop_auth.practice_operations WHERE operation_id=$1', [debtId])).rows[0];
      assert.equal(await count(review, 'SELECT count(*)::int n FROM secureshop_review.product_targets WHERE target_id=$1', [debt.target_id]), 1);
      assert.equal(await count(identity, 'SELECT count(*)::int n FROM secureshop_auth.practice_publications WHERE operation_id=$1', [debtId]), 0);
      assert.equal((await practice.read(current.context, debtId)).status, 'pending');
      const recovered = await practice.create(current.context, debtId);
      assert.equal(recovered.status, 'published');
      assert.equal(recovered.sceneId, debt.scene_id);
      assert.equal(await count(review, 'SELECT count(*)::int n FROM secureshop_review.product_targets WHERE target_id=$1', [debt.target_id]), 1);
      assert.equal(nextLaunch.platformSessionId, debt.source_execution_id);
      status.crossStoreDebtRecovered = true;

      phase = 'selection-cas';
      const casExecution = await auth.establishTenantContext(current.context);
      const casLaunch = (await launches.issueOrRenew({ platformOwnerId: casExecution.ownerId,
        platformSessionId: casExecution.sessionId, expiresAt: casExecution.expiresAt,
        shopPrincipal: casExecution })).binding;
      assert.equal(casLaunch.platformSessionId, casExecution.sessionId);
      const casId = randomUUID();
      assert.equal((await repository.admit(current.context, casId)).status, 'pending');
      const capturedSelection = (await identity.query(`SELECT scene_id,revision FROM secureshop_auth.practice_selections
        WHERE auth_session_id=$1 AND tenant_id=$2`, [current.context.sessionId, casExecution.tenantId])).rows[0];
      const chooser = await auth.login({ username: `practice_${suffix}`, password });
      const chooserExecution = await auth.establishTenantContext(chooser.context);
      const chooserLaunch = (await launches.issueOrRenew({ platformOwnerId: chooserExecution.ownerId,
        platformSessionId: chooserExecution.sessionId, expiresAt: chooserExecution.expiresAt,
        shopPrincipal: chooserExecution })).binding;
      await scenes.select(chooserLaunch, originalScene);
      assert.deepEqual((await identity.query(`SELECT scene_id,revision FROM secureshop_auth.practice_selections
        WHERE auth_session_id=$1 AND tenant_id=$2`, [current.context.sessionId, casExecution.tenantId])).rows[0], capturedSelection);
      const preference = (await identity.query(`SELECT scene_id,revision FROM secureshop_auth.practice_preferences
        WHERE tenant_id=$1 AND principal_id=$2`, [casExecution.tenantId, casExecution.principalId])).rows[0];
      assert.equal(preference.scene_id, originalScene);
      assert.equal((await practice.create(current.context, casId)).status, 'retained_unfinished');
      assert.equal(await count(identity, 'SELECT count(*)::int n FROM secureshop_auth.practice_publications WHERE operation_id=$1', [casId]), 0);
      assert.equal((await identity.query(`SELECT scene_id,revision FROM secureshop_auth.practice_preferences
        WHERE tenant_id=$1 AND principal_id=$2`, [casExecution.tenantId, casExecution.principalId])).rows[0].revision, preference.revision);
      status.preferenceCasRetainsDebt = true;

      phase = 'renewal-and-sibling';
      const revokedSource = await auth.login({ username: `practice_${suffix}`, password });
      const revokedExecution = await auth.establishTenantContext(revokedSource.context);
      await launches.issueOrRenew({ platformOwnerId: revokedExecution.ownerId,
        platformSessionId: revokedExecution.sessionId, expiresAt: revokedExecution.expiresAt,
        shopPrincipal: revokedExecution });
      const revokedId = randomUUID();
      assert.equal((await repository.admit(revokedSource.context, revokedId)).status, 'pending');
      assert.equal(await auth.logout(revokedSource.token), true);
      const replacement = await auth.login({ username: `practice_${suffix}`, password });
      assert.equal((await practice.read(replacement.context, revokedId)).status, 'retained_unfinished');
      assert.equal((await practice.create(replacement.context, revokedId)).status, 'retained_unfinished');
      assert.equal((await practice.read(replacement.context, publishedId)).status, 'published');
      assert.equal(await count(identity, 'SELECT count(*)::int n FROM secureshop_auth.practice_publications WHERE operation_id=$1', [revokedId]), 0);

      const sibling = await auth.register({ username: `sibling_${suffix}`, email: `sibling_${suffix}@example.invalid`,
        password, role: 'customer' });
      const siblingSlug = `other_${suffix}`, siblingTenantId = randomUUID();
      await identityMigration.query('INSERT INTO secureshop_auth.tenants(tenant_id,slug) VALUES($1,$2)', [siblingTenantId, siblingSlug]);
      await identityMigration.query(`INSERT INTO secureshop_auth.tenant_memberships
        (tenant_id,principal_id,shop_user_id,role) VALUES($1,$2,$3,'customer')`,
      [siblingTenantId, sibling.context.principalId, sibling.context.shopUserId]);
      const otherAuth = createSecureShopStandaloneAuthService({
        repository: createSecureShopStandaloneAuthRepository({ pool: identity, executionTenantSlug: siblingSlug }),
        hashPassword: value => require('bcryptjs').hash(value, 4),
      });
      const otherLogin = await otherAuth.login({ username: `sibling_${suffix}`, password });
      const otherPractice = createSecureShopPracticeAdmission({
        repository: createSecureShopPracticeAdmissionRepository({ pool: identity, tenantSlug: siblingSlug }), catalog,
      });
      await assert.rejects(otherPractice.read(otherLogin.context, publishedId),
        error => error?.code === 'SHOP_PRACTICE_CONFLICT');
      const otherExecution = await otherAuth.establishTenantContext(otherLogin.context);
      const otherLaunch = (await launches.issueOrRenew({ platformOwnerId: otherExecution.ownerId,
        platformSessionId: otherExecution.sessionId, expiresAt: otherExecution.expiresAt,
        shopPrincipal: otherExecution })).binding;
      await assert.rejects(scenes.select(otherLaunch, originalScene), error => error?.code === 'SHOP_SCENE_STALE');
      assert.equal(await count(identity, 'SELECT count(*)::int n FROM identity.secureshop_scenes WHERE original_platform_owner_id=$1', [otherExecution.ownerId]), 0);
      status.siblingIsolation = true;

      phase = 'reset-source-fence';
      const resetBase = await auth.login({ username: `practice_${suffix}`, password });
      const resetExecution = await auth.establishTenantContext(resetBase.context);
      const resetLaunch = (await launches.issueOrRenew({ platformOwnerId: resetExecution.ownerId,
        platformSessionId: resetExecution.sessionId, expiresAt: resetExecution.expiresAt,
        shopPrincipal: resetExecution })).binding;
      // Select a surviving sibling practice; resetting this source must not retire
      // the original scene used by the independent capacity assertion below.
      await scenes.select(resetLaunch, published.sceneId);
      const resetId = randomUUID();
      assert.equal((await repository.admit(resetBase.context, resetId)).status, 'pending');
      await launches.beginReset({ launchId: resetLaunch.launchId,
        platformSessionId: resetLaunch.platformSessionId, platformOwnerId: resetLaunch.platformOwnerId,
        expectedGeneration: resetLaunch.generation, idempotencyKey: randomUUID() });
      assert.equal((await practice.read(resetBase.context, resetId)).status, 'retained_unfinished');
      assert.equal((await practice.create(resetBase.context, resetId)).status, 'retained_unfinished');
      assert.equal(await count(identity, 'SELECT count(*)::int n FROM secureshop_auth.practice_publications WHERE operation_id=$1', [resetId]), 0);
      status.revokedExecutionDenied = true;

      phase = 'capacity-preclaim';
      const capacityExecution = await auth.establishTenantContext(replacement.context);
      await launches.issueOrRenew({ platformOwnerId: capacityExecution.ownerId,
        platformSessionId: capacityExecution.sessionId, expiresAt: capacityExecution.expiresAt,
        shopPrincipal: capacityExecution });
      const capacityCount = () => count(identity, `SELECT count(*)::int n FROM identity.secureshop_launches
        WHERE original_platform_owner_id=$1 AND identity.secureshop_launch_consumes_capacity(launch_id)`,
      [capacityExecution.ownerId]);
      // Each filler is a genuinely enrolled, live tenant execution and launch;
      // no forged capacity rows or application database are involved.
      const beforeCapacity = await capacityCount();
      assert.ok(beforeCapacity < 256);
      for (let index = beforeCapacity; index < 256; index++) {
        const filler = await auth.register({ username: `cap_${suffix}_${index}`,
          email: `cap_${suffix}_${index}@example.invalid`, password, role: 'customer' });
        const live = await auth.establishTenantContext(filler.context);
        await launches.issueOrRenew({ platformOwnerId: live.ownerId,
          platformSessionId: live.sessionId, expiresAt: live.expiresAt, shopPrincipal: live });
      }
      assert.equal(await capacityCount(), 256);
      const beforeRows = (await identity.query(`SELECT
        (SELECT count(*)::int FROM secureshop_auth.execution_sessions WHERE auth_session_id=$1) AS executions,
        (SELECT count(*)::int FROM identity.secureshop_target_reservations WHERE original_platform_owner_id=$2) AS reservations,
        (SELECT count(*)::int FROM secureshop_auth.practice_operations WHERE principal_id=$3) AS operations`,
      [replacement.context.sessionId, capacityExecution.ownerId, replacement.context.principalId])).rows[0];
      const capacityId = randomUUID();
      await assert.rejects(repository.admit(replacement.context, capacityId),
        error => error?.code === 'SHOP_PRACTICE_CAPACITY');
      const afterRows = (await identity.query(`SELECT
        (SELECT count(*)::int FROM secureshop_auth.execution_sessions WHERE auth_session_id=$1) AS executions,
        (SELECT count(*)::int FROM identity.secureshop_target_reservations WHERE original_platform_owner_id=$2) AS reservations,
        (SELECT count(*)::int FROM secureshop_auth.practice_operations WHERE principal_id=$3) AS operations`,
      [replacement.context.sessionId, capacityExecution.ownerId, replacement.context.principalId])).rows[0];
      assert.deepEqual(afterRows, beforeRows);
      assert.equal((await practice.read(replacement.context, capacityId)).status, 'unconfirmed');
      status.capacityPreclaimRollback = true;
      assert.ok(Object.values(status).every(Boolean));
    } catch (error) { failure = error; t.diagnostic(JSON.stringify({ phase, code: error?.code || null })); }
    finally {
      const cleanup = await Promise.allSettled(Object.values(pools).map(pool => pool.end()));
      cleanupComplete = cleanup.every(result => result.status === 'fulfilled');
      await fs.mkdir(path.dirname(evidence), { recursive: true });
      await fs.writeFile(evidence, JSON.stringify({ scope: SCOPE, ...status }, null, 2),
        { flag: 'wx', mode: 0o600 });
    }
    assert.equal(cleanupComplete, true);
    if (failure) throw failure;
  });
