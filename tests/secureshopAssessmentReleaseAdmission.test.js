'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createDisposableAssessmentReleaseAdmission: create, resolveAssessmentReleaseAdmission: resolve } =
  require('../server/services/secureshopAssessmentReleaseAdmission');
const { isAssessmentReleaseAllowed, RELEASE_EXCLUDED_OBJECTIVE_IDS } = require('../server/config/secureshopCurriculum');
const { readFileSync } = require('node:fs');
const ID = 'ss_idor_order_status_disclosure';
const USER_LOOKUP_ID = 'ss_user_lookup_sensitive_disclosure';
const SCOPE = Object.freeze({ launchId: '00000000-0000-4000-8000-000000000001',
  scenarioId: '00000000-0000-4000-8000-000000000002', generation: 3,
  platformOwnerId: 11, platformSessionId: 12 });
function fixture() {
  const stores = {}, rows = [], statements = [];
  let active = true;
  for (const [name, store] of Object.entries({ identity: 'identity', agents: 'secureshop_agents',
    review: 'secureshop_review', commerce: 'secureshop' })) {
    const entry = stores[name] = {};
    for (const role of ['runtime', 'migration']) {
      const database = `owasp_ai_goat_test_agent_host_012345abcdef_${store}`;
      const username = `dvaia_${store}_${role}`;
      const url = `postgresql://${username}@127.0.0.1:54321/${database}`;
      const row = { database, role: username, session_role: username,
        server_address: '172.20.0.2', server_port: 5432, server_started: '2026-10-19 00:00:00+00' };
      rows.push(row);
      entry[`${role}Url`] = url;
      entry[`${role}Pool`] = { options: { connectionString: url }, connect() {},
        async query(sql, params) {
          statements.push({ sql, params });
          if (sql.includes('current_database()')) return { rows: [{ ...row }] };
          assert.ok(sql.includes("s.realm='shop' AND o.realm='shop'"));
          assert.ok(sql.includes('l.generation=$5'));
          assert.ok(sql.includes('e.owner_id=o.id'));
          const expected = [SCOPE.platformSessionId, SCOPE.platformOwnerId,
            SCOPE.launchId, SCOPE.scenarioId, SCOPE.generation];
          return { rows: active && JSON.stringify(params) === JSON.stringify(expected)
            ? [{ launch_id: SCOPE.launchId }] : [] };
        } };
    }
  }
  return { stores, rows, statements, revoke() { active = false; } };
}
test('disposable token admits only selected candidates and never changes production policy', async () => {
  const f = fixture(), token = await create({ stores: f.stores, objectiveIds: [ID] });
  assert.ok(Object.isFrozen(token));
  assert.equal(Object.keys(token).length, 0);
  const policy = resolve(token, { identityPool: f.stores.identity.runtimePool,
    agentsPool: f.stores.agents.runtimePool, reviewPool: f.stores.review.runtimePool,
    commercePool: f.stores.commerce.runtimePool });
  assert.equal(policy.isCandidate(ID), true);
  assert.equal(policy.isAllowed(ID), true);
  for (const id of RELEASE_EXCLUDED_OBJECTIVE_IDS) {
    assert.equal(isAssessmentReleaseAllowed(id), false);
    assert.equal(policy.isAllowed(id), id === ID);
    assert.equal(resolve(undefined).isAllowed(id), false);
  }
  await policy.assertScope(SCOPE);
  assert.ok(f.statements.every(({ sql }) => /^SELECT/.test(sql)));
});
test('forged, serialized, crosspool and extra consumer identities are rejected', async () => {
  const f = fixture(), token = await create({ stores: f.stores, objectiveIds: [ID] });
  for (const fake of [null, {}, Object.freeze({}), JSON.parse(JSON.stringify(token))])
    assert.throws(() => resolve(fake, { identityPool: f.stores.identity.runtimePool }));
  assert.throws(() => resolve(token, { identityPool: f.stores.agents.runtimePool }));
  assert.throws(() => resolve(token, { identityPool: f.stores.identity.runtimePool,
    reviewPool: f.stores.commerce.runtimePool }));
  assert.throws(() => resolve(token, { identityPool: f.stores.identity.runtimePool, other: true }));
  assert.throws(() => resolve(token, {}));
});
test('candidate scope rejects foreign owner/session/launch/scenario, reset and revoked or crossrealm state', async () => {
  const f = fixture(), token = await create({ stores: f.stores, objectiveIds: [ID] });
  const policy = resolve(token, { identityPool: f.stores.identity.runtimePool });
  for (const [key, value] of [['platformOwnerId', 13], ['platformSessionId', 14], ['generation', 4],
    ['launchId', SCOPE.scenarioId], ['scenarioId', SCOPE.launchId]])
    await assert.rejects(policy.assertScope({ ...SCOPE, [key]: value }));
  f.revoke();
  await assert.rejects(policy.assertScope(SCOPE));
});
test('closed allowlist and all eight distinct nonce/role/endpoint identities are mandatory', async () => {
  for (const ids of [[], [ID, ID], ['ss_inventory_cross_merchant_stock'], ['anything'],
    [...RELEASE_EXCLUDED_OBJECTIVE_IDS, 'extra']])
    await assert.rejects(create({ stores: fixture().stores, objectiveIds: ids }));
  for (const mutate of [
    f => { delete f.stores.review; },
    f => { f.stores.identity.migrationPool = f.stores.identity.runtimePool; },
    f => { f.stores.agents.runtimeUrl = f.stores.agents.runtimeUrl.replace('127.0.0.1', 'remote.invalid'); },
    f => { f.stores.agents.runtimeUrl = f.stores.agents.runtimeUrl.replace('012345abcdef', 'ffffffffffff'); },
    f => { f.stores.agents.runtimeUrl = f.stores.agents.runtimeUrl.replace('54321', '54322'); },
    f => { f.stores.identity.runtimeUrl = f.stores.identity.runtimeUrl.replace('_runtime@', '_migration@'); },
    f => { f.stores.identity.runtimeUrl += '?sslmode=disable'; },
    f => { f.stores.identity.runtimePool.options.connectionString += '?application_name=foreign'; },
    f => { f.rows[0].role = 'foreign'; },
    f => { f.rows[0].session_role = 'foreign'; },
    f => { f.rows[0].database = 'application'; },
    f => { f.rows[7].server_started = 'other-cluster'; },
  ]) {
    const f = fixture(); mutate(f);
    await assert.rejects(create({ stores: f.stores, objectiveIds: [ID] }));
  }
});
test('live pool option, role and server replacement invalidate an issued capability', async () => {
  for (const change of [
    f => { f.stores.identity.runtimePool.options.connectionString = 'postgresql://foreign'; },
    f => { f.rows[3].role = 'foreign'; },
    f => { f.rows.forEach(row => { row.server_started = 'restarted'; }); },
  ]) {
    const f = fixture(), token = await create({ stores: f.stores, objectiveIds: [ID] });
    const policy = resolve(token, { identityPool: f.stores.identity.runtimePool });
    change(f);
    await assert.rejects(policy.assertCurrent());
  }
});

test('every runtime and migration identity is revalidated after issuance', async () => {
  for (let index = 0; index < 8; index++) {
    const f = fixture(), token = await create({ stores: f.stores, objectiveIds: [ID] });
    const policy = resolve(token, { identityPool: f.stores.identity.runtimePool });
    f.rows[index].database = 'replaced';
    await assert.rejects(policy.assertScope(SCOPE));
  }
});

test('prepared grading bootstrap binds the exact injected admission token', async () => {
  const f = fixture(), token = await create({ stores: f.stores, objectiveIds: [ID] });
  const other = await create({ stores: f.stores, objectiveIds: [ID] });
  const bootstrap = require('../server/services/secureshopGradingBootstrap');
  const identityPool = f.stores.identity.runtimePool, agentsPool = f.stores.agents.runtimePool;
  const resetComposition = { launches: { async assertCurrent() {} } };
  const bindings = Object.fromEntries(['capture','initial','inherit','commit','check','projectRecoverable',
    'assertReady'].map(key => [key, async () => {}]));
  const prepared = await bootstrap.createSecureShopGradingBootstrap({ identityPool, agentsPool,
    resetComposition, assessmentReleaseAdmission: token, progress: { async getGeneration() { return 0; } },
    async assertAuthorityReady() {} }, {
    createAuthority: () => ({ capture() {} }), createBindings: () => bindings,
  });
  const context = { identityPool, agentsPool, resetComposition, assessmentReleaseAdmission: token };
  assert.equal(bootstrap.resolveSecureShopGradingBootstrap(prepared, context), prepared);
  for (const replacement of [undefined, {}, other])
    assert.throws(() => bootstrap.resolveSecureShopGradingBootstrap(prepared,
      { ...context, assessmentReleaseAdmission: replacement }));
});

test('user-lookup admission reaches real catalog, progress, grading and recovery factories without admitting other candidates', async () => {
  const f = fixture(), token = await create({ stores: f.stores, objectiveIds: [USER_LOOKUP_ID] });
  const identityPool = f.stores.identity.runtimePool, agentsPool = f.stores.agents.runtimePool;
  const policy = resolve(token, { identityPool, agentsPool,
    reviewPool: f.stores.review.runtimePool, commercePool: f.stores.commerce.runtimePool });
  assert.equal(policy.isAllowed(USER_LOOKUP_ID), true);
  assert.equal(policy.isAllowed(ID), false);
  assert.equal(policy.isAllowed('ss_system_credential_disclosure'),
    isAssessmentReleaseAllowed('ss_system_credential_disclosure'));
  assert.equal(isAssessmentReleaseAllowed(USER_LOOKUP_ID), false);

  const authService = { async establishTenantContext() {} };
  const catalog = require('../server/services/secureshopAssessmentCatalog')
    .createSecureShopAssessmentCatalog({ pool: identityPool, authService,
      assessmentReleaseAdmission: token });
  assert.equal(typeof catalog.list, 'function');
  assert.equal(typeof catalog.set, 'function');
  const progressRepository = require('../server/database/postgres/secureshopAssessmentProgressRepository')
    .createSecureShopAssessmentProgressRepository({ pool: identityPool,
      assessmentReleaseAdmission: token });
  const progress = require('../server/services/secureshopAssessmentProgress')
    .createSecureShopAssessmentProgress({ repository: progressRepository });
  assert.equal(typeof progress.readSelf, 'function');
  const resetComposition = { launches: { async assertCurrent() {} } };
  const bindings = Object.fromEntries(['capture','initial','inherit','commit','check','projectRecoverable',
    'assertReady'].map(key => [key, async () => {}]));
  const grading = await require('../server/services/secureshopGradingBootstrap')
    .createSecureShopGradingBootstrap({ identityPool, agentsPool, resetComposition,
      progress: { async getGeneration() { return 0; } }, assessmentReleaseAdmission: token,
      async assertAuthorityReady() {} }, {
      createAuthority: () => ({ capture() {} }), createBindings: () => bindings,
    });
  const recovery = require('../server/services/secureshopAssessmentRecovery')
    .createSecureShopAssessmentRecovery({ identityPool, authService,
      bootstrap: async () => {}, launches: { async resolveCapability() {}, async assertCurrent() {} },
      personaAuth: { async authenticateBoundToken() {} },
      personaAuthority: grading.personaAuthority, assessmentReleaseAdmission: token,
      userLookupAssessment: { async assertRetainedPacket() {} } });
  assert.equal(typeof recovery.list, 'function');
  assert.equal(typeof recovery.retry, 'function');
  const foreign = fixture().stores.identity.runtimePool;
  assert.throws(() => require('../server/services/secureshopAssessmentCatalog')
    .createSecureShopAssessmentCatalog({ pool: foreign, authService,
      assessmentReleaseAdmission: token }), { code: 'SHOP_CANDIDATE_ADMISSION_INVALID' });
  assert.throws(() => require('../server/database/postgres/secureshopAssessmentProgressRepository')
    .createSecureShopAssessmentProgressRepository({ pool: foreign,
      assessmentReleaseAdmission: token }), { code: 'SHOP_CANDIDATE_ADMISSION_INVALID' });
});

test('native user-lookup cohort injects one eight-pool token through every mounted assessment path', () => {
  const source = readFileSync(require.resolve('./postgres/secureshopStandaloneRoleChoicesRendered.integration.test'), 'utf8');
  assert.match(source, /const assessmentReleaseAdmission = USER_LOOKUP_BROWSER\s*\? await require\([\s\S]*?objectiveIds: \['ss_user_lookup_sensitive_disclosure'\]/);
  assert.match(source, /stores: Object\.fromEntries\(STORES\.map\(key => \[key\.toLowerCase\(\), \{\s*runtimePool: pools\[`\$\{key\}_RUNTIME`\], migrationPool: pools\[`\$\{key\}_MIGRATION`\],\s*runtimeUrl: urls\[`\$\{key\}_RUNTIME`\], migrationUrl: urls\[`\$\{key\}_MIGRATION`\]/);
  for (const expression of [
    /createSecureShopAssessmentCatalog\(\{ pool: identity, authService: auth, assessmentReleaseAdmission \}\)/,
    /createSecureShopGradingBootstrap\(\{ identityPool: identity, agentsPool: agents,[\s\S]*?progress, resetComposition: reset, assessmentReleaseAdmission,/,
    /createSecureShopBoundReviewComposition\(\{[\s\S]*?gradingBootstrap: grading, assessmentReleaseAdmission,/,
    /createSecureShopAssessmentRecovery\(\{[\s\S]*?userLookupAssessment: composition\.roleAssistants\.admin\.userLookupAssessment,\s*assessmentReleaseAdmission/,
    /createSecureShopAssessmentProgressRepository\(\{ pool: identityPool, assessmentReleaseAdmission \}\)/,
  ]) assert.match(source, expression);
  assert.match(source, /createRoleChoicesAuthRouter\(\{ service: auth,[\s\S]*?identity, SYSTEM_CREDENTIAL_BROWSER \|\| USER_LOOKUP_BROWSER, assessmentReleaseAdmission\)/);
  assert.match(source, /UPDATE secureshop_auth\.assessment_objectives SET qualification='native-browser-judge'[\s\S]*?source_sha256=\$2 AND source_document=\$3::jsonb/);
});
