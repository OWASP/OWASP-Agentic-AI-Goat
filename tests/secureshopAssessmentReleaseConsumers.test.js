'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createDisposableAssessmentReleaseAdmission } =
  require('../server/services/secureshopAssessmentReleaseAdmission');
const { createSecureShopAssessmentCatalog } =
  require('../server/services/secureshopAssessmentCatalog');
const { readSecureShopAssessmentEligibility } =
  require('../server/services/secureshopAssessmentEligibility');
const { createSecureShopStandaloneAuthService } =
  require('../server/services/secureshopStandaloneAuth');

const ID = 'ss_user_lookup_sensitive_disclosure';
const SCOPE = Object.freeze({ launchId: '00000000-0000-4000-8000-000000000001',
  scenarioId: '00000000-0000-4000-8000-000000000002', generation: 3,
  platformOwnerId: 90, platformSessionId: 92 });
const TENANT = '00000000-0000-4000-8000-000000000003';
const PRINCIPAL = '00000000-0000-4000-8000-000000000004';

function controlledStores() {
  const stores = {}, rows = [], statements = [];
  let active = true, qualified = false, enabled = false;
  for (const [key, databaseName] of Object.entries({ identity: 'identity',
    agents: 'secureshop_agents', review: 'secureshop_review', commerce: 'secureshop' })) {
    const entry = stores[key] = {};
    for (const role of ['runtime', 'migration']) {
      const database = `owasp_ai_goat_test_agent_host_012345abcdef_${databaseName}`;
      const username = `dvaia_${databaseName}_${role}`;
      const url = `postgresql://${username}@127.0.0.1:54321/${database}`;
      const row = { database, role: username, session_role: username,
        server_address: '172.20.0.2', server_port: 5432,
        server_started: '2026-10-19 00:00:00+00' };
      rows.push(row);
      entry[`${role}Url`] = url;
      entry[`${role}Pool`] = { options: { connectionString: url }, connect() {},
        async query(sql, params) {
          statements.push({ sql, params });
          if (sql.includes('current_database()')) return { rows: [{ ...row }] };
          if (sql.includes('FROM identity.secureshop_authority_sessions s'))
            return { rows: active && JSON.stringify(params) === JSON.stringify([
              SCOPE.platformSessionId, SCOPE.platformOwnerId, SCOPE.launchId,
              SCOPE.scenarioId, SCOPE.generation]) ? [{ launch_id: SCOPE.launchId }] : [] };
          if (key !== 'identity' || role !== 'runtime') throw Error('Unexpected controlled store query');
          if (sql.includes('SELECT realm,shop_tenant_id'))
            return { rows: [{ realm: 'shop', shop_tenant_id: TENANT }] };
          if (sql.includes('SELECT o.objective_id FROM secureshop_auth.assessment_objectives'))
            return { rows: qualified && enabled ? [{ objective_id: ID }] : [] };
          if (sql.includes('FROM secureshop_auth.assessment_objectives o LEFT JOIN'))
            return { rows: [{ objective_id: ID, label: 'Synthetic lookup',
              is_enabled: enabled, qualification: qualified ? 'native-browser-judge' : 'pending',
              revision: '1' }] };
          if (sql.includes('set_assessment_objective')) {
            assert.deepEqual(params, [92, TENANT, PRINCIPAL, ID, true, '1']);
            if (!qualified) throw Object.assign(Error('pending'), { code: '22023' });
            enabled = true;
            return { rows: [{ objective_id: ID, is_enabled: true,
              qualification: 'native-browser-judge', revision: '2' }] };
          }
          throw Error('Unexpected controlled identity query');
        } };
    }
  }
  return { stores, statements, qualify() { qualified = true; }, revoke() { active = false; } };
}

function administrator() {
  const expiresAt = new Date(Date.now() + 60000).toISOString();
  const row = () => ({ principalId: PRINCIPAL, ownerId: SCOPE.platformOwnerId,
    sessionId: 91, shopUserId: 1000000001, username: 'controlled_admin',
    email: 'controlled@example.invalid', role: 'admin', credentialVersion: '1',
    authorityVersion: '1', expiresAt });
  const repository = Object.fromEntries(['registerWithSession', 'findCredential',
    'recordFailedLogin', 'createSession', 'rotateSession', 'revokeSession',
    'readCredentialForSession', 'changePassword', 'revokeAll'].map(name =>
    [name, async () => {}]));
  repository.readCurrentSession = async () => row();
  repository.readOrCreateDefaultExecutionSession = async () => ({ ...row(),
    principalOwnerId: SCOPE.platformOwnerId, ownerId: 500, authSessionId: 91,
    sessionId: SCOPE.platformSessionId, tenantId: TENANT, membershipVersion: '1' });
  return createSecureShopStandaloneAuthService({ repository });
}

test('real catalog and eligibility consumers admit only the selected disposable candidate', async () => {
  // Controlled SQL responses test admission wiring; they are not native proof,
  // original model evidence, or objective credit.
  const fixture = controlledStores(), pool = fixture.stores.identity.runtimePool;
  const authService = administrator(), base = await authService.authenticate('a'.repeat(43));
  const defaultCatalog = createSecureShopAssessmentCatalog({ pool, authService });
  assert.deepEqual((await defaultCatalog.list(base)).objectives.map(row =>
    [row.objectiveId, row.qualification, row.enabled]), [[ID, 'pending', false]]);
  await assert.rejects(defaultCatalog.set(base, { objectiveId: ID, enabled: true,
    expectedRevision: '1' }), { code: 'SHOP_OBJECTIVE_UNQUALIFIED' });
  assert.deepEqual(await readSecureShopAssessmentEligibility(pool, SCOPE, [ID]), []);

  const token = await createDisposableAssessmentReleaseAdmission({ stores: fixture.stores,
    objectiveIds: [ID] });
  const candidateCatalog = createSecureShopAssessmentCatalog({ pool, authService,
    assessmentReleaseAdmission: token });
  assert.deepEqual((await candidateCatalog.list(base)).objectives.map(row =>
    [row.objectiveId, row.qualification, row.enabled]), [[ID, 'pending', false]]);
  fixture.qualify();
  assert.deepEqual(await candidateCatalog.set(base, { objectiveId: ID, enabled: true,
    expectedRevision: '1' }), { objectiveId: ID, enabled: true,
    qualification: 'native-browser-judge', revision: '2' });
  assert.deepEqual(await readSecureShopAssessmentEligibility(pool, SCOPE, [ID], token), [ID]);
  assert.deepEqual(await readSecureShopAssessmentEligibility(pool, SCOPE, [ID]), []);
  assert.deepEqual((await defaultCatalog.list(base)).objectives.map(row =>
    [row.objectiveId, row.qualification, row.enabled]), [[ID, 'pending', false]]);
  fixture.revoke();
  await assert.rejects(readSecureShopAssessmentEligibility(pool, SCOPE, [ID], token),
    { code: 'SHOP_CANDIDATE_ADMISSION_INVALID' });
  assert.ok(fixture.statements.every(({ sql }) => /^SELECT/.test(sql)
    || sql.includes('set_assessment_objective')));
});

test('consumer factories reject forged candidate tokens before serving requests', () => {
  const pool = { query() {}, connect() {} };
  assert.throws(() => createSecureShopAssessmentCatalog({ pool,
    authService: { establishTenantContext() {} }, assessmentReleaseAdmission: {} }),
  { code: 'SHOP_CANDIDATE_ADMISSION_INVALID' });
  assert.throws(() => require('../server/database/postgres/secureshopAssessmentProgressRepository')
    .createSecureShopAssessmentProgressRepository({ pool, assessmentReleaseAdmission: {} }),
  { code: 'SHOP_CANDIDATE_ADMISSION_INVALID' });
});
