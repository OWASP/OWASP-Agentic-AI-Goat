'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createSecureShopStandaloneAuthService } =
  require('../server/services/secureshopStandaloneAuth');
const { createSecureShopAssessmentProgressRepository } =
  require('../server/database/postgres/secureshopAssessmentProgressRepository');

const ADMIN = '11111111-1111-4111-8111-111111111111';
const LEARNER = '22222222-2222-4222-8222-222222222222';
const PEER = '33333333-3333-4333-8333-333333333333';
const TENANT = '44444444-4444-4444-8444-444444444444';

function branded(principalId = ADMIN, role = 'admin') {
  const ownerId = role === 'admin' ? 11 : 12;
  const context = { principalId, ownerId, sessionId: ownerId + 100,
    shopUserId: ownerId + 1000, username: role === 'admin' ? 'shop_admin' : 'shop_learner',
    email: `${role}@owned.invalid`, role, credentialVersion: '1', authorityVersion: '1',
    expiresAt: new Date(Date.now() + 60000).toISOString() };
  const repository = Object.fromEntries([
    'registerWithSession', 'findCredential', 'recordFailedLogin', 'createSession',
    'rotateSession', 'revokeSession', 'readCredentialForSession', 'changePassword',
    'revokeAll', 'readOrCreateDefaultExecutionSession',
  ].map(name => [name, async () => null]));
  repository.readCurrentSession = async () => context;
  return createSecureShopStandaloneAuthService({ repository }).authenticate('A'.repeat(43));
}

function database({ actor = ADMIN, target = LEARNER, generation = 0,
  completed = false, includeMode = true, emptyCatalog = false, list = null } = {}) {
  const queries = [], state = { actor, target, generation, completed, includeMode, list };
  state.emptyCatalog = emptyCatalog;
  let releases = 0;
  const member = (principalId, role, shopUserId) => ({ principalId, role, shopUserId,
    username: role === 'admin' ? 'shop_admin' : `learner_${shopUserId}` });
  const client = {
    async query(sql, params = []) {
      queries.push({ sql, params });
      if (/^(BEGIN|COMMIT|ROLLBACK)/.test(sql)) return { rows: [] };
      if (sql.includes('FROM secureshop_auth.sessions s')) {
        assert.match(sql, /session_membership_snapshots/);
        assert.match(sql, /s\.revoked_at IS NULL/);
        assert.match(sql, /m\.is_active/);
        assert.match(sql, /FOR SHARE OF s,p,m,t/);
        return { rows: state.actor ? [{ tenantId: TENANT,
          ...member(state.actor, state.actor === ADMIN ? 'admin' : 'customer',
            state.actor === ADMIN ? 1011 : 1012) }] : [] };
      }
      if (sql.includes('FROM secureshop_auth.principals p')
          && sql.includes('WHERE m.tenant_id=$1::uuid')) {
        assert.equal(params[0], TENANT);
        return { rows: state.target === params[1]
          ? [member(state.target, 'customer', 1012)] : [] };
      }
      if (sql.includes('FROM secureshop_auth.tenant_memberships m')
          && sql.includes('ORDER BY m.shop_user_id LIMIT')) {
        assert.equal(params[0], TENANT);
        return { rows: state.list || [] };
      }
      if (sql.includes('FROM unnest($2::uuid[])')) {
        assert.match(sql, /JOIN secureshop_auth.tenant_modes mode/);
        assert.doesNotMatch(sql, /FOR SHARE OF mode/);
        assert.match(sql, /active_assessment_contributions/);
        assert.match(sql, /a\.generation=mode\.generation/);
        assert.match(sql, /o\.catalog_active AND COALESCE\(config\.is_enabled,o\.is_enabled\)/);
        assert.match(sql, /o\.qualification IN \('native-model','native-browser-judge'\)/);
        return { rows: state.includeMode ? params[1].flatMap(principalId =>
          state.emptyCatalog ? [{ principalId, generation: state.generation,
            objectiveId: null, label: null, completed: false }] : [
            { principalId, generation: state.generation,
              objectiveId: state.firstObjectiveId||'ss_one', label: 'One', completed: state.completed },
            { principalId, generation: state.generation,
              objectiveId: 'ss_two', label: 'Two', completed: false },
          ]) : [] };
      }
      throw new Error(`Unexpected progress SQL: ${sql.slice(0, 70)}`);
    },
    release() { releases += 1; },
  };
  return { pool: { connect: async () => client }, state, queries,
    get releases() { return releases; } };
}

test('self and same-tenant admin read share a closed active-generation projection', async () => {
  const db = database({ completed: true, generation: 3 });
  const repository = createSecureShopAssessmentProgressRepository({ pool: db.pool });
  const admin = await branded();
  const own = await repository.readSelf({ base: admin });
  const learner = await repository.readLearner({ base: admin, targetPrincipalId: LEARNER });
  for (const value of [own, learner]) {
    assert.equal(value.generation, 3);
    assert.equal(value.totalObjectives, 2);
    assert.equal(value.completedObjectives, 1);
    assert.deepEqual(value.objectives, [
      { objectiveId: 'ss_one', label: 'One', completed: true },
      { objectiveId: 'ss_two', label: 'Two', completed: false },
    ]);
    assert.deepEqual(Object.keys(value).sort(), [
      'completedObjectives', 'generation', 'objectives', 'principalId', 'role',
      'shopUserId', 'totalObjectives', 'username',
    ]);
  }
  db.state.completed = false; // Reset retirement removes active credit, not history.
  db.state.generation = 4;
  const after = await repository.readLearner({ base: admin, targetPrincipalId: LEARNER });
  assert.equal(after.completedObjectives, 0);
  assert.equal(after.generation, 4);
  db.state.emptyCatalog = true;
  const hidden = await repository.readLearner({ base: admin, targetPrincipalId: LEARNER });
  assert.deepEqual(hidden.objectives, []);
  assert.equal(hidden.totalObjectives, 0);
  assert.equal(db.queries[0].sql, 'BEGIN');
  assert.equal(db.queries.filter(row => row.sql.includes('FROM unnest($2::uuid[])')).length, 4,
    'mode generation, catalog and retirement must share one statement snapshot per read');
  assert.equal(db.releases, 4);
});

test('foreign, absent, stale-admin, unbranded, and missing-mode reads fail closed', async () => {
  const admin = await branded();
  const db = database();
  const repository = createSecureShopAssessmentProgressRepository({ pool: db.pool });
  for (const targetPrincipalId of [PEER, 'bad-id']) {
    await assert.rejects(repository.readLearner({ base: admin, targetPrincipalId }),
      error => ['SHOP_PROGRESS_UNAVAILABLE', 'INVALID_INPUT'].includes(error.code));
  }
  db.state.actor = null;
  await assert.rejects(repository.readLearner({ base: admin, targetPrincipalId: LEARNER }),
    { code: 'SHOP_ADMIN_REQUIRED' });
  db.state.actor = ADMIN; db.state.includeMode = false;
  await assert.rejects(repository.readLearner({ base: admin, targetPrincipalId: LEARNER }),
    { code: 'SHOP_PROGRESS_UNAVAILABLE' });
  await assert.rejects(repository.readSelf({ base: { ...admin } }), { code: 'SHOP_AUTH_INVALID' });
  assert.equal(db.queries.filter(row => row.sql === 'ROLLBACK').length, 5);
});

test('admin pagination is tenant-bound, bounded, and includes every active role', async () => {
  const db = database({ list: [
    { ...{ principalId: ADMIN, username: 'shop_admin', role: 'admin', shopUserId: 1011 } },
    { principalId: LEARNER, username: 'learner_1012', role: 'customer', shopUserId: 1012 },
    { principalId: PEER, username: 'merchant_1013', role: 'merchant', shopUserId: 1013 },
  ] });
  const repository = createSecureShopAssessmentProgressRepository({ pool: db.pool });
  const result = await repository.listLearners({ base: await branded(), limit: 2 });
  assert.deepEqual(result.learners.map(row => row.role), ['admin', 'customer']);
  assert.equal(result.nextCursor, 1012);
  const listQuery = db.queries.find(row => row.sql.includes('ORDER BY m.shop_user_id LIMIT'));
  assert.deepEqual(listQuery.params, [TENANT, 0, 3]);
  await assert.rejects(repository.listLearners({ base: await branded(), limit: 51 }),
    { code: 'INVALID_INPUT' });
});

test('release exclusions hide stale qualified enabled progress without altering stored contributions',async()=>{
 const db=database({completed:true});const repository=createSecureShopAssessmentProgressRepository({pool:db.pool}),base=await branded();
 for(const id of require('../server/config/secureshopCurriculum').RELEASE_EXCLUDED_OBJECTIVE_IDS){
  db.state.firstObjectiveId=id;const result=await repository.readSelf({base});
  assert.equal(result.totalObjectives,1);assert.equal(result.completedObjectives,0);assert.deepEqual(result.objectives.map(x=>x.objectiveId),['ss_two']);assert.equal(db.state.completed,true);
 }
});
