'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { createSecureShopStandaloneAuthService } = require('../server/services/secureshopStandaloneAuth');
const { createSecureShopStandaloneReset } = require('../server/services/secureshopStandaloneReset');
const { createSceneBinding } = require('../server/services/secureshopSceneBinding');

const principalId = '11111111-1111-4111-8111-111111111111';
const tenantId = '22222222-2222-4222-8222-222222222222';
const launchId = '33333333-3333-4333-8333-333333333333';
const sceneId = '44444444-4444-4444-8444-444444444444';
const requestId = '55555555-5555-4555-8555-555555555555';
const resetId = '66666666-6666-4666-8666-666666666666';
const scenarioId = '77777777-7777-4777-8777-777777777777';
const targetId = '88888888-8888-4888-8888-888888888888';
const token = 'a'.repeat(43);
const expiresAt = new Date(Date.now() + 3600000).toISOString();

function fixture({ baseRole = 'admin', tenantRole = 'admin', launchGeneration = 3,
  launchStatus = 'active', sceneStatus = 'active', adminLive = true, previewAvailable = true,
  originalSessionId = 80, resetStatus = 'fenced', cleanupComplete = false,
  recoveryPresent = true, launchLive = true, recoveryGeneration = 4,
  existingScene = 'current', grantInitiallyPresent = true } = {}) {
  const seen = [];
  let grantPresent = grantInitiallyPresent;
  let adminReads = 0;
  const repository = Object.fromEntries(['registerWithSession', 'findCredential', 'recordFailedLogin',
    'createSession', 'rotateSession', 'revokeSession', 'readCredentialForSession',
    'changePassword', 'revokeAll'].map(name => [name, async () => { throw new Error(`unexpected ${name}`); }]));
  repository.readCurrentSession = async () => ({ principalId, ownerId: 50, sessionId: 60,
    shopUserId: 1000000002, username: 'student_admin', email: 'admin@secureshop.local',
    role: baseRole, credentialVersion: '1', authorityVersion: '1', expiresAt });
  repository.readOrCreateDefaultExecutionSession = async () => ({ principalId, principalOwnerId: 50,
    ownerId: 70, authSessionId: 60, sessionId: 80, tenantId, membershipVersion: '1',
    shopUserId: 1000000002, username: 'student_admin', email: 'admin@secureshop.local',
    role: tenantRole, credentialVersion: '1', authorityVersion: '1', expiresAt });
  const authService = createSecureShopStandaloneAuthService({ repository });
  const identityPool = {
    async query(sql) {
      seen.push(sql);
      if (sql.includes('FROM identity.secureshop_launch_resets o')) return { rows: recoveryPresent ? [{
        reset_id: resetId, status: resetStatus, from_generation: 3, to_generation: 4,
        reconciliation_required: !cleanupComplete, conversation_reconciliation_required: false,
        progress_reconciliation_required: false, launch_id: launchId, launch_status: launchStatus,
        current_generation: recoveryGeneration, launch_live: launchLive,
        original_execution_session_id: originalSessionId, scene_id: sceneId, scene_claim_count: 1,
      }] : [] };
      if (sql.includes('FROM identity.secureshop_launches')) return { rows: [{ launch_id: launchId,
        generation: launchGeneration, status: launchStatus }] };
      if (sql.includes('FROM identity.secureshop_scenes')) return { rows: [{ scene_id: sceneId,
        status: sceneStatus }] };
      throw new Error('Unexpected identity query');
    },
    async connect() {
      return { async query(sql) {
        seen.push(sql);
        if (sql.includes('FROM secureshop_auth.principals')) {
          adminReads += 1;
          return { rows: (typeof adminLive === 'function' ? adminLive(adminReads) : adminLive)
            ? [{ principal_id: principalId }] : [] };
        }
        return { rows: [] };
      }, release() { seen.push('release'); } };
    },
  };
  const preflight = { async preview(input) { seen.push(['preview', input]);
    return { available: previewAvailable && grantPresent, sceneId }; } };
  const launches = { async readActiveMetadata() { seen.push('readActiveMetadata');
    return launchStatus === 'active' ? { launchId, generation: launchGeneration,
      scenarioId, platformOwnerId: 70, platformSessionId: 80 } : null; } };
  const resetCoordinator = { async reset(input, options) {
    seen.push(['coordinator', input, options.expectedSceneId]);
    await options.withAdmission(async () => { seen.push('begin'); return { resetId }; });
    seen.push('cleanup');
    return { resetId, status: 'committed', fromGeneration: 3, toGeneration: 4,
      binding: { launchId, generation: 4 } };
  }, async resumeExisting(id, options) {
    seen.push(['resumeExisting', id, options.platformSessionId]);
    await options.withAdmission(async () => { seen.push('admit'); });
    seen.push('cleanup');
    return { resetId: id, status: 'committed', activated: true,
      binding: { launchId, generation: 4 } };
  }, async recover(id) { seen.push(['cleanupOnly', id]);
    return { resetId: id, status: resetStatus, resolved: true, activated: false }; } };
  const service = createSecureShopStandaloneReset({ identityPool, authService, launches,
    scenes: { async readExisting(scope) {
      seen.push(['readExisting', scope]);
      if (existingScene === 'absent') return null;
      const altered = {
        'old-session': { platformSessionId: 79 },
        'other-owner': { platformOwnerId: 71 },
        'other-launch': { launchId: requestId },
        'other-scenario': { scenarioId: targetId },
        'other-generation': { generation: scope.generation + 1 },
      }[existingScene] || {};
      const storage = { launchId: requestId, scenarioId, generation: 1,
        platformOwnerId: altered.platformOwnerId ?? 70, platformSessionId: 79, targetId };
      const binding = createSceneBinding(storage, {
        sceneId: existingScene === 'other-scene' ? targetId : sceneId,
        sceneGeneration: 1, grantId: resetId,
        execution: { ...scope, ...altered },
        withLease: work => work(),
      });
      grantPresent = true;
      return existingScene === 'untrusted' ? { ...binding } : binding;
    } }, resetCoordinator, preflight });
  const input = { launchId, expectedGeneration: 3, idempotencyKey: requestId,
    sceneId, confirmation: 'RESET_SHARED_PRACTICE' };
  return { service, authService, seen, input };
}

test('readiness requires branded immutable and tenant admin, exact live lease, and true preflight', async () => {
  const f = fixture();
  const base = await f.authService.authenticate(token);
  assert.deepEqual(await f.service.readiness(base), { available: true, scope: 'shared_practice',
    launchId, generation: 3, scene: { id: sceneId, label: 'Shop practice 1' } });
  assert(f.seen.indexOf('COMMIT') > f.seen.findIndex(x => Array.isArray(x) && x[0] === 'preview'));
  await assert.rejects(f.service.readiness({ ...base }), { code: 'SHOP_RESET_UNAVAILABLE' });
  const noTenantAdmin = fixture({ tenantRole: 'customer' });
  await assert.rejects(noTenantAdmin.service.readiness(await noTenantAdmin.authService.authenticate(token)),
    { code: 'SHOP_ADMIN_REQUIRED' });
  assert(!noTenantAdmin.seen.some(value => Array.isArray(value) && value[0] === 'readExisting'));
  const revoked = fixture({ adminLive: false });
  await assert.rejects(revoked.service.readiness(await revoked.authService.authenticate(token)),
    { code: 'SHOP_ADMIN_REQUIRED' });
  assert(!revoked.seen.some(value => Array.isArray(value) && value[0] === 'readExisting'));
  const unavailable = fixture({ previewAvailable: false });
  await assert.rejects(unavailable.service.readiness(await unavailable.authService.authenticate(token)),
    { code: 'SHOP_RESET_UNAVAILABLE' });
});

test('readiness binds the retained practice after relogin before exact preflight', async () => {
  const f = fixture({ grantInitiallyPresent: false });
  assert.equal((await f.service.readiness(await f.authService.authenticate(token))).available, true);
  const bind = f.seen.findIndex(value => Array.isArray(value) && value[0] === 'readExisting');
  const preview = f.seen.findIndex(value => Array.isArray(value) && value[0] === 'preview');
  assert(bind > f.seen.findIndex(value => typeof value === 'string' && value.includes('FOR SHARE OF p,s,m,t,e')));
  assert(preview > bind);
  assert(f.seen.indexOf('COMMIT') > preview);
  assert.deepEqual(f.seen[bind][1], { launchId, scenarioId, generation: 3,
    platformOwnerId: 70, platformSessionId: 80 });
});

test('readiness rejects missing, substituted, untrusted, or old-session scene bindings before preflight', async () => {
  for (const existingScene of ['absent', 'other-scene', 'untrusted', 'old-session',
    'other-owner', 'other-launch', 'other-scenario', 'other-generation']) {
    const f = fixture({ existingScene });
    await assert.rejects(f.service.readiness(await f.authService.authenticate(token)),
      { code: 'SHOP_RESET_SCOPE_CHANGED' }, existingScene);
    assert(!f.seen.some(value => Array.isArray(value) && value[0] === 'preview'));
  }
});

test('reset protects exact CAS and holds canonical admin lease through begin, then releases before cleanup', async () => {
  const f = fixture();
  const value = await f.service.reset(await f.authService.authenticate(token), f.input);
  assert.deepEqual(value, { resetId, status: 'committed', cleanupComplete: true });
  const begin = f.seen.indexOf('begin');
  assert(begin > f.seen.findIndex(x => typeof x === 'string' && x.includes('FOR SHARE OF p,s,m,t,e')));
  assert(f.seen.indexOf('COMMIT') > begin);
  assert(f.seen.indexOf('cleanup') > f.seen.indexOf('COMMIT'));
  assert.equal(f.seen.find(x => Array.isArray(x) && x[0] === 'coordinator')[2], sceneId);
});

test('reset permits only exact generation-next replay while launch is resetting', async () => {
  const f = fixture({ launchGeneration: 4, launchStatus: 'resetting', sceneStatus: 'retired' });
  assert.deepEqual(await f.service.reset(await f.authService.authenticate(token), f.input),
    { resetId, status: 'committed', cleanupComplete: true });
  const stale = fixture({ launchGeneration: 5, launchStatus: 'resetting', sceneStatus: 'retired' });
  await assert.rejects(stale.service.reset(await stale.authService.authenticate(token), stale.input),
    { code: 'SHOP_RESET_SCOPE_CHANGED' });
});

test('reset rejects malformed intent and principal admin without tenant membership', async () => {
  const f = fixture();
  const base = await f.authService.authenticate(token);
  await assert.rejects(f.service.reset(base, { ...f.input, confirmation: 'RESET' }),
    { code: 'INVALID_ARGUMENT' });
  await assert.rejects(f.service.reset(base, { ...f.input, extra: true }),
    { code: 'INVALID_ARGUMENT' });
  const noAdmin = fixture({ baseRole: 'customer' });
  await assert.rejects(noAdmin.service.reset(await noAdmin.authService.authenticate(token), noAdmin.input),
    { code: 'SHOP_ADMIN_REQUIRED' });
});

test('recovery readback is exact principal journal and exposes canonical cleanup flags', async () => {
  const f = fixture();
  assert.deepEqual(await f.service.readRecovery(await f.authService.authenticate(token)), { pending: {
    resetId, launchId, fromGeneration: 3, toGeneration: 4, status: 'fenced',
    scene: { id: sceneId, label: 'Shop practice' }, cleanupComplete: false, sameExecution: true,
  } });
  assert(f.seen.some(value => typeof value === 'string'
    && value.includes('original.principal_id=$1 AND original.tenant_id=$2')));
  assert(f.seen.some(value => typeof value === 'string'
    && value.includes('o.status=\'fenced\' OR o.reconciliation_required')));
  const none = fixture({ recoveryPresent: false });
  assert.deepEqual(await none.service.readRecovery(await none.authService.authenticate(token)), { pending: null });
});

test('same live original execution resumes protected commit; a later session only settles retained cleanup', async () => {
  const original = fixture({ launchStatus: 'resetting' });
  assert.deepEqual(await original.service.recover(await original.authService.authenticate(token), { resetId }),
    { resetId, status: 'committed', cleanupComplete: true, activated: true });
  assert(original.seen.some(value => Array.isArray(value) && value[0] === 'resumeExisting'));
  assert(original.seen.indexOf('COMMIT') < original.seen.indexOf('cleanup'));
  const other = fixture({ originalSessionId: 81, launchStatus: 'resetting' });
  assert.deepEqual(await other.service.recover(await other.authService.authenticate(token), { resetId }),
    { resetId, status: 'fenced', cleanupComplete: true, activated: false });
  assert(other.seen.some(value => Array.isArray(value) && value[0] === 'cleanupOnly'));
  assert(!other.seen.some(value => Array.isArray(value) && value[0] === 'resumeExisting'));
  const aborted = fixture({ resetStatus: 'aborted' });
  assert.deepEqual(await aborted.service.recover(await aborted.authService.authenticate(token), { resetId }),
    { resetId, status: 'aborted', cleanupComplete: true, activated: false });
  const expiredLaunch = fixture({ launchStatus: 'active', launchLive: false });
  assert.deepEqual(await expiredLaunch.service.recover(
    await expiredLaunch.authService.authenticate(token), { resetId }),
  { resetId, status: 'fenced', cleanupComplete: true, activated: false });
  assert(!expiredLaunch.seen.some(value => Array.isArray(value) && value[0] === 'resumeExisting'));
  const changedGeneration = fixture({ launchStatus: 'active', recoveryGeneration: 5 });
  assert.deepEqual(await changedGeneration.service.recover(
    await changedGeneration.authService.authenticate(token), { resetId }),
  { resetId, status: 'fenced', cleanupComplete: true, activated: false });
  const revokedAdminDuringResume = fixture({ launchStatus: 'resetting', adminLive: check => check < 3 });
  await assert.rejects(revokedAdminDuringResume.service.recover(
    await revokedAdminDuringResume.authService.authenticate(token), { resetId }),
  { code: 'SHOP_ADMIN_REQUIRED' });
  assert(!revokedAdminDuringResume.seen.some(value => Array.isArray(value) && value[0] === 'cleanupOnly'));
});

test('recovery rejects foreign journal ID and never infers a missing scene claim as no pending', async () => {
  const missing = fixture({ recoveryPresent: false });
  await assert.rejects(missing.service.recover(await missing.authService.authenticate(token), { resetId }),
    { code: 'SHOP_RESET_NOT_FOUND' });
});
