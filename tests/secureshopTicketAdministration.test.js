'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { createTicketAdministration } = require('../server/services/secureshopTicketAdministration');
const { createSceneBinding } = require('../server/services/secureshopSceneBinding');

const scope = Object.freeze({ launchId: randomUUID(), scenarioId: randomUUID(), generation: 2,
  platformOwnerId: 7, platformSessionId: 13 });
const birth = Object.freeze({ launchId: randomUUID(), scenarioId: randomUUID(), generation: 1,
  platformOwnerId: scope.platformOwnerId, platformSessionId: 11 });
const persona = Object.freeze({ id: 23, role: 'admin' });
const personaSession = Object.freeze({ sessionId: randomUUID(), authorityVersion: '2' });
const scene = createSceneBinding({ ...birth, targetId: randomUUID() }, {
  sceneId: randomUUID(), sceneGeneration: 1, grantId: randomUUID(), execution: scope,
  withLease: async work => work(),
});
const input = Object.freeze({ scope, persona, personaSession });
const stale = code => Object.assign(new Error('stale authority'), { code });

function fixture(overrides = {}) {
  const state = { calls: [], staleMode: false, revokedPersona: false, revokedLaunch: false,
    revokeAfterRepository: false, changeModeAfterRepository: false,
    revokeLaunchAfterRepository: false, nullDetail: false };
  const issued = new WeakSet();
  const launches = { async assertCurrent(value) {
    state.calls.push(['launch', value]);
    if (state.revokedLaunch) throw stale('STALE_LAUNCH');
    assert.deepEqual(value, scope);
  } };
  const personaAuthority = { async capture(value) {
    state.calls.push(['capturePersona', value]);
    return { binding: { ...scope, ...overrides.fenceScope, personaId: persona.id, role: persona.role,
      sessionId: personaSession.sessionId, authorityVersion: personaSession.authorityVersion },
    async assertRemoteAdmission() {
      state.calls.push(['persona']);
      if (state.revokedPersona) throw stale('SHOP_AUTH_INVALID');
    } };
  } };
  const modeAuthority = { async capture(value, featureId) {
    state.calls.push(['captureMode', value, featureId]);
    assert.deepEqual(value, scope);
    assert.equal(featureId, 'support_tickets');
    const token = { snapshot: { version: 1, featureId, policyVersion: 'owned-ticket-render-v1',
      mode: 'vuln', generation: 2, modeStamp: 'current', scope: value },
    async assertCurrent() {
      state.calls.push(['mode']);
      if (state.staleMode) throw stale('SECURESHOP_FEATURE_MODE_STALE');
    } };
    issued.add(token);
    return token;
  }, assertToken(token) {
    if (!issued.has(token)) throw stale('SECURESHOP_FEATURE_MODE_STALE');
    return token;
  } };
  const scenes = { async readRetained(value) {
    state.calls.push(['readRetained', value]);
    assert.deepEqual(value, scope);
    return overrides.scene === undefined ? scene : overrides.scene;
  }, readExisting() { throw Error('Ticket admin GET must not call readExisting'); },
  adopt() { throw Error('Ticket admin GET must not provision a scene'); },
  select() { throw Error('Ticket admin GET must not change scene selection'); } };
  const repository = { async listForAdmin(ctx, options) {
    state.calls.push(['list', ctx, options]);
    assert.deepEqual(ctx.scope, scope);
    assert.deepEqual(ctx.persona, persona);
    assert.deepEqual(ctx.personaSession, personaSession);
    assert.equal(ctx.retainedScene, scene);
    assert.ok(issued.has(ctx.modeToken));
    if (state.revokeAfterRepository) state.revokedPersona = true;
    if (state.changeModeAfterRepository) state.staleMode = true;
    if (state.revokeLaunchAfterRepository) state.revokedLaunch = true;
    return { version: 1, tickets: [], nextCursor: null };
  }, async readForAdmin(ctx, options) {
    state.calls.push(['read', ctx, options]);
    assert.deepEqual(options, { ticketId: '37' });
    if (state.revokeAfterRepository) state.revokedPersona = true;
    if (state.changeModeAfterRepository) state.staleMode = true;
    if (state.revokeLaunchAfterRepository) state.revokedLaunch = true;
    return state.nullDetail ? null : { ticketId: '37' };
  } };
  const service = createTicketAdministration({ launches, personaAuthority, modeAuthority,
    scenes, repository });
  return { state, service };
}

test('admin ticket list/read use independent current execution and branded retained scene without provisioning', async () => {
  const f = fixture();
  assert.deepEqual(await f.service.list(input, { limit: 5 }),
    { version: 1, tickets: [], nextCursor: null });
  assert.deepEqual(await f.service.read(input, { ticketId: '37' }), { ticketId: '37' });
  assert.equal(f.state.calls.filter(([name]) => name === 'readRetained').length, 2);
  assert.equal(f.state.calls.filter(([name]) => name === 'list').length, 1);
  assert.equal(f.state.calls.filter(([name]) => name === 'read').length, 1);
  assert.ok(f.state.calls.filter(([name]) => name === 'mode').length >= 4,
    'mode token is checked before and after repository reads');
  assert.ok(f.state.calls.filter(([name]) => name === 'persona').length >= 6,
    'admin persona is checked before and after repository reads');
  assert.notEqual(scene.launchId, scope.launchId, 'ticket storage birth and current admin launch differ');
  assert.deepEqual(scene.scene.execution, scope);
});

test('admin ticket read preserves a missing protected row as null', async () => {
  const f = fixture(); f.state.nullDetail = true;
  assert.equal(await f.service.read(input, { ticketId: '37' }), null);
  assert.equal(f.state.calls.filter(([name]) => name === 'read').length, 1);
});

test('wrong role, invalid persona binding and forged scene deny before repository read', async () => {
  const wrong = fixture();
  await assert.rejects(wrong.service.list({ ...input, persona: { ...persona, role: 'customer' } }),
    { code: 'SHOP_AUTH_INVALID' });
  assert.equal(wrong.state.calls.filter(([name]) => name === 'list').length, 0);
  const mismatched = fixture({ fenceScope: { platformSessionId: scope.platformSessionId + 1 } });
  await assert.rejects(mismatched.service.list(input), { code: 'SHOP_AUTH_INVALID' });
  assert.equal(mismatched.state.calls.filter(([name]) => name === 'readRetained').length, 0);
  assert.equal(mismatched.state.calls.filter(([name]) => name === 'list').length, 0);
  const forged = fixture({ scene: { ...scene, scene: { ...scene.scene } } });
  await assert.rejects(forged.service.list(input), { code: 'SHOP_SCENE_STALE' });
  assert.equal(forged.state.calls.filter(([name]) => name === 'list').length, 0);
  const missing = fixture({ scene: null });
  await assert.rejects(missing.service.list(input), { code: 'SHOP_SCENE_STALE' });
  assert.equal(missing.state.calls.filter(([name]) => name === 'list').length, 0);
});

test('revoked persona or changed issuer mode rejects post-read output', async () => {
  const revoked = fixture(); revoked.state.revokeAfterRepository = true;
  await assert.rejects(revoked.service.list(input), { code: 'SHOP_AUTH_INVALID' });
  assert.equal(revoked.state.calls.filter(([name]) => name === 'list').length, 1);
  const changed = fixture(); changed.state.changeModeAfterRepository = true;
  await assert.rejects(changed.service.read(input, { ticketId: '37' }),
    { code: 'SECURESHOP_FEATURE_MODE_STALE' });
  assert.equal(changed.state.calls.filter(([name]) => name === 'read').length, 1);
  const pre = fixture(); pre.state.revokedPersona = true;
  await assert.rejects(pre.service.list(input), { code: 'SHOP_AUTH_INVALID' });
  assert.equal(pre.state.calls.filter(([name]) => name === 'readRetained').length, 0);
  const staleMode = fixture(); staleMode.state.staleMode = true;
  await assert.rejects(staleMode.service.list(input), { code: 'SECURESHOP_FEATURE_MODE_STALE' });
  assert.equal(staleMode.state.calls.filter(([name]) => name === 'list').length, 0);
  const staleLaunch = fixture(); staleLaunch.state.revokedLaunch = true;
  await assert.rejects(staleLaunch.service.list(input), { code: 'STALE_LAUNCH' });
  assert.equal(staleLaunch.state.calls.filter(([name]) => name === 'capturePersona').length, 0);
  const retired = fixture(); retired.state.revokeLaunchAfterRepository = true;
  await assert.rejects(retired.service.read(input, { ticketId: '37' }), { code: 'STALE_LAUNCH' });
  assert.equal(retired.state.calls.filter(([name]) => name === 'read').length, 1);
});
