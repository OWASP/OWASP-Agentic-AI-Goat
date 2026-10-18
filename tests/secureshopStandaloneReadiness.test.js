'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { standaloneReadiness, mountedReadiness, createRouter } = require('../server/routes/secureshopRuntimeReadiness');
const methods = names => Object.fromEntries(names.split(' ').map(name => [name, () => {}]));
function core() {
  return {
    standaloneAuth: { service: methods('authenticate register login renew logout changePassword establishTenantContext'),
      bootstrap() {}, cartImport() {}, reset: methods('readiness reset readRecovery recover'),
      registeredAdminReset: methods('preview reset read reveal acknowledge'), mode: methods('get set'),
      assessmentObjectives: methods('list set'), assessmentRecovery: methods('list retry') },
    publicCatalog: methods('browse product related categories reviews'),
    catalog: methods('listProducts getProduct listMerchantProducts categories createMerchantProduct updateMerchantProduct archiveMerchantProduct'),
    commerce: methods('cart add update remove summary checkout orders order'),
    account: methods('profile updateProfile addresses createAddress updateAddress deleteAddress'),
    admin: methods('users kpis'), personaAuth: methods('authenticatePersona'), router() {}, browserRouter() {},
  };
}
test('standalone core has separate readiness without unrequested teaching panels', () => {
  const value = standaloneReadiness(core());
  assert.equal(value.scope, 'standalone'); assert.equal(value.ready, true);
  assert.equal(value.panels, undefined); assert.ok(Object.isFrozen(value.checks));
  assert.throws(() => mountedReadiness(core()), /panel readiness incomplete/);
});
test('standalone readiness denies incomplete auth, reset, recovery and basic commerce', () => {
  for (const [group, name] of [['service', 'authenticate'], ['reset', 'readRecovery'],
    ['registeredAdminReset', 'reveal'], ['assessmentRecovery', 'list']]) {
    const c = core(); delete c.standaloneAuth[group][name];
    assert.throws(() => standaloneReadiness(c), /core readiness incomplete/);
  }
  for (const [group, name] of [['publicCatalog', 'browse'], ['commerce', 'checkout'], ['account', 'profile']]) {
    const c = core(); delete c[group][name];
    assert.throws(() => standaloneReadiness(c), /core readiness incomplete/);
  }
});
test('every explicitly requested optional panel must actually be ready', () => {
  for (const [flag, key] of [['personaInboxFeature', 'personaInbox'], ['mcpTrustFeature', 'mcpTrust'], ['ssrfFeature', 'ssrf']]) {
    const c = core(); assert.throws(() => standaloneReadiness(c, { [flag]: true }), /incomplete/);
    c[key] = { ready: true, router() {} };
    assert.equal(standaloneReadiness(c, { [flag]: true }).ready, true);
  }
});
test('full readiness endpoint refuses standalone projection', () => {
  const router = createRouter({ authenticateToken() {}, requireAdminLevel: () => () => {}, getReadiness: () => standaloneReadiness(core()) });
  const handler = router.stack.find(layer => layer.route)?.route.stack[0].handle;
  let status; let body;
  const res = { set() {}, status(value) { status = value; return this; }, json(value) { body = value; } };
  handler({}, res); assert.equal(status, 503); assert.match(body.error, /unavailable/);
});
