'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { randomUUID } = require('node:crypto');
const jwt = require('jsonwebtoken');
const { createSecureShopBoundPersonaAuth, ISSUER, AUDIENCE } =
  require('../server/services/secureshopBoundPersonaAuth');
const { createBoundCustomerChatRouter } = require('../server/routes/secureshop/boundCustomerChat');
const { createBoundRoleChatRouter } = require('../server/routes/secureshop/boundRoleChat');

const SECRET = 'controlled-role-isolation-secret-at-least-32-bytes';
const SESSION = '30000000-0000-4000-8000-000000000001';
const REQUEST = '40000000-0000-4000-8000-000000000001';
const BEARER_A = 'a'.repeat(43);
const BEARER_B = 'b'.repeat(43);
const original = Object.freeze({ launchId: '10000000-0000-4000-8000-000000000001',
  scenarioId: '20000000-0000-4000-8000-000000000001', generation: 1,
  platformOwnerId: 4, platformSessionId: 5 });
const foreign = Object.freeze({ ...original,
  launchId: '10000000-0000-4000-8000-000000000002',
  scenarioId: '20000000-0000-4000-8000-000000000002',
  platformOwnerId: 8, platformSessionId: 9 });
const actors = Object.freeze({ customer: { id: 6, username: 'student_customer' },
  merchant: { id: 7, username: 'student_merchant' },
  admin: { id: 8, username: 'student_admin' } });

function harness() {
  let current = original;
  const sessions = new Map(), calls = [];
  const launches = {
    async resolveCapability(value) { return value === BEARER_A ? current
      : value === BEARER_B ? foreign : null; },
    async assertCurrent(scope) {
      if (!Object.keys(current).every(key => current[key] === scope[key])
        && !Object.keys(foreign).every(key => foreign[key] === scope[key])) {
        throw Object.assign(Error('Stale launch'), { code: 'STALE_LAUNCH' });
      }
      return scope;
    },
  };
  const repository = Object.fromEntries(['findCredential', 'createSession',
    'extendSession', 'revokeSession', 'listSessions', 'revokeOwnedSession',
    'changePassword', 'readApiKey', 'rotateApiKey', 'authenticateApiKey']
    .map(name => [name, async () => { throw Error(`Unexpected ${name}`); }]));
  repository.readSession = async ({ jti, scope }) => {
    const row = sessions.get(jti);
    return row && row.active && Object.keys(row.scope).every(key =>
      row.scope[key] === scope[key]) ? row.session : null;
  };
  const auth = createSecureShopBoundPersonaAuth({ repository, launches,
    jwtSecret: SECRET });
  function issue(role, scope = original) {
    const actor = actors[role], jti = randomUUID();
    sessions.set(jti, { active: true, scope, session: {
      shop_user_id: actor.id, role, username: actor.username,
      email: `${role}@example.invalid`, session_id: SESSION,
      expires_at: new Date(Date.now() + 60000).toISOString(),
    } });
    const token = jwt.sign({ role, ss_launch_id: scope.launchId,
      ss_scenario_id: scope.scenarioId, ss_generation: scope.generation,
      ss_owner_id: scope.platformOwnerId,
      ss_platform_session_id: scope.platformSessionId }, SECRET,
    { algorithm: 'HS256', issuer: ISSUER, audience: AUDIENCE,
      subject: String(actor.id), jwtid: jti, expiresIn: 60 });
    return { token, revoke() { sessions.get(jti).active = false; } };
  }
  const runtime = Object.fromEntries(['createSession', 'run', 'readRequest',
    'confirmProfile', 'confirmInventory', 'confirmPricing', 'confirmListing',
    'readListing', 'confirmListingCreate', 'readListingCreate', 'confirmMail',
    'readMailOperation', 'confirmUserAdministration', 'confirmPolicy',
    'confirmMcpRegistry', 'confirmSystemRestart', 'confirmAcl', 'runAuditJob',
    'readAuditJob', 'readAuditOperation', 'readSystemConfigOperation']
    .map(name => [name, async (...args) => {
      calls.push({ name, args });
      if (name === 'createSession') return { id: SESSION };
      if (name === 'readRequest') return { status: 'completed', text: 'Owned saved turn' };
      throw Error(`Unexpected ${name}`);
    }]));
  const routers = {
    customer: createBoundCustomerChatRouter({ launches,
      authenticatePersona: auth.authenticatePersona, runtime }),
    merchant: createBoundRoleChatRouter({ role: 'merchant', launches,
      authenticatePersona: auth.authenticatePersona, runtime }),
    admin: createBoundRoleChatRouter({ role: 'admin', launches,
      authenticatePersona: auth.authenticatePersona, runtime }),
  };
  return { calls, issue, routers, advanceGeneration() {
    current = { ...original, generation: original.generation + 1 };
  } };
}

function invoke(router, role, method, action, { token, launch = BEARER_A } = {}) {
  const prefix = role === 'customer' ? '/agents/customer'
    : `/agents/${role}/assistant`;
  const routePath = action === 'session' ? `${prefix}/session`
    : `${prefix}/operations/:sessionId/:requestId`;
  const route = router.stack.find(layer => layer.route?.path === routePath
    && layer.route.methods[method])?.route;
  assert.ok(route, `production ${role} ${action} route required`);
  const request = new EventEmitter();
  request.headers = { 'x-dvaia-secureshop-launch': launch,
    ...(token ? { authorization: `Bearer ${token}` } : {}) };
  request.rawHeaders = ['x-dvaia-secureshop-launch', launch,
    ...(token ? ['authorization', `Bearer ${token}`] : [])];
  request.query = {}; request.body = action === 'session' ? {} : undefined;
  request.params = action === 'saved' ? { sessionId: SESSION, requestId: REQUEST } : {};
  request.get = name => request.headers[name.toLowerCase()];
  request.is = type => type === 'application/json';
  const response = new EventEmitter();
  response.statusCode = 200; response.writableEnded = false;
  response.setHeader = () => {};
  response.set = () => response;
  response.status = code => { response.statusCode = code; return response; };
  return new Promise((resolve, reject) => {
    response.json = body => { response.writableEnded = true;
      resolve({ status: response.statusCode, body }); return response; };
    let index = 0;
    const next = error => {
      if (error) return reject(Error(`Unexpected route fallthrough: ${error}`));
      const handler = route.stack[index++]?.handle;
      if (!handler) return reject(Error('Production route did not respond'));
      try { Promise.resolve(handler(request, response, next)).catch(reject); }
      catch (failure) { reject(failure); }
    };
    next();
  });
}

test('Q07 customer, merchant and admin chat routes reject role, tenant, stale and revoked authority before any tool/runtime read', async () => {
  for (const role of Object.keys(actors)) {
    const f = harness(), own = f.issue(role), other = f.issue(
      role === 'customer' ? 'merchant' : 'customer');
    const foreignToken = f.issue(role, foreign);
    const platformOnly = jwt.sign({ role, sub: String(actors[role].id) }, SECRET,
      { issuer: 'controlled-platform', audience: 'platform-session', expiresIn: 60 });
    const read = input => invoke(f.routers[role], role, 'get', 'saved', input);
    const start = input => invoke(f.routers[role], role, 'post', 'session', input);
    for (const input of [{ token: other.token }, { token: own.token, launch: BEARER_B },
      { token: foreignToken.token }, { token: platformOnly }, {}]) {
      for (const action of [start, read]) {
        const value = await action(input);
        assert.ok([401, 403].includes(value.status), `${role}: denied authority`);
        assert.equal(f.calls.length, 0, `${role}: denied before runtime`);
      }
    }
    assert.equal((await start({ token: own.token })).status, 200);
    assert.equal((await read({ token: own.token })).status, 200);
    assert.deepEqual(f.calls.map(call => call.name), ['createSession', 'readRequest']);
    f.calls.length = 0;
    own.revoke();
    assert.equal((await start({ token: own.token })).status, 401);
    assert.equal((await read({ token: own.token })).status, 401);
    assert.equal(f.calls.length, 0, `${role}: revoked before runtime`);
    const renewed = f.issue(role);
    f.advanceGeneration();
    assert.equal((await start({ token: renewed.token })).status, 401);
    assert.equal((await read({ token: renewed.token })).status, 401);
    assert.equal(f.calls.length, 0, `${role}: stale generation before runtime`);
  }
});
