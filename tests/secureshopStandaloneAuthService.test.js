'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const bcrypt = require('bcryptjs');
const { createSecureShopStandaloneAuthService,
  assertSecureShopStandalonePrincipal,
  assertSecureShopStandaloneAuthPrincipal } = require('../server/services/secureshopStandaloneAuth');
const { createSecureShopStandaloneAuthRepository } = require('../server/database/postgres/secureshopStandaloneAuthRepository');
const { createSecureShopStandaloneBootstrap } = require('../server/services/secureshopStandaloneBootstrap');
const { projectBootstrap } = require('../server/routes/secureshopStandaloneAuth');

function fixture(options = {}) {
  let nextSession = 100, nextToken = 0;
  const sessions = new Map(), executions = new Map(), calls = [];
  let principal;
  const row = session => ({ principalId: principal.principalId, ownerId: 90,
    shopUserId: 1000000001, username: principal.username, email: principal.email,
    role: principal.role, credentialVersion: principal.credentialVersion,
    authorityVersion: principal.authorityVersion, sessionId: session.id,
    expiresAt: session.expiresAt });
  const repository = {
    async registerWithSession(input) {
      principal = { ...input, credentialVersion: '1', authorityVersion: '1' };
      const session = { id: ++nextSession, expiresAt: input.expiresAt };
      sessions.set(input.tokenHash, session); return row(session);
    },
    async findCredential(username) {
      return principal?.username === username ? { ...principal, isActive: true,
        lockedUntil: null } : null;
    },
    async recordFailedLogin(id) { calls.push(['failed', id]); },
    async createSession(input) {
      assert.equal(input.principalId, principal.principalId);
      const session = { id: ++nextSession, expiresAt: input.expiresAt };
      sessions.set(input.tokenHash, session); return row(session);
    },
    async readCurrentSession(hash) { return sessions.has(hash) ? row(sessions.get(hash)) : null; },
    async readOrCreateDefaultExecutionSession(input) {
      const auth = [...sessions.values()].find(session => session.id === input.authSessionId);
      if (!auth || input.principalId !== principal.principalId) {
        throw Object.assign(new Error(), { code: 'SHOP_AUTH_INVALID' });
      }
      if (!executions.has(auth.id)) executions.set(auth.id, ++nextSession);
      return { ...row(auth), principalOwnerId: 90, ownerId: 500,
        authSessionId: auth.id, sessionId: executions.get(auth.id),
        tenantId: 'af8ea882-bcde-4123-8e11-321ef739daca', membershipVersion: '1' };
    },
    async rotateSession(input) {
      if (!sessions.has(input.tokenHash)) return null;
      sessions.delete(input.tokenHash);
      const session = { id: ++nextSession, expiresAt: input.expiresAt };
      sessions.set(input.newTokenHash, session); return row(session);
    },
    async revokeSession(hash) { return sessions.delete(hash); },
    async readCredentialForSession(hash) {
      return sessions.has(hash) ? { ...row(sessions.get(hash)),
        passwordHash: principal.passwordHash } : null;
    },
    async changePassword(input) {
      if (!sessions.has(input.tokenHash)
          || input.credentialVersion !== principal.credentialVersion) {
        throw Object.assign(new Error(), { code: 'SHOP_AUTH_INVALID' });
      }
      principal.passwordHash = input.passwordHash;
      principal.credentialVersion = String(Number(principal.credentialVersion) + 1);
      principal.authorityVersion = String(Number(principal.authorityVersion) + 1);
      sessions.clear(); return true;
    },
    async revokeAll() { const count = sessions.size; sessions.clear(); return count; },
  };
  const service = createSecureShopStandaloneAuthService({ repository,
    randomBytes: () => Buffer.alloc(32, ++nextToken),
    hashPassword: async value => `hash:${value}`,
    comparePassword: async (value, hash) => {
      calls.push(['compare', bcrypt.getRounds(hash) || 0]);
      return hash === `hash:${value}`;
    },
    ...options,
  });
  return { service, calls, sessions };
}

test('standalone bootstrap serializes PostgreSQL Date timestamps for strict HTTP projection', async () => {
  const { service } = fixture();
  const account = await service.register({ username: 'alice', email: 'alice@shop.test',
    password: 'password123', role: 'customer' });
  const expiry = new Date(Date.now() + 600000);
  const bootstrap = createSecureShopStandaloneBootstrap({ authService: service,
    launches: { async issueOrRenew() { return { bearer: 'x'.repeat(43), binding: {
      launchId: 'af8ea882-bcde-4123-8e11-321ef739daca', generation: 1,
      credentialVersion: 1, expiresAt: expiry } }; } },
    personaAuth: { async establishSession() { return { token: 'header.payload.signature',
      expiresAt: expiry, user: account.user }; } },
  });
  const result = projectBootstrap(await bootstrap(account.context));
  assert.equal(result.launch.expiresAt, expiry.toISOString());
  assert.equal(result.persona.expiresAt, expiry.toISOString());
});

test('standalone shop auth creates branded context and renews into a new execution session', async () => {
  const { service } = fixture();
  const registered = await service.register({ username: ' Alice_123 ',
    email: ' Alice@Example.test ', password: 'password123', role: 'customer' });
  assert.equal(registered.user.username, 'alice_123');
  assert.equal(registered.user.email, 'alice@example.test');
  assert.equal(registered.token.length, 43);
  assert.equal(registered.context.launchBearer.length, 43);
  assert.equal(assertSecureShopStandaloneAuthPrincipal(registered.context), registered.context);
  assert.throws(() => assertSecureShopStandalonePrincipal(registered.context),
    error => error.code === 'SHOP_AUTH_INVALID');
  assert.throws(() => assertSecureShopStandalonePrincipal({ ...registered.context }),
    error => error.code === 'SHOP_AUTH_INVALID');
  const repeated = await service.authenticate(registered.token);
  assert.equal(repeated.launchBearer, registered.context.launchBearer);
  const tenant = await service.establishTenantContext(repeated);
  const repeatedTenant = await service.establishTenantContext(repeated);
  assert.equal(assertSecureShopStandalonePrincipal(tenant), tenant);
  assert.equal(tenant.ownerId, 500);
  assert.equal(tenant.principalOwnerId, registered.context.ownerId);
  assert.equal(tenant.authSessionId, registered.context.sessionId);
  assert.equal(tenant.sessionId, repeatedTenant.sessionId);
  assert.equal(tenant.launchBearer, repeatedTenant.launchBearer);
  const sibling = await service.login({ username: 'ALICE_123', password: 'password123' });
  const renewed = await service.renew(registered.token);
  assert.notEqual(renewed.context.sessionId, registered.context.sessionId);
  assert.notEqual(renewed.context.launchBearer, registered.context.launchBearer);
  const renewedTenant = await service.establishTenantContext(renewed.context);
  assert.notEqual(renewedTenant.sessionId, tenant.sessionId);
  assert.notEqual(renewedTenant.launchBearer, tenant.launchBearer);
  assert.equal(await service.authenticate(registered.token), null);
  assert.equal((await service.authenticate(sibling.token)).sessionId, sibling.context.sessionId);
  assert.equal((await service.authenticate(renewed.token)).sessionId, renewed.context.sessionId);
});

test('shop registration blocks admin and bcrypt truncation; absent users use equal-cost comparison', async () => {
  const { service, calls } = fixture();
  await assert.rejects(service.register({ username: 'adminnew', email: 'a@b.test',
    password: 'password123', role: 'admin' }), error => error.code === 'INVALID_ARGUMENT');
  await assert.rejects(service.register({ username: 'customernew', email: 'a@b.test',
    password: 'x'.repeat(73), role: 'customer' }), error => error.code === 'INVALID_ARGUMENT');
  await assert.rejects(service.login({ username: 'nobody', password: 'password123' }),
    error => error.code === 'SHOP_CREDENTIALS_INVALID');
  assert.deepEqual(calls.at(-1), ['compare', 12]);
});

test('password change checks the current secret and revokes every shop session', async () => {
  const { service } = fixture();
  const first = await service.register({ username: 'alice', email: 'alice@shop.test',
    password: 'password123', role: 'customer' });
  const sibling = await service.login({ username: 'alice', password: 'password123' });
  await assert.rejects(service.changePassword(first.token, { currentPassword: 'wrongpassword',
    newPassword: 'replacement123' }), error => error.code === 'SHOP_CREDENTIALS_INVALID');
  assert.deepEqual(await service.changePassword(first.token, { currentPassword: 'password123',
    newPassword: 'replacement123' }), { ok: true, passwordChanged: true });
  assert.equal(await service.authenticate(first.token), null);
  assert.equal(await service.authenticate(sibling.token), null);
  await assert.rejects(service.login({ username: 'alice', password: 'password123' }),
    error => error.code === 'SHOP_CREDENTIALS_INVALID');
  const next = await service.login({ username: 'alice', password: 'replacement123' });
  assert.ok(next.context.sessionId > sibling.context.sessionId);
});

test('trusted execution tenant selector is a validated constructor option', () => {
  const pool = { query() {}, connect() {} };
  assert.throws(() => createSecureShopStandaloneAuthRepository({ pool,
    executionTenantSlug: 'default\' OR true --' }), TypeError);
  assert.throws(() => createSecureShopStandaloneAuthRepository({ pool,
    executionTenantSlug: '' }), TypeError);
  assert.ok(createSecureShopStandaloneAuthRepository({ pool,
    executionTenantSlug: 'fixture_second' }));
});

for (const [name,options,seconds] of [['default',{},14400],['shortened',{sessionTtlSeconds:120},120]]) {
  test(`shop ${name} lifetime applies equally to registration, login and renewal`,async()=>{
    let clock=Date.parse('2026-10-10T00:00:00.123Z');
    const {service}=fixture({...options,now:()=>clock});
    const expected=()=>new Date(clock+seconds*1000).toISOString();
    const registered=await service.register({username:'alice',email:'alice@shop.test',password:'password123',role:'customer'});
    assert.equal(registered.expiresAt,expected());
    clock+=10000;
    const logged=await service.login({username:'alice',password:'password123'});
    assert.equal(logged.expiresAt,expected());
    const execution=await service.establishTenantContext(logged.context);
    assert.equal(execution.expiresAt,logged.expiresAt);
    clock+=10000;
    const renewed=await service.renew(logged.token);
    assert.equal(renewed.expiresAt,expected());
    assert.equal(await service.authenticate(logged.token),null);
    assert.equal((await service.authenticate(renewed.token)).expiresAt,expected());
  });
}
test('shop constructor rejects invalid or extending lifetime policy',()=>{
  for(const sessionTtlSeconds of [0,60,119,14401,Infinity,NaN,120.5,'120',null]) {
    assert.throws(()=>fixture({sessionTtlSeconds}),{code:'INVALID_CONFIGURATION'});
  }
});
