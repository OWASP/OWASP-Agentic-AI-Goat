'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createSecureShopBoundPersonaAuth, ISSUER, AUDIENCE } = require(
  '../server/services/secureshopBoundPersonaAuth');
const { createSecureShopStandaloneAuthService } = require(
  '../server/services/secureshopStandaloneAuth');

const scope = Object.freeze({ launchId: '10000000-0000-4000-8000-000000000082',
  scenarioId: '20000000-0000-4000-8000-000000000082', generation: 5,
  platformOwnerId: 82, platformSessionId: 802 });
const sessionManagement = Object.freeze({
  async listSessions() { return []; },
  async revokeOwnedSession() { return false; },
  async changePassword() { return null; },
  async readApiKey() { return null; },
  async rotateApiKey() { return null; },
  async authenticateApiKey() { return null; },
});

test('standalone bootstrap reuses the persona JTI while re-signing a valid JWT at a later clock', async () => {
  const originalNow = Date.now;
  let clock = 1792750000000;
  Date.now = () => clock;
  try {
    const expiry = new Date(clock + 3600000).toISOString();
    const authRepository = {
      registerWithSession: async input => ({ principalId: input.principalId, ownerId: 82,
        shopUserId: 1000000001, username: input.username, email: input.email,
        role: input.role, credentialVersion: '1', authorityVersion: '1',
        sessionId: 802, expiresAt: input.expiresAt }),
      async readOrCreateDefaultExecutionSession(input) { return {
        principalId: input.principalId, principalOwnerId: 82, ownerId: 82,
        authSessionId: 802, sessionId: 802, tenantId: scope.launchId,
        membershipVersion: '1', shopUserId: 1000000001,
        username: 'avatar_customer', email: 'avatar@example.invalid', role: 'customer',
        credentialVersion: '1', authorityVersion: '1', expiresAt: expiry,
      }; },
    };
    for (const name of ['findCredential', 'recordFailedLogin', 'createSession',
      'readCurrentSession', 'rotateSession', 'revokeSession', 'readCredentialForSession',
      'changePassword', 'revokeAll']) authRepository[name] = async () => null;
    const standalone = createSecureShopStandaloneAuthService({ repository: authRepository,
      now: () => clock, randomBytes: () => Buffer.alloc(32, 0x41),
      hashPassword: async () => 'controlled-hash' });
    const registered = await standalone.register({ username: 'avatar_customer',
      email: 'avatar@example.invalid', password: 'controlled-password', role: 'customer' });
    assert.match(registered.context.principalId, /^[a-f0-9-]{36}$/);
    const principal = await standalone.establishTenantContext(registered.context);
    const actor = { id: 1000000001, username: 'avatar_customer',
      email: 'avatar@example.invalid', role: 'customer', full_name: null, phone: null };
    const sessionId = '40000000-0000-4000-8000-000000000082';
    const jti = '50000000-0000-4000-8000-000000000082';
    let creates = 0;
    const authority = { async read() { return { role: 'customer', authority_version: '1' }; } };
    const repository = {
      ...sessionManagement,
      candidatePersonaAuthority: authority,
      async findCredential() { return null; },
      async findCredentialById() { return actor; },
      async ensureStandaloneActor() { return actor; },
      async createSession() { creates++; return { sessionId, jti, expiresAt: expiry,
        reused: creates > 1 }; },
      async readSession() { return { session_id: sessionId, shop_user_id: actor.id,
        username: actor.username, email: actor.email, role: actor.role,
        full_name: null, phone: null, expires_at: expiry }; },
      async extendSession() { return null; }, async revokeSession() { return true; },
    };
    const persona = createSecureShopBoundPersonaAuth({ repository, personaAuthority: authority,
      launches: { async assertCurrent() { return { expiresAt: expiry }; } },
      jwtSecret: 'owned-bound-persona-secret-at-least-32-bytes', now: () => clock });
    const first = await persona.establishSession({ scope, shopPrincipal: principal });
    clock += 2000;
    const second = await persona.establishSession({ scope, shopPrincipal: principal });
    assert.equal(creates, 2);
    assert.notEqual(first.token, second.token, 'a re-signed JWT need not retain its bytes');
    const firstClaims = jwt.verify(first.token, 'owned-bound-persona-secret-at-least-32-bytes',
      { issuer: ISSUER, audience: AUDIENCE });
    const secondClaims = jwt.verify(second.token, 'owned-bound-persona-secret-at-least-32-bytes',
      { issuer: ISSUER, audience: AUDIENCE });
    assert.equal(firstClaims.jti, secondClaims.jti);
    assert.equal(firstClaims.ss_launch_id, secondClaims.ss_launch_id);
    assert.equal(firstClaims.ss_platform_session_id, secondClaims.ss_platform_session_id);
    assert.notEqual(firstClaims.iat, secondClaims.iat);
    assert.equal((await persona.authenticateBoundToken({ scope, token: first.token })).sessionId,
      sessionId);
    assert.equal((await persona.authenticateBoundToken({ scope, token: second.token })).sessionId,
      sessionId);
  } finally { Date.now = originalNow; }
});

test('real credential verification issues a launch-bound durable persona token', async () => {
  const password = 'owned-persona-password';
  const hash = await bcrypt.hash(password, 4);
  const sessions = new Map(); let checks = 0; let sequence = 0;
  const user = { id: 12, username: 'student_merchant', email: 'merchant@owned.invalid',
    password: hash, role: 'merchant', full_name: 'Student Merchant', phone: null, banned_at: null };
  const repository = {
    ...sessionManagement,
    findCredential: async username => username === user.username ? user : null,
    readPersona: async id => id === user.id ? user : null,
    async createSession(value) { sessions.set(value.jti, value); },
    async readSession({ jti }) { const value = sessions.get(jti); return value && {
      session_id: value.sessionId, shop_user_id: value.persona.id, username: value.persona.username,
      email: value.persona.email, role: value.persona.role,
      full_name: value.persona.full_name, phone: value.persona.phone, expires_at: value.expiresAt,
    }; },
    async extendSession({ jti, expiresAt }) {
      const value = sessions.get(jti); if (!value) return null;
      value.expiresAt = new Date(Math.max(Date.parse(value.expiresAt), Date.parse(expiresAt))).toISOString();
      return { session_id: value.sessionId, shop_user_id: value.persona.id, username: value.persona.username,
        email: value.persona.email, role: value.persona.role, full_name: value.persona.full_name,
        phone: value.persona.phone, expires_at: value.expiresAt };
    },
    async revokeSession({ jti }) { return sessions.delete(jti); },
  };
  const auth = createSecureShopBoundPersonaAuth({ repository,
    launches: { async assertCurrent(value) { checks++; return { ...value,
      expiresAt: new Date(Date.now() + 3600000) }; } },
    jwtSecret: 'owned-bound-persona-secret-at-least-32-bytes',
    randomId: () => `00000000-0000-4000-8000-${String(++sequence).padStart(12, '0')}` });
  const login = await auth.login({ scope, username: user.username, password,
    ip: '127.0.0.1', userAgent: 'Controlled Browser' });
  assert.equal(login.user.role, 'merchant');
  assert.equal(sessions.size, 1);
  assert.deepEqual([...sessions.values()].map(value => [value.ip, value.userAgent]),
    [['127.0.0.1', 'Controlled Browser']]);
  assert.equal(checks, 2);

  const request = { ssLaunch: scope, headers: { authorization: `Bearer ${login.token}` },
    get(name) { return this.headers[name.toLowerCase()]; } };
  const response = { statusCode: 200, status(value) { this.statusCode = value; return this; },
    json(value) { this.body = value; } };
  await new Promise((resolve, reject) => auth.authenticatePersona(request, response,
    error => error ? reject(error) : resolve()));
  assert.deepEqual(request.ssUser, { id: 12, username: 'student_merchant',
    email: 'merchant@owned.invalid', role: 'merchant', full_name: 'Student Merchant', phone: null });
  assert.deepEqual(request.ssPersonaSession, { sessionId: [...sessions.values()][0].sessionId,
    expiresAt: [...sessions.values()][0].expiresAt });
  assert.equal(checks, 4);
  const renewed = await auth.renew({ scope, token: login.token });
  assert.equal(renewed.user.role, 'merchant');
  assert.equal(require('jsonwebtoken').decode(renewed.token).jti,
    require('jsonwebtoken').decode(login.token).jti);
  assert.ok(Date.parse(renewed.expiresAt) >= Date.parse(login.expiresAt));
  assert.deepEqual(await auth.logout({ scope, token: login.token }), { ok: true });
  assert.equal(sessions.size, 0);
});

test('tokens cannot cross launch owners and stale issuance is revoked before publication', async () => {
  const hash = await bcrypt.hash('password', 4); let created; let revoked = false; let checks = 0;
  const repository = {
    ...sessionManagement,
    findCredential: async () => ({ id: 11, username: 'student_customer', email: 'c@owned.invalid',
      password: hash, role: 'customer', banned_at: null }),
    readPersona: async () => null,
    async createSession(value) { created = value; },
    async readSession() { return null; },
    async extendSession() { return null; },
    async revokeSession() { revoked = true; return true; },
  };
  const auth = createSecureShopBoundPersonaAuth({ repository,
    launches: { async assertCurrent(value) {
      checks++;
      if (checks === 2) throw Object.assign(new Error('stale'), { code: 'STALE_LAUNCH' });
      return { ...value, expiresAt: new Date(Date.now() + 3600000) };
    } }, jwtSecret: 'owned-bound-persona-secret-at-least-32-bytes' });
  await assert.rejects(auth.login({ scope, username: 'student_customer', password: 'password' }),
  { code: 'STALE_LAUNCH' });
  assert.ok(created);
  assert.equal(revoked, true);
});

test('API-key service binds listing, rotation and authentication to the trusted launch tuple', async () => {
  const calls = []; let checks = 0;
  const customer = { id: 12, username: 'student_customer', email: 'customer@owned.invalid',
    role: 'customer', full_name: 'Student Customer', phone: null };
  const repository = {
    ...sessionManagement,
    async findCredential() { return null; }, async createSession() {}, async readSession() { return null; },
    async extendSession() { return null; }, async revokeSession() {},
    async readApiKey(input) { calls.push(['read', input]); return { apiKey:
      'sk_ss_live_11111111111111111111111111111111', version: 1,
      createdAt: '2026-09-18T00:00:00.000Z', rotatedAt: '2026-09-18T00:00:00.000Z' }; },
    async rotateApiKey(input) { calls.push(['rotate', input]); return { apiKey: input.nextKey,
      version: 2, createdAt: '2026-09-18T00:00:00.000Z',
      rotatedAt: '2026-09-18T00:01:00.000Z' }; },
    async authenticateApiKey(input) { calls.push(['authenticate', input]);
      return input.presentedKey === 'sk_ss_live_22222222222222222222222222222222'
        ? { ...customer, apiKeyVersion: 2 } : null; },
  };
  const auth = createSecureShopBoundPersonaAuth({ repository,
    launches: { async assertCurrent(value) { checks++; return value; } },
    jwtSecret: 'owned-bound-persona-secret-at-least-32-bytes',
    randomKeyBytes: size => { assert.equal(size, 16); return Buffer.alloc(16, 0x22); } });
  assert.deepEqual(await auth.listApiKey({ scope, shopPersona: customer }), {
    api_key: 'sk_ss_live_11111111111111111111111111111111',
    created_at: '2026-09-18T00:00:00.000Z', version: 1,
  });
  assert.deepEqual(await auth.rotateApiKey({ scope, shopPersona: customer }), {
    ok: true, api_key: 'sk_ss_live_22222222222222222222222222222222',
    created_at: '2026-09-18T00:00:00.000Z', version: 2,
  });
  assert.deepEqual(await auth.authenticateApiKey({ scope,
    presentedKey: 'sk_ss_live_22222222222222222222222222222222' }), {
    user: customer, apiKeyVersion: 2,
  });
  assert.equal(checks, 6);
  for (const call of calls) assert.deepEqual(call[1].scope, scope);
  assert.deepEqual(calls.map(call => call[0]), ['read', 'rotate', 'authenticate']);
});

test('API-key service rejects malformed and foreign keys without changing trusted scope', async () => {
  let storageCalls = 0;
  const repository = {
    ...sessionManagement,
    async findCredential() { return null; }, async createSession() {}, async readSession() { return null; },
    async extendSession() { return null; }, async revokeSession() {},
    async authenticateApiKey() { storageCalls++; return null; },
  };
  const auth = createSecureShopBoundPersonaAuth({ repository,
    launches: { async assertCurrent(value) { return value; } },
    jwtSecret: 'owned-bound-persona-secret-at-least-32-bytes' });
  for (const presentedKey of ['bad', 'sk_ss_live_' + 'A'.repeat(32),
    'sk_ss_live_' + '1'.repeat(33), true]) {
    await assert.rejects(auth.authenticateApiKey({ scope, presentedKey }),
      { code: 'SHOP_API_KEY_INVALID' });
  }
  await assert.rejects(auth.authenticateApiKey({ scope,
    presentedKey: 'sk_ss_live_' + '1'.repeat(32) }), { code: 'SHOP_API_KEY_INVALID' });
  assert.equal(storageCalls, 1);
});

test('persona middleware marks only trusted launch invalidation, never shop token or owner failures', async () => {
  const secret = 'owned-bound-persona-secret-at-least-32-bytes';
  const validToken = jwt.sign({ role: 'customer', username: 'student_customer',
    ss_launch_id: scope.launchId, ss_scenario_id: scope.scenarioId, ss_generation: scope.generation,
    ss_owner_id: scope.platformOwnerId, ss_platform_session_id: scope.platformSessionId }, secret, {
    algorithm: 'HS256', issuer: ISSUER, audience: AUDIENCE, subject: '12', jwtid: 'valid-jti',
    expiresIn: 3600,
  });
  for (const [code, token, marked] of [
    ['STALE_LAUNCH', validToken, true],
    ['SESSION_UNAVAILABLE', validToken, true],
    ['OWNER_MISMATCH', validToken, false],
    ['SHOP_AUTH_INVALID', 'not-a-token', false],
  ]) {
    const auth = createSecureShopBoundPersonaAuth({
      repository: { ...sessionManagement, async findCredential() { return null; }, async createSession() {},
        async readSession() { throw new Error('storage should not run'); },
        async extendSession() {}, async revokeSession() {} },
      launches: { async assertCurrent() { throw Object.assign(new Error('private'), { code }); } },
      jwtSecret: secret,
    });
    const req = { ssLaunch: scope, headers: { authorization: `Bearer ${token}` },
      get(name) { return this.headers[name.toLowerCase()]; } };
    const res = { headers: {}, setHeader(name, value) { this.headers[name] = value; },
      status(value) { this.statusCode = value; return this; } };
    await new Promise((resolve, reject) => {
      res.json = value => { res.body = value; resolve(); return res; };
      auth.authenticatePersona(req, res, reject);
    });
    assert.equal(res.statusCode, 401);
    assert.equal(res.headers['X-DVAIA-SecureShop-Launch-State'], marked ? 'unavailable' : undefined);
  }
});

test('bound login admits only the three synthetic workshop personas', async () => {
  const password = 'password'; const hash = await bcrypt.hash(password, 4); let created = 0;
  const repository = {
    ...sessionManagement,
    findCredential: async () => ({ id: 5, username: 'student_m', email: 'legacy@owned.invalid',
      password: hash, role: 'merchant', banned_at: null }), readPersona: async () => null,
    async createSession() { created++; }, async readSession() { return null; },
    async extendSession() { return null; }, async revokeSession() {},
    async changePassword() { return null; },
  };
  const auth = createSecureShopBoundPersonaAuth({ repository,
    launches: { async assertCurrent(value) { return { ...value,
      expiresAt: new Date(Date.now() + 3600000) }; } },
    jwtSecret: 'owned-bound-persona-secret-at-least-32-bytes' });
  await assert.rejects(auth.login({ scope, username: 'student_m', password }),
  { code: 'SHOP_CREDENTIALS_INVALID' });
  assert.equal(created, 0);
});

test('a reset winning after expiry extension revokes the same JTI before refresh publication', async () => {
  const password = 'password'; const hash = await bcrypt.hash(password, 4);
  let stored; let revoked = false; let checks = 0;
  const user = { id: 14, username: 'student_customer', email: 'c@owned.invalid',
    password: hash, role: 'customer', full_name: null, phone: null };
  const repository = {
    ...sessionManagement,
    async findCredential() { return user; },
    async createSession(value) { stored = value; },
    async readSession() { return { session_id: stored.sessionId, shop_user_id: user.id, username: user.username,
      email: user.email, role: user.role, full_name: null, phone: null,
      expires_at: stored.expiresAt }; },
    async extendSession({ expiresAt }) { stored.expiresAt = expiresAt; return {
      session_id: stored.sessionId, shop_user_id: user.id, username: user.username, email: user.email, role: user.role,
      full_name: null, phone: null, expires_at: expiresAt,
    }; },
    async revokeSession() { revoked = true; return true; },
  };
  const launches = { async assertCurrent(value) {
    checks++;
    if (checks === 4) throw Object.assign(new Error('retired'), { code: 'STALE_LAUNCH' });
    return { ...value, expiresAt: new Date(Date.now() + 3600000) };
  } };
  const auth = createSecureShopBoundPersonaAuth({ repository, launches,
    jwtSecret: 'owned-bound-persona-secret-at-least-32-bytes' });
  const login = await auth.login({ scope, username: user.username, password });
  await assert.rejects(auth.renew({ scope, token: login.token }), { code: 'STALE_LAUNCH' });
  assert.equal(revoked, true);
});

test('an expired original JWT cannot extend its durable session', async () => {
  const secret = 'owned-bound-persona-secret-at-least-32-bytes'; let extensions = 0;
  const repository = { ...sessionManagement, async findCredential() { return null; }, async createSession() {},
    async readSession() { throw new Error('expired token reached storage'); },
    async extendSession() { extensions++; }, async revokeSession() {} };
  const auth = createSecureShopBoundPersonaAuth({ repository,
    launches: { async assertCurrent() { throw new Error('expired token reached launch'); } }, jwtSecret: secret });
  const token = jwt.sign({ role: 'customer', username: 'student_customer',
    ss_launch_id: scope.launchId, ss_scenario_id: scope.scenarioId, ss_generation: scope.generation,
    ss_owner_id: scope.platformOwnerId, ss_platform_session_id: scope.platformSessionId }, secret, {
    algorithm: 'HS256', issuer: ISSUER, audience: AUDIENCE, subject: '12', jwtid: 'expired-jti',
    expiresIn: -1,
  });
  await assert.rejects(auth.renew({ scope, token }), { code: 'SHOP_AUTH_INVALID' });
  assert.equal(extensions, 0);
});

test('session inventory and revocation use authenticated scope, persona and current session identity', async () => {
  const current = '30000000-0000-4000-8000-000000000082';
  const other = '40000000-0000-4000-8000-000000000082';
  const calls = []; let checks = 0;
  const repository = {
    ...sessionManagement,
    async findCredential() { return null; }, async createSession() {}, async readSession() { return null; },
    async extendSession() { return null; }, async revokeSession() {},
    async changePassword() { return null; },
    async listSessions(input) { calls.push(['list', input]); return [
      { id: other, user_agent: null, ip: null, created_at: '2026-09-18T00:00:00.000Z',
        last_seen_at: '2026-09-18T00:01:00.000Z', is_current: false },
      { id: current, user_agent: 'Controlled Browser', ip: '127.0.0.1',
        created_at: '2026-09-18T00:00:00.000Z', last_seen_at: '2026-09-18T00:02:00.000Z',
        is_current: true },
    ]; },
    async revokeOwnedSession(input) { calls.push(['revoke', input]); return input.sessionId === other; },
  };
  const auth = createSecureShopBoundPersonaAuth({ repository,
    launches: { async assertCurrent(value) { checks++; return value; } },
    jwtSecret: 'owned-bound-persona-secret-at-least-32-bytes' });
  const shopPersona = Object.freeze({ id: 12, role: 'merchant' });
  assert.deepEqual(await auth.listSessions({ scope, shopPersona, currentSessionId: current }), [
    { id: other, user_agent: null, ip: null, created_at: '2026-09-18T00:00:00.000Z',
      last_seen_at: '2026-09-18T00:01:00.000Z', is_current: false },
    { id: current, user_agent: 'Controlled Browser', ip: '127.0.0.1',
      created_at: '2026-09-18T00:00:00.000Z', last_seen_at: '2026-09-18T00:02:00.000Z',
      is_current: true },
  ]);
  assert.equal(await auth.revokeOwnedSession({ scope, shopPersona,
    currentSessionId: current, sessionId: other }), true);
  assert.deepEqual(calls, [
    ['list', { scope, shopUserId: 12, currentSessionId: current }],
    ['revoke', { scope, shopUserId: 12, sessionId: other }],
  ]);
  assert.equal(checks, 4);
});

test('session inventory fails closed when reset wins after the repository read', async () => {
  const current = '30000000-0000-4000-8000-000000000082'; let checks = 0;
  const auth = createSecureShopBoundPersonaAuth({ repository: {
    ...sessionManagement,
    async findCredential() { return null; }, async createSession() {}, async readSession() { return null; },
    async extendSession() { return null; }, async revokeSession() {}, async revokeOwnedSession() { return false; },
    async changePassword() { return null; },
    async listSessions() { return [{ id: current, user_agent: null, ip: null,
      created_at: '2026-09-18T00:00:00.000Z', last_seen_at: '2026-09-18T00:00:00.000Z',
      is_current: true }]; },
  }, launches: { async assertCurrent() {
    checks++;
    if (checks === 2) throw Object.assign(new Error('retired'), { code: 'STALE_LAUNCH' });
    return scope;
  } }, jwtSecret: 'owned-bound-persona-secret-at-least-32-bytes' });
  await assert.rejects(auth.listSessions({ scope, shopPersona: { id: 12, role: 'merchant' },
    currentSessionId: current }), { code: 'STALE_LAUNCH' });
});

test('oversized request metadata is discarded without weakening credential admission', async () => {
  const hash = await bcrypt.hash('password', 4); let stored;
  const auth = createSecureShopBoundPersonaAuth({ repository: {
    ...sessionManagement,
    async findCredential() { return { id: 11, username: 'student_customer',
      email: 'customer@example.test', password: hash, role: 'customer' }; },
    async createSession(value) { stored = value; }, async readSession() { return null; },
    async extendSession() { return null; }, async revokeSession() {},
  }, launches: { async assertCurrent(value) { return { ...value,
    expiresAt: new Date(Date.now() + 3600000) }; } },
  jwtSecret: 'owned-bound-persona-secret-at-least-32-bytes' });
  await auth.login({ scope, username: 'student_customer', password: 'password',
    ip: 'x'.repeat(129), userAgent: 'u'.repeat(1025) });
  assert.equal(stored.ip, null);
  assert.equal(stored.userAgent, null);
});

test('password change verifies the effective password and preserves only the authenticated session', async () => {
  const currentHash = await bcrypt.hash('current-password', 4);
  const currentSessionId = '30000000-0000-4000-8000-000000000082';
  const calls = []; let checks = 0;
  const repository = {
    ...sessionManagement,
    async findCredential(username, trusted) {
      calls.push(['credential', username, trusted]);
      return { id: 11, username: 'student_customer', role: 'customer', password: currentHash };
    },
    async createSession() {}, async readSession() { return null; }, async extendSession() { return null; },
    async revokeSession() {},
    async changePassword(input) { calls.push(['change', input]); return { credentialVersion: 2 }; },
  };
  const auth = createSecureShopBoundPersonaAuth({ repository,
    launches: { async assertCurrent(value) { checks++; return value; } },
    jwtSecret: 'owned-bound-persona-secret-at-least-32-bytes' });
  assert.deepEqual(await auth.changePassword({ scope, shopPersona: { id: 11, role: 'customer' },
    currentSessionId, currentPassword: 'current-password', newPassword: 'replacement-password' }),
  { ok: true });
  assert.equal(checks, 2);
  const changed = calls.find(row => row[0] === 'change')[1];
  assert.equal(changed.currentSessionId, currentSessionId);
  assert.equal(changed.expectedHash, currentHash);
  assert.equal(await bcrypt.compare('replacement-password', changed.nextHash), true);
  assert.equal(Object.hasOwn(changed, 'currentPassword'), false);
  await assert.rejects(auth.changePassword({ scope, shopPersona: { id: 11, role: 'customer' },
    currentSessionId, currentPassword: 'wrong-password', newPassword: 'another-password' }),
  { code: 'SHOP_PASSWORD_MISMATCH' });
  await assert.rejects(auth.changePassword({ scope, shopPersona: { id: 11, role: 'customer' },
    currentSessionId, currentPassword: 'current-password', newPassword: 'short' }),
  { code: 'SHOP_PASSWORD_INVALID' });
  await assert.rejects(auth.changePassword({ scope, shopPersona: { id: 11, role: 'customer' },
    currentSessionId, currentPassword: 'current-password', newPassword: 'é'.repeat(37) }),
  { code: 'SHOP_PASSWORD_INVALID' });
  assert.deepEqual(await auth.changePassword({ scope, shopPersona: { id: 11, role: 'customer' },
    currentSessionId, currentPassword: 'current-password', newPassword: 'é'.repeat(36) }),
  { ok: true });
});

test('login rejects a distinct suffix beyond the bcrypt 72-byte boundary', async () => {
  const prefix = 'p'.repeat(72); const hash = await bcrypt.hash(prefix, 4); let created = 0;
  const auth = createSecureShopBoundPersonaAuth({ repository: {
    ...sessionManagement,
    async findCredential() { return { id: 11, username: 'student_customer', role: 'customer',
      email: 'customer@example.test', password: hash, credential_version: 1 }; },
    async createSession() { created++; }, async readSession() { return null; },
    async extendSession() { return null; }, async revokeSession() {},
  }, launches: { async assertCurrent(value) { return { ...value,
    expiresAt: new Date(Date.now() + 3600000) }; } },
  jwtSecret: 'owned-bound-persona-secret-at-least-32-bytes' });
  await assert.rejects(auth.login({ scope, username: 'student_customer',
    password: `${prefix}different-suffix` }), { code: 'SHOP_CREDENTIALS_INVALID' });
  assert.equal(created, 0);
});

test('API authority is branded, scope-bound, secret-free and rechecks rotation/role/revocation',async()=>{
 const key='sk_ss_live_22222222222222222222222222222222';let role='customer',version=2,revoked=false,launchRevoked=false;
 const repository={...sessionManagement,findCredential:async()=>null,createSession:async()=>{},readSession:async()=>null,extendSession:async()=>null,revokeSession:async()=>{},authenticateApiKey:async()=>revoked?null:{id:12,username:'student_customer',role,email:'x@example.test',apiKeyVersion:version}};
 const auth=createSecureShopBoundPersonaAuth({repository,launches:{assertCurrent:async()=>{if(launchRevoked)throw Object.assign(Error('reset'),{code:'STALE_LAUNCH'});}},jwtSecret:'owned-bound-persona-secret-at-least-32-bytes'});
 const {resolveBoundApiKeyAuthority:resolve}=require('../server/services/secureshopBoundPersonaAuth');
 const fence=await auth.captureApiKeyAuthority({scope,presentedKey:key});assert.equal(resolve(fence,{scope,persona:{id:12,role:'customer'}}),fence);assert.ok(!JSON.stringify(fence).includes(key));assert.throws(()=>resolve({...fence},{scope,persona:{id:12,role:'customer'}}),{code:'SHOP_API_KEY_INVALID'});assert.throws(()=>resolve(fence,{scope:{...scope,generation:6},persona:{id:12,role:'customer'}}),{code:'SHOP_API_KEY_INVALID'});
 await fence.assertRemoteAdmission();version=3;await assert.rejects(fence.assertRemoteAdmission(),{code:'SHOP_API_KEY_INVALID'});version=2;role='admin';await assert.rejects(fence.assertRemoteAdmission(),{code:'SHOP_API_KEY_INVALID'});role='customer';revoked=true;await assert.rejects(fence.assertRemoteAdmission(),{code:'SHOP_API_KEY_INVALID'});revoked=false;launchRevoked=true;await assert.rejects(fence.assertRemoteAdmission(),{code:'STALE_LAUNCH'});
});

test('session management retains middleware version and rejects revoked private-read projection',async()=>{
 const current='70000000-0000-4000-8000-000000000001',other='70000000-0000-4000-8000-000000000002',owner={id:12,role:'merchant'};let revoked=false,mutation;
 const authority={read:async()=>({role:'merchant',authority_version:'99'}),capture:async input=>{assert.equal(input.authorityVersion,'7');assert.equal(input.sessionId,current);return{assertRemoteAdmission:async()=>{if(revoked)throw Object.assign(Error('revoked'),{code:'SHOP_AUTH_INVALID'});}};}};
 const repository={...sessionManagement,candidatePersonaAuthority:authority,findCredentialById:async()=>null,findCredential:async()=>null,createSession:async()=>{},readSession:async()=>null,extendSession:async()=>null,revokeSession:async()=>{},revokeOwnedSession:async input=>{mutation=input;return true;},listSessions:async()=>{revoked=true;return[];},readApiKey:async()=>{revoked=true;return null;}};
 const auth=createSecureShopBoundPersonaAuth({repository,personaAuthority:authority,launches:{assertCurrent:async()=>{}},jwtSecret:'owned-bound-persona-secret-at-least-32-bytes'});
 await auth.revokeOwnedSession({scope,shopPersona:owner,currentSessionId:current,authorityVersion:'7',sessionId:other});assert.deepEqual(mutation.actingCredential,{sessionId:current,role:'merchant',authorityVersion:'7'});
 await assert.rejects(auth.revokeOwnedSession({scope,shopPersona:owner,currentSessionId:current,sessionId:other}),{code:'SHOP_AUTH_INVALID'});
 await assert.rejects(auth.listSessions({scope,shopPersona:owner,currentSessionId:current,authorityVersion:'7'}),{code:'SHOP_AUTH_INVALID'});revoked=false;await assert.rejects(auth.listApiKey({scope,shopPersona:owner,currentSessionId:current,authorityVersion:'7'}),{code:'SHOP_AUTH_INVALID'});
});

test('promoted and demoted personas change their immutable-ID credential without role-to-template lookup',async()=>{
 const hash=await bcrypt.hash('original-password',4),session='70000000-0000-4000-8000-000000000007';
 for(const [id,role] of [[11,'admin'],[13,'customer']]){
  let mutation,lookup;const authority={read:async(_scope,selected,expected)=>{assert.equal(selected,id);assert.equal(expected.role,role);return{authority_version:'8',role};}};
  const repository={...sessionManagement,candidatePersonaAuthority:authority,findCredential:async()=>{throw Error('Must not map effective role to template username');},findCredentialById:async(selected,trusted)=>{lookup=selected;assert.deepEqual(trusted,scope);return{id:selected,password:hash};},createSession:async()=>{},readSession:async()=>null,extendSession:async()=>null,revokeSession:async()=>{},changePassword:async input=>{mutation=input;return{credentialVersion:2};}};
  const auth=createSecureShopBoundPersonaAuth({repository,personaAuthority:authority,launches:{assertCurrent:async()=>{}},jwtSecret:'owned-bound-persona-secret-at-least-32-bytes'});
  assert.deepEqual(await auth.changePassword({scope,shopPersona:{id,role},currentSessionId:session,currentPassword:'original-password',newPassword:'new-owned-password'}),{ok:true});assert.equal(lookup,id);assert.equal(mutation.shopUserId,id);assert.equal(mutation.currentSessionId,session);assert.equal(mutation.expectedRole,role);assert.equal(mutation.authorityVersion,'8');
  repository.findCredentialById=async()=>({id:id+1,password:hash});await assert.rejects(auth.changePassword({scope,shopPersona:{id,role},currentSessionId:session,currentPassword:'original-password',newPassword:'new-owned-password'}),{code:'SHOP_PASSWORD_MISMATCH'});
 }
});
