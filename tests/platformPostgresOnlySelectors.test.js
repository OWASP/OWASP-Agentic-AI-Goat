'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');
const path = require('node:path');

const selectors = [
  '../server/middleware/sessionManager',
  '../server/routes/auth',
  '../server/routes/admin',
  '../server/routes/workshop',
  '../server/middleware/adminAuth',
  '../server/middleware/rateLimiter',
];

async function load(engine) {
  const prior = process.env.PLATFORM_DATABASE_ENGINE;
  if (engine === undefined) delete process.env.PLATFORM_DATABASE_ENGINE;
  else process.env.PLATFORM_DATABASE_ENGINE = engine;
  const original = Module._load;
  const calls = [];
  const session = { kind: 'session', stopCleanupTask() {} };
  const auth = { kind: 'auth' };
  const admin = { kind: 'admin' };
  const workshop = { kind: 'workshop' };
  const progressFactory = () => 'progress';
  const timeFactory = () => 'time';
  const audits = [];
  let configReads = 0;
  const adapter = { kind: 'adapter', jwtSecret: 'controlled', repository: {
    async getConfig(key) { assert.equal(key, 'enable_rate_limiting'); configReads += 1; return 'true'; },
    async recordAudit(record) { audits.push(record); },
  } };
  const stores = { kind: 'stores' };
  const authenticateToken = () => {};
  const requirePermission = () => {};
  const platformAuth = { authenticateToken, requirePermission };
  Module._load = function(request, parent, isMain) {
    calls.push(request);
    const directSelectorLoad = parent?.filename === __filename;
    if (/authDb|database\/init|sqlite3|better-sqlite3/.test(request)
        || (/\/adminAuth$/.test(request) && !directSelectorLoad)) {
      assert.fail(`legacy platform dependency imported: ${request}`);
    }
    if (request.endsWith('/postgresSessionManager') || request === './postgresSessionManager') {
      return { createPostgresSessionManager(value) { assert.equal(value, adapter); return session; } };
    }
    if (request.endsWith('/postgresIdentityAdapter') || request === '../services/postgresIdentityAdapter') {
      return { getPostgresIdentityAdapter() { return adapter; } };
    }
    if (request.endsWith('/postgresAuth') || request === './postgresAuth') {
      return { createPostgresAuthRouter(options) { assert.equal(options.adapter, adapter); assert.equal(options.limiters.kind, 'limiters'); return auth; } };
    }
    if ((request.endsWith('/rateLimiter') || request === '../middleware/rateLimiter') && !directSelectorLoad) return { kind: 'limiters' };
    if (request.endsWith('/postgresAdmin') || request === './postgresAdmin') {
      return { createPostgresAdminRouter() { return admin; } };
    }
    if (request.endsWith('/postgresAdminAuth') || request === '../middleware/postgresAdminAuth') {
      return { createPostgresAdminAuth(value) {
        assert.equal(value, adapter);
        return platformAuth;
      } };
    }
    if (request.endsWith('/postgresPlatformStores') || request === '../services/postgresPlatformStores') {
      return { getPostgresPlatformStores() { return stores; } };
    }
    if (request.endsWith('/postgresWorkshop') || request === './postgresWorkshop') {
      return { createPostgresWorkshopRouter(options) {
        assert.deepEqual(options, { stores, authenticateToken, requirePermission });
        return workshop;
      } };
    }
    if (request.endsWith('/workshopProgressHandlers') || request === './workshopProgressHandlers') return { createWorkshopProgressHandlers: progressFactory };
    if (request.endsWith('/workshopTimeHandlers') || request === './workshopTimeHandlers') return { createWorkshopTimeHandlers: timeFactory };
    return original.call(this, request, parent, isMain);
  };
  try {
    for (const selector of selectors) delete require.cache[require.resolve(selector)];
    const loaded = selectors.map(selector => require(selector));
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(loaded[0], session);
    assert.equal(loaded[1], auth);
    assert.equal(loaded[2], admin);
    assert.equal(loaded[3], workshop);
    assert.equal(loaded[4], platformAuth);
    assert.equal(typeof loaded[5].loginRateLimiter, 'function');
    assert.equal(typeof loaded[5].registerRateLimiter, 'function');
    assert.equal(typeof loaded[5].passwordResetRateLimiter, 'function');
    await loaded[5].refreshRateLimitConfig();
    await loaded[5].recordRateLimitEvent({
      userId: 17, actionType: 'rate_limit_exceeded',
      actionDetails: JSON.stringify({ method: 'POST', url: '/api/auth/login', attempts: 21, limit: 20 }),
      ipAddress: '127.0.0.1', userAgent: 'controlled', sessionId: '31', riskLevel: 'high', success: 0,
    });
    assert.ok(configReads >= 2);
    assert.deepEqual(audits, [{
      userId: 17, actionType: 'rate_limit_exceeded',
      details: { method: 'POST', url: '/api/auth/login', attempts: 21, limit: 20 },
      ipAddress: '127.0.0.1', userAgent: 'controlled', sessionId: '31', riskLevel: 'high', success: 0,
    }]);
    assert.equal(workshop.createWorkshopProgressHandlers, progressFactory);
    assert.equal(workshop.createWorkshopTimeHandlers, timeFactory);
    assert.ok(calls.some(name => /postgresSessionManager$/.test(name)));
    assert.ok(calls.some(name => /postgresAuth$/.test(name)));
    assert.ok(calls.some(name => /postgresAdmin$/.test(name)));
    assert.ok(calls.some(name => /postgresWorkshop$/.test(name)));
  } finally {
    Module._load = original;
    for (const selector of selectors) delete require.cache[require.resolve(selector)];
    if (prior === undefined) delete process.env.PLATFORM_DATABASE_ENGINE;
    else process.env.PLATFORM_DATABASE_ENGINE = prior;
  }
}

test('platform selectors always compose existing PostgreSQL implementations without legacy imports', async () => {
  for (const engine of [undefined, 'sqlite', 'postgres']) await load(engine);
});
