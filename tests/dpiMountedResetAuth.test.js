'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

// Engine selection and legacy-import denial must precede every application import.
test('mounted DPI reset rechecks its admitted session after the reset queue wait', async t => {
  const envKeys = ['PLATFORM_DATABASE_ENGINE', 'WORKSHOP_DATABASE_ENGINE', 'JWT_SECRET', 'IDENTITY_DATABASE_URL'];
  const prior = Object.fromEntries(envKeys.map(key => [key, process.env[key]]));
  Object.assign(process.env, {
    PLATFORM_DATABASE_ENGINE: 'postgres', WORKSHOP_DATABASE_ENGINE: 'postgres',
    JWT_SECRET: require('node:crypto').randomBytes(48).toString('base64url'),
    IDENTITY_DATABASE_URL: 'postgresql://fixture@127.0.0.1:1/owasp_ai_goat_test_dpi_reset',
  });
  const Module = require('node:module');
  const originalLoad = Module._load;
  const controlledAi = {
    getActiveProviderInfo: () => ({ provider: 'controlled', model: 'no-model' }),
    verifyProviderConnectionLite: async () => ({ available: true, healthy: true, configured: true }),
  };
  Module._load = function(name, parent, isMain) {
    if (/(?:^|\/)(?:authDb|sqlite|sqlite3|better-sqlite3)(?:\.js)?$/.test(name)) {
      throw Error('Legacy database import forbidden in mounted DPI reset test');
    }
    if (name === '../services/multiProviderAIService' || name === './multiProviderAIService') return controlledAi;
    return originalLoad.call(this, name, parent, isMain);
  };
  t.after(() => {
    Module._load = originalLoad;
    for (const [key, value] of Object.entries(prior)) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
  });

  const source = fs.readFileSync(path.join(__dirname, '../server/applicationServer.js'), 'utf8');
  const authMount = "app.post('/api/workshop/prompt-injection/progress/reset', authenticateToken);";
  const routerMount = "app.use('/api/workshop/prompt-injection', require('./routes/promptInjectionWorkshop'));";
  assert.ok(source.indexOf(authMount) > 0 && source.indexOf(authMount) < source.indexOf(routerMount));
  const express = require('express');
  const { createPostgresAdminAuth } = require('../server/middleware/postgresAdminAuth');
  const { createPromptInjectionWorkshopRouter } = require('../server/routes/promptInjectionWorkshop');
  let current = { user: { id: 7, username: 'owner', role: 'student' }, session: { id: 9, user_id: 7 } };
  let validations = 0, queuedResets = 0, writes = 0, hold = false, release, entered;
  const validateSession = async token => { validations++; return token === 'owned-token' ? current : null; };
  const auth = createPostgresAdminAuth({ repository: {}, validateSession });
  const app = express(); app.use(express.json());
  app.post('/api/workshop/prompt-injection/progress/reset', auth.authenticateToken);
  app.use('/api/workshop/prompt-injection', createPromptInjectionWorkshopRouter({
    aiService: controlledAi, validateSession, logger: { error() {} },
    progressService: { resetProgress: async args => {
      writes++; assert.deepEqual(args, { userId: 7, userKey: '7' }); return { objectives: {} };
    } },
    runCoordinator: { reset: async (_owner, callback) => {
      queuedResets++;
      if (hold) await new Promise(resolve => { release = resolve; entered(); });
      return callback();
    } },
  }));
  let legacyFixtureWrites = 0;
  app.use('/legacy-fixture-dpi', (req, _res, next) => { req.user = { id: 7 }; next(); },
    createPromptInjectionWorkshopRouter({
      legacyFixture: true, aiService: controlledAi, logger: { error() {} },
      progressService: { resetProgress: async () => { legacyFixtureWrites++; return { objectives: {} }; } },
      runCoordinator: { reset: async (_owner, callback) => callback() },
    }));
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  t.after(() => { release?.(); return new Promise(resolve => server.close(resolve)); });
  const base = `http://127.0.0.1:${server.address().port}/api/workshop/prompt-injection`;
  const reset = token => fetch(base + '/progress/reset', {
    method: 'POST', headers: { 'content-type': 'application/json', ...(token ? { authorization: 'Bearer ' + token } : {}) }, body: '{}',
  });
  assert.equal((await fetch(base + '/health')).status, 200);
  assert.equal((await reset(null)).status, 401);
  assert.equal((await reset('stale-token')).status, 401);
  assert.equal(queuedResets, 0); assert.equal(writes, 0);

  // Entry authentication succeeds; revocation occurs while reset awaits prior work.
  hold = true;
  const queued = new Promise(resolve => { entered = resolve; });
  const pending = reset('owned-token'); await queued;
  assert.equal(writes, 0); current = null; release();
  const revoked = await pending;
  assert.equal(revoked.status, 401);
  assert.equal((await revoked.json()).code, 'SESSION_REVOKED');
  assert.equal(writes, 0, 'Revoked admitted session must not persist a progress reset');

  // A replacement session for the same owner cannot authorize the admitted request.
  current = { user: { id: 7 }, session: { id: 9, user_id: 7 } };
  const queuedAgain = new Promise(resolve => { entered = resolve; });
  const replaced = reset('owned-token'); await queuedAgain;
  current = { user: { id: 7 }, session: { id: 10, user_id: 7 } }; release();
  assert.equal((await replaced).status, 401); assert.equal(writes, 0);

  hold = false;
  const valid = await reset('owned-token');
  assert.equal(valid.status, 200); assert.deepEqual((await valid.json()).progress, { objectives: {} });
  assert.equal(writes, 1); assert.equal(queuedResets, 3); assert.ok(validations >= 9);
  assert.equal((await fetch(base + '/health')).status, 200, 'Public health remains open');
  assert.equal((await fetch(`http://127.0.0.1:${server.address().port}/legacy-fixture-dpi/progress/reset`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}',
  })).status, 200, 'Explicit legacy fixture retains its controlled reset path');
  assert.equal(legacyFixtureWrites, 1);
});
