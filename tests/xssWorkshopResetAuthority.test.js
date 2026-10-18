'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');
const path = require('node:path');

const routePath = path.resolve(__dirname, '../server/routes/xssWorkshop.js');
const priorEngine = process.env.PLATFORM_DATABASE_ENGINE;

function loadFixture() {
  const posts = new Map();
  const calls = { local: [], canonical: [] };
  let checks = 0;
  const router = {
    use() {}, get() {},
    post(route, handler) { posts.set(route, handler); },
  };
  const db = {
    resetProgress(userKey, objectives, callback) {
      calls.local.push({ userKey, objectives });
      queueMicrotask(() => callback(null));
    },
  };
  const originalLoad = Module._load;
  process.env.PLATFORM_DATABASE_ENGINE = 'postgres';
  Module._load = function loadXssFixture(request, parent, isMain) {
    if (parent?.filename === routePath) {
      if (request === '../middleware/adminAuth') return { authenticateToken(req, res, next) {
        if (req.headers?.authorization !== 'Bearer fixture') return res.status(401).json({ error: 'fixture credential required' });
        req.user = { id: 17, role: 'student' }; return next();
      } };
      if (request === 'express') return { Router: () => router };
      if (request === '../agent-runtime/runCoordinator') return { createRunCoordinator: () => ({}) };
      if (request === '../agent-runtime/ownerWorkflowRoutes') return {
        checkOwnerRun: async () => {
          checks += 1;
          if (checks === 2) throw new Error('reset authority lost');
        },
        getOwnerExecution: () => null,
      };
      if (request === '../agent-runtime/xssOwnerWorkflowRoute') return {
        createXssOwnerWorkflowRoute: () => handler => handler,
      };
      if (request === '../database/xssWorkshopDb') return db;
      if (request === '../services/multiProviderAIService') return {};
      if (request === '../services/xssMailProvider') return {
        getXssMailProvider: () => ({ mailbox: {} }),
        resolveXssMailContext: async () => ({ email: null }),
      };
      if (request === '../services/xssEmailDispatch') return { getXssEmailDispatch: () => ({}) };
      if (request === '../services/xssObjectiveGrader') return {
        createXssObjectiveGrader: () => ({ close() {} }),
      };
      if (request === '../utils/progressSync') return {
        syncObjectiveComplete: async () => {},
        checkAndMarkWorkshopComplete: async () => {},
        getUserWorkshopProgress: async () => [],
        getCanonicalWorkshopCompletions: async () => ({ objectiveIds: [] }),
        resetWorkshopProgress: async (...args) => { calls.canonical.push(args); },
      };
    }
    return originalLoad.call(this, request, parent, isMain);
  };
  try {
    delete require.cache[require.resolve(routePath)];
    require(routePath);
  } finally {
    Module._load = originalLoad;
    delete require.cache[require.resolve(routePath)];
  }
  return { posts, calls };
}

function response() {
  let resolve;
  const sent = new Promise(done => { resolve = done; });
  return {
    statusCode: 200,
    payload: undefined,
    sent,
    status(code) { this.statusCode = code; return this; },
    json(payload) { this.payload = payload; resolve(); return this; },
  };
}

test.after(() => {
  if (priorEngine === undefined) delete process.env.PLATFORM_DATABASE_ENGINE;
  else process.env.PLATFORM_DATABASE_ENGINE = priorEngine;
});

for (const scenario of [
  { route: '/progress/reset', body: {}, objectives: null },
  { route: '/progress/reset-tab', body: { exerciseId: 'stored_llm' },
    objectives: ['xss_g1', 'xss_g2', 'xss_g3'] },
]) {
  test(`${scenario.route} rejects authority loss after local reset without canonical mutation`, async () => {
    const fixture = loadFixture();
    const handler = fixture.posts.get(scenario.route);
    assert.equal(typeof handler, 'function');
    const res = response();
    await handler({ body: scenario.body,
      xssIdentity: { userKey: '7', platformUserId: 7 } }, res);
    await res.sent;
    assert.deepEqual(fixture.calls.local, [{ userKey: '7', objectives: scenario.objectives }]);
    assert.deepEqual(fixture.calls.canonical, []);
    assert.equal(res.statusCode, 503);
    assert.deepEqual(res.payload, { error: 'Reset incomplete; retry to reconcile progress' });
  });
}
