'use strict';

const assert = require('node:assert/strict');
const express = require('express');
const Module = require('node:module');
const path = require('node:path');
const test = require('node:test');

const routePath = path.resolve(__dirname, '../server/routes/xssWorkshop.js');

test('PostgreSQL profile reset uses the scoped composition and preserves legacy reset routing', async () => {
  const oldEngine = process.env.PLATFORM_DATABASE_ENGINE;
  const oldInternals = process.env.EXPORT_INTERNALS;
  process.env.PLATFORM_DATABASE_ENGINE = 'postgres';
  process.env.EXPORT_INTERNALS = '1';
  const originalLoad = Module._load;
  const compositionCalls = [];
  const legacyCalls = [];
  const quiescenceCalls = [];
  let profile = { name: 'Before', bio: 'old', website: 'https://old.invalid' };
  const resetComposition = {
    async assertReady() { compositionCalls.push(['assertReady']); return true; },
    async reset(input) {
      compositionCalls.push(['reset', input]);
      profile = { name: 'After', bio: 'clean', website: 'https://example.com' };
      return { operationId: input.operationId || '22222222-2222-4222-8222-222222222222', status: 'completed' };
    },
  };
  const db = {
    async getProfile() { return profile; },
    resetProfile(userKey, callback) { legacyCalls.push(userKey); callback(null); },
    async listProgress() { return []; },
    async completeObjective() {},
  };
  const ownerCoordinator = {
    cancelScopes(){},
    withScopesQuiesced: async (owner, scopes, work) => {
      quiescenceCalls.push({ owner, scopes });
      return work({ scopeKeys: scopes });
    },
  };

  Module._load = function mockRouteDependencies(request, parent, isMain) {
    if (parent?.filename === routePath) {
      if (request === '../services/postgresIdentityAdapter') return {getPostgresIdentityAdapter:()=>({validateSession:async()=>({user:{id:17},session:{id:9,user_id:17}})})};
      if (request === '../middleware/adminAuth') return { authenticateToken(req, res, next) {
        if (req.headers?.authorization !== 'Bearer fixture') return res.status(401).json({ error: 'fixture credential required' });
        req.user = { id: 17, role: 'student' }; req.identitySession={id:9}; return next();
      } };
      if (request === '../agent-runtime/ownerWorkflowRoutes') return {
        checkOwnerRun: async () => {}, getOwnerExecution: () => ({ trace: async () => {} }),
      };
      if (request === '../agent-runtime/xssOwnerWorkflowRoute') return {
        createXssOwnerWorkflowRoute: () => (handler, options = {}) => {
          return async (req, res, next) => {
            if (options.reset) legacyCalls.push(['ownerRoute', req.user?.id ?? null]);
            return handler(req, res, next);
          };
        },
      };
      if (request === '../agent-runtime/runCoordinator') return { createRunCoordinator: () => ownerCoordinator };
      if (request === '../database/xssWorkshopDb') return db;
      if (request === '../services/xssScopedProfileResetComposition') return {
        getXssScopedProfileResetComposition: async () => resetComposition,
      };
      if (request === '../services/xssObjectiveGrader') return {
        createXssObjectiveGrader: () => ({ begin: async () => ({ generation: 1 }), evaluate: async () => ({ completed: false }), close: async () => {} }),
      };
      if (request === '../services/multiProviderAIService') return { getActiveProviderInfo: () => ({ provider: 'fixture', model: 'fixture' }) };
      if (request === '../services/xssMailProvider') return { getXssMailProvider: () => ({ mailbox: {} }), resolveXssMailContext: async () => ({}) };
      if (request === '../services/xssEmailDispatch') return { getXssEmailDispatch: () => ({}) };
      if (request === '../utils/contextLogger') return { error() {} };
      if (request === '../utils/progressSync') return {
        syncObjectiveComplete: async () => {}, checkAndMarkWorkshopComplete: async () => {},
        resetWorkshopProgress: async () => {}, getUserWorkshopProgress: async () => [],
        getCanonicalWorkshopCompletions: async () => ({ objectiveIds: [], generation: 1 }),
      };
    }
    return originalLoad.call(this, request, parent, isMain);
  };

  delete require.cache[routePath];
  let server;
  try {
    const router = require(routePath);
    const app = express();
    app.use(express.json());
    app.use((req, _res, next) => { if (req.headers.authorization) {req.user = { id: 17 };req.identitySession={id:9};} next(); });
    app.use('/api/workshop/xss', router);
    server = await new Promise(resolve => { const listener = app.listen(0, '127.0.0.1', () => resolve(listener)); });
    const base = `http://127.0.0.1:${server.address().port}`;

    const operationId = '11111111-1111-4111-8111-111111111111';
    const pgReset = await fetch(`${base}/api/workshop/xss/profile/reset`, {
      method: 'POST', headers: { Authorization: 'Bearer fixture', 'x-reset-operation-id': operationId },
    });
    assert.equal(pgReset.status, 200);
    assert.deepEqual(await pgReset.json(), {
      success: true, profile, operationId, resetStatus: 'completed',
    });
    assert.deepEqual(compositionCalls, [['assertReady'], ['reset', { ownerId: 17, operationId }]]);
    assert.deepEqual(legacyCalls, []);

    await router.withProfileScopesQuiesced(17, ['stored_user', 'stored_llm'], async ({ scopeKeys }) => {
      assert.deepEqual(scopeKeys, ['stored_user', 'stored_llm']);
    });
    assert.deepEqual(quiescenceCalls, [{ owner: '17', scopes: ['stored_user', 'stored_llm'] }]);

    const anonymousReset = await fetch(`${base}/api/workshop/xss/profile/reset`, { method: 'POST' });
    assert.equal(anonymousReset.status, 200);
    assert.deepEqual(legacyCalls[0], ['ownerRoute', null]);
    assert.match(legacyCalls[1], /^anon_/);
    assert.deepEqual(compositionCalls, [['assertReady'], ['reset', { ownerId: 17, operationId }]]);
  } finally {
    if (server) await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    Module._load = originalLoad;
    delete require.cache[routePath];
    if (oldEngine === undefined) delete process.env.PLATFORM_DATABASE_ENGINE; else process.env.PLATFORM_DATABASE_ENGINE = oldEngine;
    if (oldInternals === undefined) delete process.env.EXPORT_INTERNALS; else process.env.EXPORT_INTERNALS = oldInternals;
  }
});
