'use strict';

const assert = require('node:assert/strict');
const express = require('express');
const Module = require('node:module');
const path = require('node:path');
const test = require('node:test');

const routePath = path.resolve(__dirname, '../server/routes/xssWorkshop.js');

test('mounted PostgreSQL XSS route keeps model origin private while binding its write and grader read', async () => {
  const priorEngine = process.env.PLATFORM_DATABASE_ENGINE;
  const priorExport = process.env.EXPORT_INTERNALS;
  process.env.PLATFORM_DATABASE_ENGINE = 'postgres';
  process.env.EXPORT_INTERNALS = '1';
  const originalLoad = Module._load;
  const writes = [];
  const manualWrites = [];
  const originReads = [];
  const graphInputs = [];
  let localProgressReads = 0;
  let canonicalProgress = [];
  let graderOptions;
  let ownerMode = null;
  const validExecution = Object.freeze({
    runId: '00000000-0000-4000-8000-000000000017', ownerKey: '["XSS","17"]', durableGeneration: 4,
    scopeBinding: Object.freeze({ childGeneration: '0', ownerId: 17, ownerKey: '["XSS","17"]',
      parentGeneration: '4', runId: '00000000-0000-4000-8000-000000000017', scopeKey: 'stored_llm' }),
    check: async () => {}, trace: async () => {},
  });
  let activeExecution = validExecution;
  let routeOptions;
  const db = {
    listProgress: async () => { localProgressReads += 1; throw new Error('local progress projection unavailable'); },
    getProfile: async () => ({ name: 'Owner', bio: 'Before', website: 'https://fixture.invalid' }),
    completeObjective: async () => {},
    writeModelProfileField: async input => { writes.push(input); return { version: 'private-origin' }; },
    writeScopedManualProfileField: async input => { manualWrites.push(input); return { version: 'manual' }; },
    readCurrentProfileField: async input => { originReads.push(input); return { value: 'private' }; },
  };
  const toolCall = { tool: 'updateProfile', args: { field: 'bio', value: '<img src=x onerror="one()">' } };
  const decisionContext = Object.freeze({ decisionSource: 'model', modelSucceeded: true, provider: 'ollama',
    model: 'llama3.1:8b', rawResponse: JSON.stringify(toolCall), observationIndex: 2 });

  Module._load = function mockRouteDependencies(request, parent, isMain) {
    if (parent?.filename === routePath) {
      if (request === '../middleware/adminAuth') return { authenticateToken(req, res, next) {
        if (req.headers?.authorization !== 'Bearer fixture') return res.status(401).json({ error: 'fixture credential required' });
        req.user = { id: 17, role: 'student' }; return next();
      } };
      if (request === '../agent-runtime/ownerWorkflowRoutes') return {
        checkOwnerRun: async () => {}, getOwnerExecution: () => activeExecution,
      };
      if (request === '../agent-runtime/xssOwnerWorkflowRoute') return {
        createXssOwnerWorkflowRoute: () => (handler, options) => {
          if (typeof options?.scopeFor === 'function') routeOptions = options;
          return handler;
        },
      };
      if (request === '../agent-runtime/runCoordinator') return { createRunCoordinator: () => ({}) };
      if (request === '../database/xssWorkshopDb') return db;
      if (request === '../services/xssObjectiveGrader') return { createXssObjectiveGrader(options) {
        graderOptions = options;
        return { begin: async () => ({ generation: 9 }), close: async () => {}, evaluate: async ({ objectiveId }) => {
          canonicalProgress = [{ workshop_key: 'xss_workshop', objective_id: objectiveId, completed: true }];
          return { completed: true, qualification: { executed: false }, judgment: { objectiveId, verdict: 'pass' } };
        } };
      } };
      if (request === '../services/multiProviderAIService') return {};
      if (request === '../services/xssMailProvider') return { getXssMailProvider: () => ({}), resolveXssMailContext: async () => ({}) };
      if (request === '../services/xssEmailDispatch') return { getXssEmailDispatch: () => ({}) };
      if (request === '../services/postgresPlatformStores') return {
        getPostgresPlatformStores: () => ({ progress: { getEvaluationScope: async () => ({
          generation: 9, mode: null, modeStamp: undefined,
        }) } }),
      };
      if (request === '../services/workshopModeService') return {
        getMode: async ({ userId, workshopKey }) => {
          assert.equal(userId, 17); assert.equal(workshopKey, 'xss_workshop'); return ownerMode;
        },
        setMode: async ({ userId, workshopKey, mode }) => {
          assert.equal(userId, 17); assert.equal(workshopKey, 'xss_workshop'); ownerMode = mode; return mode;
        },
      };
      if (request === '../utils/contextLogger') return { error() {} };
      if (request === '../utils/progressSync') return {
        syncObjectiveComplete: async () => {}, checkAndMarkWorkshopComplete: async () => {},
        resetWorkshopProgress: async () => {}, getUserWorkshopProgress: async () => canonicalProgress,
        getCanonicalWorkshopCompletions: async (_userId, _workshop, options) => ({
          objectiveIds: canonicalProgress.filter(row => row.completed).map(row => row.objective_id),
          generation: options.expectedGeneration,
        }),
      };
      if (request === '../agent-runtime/xssWorkshopGraph') return { async runXssWorkshopGraph(input, deps) {
        graphInputs.push(structuredClone(input));
        if (input.message.startsWith('Show')) {
          return { response: 'Shown.', grading: {}, completedObjectiveId: null };
        }
        const toolResult = await deps.executeXssTool(toolCall, input.userKey, input.exerciseId, '', decisionContext);
        const candidate = input.message.startsWith('Complete g2') ? 'xss_g2' : null;
        return { response: 'Saved.', toolUsed: 'updateProfile', toolResult,
          grading: { toolCall, toolResult, modelSucceeded: true }, completedObjectiveId: candidate };
      } };
    }
    return originalLoad.call(this, request, parent, isMain);
  };

  delete require.cache[routePath];
  let server;
  try {
    const router = require(routePath);
    assert.equal(typeof routeOptions.scopeFor, 'function');
    assert.deepEqual(routeOptions.scopeFor({ user: { id: 17 }, body: {
      exerciseId: 'stored_llm', scope: { userId: 999, scopeKey: 'email' },
    }}), { userId: 17, scopeKey: 'stored_llm' }, 'request body scope cannot choose a sibling');
    assert.equal(routeOptions.scopeFor({ user: { id: 17 }, body: { exerciseId: 'email' }}), undefined);
    const app = express();
    app.use(express.json());
    app.use((req, _res, next) => { req.user = { id: 17 }; next(); });
    app.use('/api/workshop/xss', router);
    server = await new Promise(resolve => { const listener = app.listen(0, '127.0.0.1', () => resolve(listener)); });
    const modeUrl = `http://127.0.0.1:${server.address().port}/api/workshop/xss/mode`;
    const modeHeaders = { Authorization: 'Bearer fixture', 'Content-Type': 'application/json' };
    assert.equal((await fetch(modeUrl)).status, 401);
    const initialMode = await (await fetch(modeUrl, { headers: modeHeaders })).json();
    assert.equal(initialMode.mode, null);
    assert.equal(initialMode.effectiveMode, 'vuln');
    const fixedMode = await (await fetch(modeUrl, { method: 'POST', headers: modeHeaders,
      body: JSON.stringify({ mode: 'fixed' }) })).json();
    assert.equal(fixedMode.mode, 'fixed');
    assert.equal(fixedMode.fixedSupported, true);
    assert.deepEqual(fixedMode.scope, { kind: 'workshop', id: 'xss_workshop' });
    assert.equal((await fetch(modeUrl, { method: 'POST', headers: modeHeaders,
      body: JSON.stringify({ mode: 'other' }) })).status, 400);
    await fetch(modeUrl, { method: 'POST', headers: modeHeaders, body: JSON.stringify({ mode: 'vuln' }) });
    const response = await fetch(`http://127.0.0.1:${server.address().port}/api/workshop/xss/chat`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer fixture' },
      body: JSON.stringify({ exerciseId: 'stored_llm', message: 'Generate and save a test value.' }),
    });
    const body = await response.json();

    assert.equal(response.status, 200);
    assert.deepEqual(body.toolResult, {
      success: true, field: 'bio', value: toolCall.args.value,
      message: 'Profile field "bio" updated successfully.',
    });
    assert.equal(JSON.stringify(body).includes('private-origin'), false, 'origin receipt must stay server-only');
    assert.equal(writes.length, 1);
    assert.deepEqual(writes[0], {
      userKey: '17', platformUserId: 17, field: 'bio', value: toolCall.args.value,
      workshopGeneration: 9, execution: { ...validExecution, ownerId: '17', emit: validExecution.trace },
      decision: { decisionSource: 'model', modelSucceeded: true, provider: 'ollama', model: 'llama3.1:8b',
        rawDecisionResponse: decisionContext.rawResponse },
      observationIndex: 2,
      learnerMessage: 'Generate and save a test value.',
    });
    assert.equal(typeof graderOptions.readProfileOrigin, 'function');
    assert.deepEqual(await graderOptions.readProfileOrigin({ userKey: '17', platformUserId: 17, field: 'bio' }),
      { value: 'private' });
    assert.deepEqual(originReads, [{ userKey: '17', platformUserId: 17, field: 'bio' }]);

    router._internals.setProgressProjectorForTests(async () => { throw new Error('local projection unavailable'); });
    const failedProjection = await fetch(`http://127.0.0.1:${server.address().port}/api/workshop/xss/chat`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer fixture' },
      body: JSON.stringify({ exerciseId: 'stored_llm', message: 'Complete g2 with a model write.' }),
    });
    assert.equal(failedProjection.status, 200);
    assert.deepEqual((await failedProjection.json()).projectionPending, ['xss_g2']);
    assert.equal(localProgressReads, 0, 'PostgreSQL chat sequencing must not depend on the local projection');

    await fetch(`http://127.0.0.1:${server.address().port}/api/workshop/xss/chat`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer fixture' },
      body: JSON.stringify({ exerciseId: 'stored_llm', message: 'Show canonical progress.' }),
    });
    assert.deepEqual(graphInputs.at(-1).clientCompleted, ['xss_g2'],
      'canonical g2 remains eligible even when local projection failed');

    canonicalProgress = [];
    await fetch(`http://127.0.0.1:${server.address().port}/api/workshop/xss/chat`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer fixture' },
      body: JSON.stringify({ exerciseId: 'stored_llm', message: 'Show stale local progress.' }),
    });
    assert.deepEqual(graphInputs.at(-1).clientCompleted, [],
      'canonical absence cannot nominate g3');
    assert.equal(localProgressReads, 0);

    const beforeRejected = graphInputs.length;
    activeExecution = Object.freeze({ ...validExecution,
      scopeBinding: Object.freeze({ ...validExecution.scopeBinding, ownerId: 18, ownerKey: '["XSS","18"]' }),
    });
    const rejected = await fetch(`http://127.0.0.1:${server.address().port}/api/workshop/xss/chat`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer fixture' },
      body: JSON.stringify({ exerciseId: 'stored_llm', message: 'This must fail before model dispatch.' }),
    });
    assert.equal(rejected.status, 503);
    assert.equal((await rejected.json()).code, 'XSS_SCOPE_UNAVAILABLE');
    assert.equal(graphInputs.length, beforeRejected, 'scope mismatch must reject before model/graph execution');

    activeExecution = Object.freeze({ ...validExecution,
      scopeBinding: Object.freeze({ ...validExecution.scopeBinding, scopeKey: 'stored_user' }),
    });
    const manual = await fetch(`http://127.0.0.1:${server.address().port}/api/workshop/xss/chat`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer fixture' },
      body: JSON.stringify({ exerciseId: 'stored_user', message: 'Set a user supplied value.' }),
    });
    assert.equal(manual.status, 200);
    assert.equal(manualWrites.length, 1, 'stored_user must use the scoped manual writer');
    assert.equal(manualWrites[0].platformUserId, 17);
    assert.equal(manualWrites[0].execution.scopeBinding.scopeKey, 'stored_user');
  } finally {
    if (server) await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    Module._load = originalLoad;
    delete require.cache[routePath];
    if (priorEngine === undefined) delete process.env.PLATFORM_DATABASE_ENGINE;
    else process.env.PLATFORM_DATABASE_ENGINE = priorEngine;
    if (priorExport === undefined) delete process.env.EXPORT_INTERNALS;
    else process.env.EXPORT_INTERNALS = priorExport;
  }
});
