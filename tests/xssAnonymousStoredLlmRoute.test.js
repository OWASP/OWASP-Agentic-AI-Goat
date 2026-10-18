'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');
const path = require('node:path');
const { anonymousOwner } = require('../server/database/postgres/xssProfileOriginRepository');
const { createXssObjectiveGrader } = require('../server/services/xssObjectiveGrader');

const ROUTE_PATH = path.join(__dirname, '..', 'server', 'routes', 'xssWorkshop.js');
const priorEngine = process.env.PLATFORM_DATABASE_ENGINE;
const priorInternals = process.env.EXPORT_INTERNALS;
process.env.PLATFORM_DATABASE_ENGINE = 'postgres';
process.env.EXPORT_INTERNALS = '1';

const calls = { anonymous: [], canonical: [] };
const fakeDb = {
  updateAnonymousProfileField(userKey, field, value, callback) {
    try {
      calls.anonymous.push({ userKey: anonymousOwner(userKey), field, value });
      callback(null, { canonical: false });
    } catch (error) { callback(error); }
  },
  async writeModelProfileField(input) {
    calls.canonical.push(input);
    return { written: true };
  },
};

function loadRouteInternals() {
  const originalLoad = Module._load;
  Module._load = function loadXssRouteDependency(request, parent, isMain) {
    if (parent?.filename === ROUTE_PATH) {
      if (request === '../middleware/adminAuth') return { authenticateToken(req, res, next) {
        if (req.headers?.authorization !== 'Bearer fixture') return res.status(401).json({ error: 'fixture credential required' });
        req.user = { id: 17, role: 'student' }; return next();
      } };
      if (request === '../database/xssWorkshopDb') return fakeDb;
      if (request === '../services/multiProviderAIService') return {};
      if (request === '../services/xssMailProvider') return {
        getXssMailProvider: () => ({ mailbox: {} }), resolveXssMailContext: async () => ({ email: null }),
      };
      if (request === '../services/xssEmailDispatch') return { getXssEmailDispatch: () => ({}) };
      if (request === '../services/xssObjectiveGrader') return { createXssObjectiveGrader: () => ({ close() {} }) };
      if (request === '../utils/progressSync') return {
        syncObjectiveComplete: async () => {}, checkAndMarkWorkshopComplete: async () => {},
        resetWorkshopProgress: async () => {}, getUserWorkshopProgress: async () => [],
        getCanonicalWorkshopCompletions: async () => ({ objectiveIds: [] }),
      };
    }
    return originalLoad.call(this, request, parent, isMain);
  };
  try {
    delete require.cache[require.resolve(ROUTE_PATH)];
    return require(ROUTE_PATH)._internals;
  } finally {
    Module._load = originalLoad;
    delete require.cache[require.resolve(ROUTE_PATH)];
  }
}

const { executeXssTool } = loadRouteInternals();
const update = value => ({ tool: 'updateProfile', args: { field: 'bio', value } });
const decision = { decisionSource: 'model', modelSucceeded: true, provider: 'ollama',
  model: 'llama3.1:8b', rawResponse: '{"tool":"updateProfile"}', observationIndex: 0 };

test.after(() => {
  if (priorEngine === undefined) delete process.env.PLATFORM_DATABASE_ENGINE;
  else process.env.PLATFORM_DATABASE_ENGINE = priorEngine;
  if (priorInternals === undefined) delete process.env.EXPORT_INTERNALS;
  else process.env.EXPORT_INTERNALS = priorInternals;
});

test.beforeEach(() => { calls.anonymous.length = 0; calls.canonical.length = 0; });

test('anonymous stored-LLM update uses only the noncanonical anonymous adapter', async () => {
  const userKey = 'anon_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
  const value = '<img src=x onerror="alert(1)">';
  const result = await executeXssTool(update(value), userKey, 'stored_llm', null,
    { userId: null, generation: undefined, execution: undefined, originalMessage: 'save it' }, decision);
  assert.equal(result.success, true);
  assert.deepEqual(calls.anonymous, [{ userKey, field: 'bio', value }]);
  assert.equal(calls.canonical.length, 0);

  const invalidOwner = await executeXssTool(update(value), '7', 'stored_llm', null,
    { userId: null }, decision);
  assert.match(invalidOwner.error, /anonymous profile owner|owner/i);
  assert.equal(calls.canonical.length, 0);
});

test('only a positive numeric platform identity reaches canonical model-origin writes', async () => {
  const value = '<img src=x onerror="alert(2)">';
  const execution = { runId: '11111111-1111-4111-8111-111111111111' };
  const authenticated = await executeXssTool(update(value), '7', 'stored_llm', null,
    { userId: 7, generation: 4, execution, originalMessage: 'save it' }, decision);
  assert.equal(authenticated.success, true);
  assert.equal(calls.canonical.length, 1);
  assert.equal(calls.canonical[0].platformUserId, 7);
  assert.equal(calls.anonymous.length, 0);

  for (const userId of ['7', 0, -1, undefined, Number.NaN]) {
    const rejected = await executeXssTool(update(value), '7', 'stored_llm', null,
      { userId, generation: 4, execution, originalMessage: 'save it' }, decision);
    assert.equal(rejected.error, 'Authenticated platform user required');
  }
  assert.equal(calls.canonical.length, 1);
  assert.equal(calls.anonymous.length, 0);
});

test('actual objective grader keeps anonymous stored-LLM attempts diagnostic and uncredited', async () => {
  let judged = 0;
  let synced = 0;
  const grader = createXssObjectiveGrader({ postgres: true,
    completionService: { beginAttempt: async () => { throw new Error('anonymous attempt must not begin'); } },
    judge: { evaluate: async () => { judged++; return { verdict: 'pass' }; } },
    browserQualification: { qualify: async () => ({ executed: true }), close() {} },
    syncObjectiveComplete: async () => { synced++; },
  });
  const execution = { check: async () => {}, signal: new AbortController().signal };
  const attempt = await grader.begin(null, 'xss_g2', execution);
  assert.equal(attempt, null);
  const result = await grader.evaluate({ userId: null, objectiveId: 'xss_g2', exerciseId: 'stored_llm',
    message: 'save it', response: 'saved', grading: { modelSucceeded: true,
      toolCall: { tool: 'updateProfile' }, toolResult: { success: true, field: 'bio', value: '<img onerror=x>' } },
    profileBefore: {}, profileReadback: { bio: '<img onerror=x>' }, execution, attempt });
  assert.equal(result.completed, false);
  assert.equal(result.judgment.verdict, 'inconclusive');
  assert.equal(judged, 0);
  assert.equal(synced, 0);
});
