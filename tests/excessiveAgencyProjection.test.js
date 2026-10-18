'use strict';

const assert = require('node:assert/strict');
const http = require('node:http');
const Module = require('node:module');
const path = require('node:path');
const test = require('node:test');
const express = require('express');

const routePath = path.resolve(__dirname, '../server/routes/excessiveAgencyLab.js');
const originalLoad = Module._load;
const effects = [];
let canonicalRows = [{ workshop_key: 'excessive_agency', objective_id: 'objective_1', completed: true, completed_at: 'canonical-fixture' }];
let failLocalRead = false;
const localProgress = {
  objectives: { 1: true, 2: true },
  completedAt: { 1: 'local-fixture', 2: 'local-fixture' },
};
const state = {
  database: {
    async getUserProgress() {
      if (failLocalRead) throw new Error('local projection read unavailable');
      return localProgress;
    },
    async markObjectiveComplete() {
      effects.push(['local-complete']);
      throw new Error('local projection unavailable');
    },
  },
  conversations: {
    async get() { return []; },
    async set() {},
    async delete() {},
  },
  toolRouter: { getToolDefinitions: () => [], executeTool: async () => ({}) },
};

const fakeProgressSync = {
  async syncObjectiveComplete(userId, workshopKey, objectiveId) {
    effects.push(['canonical-complete', userId, workshopKey, objectiveId]);
    canonicalRows.push({ workshop_key: workshopKey, objective_id: objectiveId, completed: true, completed_at: 'canonical-fixture' });
  },
  async checkAndMarkWorkshopComplete() {},
  async getUserWorkshopProgress(userId) {
    effects.push(['canonical-read', userId]);
    return canonicalRows;
  },
  async resetWorkshopProgress(userId, workshopKey) {
    effects.push(['canonical-reset', userId, workshopKey]);
    canonicalRows = canonicalRows.filter(row => row.workshop_key !== workshopKey);
  },
};

const fakeAttendeeLabs = {
  async resolveSession(token, userId) {
    if (token !== 'lab-fixture') return null;
    return { labUser: { userId }, state };
  },
  async getOrCreate() { return state; },
  async resetAttendee() {
    effects.push(['local-reset']);
    // Deliberately leave the local row present: GET must follow canonical reset.
    return state;
  },
};

function authenticateToken(req, res, next) {
  if (req.headers.authorization !== 'Bearer fixture') return res.status(401).json({ error: 'Authentication required' });
  req.user = { id: 41, admin_level: 0 };
  next();
}

const visibleObjectives = Object.fromEntries(Array.from({ length: 9 }, (_, index) => [
  `objective_${index + 1}`, { isVisible: true },
]));

Module._load = function load(request, parent, isMain) {
  if (parent?.filename === routePath) {
    // Fail closed if a route dependency starts importing a live database or
    // repository. Every dependency used by this isolated test is explicit below.
    if (/(?:^|\/)(?:database|authDb|sqlite|postgres)(?:\/|\.js|$)/i.test(request)) {
      throw new Error(`Unexpected database dependency in isolated EA route test: ${request}`);
    }
    if (request === '../agent-runtime/ownerWorkflowRoutes') {
      return {
        checkOwnerRun: async () => {},
        getOwnerExecution: () => null,
        ownerWorkflowRoute: (_coordinator, _ownerFor, handler) => handler,
      };
    }
    if (request === '../agent-runtime/runCoordinator') {
      return { createRunCoordinator: () => ({
        async run(_owner, _options, work) { return work({ check: async () => {} }); },
        async reset(_owner, work) { return work(); },
      }) };
    }
    if (request === '../services/excessiveAgencyAttendeeLabStore') return { excessiveAgencyAttendeeLabStore: fakeAttendeeLabs };
    if (request === '../services/multiProviderAIService') return { getActiveProviderInfo: () => ({ provider: 'fixture', model: 'fixture' }) };
    if (request === '../utils/contextLogger') return { error: () => {}, info: () => {} };
    if (request === '../middleware/adminAuth') return { authenticateToken };
    if (request === '../services/workshopModeService') return { getMode: async () => 'vulnerable' };
    if (request === '../services/workshopModeHandlers') return { createWorkshopModeHandlers: () => ({ get: (_req, res) => res.json({}), set: (_req, res) => res.json({}) }) };
    if (request === '../services/workshopConfigService') return { createWorkshopConfigService: () => ({ getSnapshot: async () => ({ exercises: { excessive_agency: { isVisible: true, objectives: visibleObjectives } } }) }) };
    if (request === '../utils/progressSync') return fakeProgressSync;
    if (request === '../agent-runtime/excessiveAgencyJudge') return { detectEACandidates: () => [1] };
    if (request === '../agent-runtime/excessiveAgencyGraph') {
      return {
        async runExcessiveAgencyGraph(_input, deps) {
          const grading = await deps.trackProgressFromToolResult(
            deps.database, deps.progressOwnerKey(41), '41', 'list_notes', {}, {}, 'vulnerable', 41, {},
            async () => ({ completed: true, durable: true, judgment: { verdict: 'pass' } })
          );
          return { finalResponse: 'fixture response', toolCall: null, toolResult: {}, ...grading };
        },
      };
    }
  }
  return originalLoad.call(this, request, parent, isMain);
};

const router = require(routePath);

test.after(() => {
  Module._load = originalLoad;
});

function request(app, { method, path: requestPath, body, authorization = 'Bearer fixture', labSession = 'lab-fixture' }) {
  return new Promise((resolve, reject) => {
    const server = http.createServer(app);
    server.listen(0, '127.0.0.1', () => {
      const payload = body == null ? '' : JSON.stringify(body);
      const req = http.request({
        hostname: '127.0.0.1', port: server.address().port, path: requestPath, method,
        headers: {
          authorization,
          'x-lab-session': labSession,
          ...(payload ? { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) } : {}),
        },
      }, res => {
        let output = '';
        res.on('data', chunk => { output += chunk; });
        res.on('end', () => server.close(() => resolve({ status: res.statusCode, body: output ? JSON.parse(output) : null })));
      });
      req.on('error', error => server.close(() => reject(error)));
      if (payload) req.write(payload);
      req.end();
    });
    server.on('error', reject);
  });
}

test('EA preserves canonical completion when local projection fails and reports the pending projection', async () => {
  effects.length = 0;
  canonicalRows = [{ workshop_key: 'excessive_agency', objective_id: 'objective_1', completed: true, completed_at: 'canonical-fixture' }];
  failLocalRead = true;
  const app = express();
  app.use(express.json());
  app.use('/ea', router);

  const response = await request(app, { method: 'POST', path: '/ea/chat', body: { message: 'show my notes' } });
  assert.equal(response.status, 200);
  assert.deepEqual(response.body.completedObjectiveIds, ['objective_1']);
  assert.deepEqual(response.body.projectionPending, ['objective_1']);
  assert.deepEqual(effects, [['local-complete'], ['canonical-read', 41]]);

  const progress = await request(app, { method: 'GET', path: '/ea/progress' });
  assert.equal(progress.status, 200);
  assert.equal(progress.body.progress.objectives[1], true);
  assert.equal(progress.body.progress.objectives[2], false);
  assert.equal(progress.body.objectives.find(objective => objective.id === 1).completed, true);
  assert.equal(progress.body.objectives.find(objective => objective.id === 2).completed, false);

  // Exercise the opposite mismatch too: canonical completion must appear even
  // when the local attendee projection has not caught up.
  canonicalRows.push({ workshop_key: 'excessive_agency', objective_id: 'objective_2', completed: true });
  localProgress.objectives[2] = false;
  const canonicalWins = await request(app, { method: 'GET', path: '/ea/progress' });
  assert.equal(canonicalWins.status, 200);
  assert.equal(canonicalWins.body.progress.objectives[2], true);
  assert.equal(canonicalWins.body.objectives.find(objective => objective.id === 2).completed, true);
  localProgress.objectives[2] = true;
  failLocalRead = false;
});

test('EA progress reset clears canonical state before local state and cannot resurrect a completed objective', async () => {
  effects.length = 0;
  failLocalRead = false;
  canonicalRows = [
    { workshop_key: 'excessive_agency', objective_id: 'objective_1', completed: true },
    { workshop_key: 'indirect_prompt_injection', objective_id: 'rag_upload', completed: true },
  ];
  const app = express();
  app.use(express.json());
  app.use('/ea', router);

  const reset = await request(app, { method: 'POST', path: '/ea/progress/reset' });
  assert.equal(reset.status, 200);
  assert.deepEqual(effects, [
    ['canonical-reset', 41, 'excessive_agency'],
    ['local-reset'],
  ]);
  assert.deepEqual(canonicalRows, [{ workshop_key: 'indirect_prompt_injection', objective_id: 'rag_upload', completed: true }]);

  const progress = await request(app, { method: 'GET', path: '/ea/progress' });
  assert.equal(progress.status, 200);
  assert.equal(progress.body.progress.objectives[1], false);
  assert.equal(progress.body.progress.objectives[2], false);
});

test('EA progress uses instructor labels and gated canonical hints without leaking hidden content', async () => {
  const app = express(); app.use('/ea', router);
  const original = { ...visibleObjectives.objective_1 };
  try {
    Object.assign(visibleObjectives.objective_1, {
      label: 'Instructor owner boundary', hintVisible: true,
      raw: { hint: { hints: ['Canonical first hint', 'Canonical second hint'] }, solution: { secret: 'Do not expose solution' } },
    });
    let response = await request(app, { method: 'GET', path: '/ea/progress' });
    assert.equal(response.status, 200);
    let objective = response.body.objectives.find(row => row.id === 1);
    assert.equal(objective.title, 'Instructor owner boundary');
    assert.equal(objective.hint, 'Canonical first hint\nCanonical second hint');
    assert.equal(JSON.stringify(response.body).includes('Do not expose solution'), false);
    visibleObjectives.objective_1.hintVisible = false;
    response = await request(app, { method: 'GET', path: '/ea/progress' });
    objective = response.body.objectives.find(row => row.id === 1);
    assert.equal(Object.hasOwn(objective, 'hint'), false);
    assert.equal(JSON.stringify(response.body).includes('Canonical first hint'), false);
    visibleObjectives.objective_1.isVisible = false;
    response = await request(app, { method: 'GET', path: '/ea/progress' });
    assert.equal(response.body.objectives.some(row => row.id === 1), false);
    assert.equal(response.body.totalObjectives, 8);
  } finally { visibleObjectives.objective_1 = original; }
});
