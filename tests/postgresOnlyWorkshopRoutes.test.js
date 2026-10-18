'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const Module = require('node:module');
const path = require('node:path');
const test = require('node:test');

const repositoryRoot = path.join(__dirname, '..');
const routeFiles = [
  'sqlWorkshop.js',
  'nosqlWorkshop.js',
  'csrfWorkshop.js',
  'promptInjectionWorkshop.js',
  'xssEmail.js'
];

function response() {
  return {
    statusCode: 200,
    status(value) { this.statusCode = value; return this; },
    json(value) { this.body = value; return this; }
  };
}

function routeHandler(router, routePath) {
  const layer = router.stack.find(candidate => candidate.route?.path === routePath);
  assert.ok(layer, `missing ${routePath}`);
  return layer.route.stack.at(-1).handle;
}

function loadContentRoute(filename, config) {
  const routePath = require.resolve(`../server/routes/${filename}`);
  const original = Module._load;
  Module._load = function load(request, parent, isMain) {
    if (request === '../database/authDb' || request === 'sqlite3' || request === 'better-sqlite3') {
      throw new Error(`retired database import: ${request}`);
    }
    if (parent?.filename === routePath) {
      if (request === '../services/ariaAgentService' || request === '../services/novaAgentService') return {};
      if (request === '../database/sqlWorkshopDb' || request === '../database/nosqlWorkshopDb') return {};
      if (request === '../middleware/adminAuth') return { authenticateToken(_req, _res, next) { next(); } };
      if (request === '../services/workshopModeService') return {};
      if (request === '../services/workshopModeHandlers') {
        return { createWorkshopModeHandlers: () => ({ get() {}, set() {} }) };
      }
      if (request === '../services/workshopConfigService') {
        return { createWorkshopConfigService: () => config };
      }
      if (request === '../utils/progressSync') {
        return { syncObjectiveComplete() {}, resetWorkshopProgress() {} };
      }
      if (request === '../agent-runtime/workshopRouteHandlers') {
        return { createWorkshopRouteHandlers: () => ({ chat() {}, reset() {} }) };
      }
    }
    return original.call(this, request, parent, isMain);
  };
  delete require.cache[routePath];
  try { return require(routePath); }
  finally { Module._load = original; delete require.cache[routePath]; }
}

test('owned workshop routes contain no SQLite or engine-selected imports', () => {
  for (const filename of routeFiles) {
    const source = fs.readFileSync(path.join(repositoryRoot, 'server/routes', filename), 'utf8');
    assert.doesNotMatch(source, /(?:authDb|sqlite3|better-sqlite3|DATABASE_ENGINE)/, filename);
  }

  const xssEmail = fs.readFileSync(path.join(repositoryRoot, 'server/routes/xssEmail.js'), 'utf8');
  assert.match(xssEmail, /require\('\.\.\/database\/postgres\/xssWorkshopDb'\)\.emailBuilder/);
  assert.match(xssEmail, /const canonical = require\('\.\.\/services\/xssEmailBuilderCanonical'\)\.getXssEmailBuilderCanonical\(\)/);
  assert.doesNotMatch(xssEmail, /if\s*\(\s*!?canonical|canonical\s*\?/);
});

test('XSS email route always admits the owner and binds grading to canonical PostgreSQL state', async () => {
  const routePath = require.resolve('../server/routes/xssEmail');
  const original = Module._load;
  const admissions = [];
  let graderOptions;
  const canonical = {
    async admit(owner, execution) { admissions.push({ owner, execution }); },
    async snapshot() { return { objectives: [] }; }
  };
  const execution = { check: async () => {} };
  const store = {
    async ensureProfile(owner) { return { user_id: owner, full_name: 'Owned profile' }; },
    async persistCompletion() {},
    async persistJudgment() {}
  };
  Module._load = function load(request, parent, isMain) {
    if (request === '../database/xssEmailDb' || request === '../database/xssEmailStore'
      || request === 'sqlite3' || request === 'better-sqlite3') {
      throw new Error(`retired database import: ${request}`);
    }
    if (parent?.filename === routePath) {
      if (request === '../database/postgres/xssWorkshopDb') return { emailBuilder: store };
      if (request === '../services/multiProviderAIService') return {};
      if (request === '../middleware/adminAuth') return { authenticateToken(_req, _res, next) { next(); } };
      if (request === '../services/xssEmailObjectiveGrader') {
        return { createXssEmailObjectiveGrader(options) { graderOptions = options; return { evaluate: async () => ({ completedLevels: [], judgments: [] }) }; } };
      }
      if (request === '../agent-runtime/ownerWorkflowRoutes') return { getOwnerExecution: () => execution };
      if (request === '../agent-runtime/runCoordinator') return { createRunCoordinator: () => ({}) };
      if (request === '../agent-runtime/postgresRunLedger') return { configuredRunLedger: () => ({}) };
      if (request === '../agent-runtime/xssOwnerWorkflowRoute') return { createXssOwnerWorkflowRoute: () => handler => handler };
      if (request === '../services/xssEmailBuilderCanonical') return { getXssEmailBuilderCanonical: () => canonical };
    }
    return original.call(this, request, parent, isMain);
  };
  delete require.cache[routePath];
  let router;
  try { router = require(routePath); }
  finally { Module._load = original; delete require.cache[routePath]; }

  const result = response();
  await routeHandler(router, '/profile/:userId')({ user: { id: 42 }, params: { userId: '999' } }, result);
  assert.deepEqual(result.body, { profile: { user_id: 42, full_name: 'Owned profile' } });
  assert.deepEqual(admissions, [{ owner: 42, execution }]);
  assert.strictEqual(graderOptions.canonical, canonical);
  assert.equal(typeof graderOptions.persistCompletion, 'function');
  assert.equal(typeof graderOptions.persistJudgment, 'function');
});

for (const fixture of [
  { route: 'sqlWorkshop.js', key: 'sql_injection_workshop', denied: 'sqli_1', allowed: 'sqli_2' },
  { route: 'nosqlWorkshop.js', key: 'nosql_injection_workshop', denied: 'nosqli_1', allowed: 'nosqli_2' }
]) {
  test(`${fixture.key} solution endpoints preserve canonical gates and instructor content`, async () => {
    const instructorContent = {
      title: 'Instructor title',
      difficulty: 'custom',
      hints: ['Instructor hint'],
      examples: ['Instructor example'],
      approach: 'Instructor approach',
      tips: ['Instructor tip']
    };
    const calls = [];
    const config = {
      async getSolutionVisibilityMap(key) {
        calls.push(['visibility', key]);
        return { [fixture.denied]: false, [fixture.allowed]: true };
      },
      async getStudentContent(key, objectiveId, kind) {
        calls.push(['content', key, objectiveId, kind]);
        if (objectiveId === fixture.denied) throw Object.assign(new Error('Content is hidden'), { code: 'FORBIDDEN' });
        return instructorContent;
      }
    };
    const router = loadContentRoute(fixture.route, config);
    const status = response();
    await routeHandler(router, '/solutions/status')({}, status);
    assert.deepEqual(status.body, {
      success: true,
      objectives: { [fixture.denied]: false, [fixture.allowed]: true }
    });

    const denied = response();
    await routeHandler(router, '/solutions/:objectiveId')({ params: { objectiveId: fixture.denied } }, denied);
    assert.equal(denied.statusCode, 403);
    assert.deepEqual(denied.body, { success: false, error: 'Solution not available for this objective' });

    const allowed = response();
    await routeHandler(router, '/solutions/:objectiveId')({ params: { objectiveId: fixture.allowed } }, allowed);
    assert.equal(allowed.statusCode, 200);
    assert.deepEqual(allowed.body, { success: true, solution: instructorContent });
    assert.deepEqual(calls, [
      ['visibility', fixture.key],
      ['content', fixture.key, fixture.denied, 'solution'],
      ['content', fixture.key, fixture.allowed, 'solution']
    ]);
  });
}
