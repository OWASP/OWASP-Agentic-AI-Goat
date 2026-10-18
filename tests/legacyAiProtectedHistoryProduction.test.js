'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createLegacyAiProtectedHistoryProduction } = require('../server/services/legacyAiProtectedHistoryProduction');
function fixture(overrides = {}) {
  const calls = [];
  const env = { PLATFORM_DATABASE_ENGINE: 'postgres', IDENTITY_DATABASE_URL: 'postgres://runtime:private@localhost/test_identity' };
  const adapter = { pool: {}, validateSession() {} };
  const infer = () => {};
  const gate = () => {};
  const runtime = createLegacyAiProtectedHistoryProduction({ env,
    getIdentityAdapter: () => adapter,
    createInference: options => { calls.push({ inference: options }); return infer; },
    createExperimentAccess: key => { calls.push({ key }); return gate; },
    createComposition: async options => { calls.push({ options }); return { readiness: { ready: true }, router: (req, res) => res.json({ protected: true }) }; },
    ...overrides,
  });
  return { runtime, env, adapter, infer, gate, calls };
}
function dispatch(runtime, method, path) {
  const result = { status: 200, next: 0 };
  const res = { status(code) { result.status = code; return this; }, json(body) { result.body = body; return this; } };
  runtime.middleware({ method, path }, res, () => { result.next++; });
  return result;
}
test('all protected operations fail closed before startup and unrelated routes pass', () => {
  const { runtime } = fixture();
  for (const path of ['/prompt-injection', '/chain-of-thought', '/context-stuffing', '/multi-turn-jailbreak', '/PROMPT-INJECTION/']) {
    assert.deepEqual(dispatch(runtime, 'POST', path), { status: 503, next: 0, body: { error: 'Protected history unavailable' } });
  }
  for (const method of ['GET', 'HEAD']) for (const path of ['/history', '/history/admin']) assert.equal(dispatch(runtime, method, path).status, 503);
  assert.equal(dispatch(runtime, 'GET', '/conversations/1').next, 1);
  assert.equal(dispatch(runtime, 'POST', '/model-poisoning').next, 1);
});
test('initialization binds canonical pool, gate and reloadable operator inference exactly once', async () => {
  const { runtime, calls, adapter, infer, gate, env } = fixture();
  const first = runtime.initialize();
  assert.equal(runtime.initialize(), first);
  assert.deepEqual(await first, { enabled: true, ready: true });
  const options = calls.find(call => call.options).options;
  assert.equal(options.identityAdapter, adapter);
  assert.equal(options.identityPool, adapter.pool);
  assert.equal(options.expectedDatabase, 'test_identity');
  assert.equal(options.infer, infer);
  assert.equal(options.experimentAccess, gate);
  assert.equal(calls.find(call => call.key).key, 'prompt_injection');
  env.JUDGE_MODEL = 'changed';
  assert.equal(calls.find(call => call.inference).inference.getEnvironment().JUDGE_MODEL, 'changed');
  assert.deepEqual(dispatch(runtime, 'POST', '/prompt-injection'), { status: 200, next: 0, body: { protected: true } });
});
test('initialization errors are sanitized and cannot expose old writes', async () => {
  const { runtime } = fixture({ createComposition: async () => { throw new Error('private password'); } });
  await assert.rejects(runtime.initialize(), error => error.code === 'LEGACY_AI_PROTECTED_HISTORY_UNAVAILABLE' && !error.message.includes('password'));
  assert.equal(dispatch(runtime, 'POST', '/prompt-injection').status, 503);
});
test('router fallthrough remains closed', async () => {
  const { runtime } = fixture({ createComposition: async () => ({ readiness: { ready: true }, router: (req, res, next) => next() }) });
  await runtime.initialize();
  assert.equal(dispatch(runtime, 'POST', '/prompt-injection').status, 503);
  assert.equal(dispatch(runtime, 'POST', '/prompt-injection').next, 0);
});
test('invalid database URL and missing readiness reject activation', async () => {
  for (const url of ['http://localhost/db', 'postgres://localhost/', 'postgres://localhost/db/other', 'postgres://localhost/%ZZ']) {
    const { runtime } = fixture({ env: { PLATFORM_DATABASE_ENGINE: 'postgres', IDENTITY_DATABASE_URL: url } });
    await assert.rejects(runtime.initialize(), { code: 'LEGACY_AI_PROTECTED_HISTORY_UNAVAILABLE' });
  }
  const { runtime } = fixture({ createComposition: async () => ({ router() {} }) });
  await assert.rejects(runtime.initialize(), { code: 'LEGACY_AI_PROTECTED_HISTORY_UNAVAILABLE' });
});
test('explicit legacy fixture engine bypasses dependencies', async () => {
  const { runtime } = fixture({ env: { PLATFORM_DATABASE_ENGINE: 'sqlite' }, getIdentityAdapter() { throw new Error('must not load'); } });
  assert.deepEqual(await runtime.initialize(), { enabled: false, ready: false });
  assert.equal(dispatch(runtime, 'POST', '/prompt-injection').next, 1);
});
