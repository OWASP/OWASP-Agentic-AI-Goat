'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createSecureShopSystemConfigComposition } = require(
  '../server/services/secureshopSystemConfigComposition');

function dependencies() {
  return { agentsPool: { query: async () => ({ rows: [] }) },
    personaAuthority: { capture: async () => ({}) }, audit: { append: async () => {} },
    client: { read: async () => ({}), metrics: async () => ({}), assertReady: async () => true },
    authenticatePersona: (_req, _res, next) => next() };
}

test('System composition awaits repository readiness before creating service or router', async () => {
  const calls = []; let release; const deps = {...dependencies(), modeAuthority:{capture(){},assertToken(){}}};
  const pending = new Promise(resolve => { release = resolve; });
  const repository = { checkReadiness: async () => { calls.push('readiness'); await pending; } };
  const creating = createSecureShopSystemConfigComposition(deps, {
    createRepository(input) { calls.push('repository'); assert.equal(input.pool, deps.agentsPool);
      assert.equal(input.personaAuthority, deps.personaAuthority); assert.equal(input.audit, deps.audit); assert.equal(input.modeAuthority,deps.modeAuthority);
      return repository; },
    createService(input) { calls.push('service'); assert.equal(input.repository, repository); assert.equal(input.modeAuthority,deps.modeAuthority);
      return { read() {}, operation() {}, administration() {} }; },
    createRouter() { calls.push('router'); return () => {}; },
    createHealthService() { calls.push('health-service'); return { health() {} }; },
    createHealthRouter() { calls.push('health-router'); return () => {}; },
  });
  await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(calls, ['repository', 'readiness']);
  release(); const result = await creating;
  assert.deepEqual(calls, ['repository', 'readiness', 'service', 'router', 'health-service', 'health-router']);
  assert.equal(result.ready, true); assert.ok(Object.isFrozen(result));
});

test('System composition rejects partial authority, client and repository readiness', async () => {
  for (const change of [{ personaAuthority: {} }, { audit: {} }, { client: { read() {} } },
    { authenticatePersona: null }]) {
    await assert.rejects(createSecureShopSystemConfigComposition({ ...dependencies(), ...change }),
      /dependencies required/);
  }
  await assert.rejects(createSecureShopSystemConfigComposition(dependencies(), {
    createRepository: () => ({}),
  }), /repository readiness required/);
  await assert.rejects(createSecureShopSystemConfigComposition(dependencies(), {
    createRepository: () => ({ checkReadiness: async () => { throw new Error('not ready'); } }),
  }), /not ready/);
});
