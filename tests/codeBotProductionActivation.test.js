'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { enabled, runnerOrigin, requestKey, readRunnerReadiness, admitCodeBotRequest, createCodeBotProductionActivation } =
  require('../server/services/supplyChain/codeBotProduction');

const pgEnv = (extra = {}) => ({ PLATFORM_DATABASE_ENGINE: 'postgres',
  CODEBOT_OWNED_EXECUTION_ENABLED: 'true', CODEBOT_SANDBOX_RUNNER_URL: 'http://127.0.0.1:8092', ...extra });

test('CodeBot activation flag and runner origin reject ambiguous configuration', () => {
  assert.equal(enabled({}), false); assert.equal(enabled({ CODEBOT_OWNED_EXECUTION_ENABLED: 'false' }), false);
  assert.equal(enabled(pgEnv()), true);
  assert.throws(() => enabled({ CODEBOT_OWNED_EXECUTION_ENABLED: 'yes' }), /must be true or false/);
  assert.equal(runnerOrigin(pgEnv()).href, 'http://127.0.0.1:8092/');
  for (const value of ['', 'file:///tmp/runner', 'http://user:pass@localhost:8092/', 'http://localhost:8092/path']) {
    assert.throws(() => runnerOrigin(pgEnv({ CODEBOT_SANDBOX_RUNNER_URL: value })));
  }
});

test('PostgreSQL request admission requires one bounded session-scoped replay key', () => {
  assert.throws(() => requestKey(undefined, 7), error => error.status === 400 && /required/.test(error.message));
  assert.throws(() => requestKey('short', 7), error => error.status === 400 && /16-128/.test(error.message));
  assert.equal(requestKey(undefined, 'legacy', { postgres: false }), undefined);
  const first = requestKey('stable-request-key-0001', 7);
  assert.match(first, /^[a-f0-9]{64}$/); assert.equal(first, requestKey('stable-request-key-0001', 7));
  assert.notEqual(first, requestKey('stable-request-key-0001', 8));
});

test('strict runner readiness requires the exact CodeBot isolation receipt', async () => {
  const response = value => ({ ok: true, async text() { return JSON.stringify(value); } });
  const ready = await readRunnerReadiness({ env: pgEnv(), fetchImpl: async () => response({
    status: 'ok', bwrap: true, codebotAvailable: true, codebotIsolation: 'bwrap-codebot-v1',
  }) });
  assert.deepEqual(ready, { ready: true, runnerReady: true, isolation: 'bwrap-codebot-v1' });
  for (const value of [
    { status: 'ok', bwrap: true, codebotAvailable: false, codebotIsolation: 'unavailable' },
    { status: 'ok', bwrap: true, codebotAvailable: true, codebotIsolation: 'bwrap-netns' },
  ]) assert.equal((await readRunnerReadiness({ env: pgEnv(), fetchImpl: async () => response(value) })).ready, false);
});

test('configured replay remains available while new effects require a ready runner', async () => {
  const events = [];
  const activation = createCodeBotProductionActivation({ env: pgEnv(),
    journal: { async assertReady() { events.push('journal'); } },
    runnerReadiness: async () => ({ ready: false, runnerReady: false, isolation: null }) });
  const startup = await activation.initialize(); assert.equal(startup.ready, false);
  const response = { status(code) { events.push(['status', code]); return this; }, json(body) { events.push(['body', body]); } };
  await activation.requireConfigured({}, response, () => events.push('configured'));
  assert.equal(events.includes('configured'), true, 'journal replay is not gated on transient runner health');
  await activation.requireReady({}, response, () => events.push('next'));
  assert.equal(events.includes('next'), false); assert.ok(events.some(value => value?.[0] === 'status' && value[1] === 503));
  assert.match(events.find(value => value?.[0] === 'body')[1].error, /No model or tool was run/);
  await assert.rejects(activation.assertEffectReady(), { code: 'CODEBOT_RUNNER_UNAVAILABLE' });

  const ready = createCodeBotProductionActivation({ env: pgEnv(), journal: { async assertReady() {} },
    runnerReadiness: async () => ({ ready: true, runnerReady: true, isolation: 'bwrap-codebot-v1' }) });
  let proceeded = false; await ready.requireReady({}, response, () => { proceeded = true; }); assert.equal(proceeded, true);
});

test('disabled PostgreSQL remains a truthful 503 while non-PostgreSQL fixtures retain legacy routing', async () => {
  const response = { code: null, status(code) { this.code = code; return this; }, json() {} };
  const disabled = createCodeBotProductionActivation({ env: { PLATFORM_DATABASE_ENGINE: 'postgres',
    CODEBOT_OWNED_EXECUTION_ENABLED: 'false' }, journal: null, runnerReadiness: async () => { throw Error('must not probe'); } });
  assert.deepEqual(await disabled.initialize(), { enabled: false, ready: false, journalReady: false, runnerReady: false });
  await disabled.requireReady({}, response, () => assert.fail('disabled PostgreSQL must not continue')); assert.equal(response.code, 503);
  await disabled.requireConfigured({}, response, () => assert.fail('disabled PostgreSQL must not expose stored requests')); assert.equal(response.code, 503);
  const legacy = createCodeBotProductionActivation({ env: {}, journal: null }); let next = 0;
  await legacy.requireReady({}, response, () => { next++; }); assert.equal(next, 1);
  await legacy.requireConfigured({}, response, () => { next++; }); assert.equal(next, 2);
});

test('invalid origin and unavailable journal fail configured requests without probing the runner', async () => {
  let probes = 0;
  for (const activation of [
    createCodeBotProductionActivation({ env: pgEnv({ CODEBOT_SANDBOX_RUNNER_URL: 'file:///tmp/runner' }),
      journal: { async assertReady() {} }, runnerReadiness: async () => { probes++; return { ready: true }; } }),
    createCodeBotProductionActivation({ env: pgEnv(), journal: { async assertReady() { throw Error('missing'); } },
      runnerReadiness: async () => { probes++; return { ready: true }; } }),
  ]) {
    const response = { code: null, status(code) { this.code = code; return this; }, json() {} };
    await activation.requireConfigured({}, response, () => assert.fail('invalid configuration must fail closed'));
    assert.equal(response.code, 503);
  }
  assert.equal(probes, 0);
});

test('request admission replays before runner health and gates new work before journal claim', async () => {
  const value = { requestKey: 'a'.repeat(64) };
  const replayEvents = [];
  const replay = await admitCodeBotRequest({ value,
    journal: { async assertReady() { replayEvents.push('journal'); }, async replay() {
      replayEvents.push('replay'); return { replayed: true, response: { success: true } };
    }, async claim() { assert.fail('completed replay must not claim again'); } },
    execution: { async check() { replayEvents.push('authority'); } },
    activation: { async assertEffectReady() { assert.fail('completed replay must not require runner health'); } },
  });
  assert.deepEqual(replay, { replayed: true, response: { success: true } });
  assert.deepEqual(replayEvents, ['journal', 'replay', 'authority']);

  let outageProbe = 0;
  await assert.rejects(admitCodeBotRequest({ value,
    journal: { async assertReady() {}, async replay() { return { replayed: true, response: { success: true } }; } },
    execution: { async check() { throw Object.assign(Error('revoked'), { code: 'CODEBOT_PLATFORM_SESSION_STALE' }); } },
    activation: { async assertEffectReady() { outageProbe++; } },
  }), { code: 'CODEBOT_PLATFORM_SESSION_STALE' });
  assert.equal(outageProbe, 0, 'revoked sessions cannot receive a stored response or trigger a runner probe');

  const newEvents = [];
  await assert.rejects(admitCodeBotRequest({ value,
    journal: { async assertReady() { newEvents.push('journal'); }, async replay() { newEvents.push('replay'); return null; },
      async claim() { newEvents.push('claim'); return { replayed: false }; } },
    execution: { async check() { newEvents.push('authority'); } },
    activation: { async assertEffectReady() { newEvents.push('runner'); throw Object.assign(Error('down'), { code: 'CODEBOT_RUNNER_UNAVAILABLE' }); } },
  }), { code: 'CODEBOT_RUNNER_UNAVAILABLE' });
  assert.deepEqual(newEvents, ['journal', 'replay', 'authority', 'runner'], 'runner outage creates no journal claim or actor work');
});

test('malformed optional activation configuration never prevents application startup', async () => {
  const activation = createCodeBotProductionActivation({ env: pgEnv({ CODEBOT_OWNED_EXECUTION_ENABLED: 'invalid' }), journal: null });
  assert.deepEqual(await activation.initialize(), { enabled: false, ready: false, journalReady: false, runnerReady: false });
});
