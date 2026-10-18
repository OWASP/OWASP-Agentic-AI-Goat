'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { createCsrfBrowserAttempt } = require('../server/services/csrfBrowserAttempt');
function fixture(extra = {}) {
  const controller = new AbortController();
  const execution = { ownerKey: '["CSRF","17"]', runId: 'owned-run', generation: 3,
    signal: controller.signal, check: async () => {} };
  return { controller, execution, options: { execution, objectiveId: 'csrf_p1', tab: 'post',
    html: '<form>exact learner bytes</form>', dispatch: async () => ({ status: 200 }), ...extra } };
}
test('private attempt preserves payload digest and admits only one concurrent dispatch', async () => {
  let release, calls = 0, retainedCheck;
  const gate = new Promise(resolve => { release = resolve; });
  const { options } = fixture({ dispatch: async ({ binding, check }) => {
    calls++; retainedCheck = check;
    assert.equal(binding.payloadDigest, createHash('sha256').update(options.html).digest('hex'));
    await gate; return { status: 200 };
  } });
  const attempt = createCsrfBrowserAttempt(options);
  const first = attempt.consume({ method: 'POST' });
  await assert.rejects(attempt.consume({ method: 'POST' }), /consumed/);
  release(); assert.deepEqual(await first, { status: 200 }); assert.equal(calls, 1);
  await assert.rejects(retainedCheck(), /expired or cancelled/);
});
test('reset during prerequisite work prevents subsequent effect and publication', async () => {
  let entered, release, effects = 0;
  const started = new Promise(resolve => { entered = resolve; });
  const gate = new Promise(resolve => { release = resolve; });
  const f = fixture({ dispatch: async ({ check }) => {
    entered(); await gate; await check(); effects++; return { status: 200 };
  } });
  const attempt = createCsrfBrowserAttempt(f.options), pending = attempt.consume({});
  await started; f.controller.abort(); release();
  await assert.rejects(pending, { name: 'AbortError' }); assert.equal(effects, 0);
  await assert.rejects(attempt.consume({}), /revoked/);
});
test('expiry and stale execution reject before dispatch without retrying', async () => {
  let time = 0, calls = 0;
  const f = fixture({ now: () => time, ttlMs: 10, dispatch: async () => { calls++; } });
  const attempt = createCsrfBrowserAttempt(f.options); time = 10;
  await assert.rejects(attempt.consume({}), { name: 'AbortError' }); assert.equal(calls, 0);
  const fresh = fixture({ dispatch: async () => { calls++; } });
  const stale = createCsrfBrowserAttempt(fresh.options); fresh.execution.generation++;
  await assert.rejects(stale.consume({}), /scope changed/); assert.equal(calls, 0);
});
test('revocation and invalid objective cannot authorize an action', async () => {
  const f = fixture();
  assert.throws(() => createCsrfBrowserAttempt({ ...f.options, objectiveId: 'csrf_g2' }), /objective/);
  const attempt = createCsrfBrowserAttempt(f.options); attempt.revoke();
  await assert.rejects(attempt.consume({}), /revoked/);
});
