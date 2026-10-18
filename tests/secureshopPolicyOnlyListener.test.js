'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { createPolicyOnlyListener } = require('../sidecars/sandbox-runner/policy-render/listener');
const { requestDigest } = require('../server/services/secureshopPromptPolicyContract');

const executable = () => ({ uid: 0, gid: 0, mode: 0o100555,
  isFile: () => true, isSymbolicLink: () => false });
const request = () => ({ operationId: crypto.randomUUID(), name: 'owned-policy',
  markdown: 'Returns for {{ store_name }}.', targets: ['admin'] });
const receipt = value => ({ version: 1, operationId: value.operationId,
  requestSha256: requestDigest(value), isolation: 'bwrap-policy-template-v1',
  rendered: 'Returns for SecureShop.',
  renderedSha256: crypto.createHash('sha256').update('Returns for SecureShop.').digest('hex'),
  exitCode: 0, timedOut: false, truncated: false, drained: true });
const dependencies = overrides => ({ env: { SECURESHOP_POLICY_RENDER_ENABLED: 'true',
  SECURESHOP_POLICY_RENDER_MAX_CONCURRENT: '1' }, lstatSync: executable,
checkAssets: () => {}, strictProbe: () => true,
createExecutor: () => ({ render: async value => receipt(value) }), ...overrides });

test('dedicated listener admits only strict packaged renderer and bounded capacity', () => {
  let touched = 0;
  assert.throws(() => createPolicyOnlyListener(dependencies({ env: {},
    lstatSync: () => { touched++; return executable(); } })), { code: 'POLICY_RENDER_UNAVAILABLE' });
  assert.equal(touched, 0);
  assert.throws(() => createPolicyOnlyListener(dependencies({
    lstatSync: () => ({ ...executable(), uid: 10001 }),
  })), { code: 'POLICY_RENDER_UNAVAILABLE' });
  assert.throws(() => createPolicyOnlyListener(dependencies({
    lstatSync: filename => filename === '/usr/bin/bwrap'
      ? { ...executable(), mode: 0o100577 } : executable(),
  })), { code: 'POLICY_RENDER_UNAVAILABLE' });
  assert.throws(() => createPolicyOnlyListener(dependencies({ strictProbe: () => false })),
    { code: 'POLICY_RENDER_UNAVAILABLE' });
  assert.throws(() => createPolicyOnlyListener(dependencies({ checkAssets: () => { throw Error('mismatch'); } })),
    { code: 'POLICY_RENDER_UNAVAILABLE' });
  assert.throws(() => createPolicyOnlyListener(dependencies({ env: {
    SECURESHOP_POLICY_RENDER_ENABLED: 'true', SECURESHOP_POLICY_RENDER_MAX_CONCURRENT: '2',
  } })), { code: 'POLICY_RENDER_UNAVAILABLE' });
});

test('shutdown bounds a never-settling handler and does not claim a drained renderer', async () => {
  const listener = createPolicyOnlyListener(dependencies({ policyDrainMs: 100,
    createHandler: () => ({ handle: async () => true, close: () => new Promise(() => {}) }),
  }));
  await listener.listen(0, '127.0.0.1');
  const closing = listener.close();
  assert.equal(listener.close(), closing);
  await assert.rejects(closing, { code: 'POLICY_RENDER_DRAIN_TIMEOUT' });
  assert.equal(listener.server.listening, false);
});

test('dedicated listener exposes only health and real handler render, then drains on close', async t => {
  let renders = 0;
  const listener = createPolicyOnlyListener(dependencies({ createExecutor: () => ({
    render: async value => { renders++; return receipt(value); },
  }) }));
  await listener.listen(0, '127.0.0.1');
  t.after(() => listener.close());
  const base = `http://127.0.0.1:${listener.server.address().port}`;
  const health = await fetch(`${base}/health`);
  assert.equal(health.status, 200);
  assert.equal(health.headers.get('cache-control'), 'no-store');
  assert.deepEqual((await health.json()).policyRenderer,
    { enabled: true, available: true, isolation: 'bwrap-policy-template-v1' });
  for (const [method, pathname, expected] of [
    ['POST', '/health', 405], ['GET', '/exec', 404], ['POST', '/reset', 404],
    ['GET', '/owned-targets/status', 404], ['GET', '/secureshop/policy-render', 405],
  ]) assert.equal((await fetch(`${base}${pathname}`, { method })).status, expected);
  assert.equal(renders, 0);
  const value = request();
  const rendered = await fetch(`${base}/secureshop/policy-render`, { method: 'POST',
    headers: { 'content-type': 'application/json' }, body: JSON.stringify(value) });
  assert.equal(rendered.status, 200);
  assert.deepEqual(await rendered.json(), receipt(value));
  assert.equal(renders, 1);
  const first = listener.close();
  assert.equal(listener.close(), first);
  await first;
});

test('dedicated listener never projects an invalid effect as a successful render', async t => {
  const listener = createPolicyOnlyListener(dependencies({ createExecutor: () => ({
    render: async value => ({ ...receipt(value), drained: false }),
  }) }));
  await listener.listen(0, '127.0.0.1');
  t.after(() => listener.close());
  const response = await fetch(`http://127.0.0.1:${listener.server.address().port}/secureshop/policy-render`,
    { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(request()) });
  assert.equal(response.status, 503);
  assert.deepEqual(await response.json(), { error: 'POLICY_RENDER_UNAVAILABLE' });
});
