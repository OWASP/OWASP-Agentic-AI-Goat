'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createPolicyRendererFromEnvironment, createSandboxRunnerShutdown }
  = require('../sidecars/sandbox-runner/index');

const executable = (mode = 0o100555) => ({ uid: 0, gid: 0, mode,
  isFile: () => true, isSymbolicLink: () => false });

test('policy renderer stays absent by default without probing or constructing an executor', () => {
  let called = false;
  const value = createPolicyRendererFromEnvironment({}, {
    lstatSync: () => { called = true; }, checkAssets: () => { called = true; },
    strictProbe: () => { called = true; }, createExecutor: () => { called = true; },
    createHandler: () => { called = true; },
  });
  assert.deepEqual({ enabled: value.enabled, available: value.available, isolation: value.isolation, reason: value.reason },
    { enabled: false, available: false, isolation: 'unavailable', reason: 'disabled' });
  assert.equal(value.handler, null); assert.equal(called, false);
});

test('requested renderer advertises unavailable unless checked helpers, assets and strict probe all pass', () => {
  let probed = false, constructed = false;
  const value = createPolicyRendererFromEnvironment({ SECURESHOP_POLICY_RENDER_ENABLED: 'true' }, {
    lstatSync: () => executable(0o100577), checkAssets: () => {},
    strictProbe: () => { probed = true; return true; }, createExecutor: () => { constructed = true; },
    createHandler: () => { constructed = true; },
  });
  assert.deepEqual({ enabled: value.enabled, available: value.available, isolation: value.isolation, reason: value.reason },
    { enabled: true, available: false, isolation: 'unavailable', reason: 'strict_preflight_failed' });
  assert.equal(probed, false); assert.equal(constructed, false); assert.equal(value.handler, null);
});

test('checked strict renderer becomes available with bounded capacity and drains through its handler', async () => {
  let checked = 0, closed = 0, maximum;
  const handler = { handle() {}, async close() { closed++; } };
  const value = createPolicyRendererFromEnvironment({ SECURESHOP_POLICY_RENDER_ENABLED: 'true',
    SECURESHOP_POLICY_RENDER_MAX_CONCURRENT: '3' }, {
    lstatSync: () => executable(), checkAssets: () => { checked++; }, strictProbe: () => true,
    createExecutor: () => ({ render() {} }),
    createHandler: options => { maximum = options.maxConcurrent; return handler; },
  });
  assert.deepEqual({ enabled: value.enabled, available: value.available, isolation: value.isolation, reason: value.reason },
    { enabled: true, available: true, isolation: 'bwrap-policy-template-v1', reason: null });
  assert.equal(checked, 1); assert.equal(maximum, 3); assert.equal(value.handler, handler);
  await value.close(); assert.equal(closed, 1);
});

test('shared server shutdown waits for policy drain before closing the listener and is idempotent', async () => {
  const events = []; let release;
  const drained = new Promise(resolve => { release = resolve; });
  const server = { listening: true, close(callback) { events.push('server-close'); callback(); } };
  const shutdown = createSandboxRunnerShutdown({ serverInstance: server,
    policyRendererInstance: { async close() { events.push('policy-close'); await drained; events.push('policy-drained'); } } });
  const first = shutdown(); const second = shutdown(); assert.equal(first, second);
  await new Promise(resolve => setImmediate(resolve)); assert.deepEqual(events, ['policy-close']);
  release(); await first;
  assert.deepEqual(events, ['policy-close', 'policy-drained', 'server-close']);
});

test('shared shutdown bounds a stalled non-policy transport only after policy drain', async () => {
  const events = []; let closeCallback;
  const server = { listening: true,
    close(callback) { events.push('server-close'); closeCallback = callback; },
    closeAllConnections() { events.push('transport-cutoff'); closeCallback(); } };
  const shutdown = createSandboxRunnerShutdown({ serverInstance: server, transportDrainMs: 100,
    policyRendererInstance: { async close() { events.push('policy-drained'); } } });
  await shutdown();
  assert.deepEqual(events, ['policy-drained', 'server-close', 'transport-cutoff']);
});

test('sandbox image compiles fixed helpers and packages only checked runtime assets with an exact shared contract copy', () => {
  const root = path.join(__dirname, '..');
  const dockerfile = fs.readFileSync(path.join(root, 'sidecars/sandbox-runner/Dockerfile'), 'utf8');
  assert.match(dockerfile, /gcc -static[^\n]+process-supervisor\.c[^\n]+dvaia-policy-render-supervisor/);
  assert.match(dockerfile, /gcc -static[^\n]+policy-init\.c[^\n]+dvaia-policy-render-init/);
  assert.match(dockerfile, /chmod 0555[^\n]*\/usr\/bin\/bwrap/);
  assert.match(dockerfile, /COPY policy-render\/executor\.js policy-render\/http-handler\.js policy-render\/worker\.js/);
  assert.match(dockerfile, /COPY policy-render\/assets \.\/policy-render\/assets/);
  assert.doesNotMatch(dockerfile, /COPY policy-render\/native-qualification\.js|COPY policy-render\/http-native-qualification\.js/);
  const canonical = fs.readFileSync(path.join(root, 'server/services/secureshopPromptPolicyContract.js'));
  const packaged = fs.readFileSync(path.join(root, 'sidecars/sandbox-runner/policy-render/secureshopPromptPolicyContract.js'));
  assert.deepEqual(packaged, canonical);
});
