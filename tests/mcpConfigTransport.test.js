'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { configSnapshot } = require('../server/services/mcp/sandboxRunnerClient');

test('old sidecar compatibility executes the fixed snapshot program and requires complete process output', async t => {
  const invocationId = randomUUID();
  const expected = { ok: true, invocationId, output: 'fixture bytes', observation: {} };
  let processResult = { exitCode: 0, truncated: false, timedOut: false, stdout: JSON.stringify(expected) };
  let calls = 0;
  t.mock.method(global, 'fetch', async (url, options) => {
    calls++;
    if (url.endsWith('/config/snapshot')) return new Response('', { status: 404 });
    assert.ok(url.endsWith('/exec'));
    const request = JSON.parse(options.body);
    assert.equal(request.sessionId, 'mcp_7');
    assert.match(request.command, /^node -e '/);
    assert.ok(request.command.includes('/opt/app/config/.env'));
    assert.ok(request.command.includes('/var/secrets/credentials.json'));
    assert.ok(request.command.includes(invocationId));
    return Response.json(processResult);
  });
  assert.deepEqual(await configSnapshot('mcp_7', invocationId), expected);
  for (const invalid of [{ exitCode: 1 }, { truncated: true }, { timedOut: true }, { exitCode: undefined }]) {
    processResult = { exitCode: 0, truncated: false, timedOut: false, stdout: JSON.stringify(expected), ...invalid };
    assert.equal((await configSnapshot('mcp_7', invocationId)).ok, false);
  }
  assert.equal(calls, 10);
});

test('a supported snapshot endpoint failure never starts a second read through exec', async t => {
  let calls = 0;
  t.mock.method(global, 'fetch', async url => {
    calls++; assert.ok(url.endsWith('/config/snapshot'));
    return new Response('', { status: 503 });
  });
  assert.equal((await configSnapshot('mcp_7', randomUUID())).ok, false);
  assert.equal(calls, 1);
});

test('snapshot cancellation remains active while reading the response body', async t => {
  const controller = new AbortController();
  let bodyStarted;
  const started = new Promise(resolve => { bodyStarted = resolve; });
  t.mock.method(global, 'fetch', async (_url, { signal }) => ({ ok: true, status: 200,
    json: () => new Promise((_resolve, reject) => {
      signal.addEventListener('abort', () => reject(signal.reason), { once: true });
      bodyStarted();
    }),
  }));
  const pending = configSnapshot('mcp_7', randomUUID(), { signal: controller.signal });
  await started;
  controller.abort(new Error('owned read cancelled'));
  await assert.rejects(pending, /owned read cancelled/);
});
