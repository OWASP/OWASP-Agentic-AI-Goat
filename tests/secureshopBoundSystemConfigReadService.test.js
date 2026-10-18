'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID, createHash } = require('node:crypto');
const { createBoundSystemConfigReadService } = require('../server/services/secureshopBoundSystemConfigReadService');
const { requestDigest } = require('../sidecars/sandbox-runner/owned-system/contract');
const { createSecureShopSystemConfigClient, HTTP_VERSION, CAPABILITY } = require('../server/services/secureshopSystemConfigClient');

function fixture() {
  const input = { operationId: randomUUID(), path: 'application.json', scope: { launchId: randomUUID() } };
  const request = { operationId: input.operationId, path: input.path };
  const result = { version: 1, isolation: 'bwrap-system-config-v1', ...request, requestSha256: requestDigest(request),
    status: 'completed', exitCode: 0, timedOut: false, truncated: false, drained: true,
    readResult: { ok: true, input: input.path, sanitized: input.path, targetPath: '/app/config/application.json',
      content: '{}', size: 2, contentSha256: createHash('sha256').update('{}').digest('hex') } };
  delete result.path;
  let row, calls = 0, assertions = 0;
  const repository = {
    async administration() { return { scopeKey: 'a'.repeat(64) }; },
    async begin() {
      if (row) return row;
      row = { state: 'pending', operationId: input.operationId, requestSha256: requestDigest(request) };
      return { ...row, state: 'admitted' };
    },
    async complete(value) { row = { ...row, state: 'completed', receipt: value.receipt }; return row; },
    async markUnknown() { if (row.state !== 'completed') row = { ...row, state: 'unknown' }; return row; },
    async markNotExecuted() { if (row.state === 'pending') row = { ...row, state: 'not_executed' }; return row; },
    async operation() { return row; },
    async assertCurrent() { assertions++; },
  };
  const client = { async read(_request, { assertCurrent }) { calls++; await assertCurrent(); return result; } };
  return { input, request, result, repository, client, calls: () => calls, assertions: () => assertions };
}

test('fresh read publishes checked receipt; replay never executes again', async () => {
  const f = fixture(), service = createBoundSystemConfigReadService(f);
  assert.equal((await service.read(f.input)).state, 'completed');
  assert.equal((await service.read(f.input)).state, 'completed');
  assert.equal(f.calls(), 1); assert.equal(f.assertions(), 1);
});

test('administration projects only a validated opaque scope key and capability', async () => {
  const f = fixture(), service = createBoundSystemConfigReadService(f);
  f.repository.administration = async () => ({ scopeKey: 'b'.repeat(64), privateField: 'hidden' });
  assert.deepEqual(await service.administration({ scope: {} }), { scopeKey: 'b'.repeat(64), configReadCapability: CAPABILITY });
  f.repository.administration = async () => ({ scopeKey: 'invalid' });
  await assert.rejects(service.administration({}), { code: 'SYSTEM_CONFIG_ADMISSION_INVALID' });
  assert.equal(f.calls(), 0);
});

test('transport loss becomes durable unknown and cannot re-dispatch', async () => {
  const f = fixture(); let attempts = 0;
  f.client = createSecureShopSystemConfigClient({ baseURL: 'http://127.0.0.1:9999', token: 'a'.repeat(43),
    fetchImpl: async (_url, options) => {
      if (options.method === 'GET') return new Response(JSON.stringify({ version: HTTP_VERSION, ready: true,
        isolation: 'bwrap-system-config-v1', configReadCapability: CAPABILITY }));
      attempts++; throw new Error('private service details');
    } });
  const service = createBoundSystemConfigReadService(f);
  await assert.rejects(service.read(f.input), error => error.code === 'SYSTEM_CONFIG_OUTCOME_UNCERTAIN'
    && error.automaticRetry === false && !error.message.includes('private'));
  assert.equal((await service.read(f.input)).state, 'unknown');
  assert.equal(attempts, 1);
});

for (const code of ['SYSTEM_CONFIG_UNAVAILABLE', 'SHOP_AUTH_INVALID']) {
  test(`pre-dispatch ${code} is preserved and admission cannot re-dispatch`, async () => {
    const f = fixture(); let attempts = 0;
    const original = Object.assign(new Error('Unavailable'), { code });
    f.client.read = async () => { attempts++; throw original; };
    const service = createBoundSystemConfigReadService(f);
    await assert.rejects(service.read(f.input), error => error === original);
    assert.equal((await service.read(f.input)).state, 'not_executed');
    assert.equal(attempts, 1);
  });
}

test('lost publication reply preserves completed receipt for readback', async () => {
  const f = fixture(), complete = f.repository.complete;
  f.repository.complete = async value => { await complete(value); throw new Error('lost reply'); };
  const service = createBoundSystemConfigReadService(f);
  await assert.rejects(service.read(f.input), { code: 'SYSTEM_CONFIG_OUTCOME_UNCERTAIN' });
  assert.equal((await service.operation(f.input)).state, 'completed');
  assert.equal((await service.read(f.input)).state, 'completed');
  assert.equal(f.calls(), 1);
});

test('busy refusal precedes admission and async input changes cannot alter request', async () => {
  const f = fixture(); let release, captured;
  const begin = f.repository.begin;
  f.repository.begin = async value => { captured = value; await new Promise(resolve => { release = resolve; }); return begin(); };
  const service = createBoundSystemConfigReadService({ ...f, maxConcurrent: 1 });
  const originalLaunch = f.input.scope.launchId;
  const pending = service.read(f.input);
  f.input.scope.launchId = randomUUID(); f.input.path = '....//.env';
  await assert.rejects(service.read(f.input), { code: 'SYSTEM_CONFIG_BUSY' });
  assert.equal(captured.scope.launchId, originalLaunch); assert.equal(captured.path, 'application.json');
  release(); await pending;
  assert.equal(f.calls(), 1);
});

test('invalid transport receipt is never published and authority failures before admission retain identity', async () => {
  const f = fixture(); let completed = false;
  f.repository.complete = async () => { completed = true; };
  f.result.operationId = randomUUID();
  const service = createBoundSystemConfigReadService(f);
  await assert.rejects(service.read(f.input), { code: 'SYSTEM_CONFIG_OUTCOME_UNCERTAIN' });
  assert.equal(completed, false);
  const denied = Object.assign(new Error('Denied'), { code: 'SHOP_AUTH_INVALID' });
  f.repository.begin = async () => { throw denied; };
  await assert.rejects(service.read(f.input), error => error === denied);
});

test('scene fence runs inside admitted client boundary before config dispatch', async () => {
  const f = fixture(); let sceneChecks = 0, dispatched = 0;
  f.client.read = async (_request, { assertCurrent }) => {
    // Mirrors the production client readiness boundary: no config POST may
    // occur after the original chat scene changes while admission awaits.
    await assertCurrent();
    dispatched++;
    return f.result;
  };
  const service = createBoundSystemConfigReadService(f);
  const stale = Object.assign(new Error('Scene changed'), { code: 'STALE_AUTHORITY' });
  await assert.rejects(service.read(f.input, { beforeEffect: () => {
    sceneChecks++;
    throw stale;
  } }), error => error === stale);
  assert.equal(sceneChecks, 1);
  assert.equal(dispatched, 0);
  assert.equal((await service.operation(f.input)).state, 'not_executed');
  assert.equal((await service.read(f.input)).state, 'not_executed');
  assert.equal(dispatched, 0);
});

test('scene switch during readiness prevents the actual client config POST', async () => {
  const f = fixture(); let checks = 0, posts = 0;
  f.client = createSecureShopSystemConfigClient({ baseURL: 'http://127.0.0.1:9999',
    token: 'a'.repeat(43), fetchImpl: async (_url, options) => {
      if (options.method === 'POST') { posts++; throw new Error('must not dispatch'); }
      return new Response(JSON.stringify({ version: HTTP_VERSION, ready: true,
        isolation: 'bwrap-system-config-v1', configReadCapability: CAPABILITY }));
    } });
  const service = createBoundSystemConfigReadService(f);
  const stale = Object.assign(new Error('Scene changed'), { code: 'STALE_AUTHORITY' });
  await assert.rejects(service.read(f.input, { beforeEffect: () => {
    if (++checks === 2) throw stale;
  } }), error => error === stale);
  assert.equal(checks, 2);
  assert.equal(posts, 0);
  assert.equal((await service.operation(f.input)).state, 'not_executed');
});

test('scene is checked after an awaited repository authority read', async () => {
  const f = fixture(); let sceneCurrent = true, dispatched = 0;
  f.repository.assertCurrent = async () => { await Promise.resolve(); sceneCurrent = false; };
  f.client.read = async (_request, { assertCurrent }) => {
    await assertCurrent();
    dispatched++;
    return f.result;
  };
  const service = createBoundSystemConfigReadService(f);
  const stale = Object.assign(new Error('Scene changed'), { code: 'STALE_AUTHORITY' });
  await assert.rejects(service.read(f.input, { beforeEffect: () => {
    if (!sceneCurrent) throw stale;
  } }), error => error === stale);
  assert.equal(dispatched, 0);
  assert.equal((await service.operation(f.input)).state, 'not_executed');
});
