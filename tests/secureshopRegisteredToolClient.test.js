'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createOwnedMcpRegistryClient } = require('../server/services/secureshopOwnedMcpRegistryClient');
const { isOwnedMcpRegistryNotDispatched } = require('../server/services/secureshopOwnedMcpRegistryClient');
const { mcpSchemaDigest } = require('../server/services/secureshopMcpSchemaDigest');
const { canonicalDigest } = require('../server/services/mcp/protocolContext');

const baseURL = 'http://127.0.0.1:8099/';
const token = 'a'.repeat(43);
const digest = 'b'.repeat(64);
const instanceId = '11111111-1111-4111-8111-111111111111';
const operationId = '22222222-2222-4222-8222-222222222222';
const entryId = '33333333-3333-4333-8333-333333333333';
const tools = [{ name: 'lookup', description: 'lookup', inputSchema: { type: 'object', properties: {} } }];
const request = {
  version: 1, instanceId, operationId,
  entry: { entryId, registryVersion: '4', transport: 'streamable-http', endpoint: 'http://127.0.0.1:8091/', schemaSha256: mcpSchemaDigest(tools), tools },
  toolName: 'lookup', args: {},
};

function response(value, status = 200) {
  return new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json' } });
}
function health(id = instanceId) {
  return { version: 1, instanceId: id, runtimeDigest: digest };
}
function drained(state = 'retired', id = instanceId) {
  return { version: 1, instanceId: id, operationId, requestSha256: canonicalDigest(request), state, drained: ['completed', 'retired'].includes(state) };
}
function client(fetchImpl) {
  return createOwnedMcpRegistryClient({ baseURL, token, expectedRuntimeDigest: digest, fetchImpl });
}
async function rejection(promise, code) {
  let error;
  try { await promise; assert.fail('expected rejection'); } catch (cause) { error = cause; }
  assert.equal(error.code, code);
  return error;
}

test('accepts exact invocation health identity and rejects an instance epoch change', async () => {
  const good = client(async url => response(health()));
  assert.deepEqual(await good.invocationHealth(), health());
  const calls = [];
  const changed = client(async url => { calls.push(String(url)); return response(health('44444444-4444-4444-8444-444444444444')); });
  await assert.rejects(changed.invoke(request), { code: 'MCP_REGISTRY_INSTANCE_CHANGED' });
  assert.equal(calls.length, 1);
});

test('joins altered receipt failure to a bounded drained retirement', async () => {
  const calls = [];
  const c = client(async url => {
    const path = new URL(url).pathname; calls.push(path);
    if (path.endsWith('/invoke/health')) return response(health());
    if (path.endsWith('/invoke')) return response({ version: 1, receipt: { version: 1, altered: true } });
    if (path.endsWith('/invoke/drain')) return response(drained());
    throw new Error(`unexpected ${path}`);
  });
  const error = await rejection(c.invoke(request), 'MCP_REGISTRY_INVOCATION_UNCERTAIN');
  assert.equal(error.drained, true);
  assert.deepEqual(calls, ['/secureshop/mcp-registry/invoke/health', '/secureshop/mcp-registry/invoke', '/secureshop/mcp-registry/invoke/drain']);
});

test('caller abort waits for exact worker drain before returning uncertainty', async () => {
  const controller = new AbortController();
  let invocationStarted = false, drainObserved = false;
  const c = client(async url => {
    const path = new URL(url).pathname;
    if (path.endsWith('/invoke/health')) return response(health());
    if (path.endsWith('/invoke')) { invocationStarted = true; return new Promise(() => {}); }
    if (path.endsWith('/invoke/drain')) { drainObserved = true; return response(drained()); }
    throw new Error('unexpected path');
  });
  const pending = c.invoke(request, { signal: controller.signal });
  while (!invocationStarted) await new Promise(resolve => setImmediate(resolve));
  controller.abort();
  const error = await rejection(pending, 'MCP_REGISTRY_INVOCATION_UNCERTAIN');
  assert.equal(drainObserved, true);
  assert.equal(error.drained, true);
});

test('unknown drain fails closed and disables automatic retry', async () => {
  const c = client(async url => {
    const path = new URL(url).pathname;
    if (path.endsWith('/invoke/health')) return response(health());
    if (path.endsWith('/invoke')) return response({ version: 1, receipt: { version: 1, altered: true } });
    if (path.endsWith('/invoke/drain')) throw new Error('drain unavailable');
    throw new Error('unexpected path');
  });
  const error = await rejection(c.invoke(request), 'MCP_REGISTRY_INVOCATION_UNCERTAIN');
  assert.equal(error.drained, false);
  assert.equal(error.automaticRetry, false);
  assert.equal(error.retirement, null);
});

test('health failures carry private exact-request no-dispatch proof, not a forgeable flag', async () => {
  let calls = 0;
  const c = client(async () => { calls++; throw Error('health unavailable'); });
  const error = await rejection(c.invoke(request), 'MCP_REGISTRY_NOT_DISPATCHED');
  assert.equal(calls, 1);
  assert.equal(isOwnedMcpRegistryNotDispatched(error, request), true);
  assert.equal(isOwnedMcpRegistryNotDispatched(error, { ...request, args: { changed: true } }), false);
  assert.equal(isOwnedMcpRegistryNotDispatched({ code: error.code, effectNotStarted: true }, request), false);
});

test('capacity rejection proves no worker dispatch but existing-operation conflict does not', async () => {
  for (const capacity of [true, false]) {
    const calls = [];
    const c = client(async url => {
      const path = new URL(url).pathname; calls.push(path);
      if (path.endsWith('/health')) return response(health());
      if (path.endsWith('/invoke')) return response({ error: capacity ? 'MCP_REGISTRY_HTTP_CAPACITY' : 'MCP_REGISTRY_OPERATION_CONFLICT' }, capacity ? 429 : 409);
      if (path.endsWith('/drain')) return response(drained('unknown'));
      throw Error('unexpected request');
    });
    const error = await rejection(c.invoke(request), capacity ? 'MCP_REGISTRY_NOT_DISPATCHED' : 'MCP_REGISTRY_INVOCATION_UNCERTAIN');
    assert.equal(isOwnedMcpRegistryNotDispatched(error, request), capacity);
    assert.equal(calls.length, capacity ? 2 : 3);
  }
});
