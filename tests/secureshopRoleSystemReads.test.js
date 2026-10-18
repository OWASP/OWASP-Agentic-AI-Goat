'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID, createHash } = require('node:crypto');
const { createRoleSystemReads, configReadOperationId, boundedConfigObservation }
  = require('../server/services/secureshopRoleSystemReads');
const { requestDigest } = require('../sidecars/sandbox-runner/owned-system/contract');

const hash = value => createHash('sha256').update(value).digest('hex');
const context = () => ({ scope: { launchId: randomUUID(), scenarioId: randomUUID(), generation: 1,
  platformOwnerId: 21, platformSessionId: 34 }, persona: { id: 7, role: 'admin' },
  personaSession: { sessionId: randomUUID(), authorityVersion: '1' } });
const source = () => ({ sessionId: randomUUID(), requestId: randomUUID() });
const origin = () => ({ step: 2, callId: 'call-1' });

test('original System execution is private provenance and cannot be copied onto an observation', async () => {
  const c=context(), execution={version:1,featureId:'system_config',policyVersion:'owned-config-directory-v1',
    mode:'fixed',generation:0,modeStamp:'original',scope:c.scope};
  const system={ready:true,healthService:{health(){}},service:{
    administration:async()=>({scopeKey:'a'.repeat(64)}),operation(){},
    async read(input){const request={operationId:input.operationId,path:input.path};return {
      operationId:request.operationId,requestSha256:requestDigest(request),state:'not_executed',execution};}
  }};
  const reads=createRoleSystemReads({getSystemConfig:async()=>system});
  const value=await reads.configRead({context:c,source:source(),origin:origin(),path:'....//.env',assertCurrent:async()=>{}});
  assert.equal(value.state,'not_executed');assert.equal(value.result,null);
  assert.equal(Object.hasOwn(value,'execution'),false);
  assert.deepEqual(reads.executionFor(value),execution);
  assert.equal(reads.executionFor(structuredClone(value)),null);
  const projected=reads.executionFor(value);projected.mode='vuln';
  assert.equal(reads.executionFor(value).mode,'fixed');
});
function receipt(request, content = '{}') {
  return { version: 1, isolation: 'bwrap-system-config-v1', operationId: request.operationId,
    requestSha256: requestDigest(request), status: 'completed', exitCode: 0,
    timedOut: false, truncated: false, drained: true,
    readResult: { ok: true, input: request.path, sanitized: request.path,
      targetPath: `/app/config/${request.path}`, size: Buffer.byteLength(content),
      content, contentSha256: hash(content) } };
}

test('config read derives owner-bound stable UUID, preserves full receipt for GET, and never redispatches replay', async () => {
  const c = context(), s = source(), o = origin();
  let dispatches = 0, checks = 0, stored;
  const system = { ready: true,
    service: {
      administration: async () => ({ scopeKey: 'a'.repeat(64) }),
      async read(input, { beforeEffect }) {
        if (stored) {
          assert.equal(input.operationId, stored.operationId);
          assert.equal(requestDigest({ operationId: input.operationId, path: input.path }), stored.requestSha256);
          return stored;
        }
        await beforeEffect();
        dispatches++;
        const request = { operationId: input.operationId, path: input.path };
        stored = { operationId: input.operationId, requestSha256: requestDigest(request),
          state: 'completed', receipt: receipt(request) };
        return stored;
      },
      operation: async () => stored,
    }, healthService: { health: async () => ({ ok: true }) } };
  const reads = createRoleSystemReads({ getSystemConfig: async () => system });
  const args = { context: c, source: s, origin: o, path: 'application.json',
    assertCurrent: async () => { checks++; } };
  const first = await reads.configRead(args);
  const second = await reads.configRead(args);
  assert.deepEqual(second, first);
  assert.equal(dispatches, 1);
  assert.equal(first.operationId, configReadOperationId(c, s, o));
  assert.equal(first.result.content, '{}');
  assert.equal((await reads.operation({ context: c, operationId: first.operationId })).receipt.readResult.content, '{}');
  assert.ok(checks >= 8);
  assert.notEqual(configReadOperationId({ ...c, scope: { ...c.scope, platformOwnerId: 22 } }, s, o), first.operationId);
  assert.notEqual(configReadOperationId(c, s, { ...o, callId: 'call-2' }), first.operationId);
});

test('large config output is explicitly marked oversized while exact journal keeps all bytes', async () => {
  const request = { operationId: randomUUID(), path: 'application.json' };
  const full = 'x'.repeat(17000);
  const value = { operationId: request.operationId, requestSha256: requestDigest(request),
    state: 'completed', receipt: receipt(request, full) };
  const observation = boundedConfigObservation(value, request, 'a'.repeat(64));
  assert.equal(observation.result.oversized, true);
  assert.equal(observation.result.content, null);
  assert.equal(observation.result.size, 17000);
  assert.equal(observation.result.contentSha256, hash(full));
  assert.equal(value.receipt.readResult.content, full);
  assert.ok(Buffer.byteLength(JSON.stringify(observation)) <= 16384);
  const escaped = '"\\'.repeat(5000);
  const escapedValue = { ...value, receipt: receipt(request, escaped) };
  const escapedObservation = boundedConfigObservation(escapedValue, request, 'a'.repeat(64));
  assert.equal(escapedObservation.result.oversized, true);
  assert.equal(escapedObservation.result.content, null);
  assert.ok(Buffer.byteLength(JSON.stringify(escapedObservation)) <= 16384);
});

test('uncertain and unavailable outcomes stay distinct from successful content', () => {
  const request = { operationId: randomUUID(), path: 'application.json' };
  const base = { operationId: request.operationId, requestSha256: requestDigest(request) };
  assert.deepEqual(boundedConfigObservation({ ...base, state: 'unknown' }, request, 'a'.repeat(64)).result, null);
  const unavailable = { version: 1, isolation: 'bwrap-system-config-v1',
    operationId: request.operationId, requestSha256: base.requestSha256,
    status: 'unavailable', exitCode: null, timedOut: true, truncated: false, drained: false };
  assert.deepEqual(boundedConfigObservation({ ...base, state: 'completed', receipt: unavailable },
    request, 'a'.repeat(64)).result, { status: 'unavailable' });
});

test('health checks current authority around lazy composition and metric read; operation GET is scene-independent', async () => {
  const c = context(); let checks = 0, observed = 0;
  const reads = createRoleSystemReads({ getSystemConfig: async () => ({ ready: true,
    service: { administration: async () => ({ scopeKey: 'b'.repeat(64) }),
      read: async () => { throw new Error('not expected'); },
      operation: async ({ operationId }) => ({ state: 'not_found', operationId }) },
    healthService: { health: async () => { observed++; return { version: 1, ok: true }; } } }) });
  const value = await reads.health({ context: c, assertCurrent: () => { checks++; } });
  assert.equal(value.scopeKey, 'b'.repeat(64));
  assert.equal(observed, 1);
  assert.ok(checks >= 4);
  const id = randomUUID();
  assert.deepEqual(await reads.operation({ context: c, operationId: id }), { state: 'not_found', operationId: id });
});

test('invalid provenance and unavailable composition fail before a config dispatch', async () => {
  const c = context(), s = source(), o = origin(); let lazy = 0;
  const reads = createRoleSystemReads({ getSystemConfig: async () => { lazy++; return null; } });
  await assert.rejects(reads.configRead({ context: c, source: s, origin: o,
    path: 'application.json', assertCurrent: () => {} }), { code: 'SYSTEM_READ_UNAVAILABLE' });
  assert.equal(lazy, 1);
  await assert.rejects(reads.configRead({ context: c, source: s, origin: { ...o, step: 0 },
    path: 'application.json', assertCurrent: () => {} }), { code: 'SYSTEM_READ_ORIGIN_INVALID' });
  await assert.rejects(reads.configRead({ context: { ...c, persona: { id: 7, role: 'customer' } },
    source: s, origin: o, path: 'application.json', assertCurrent: () => {} }),
  { code: 'SYSTEM_READ_CONTEXT_INVALID' });
  assert.equal(lazy, 1);
});
