'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { createHash, randomUUID } = require('node:crypto');
const { inspectXssProfileOrigin } = require('../server/services/xssProfileOriginValidation');
function fixture() {
  const value = '<img src=x onerror="alert(7)">';
  const valueSha256 = createHash('sha256').update(value).digest('hex');
  const execution = { runId: randomUUID(), ownerKey: '["XSS","17"]', durableGeneration: 4 };
  return { userKey: '17', platformUserId: 17, field: 'bio', workshopGeneration: 2, execution,
    snapshot: { value, valueSha256, revision: '3', origin: {
      version: 'xss-profile-origin-v1', userKey: '17', platformUserId: 17, field: 'bio', revision: '3', valueSha256,
      workshopGeneration: 2, runId: execution.runId, ownerKey: execution.ownerKey, durableGeneration: 4,
      decisionSource: 'model', provider: 'ollama', model: 'llama3.1:8b', rawDecisionSha256: 'a'.repeat(64), observationIndex: 0,
    } } };
}
test('private current-origin integrity supports current writes and later reads without conflating runs', () => {
  const input = fixture();
  assert.equal(inspectXssProfileOrigin({ ...input, requireWriterRun: true }).valid, true);
  input.execution.durableGeneration = '4'; // Native run ledger represents bigint generations as strings.
  assert.equal(inspectXssProfileOrigin(input).valid, true);
  input.execution.runId = randomUUID();
  assert.equal(inspectXssProfileOrigin(input).eventSource, input.snapshot.value);
  assert.equal(inspectXssProfileOrigin({ ...input, requireWriterRun: true }).reason, 'writer_run_mismatch');
});
test('missing, overwritten, foreign, stale, malformed and nonmodel origin cannot qualify', () => {
  const changes = [
    x => { x.snapshot.origin = null; }, x => { x.snapshot.revision = '4'; },
    x => { x.snapshot.value += '/'; }, x => { x.snapshot.valueSha256 = 'b'.repeat(64); },
    x => { x.snapshot.origin.valueSha256 = 'b'.repeat(64); },
    x => { x.snapshot.origin.field = 'name'; }, x => { x.snapshot.origin.platformUserId = 18; },
    x => { x.snapshot.origin.userKey = '18'; }, x => { x.snapshot.origin.ownerKey = '["XSS","18"]'; },
    x => { x.snapshot.origin.workshopGeneration = 1; }, x => { x.snapshot.origin.durableGeneration = 3; },
    x => { x.snapshot.origin.decisionSource = 'scripted'; }, x => { x.snapshot.origin.provider = 'mock'; },
    x => { x.snapshot.origin.model = 'fixture-model'; }, x => { x.snapshot.origin.rawDecisionSha256 = 'bad'; },
    x => { x.snapshot.origin.runId = 'fake'; }, x => { x.snapshot.origin.observationIndex = -1; },
    x => { x.execution.durableGeneration = '04'; }, x => { x.execution.durableGeneration = true; },
    x => { x.snapshot.revision = 9007199254740992; }, x => { x.execution.ownerKey = '17'; },
  ];
  for (const change of changes) { const input = fixture(); change(input); assert.equal(inspectXssProfileOrigin(input).valid, false); }
});

test('int64 decimal generations remain exact while ambiguous values fail closed', () => {
  const input = fixture();
  const large = '9007199254740993';
  input.execution.durableGeneration = large;
  input.snapshot.origin.durableGeneration = large;
  assert.equal(inspectXssProfileOrigin(input).valid, true);
  input.execution.durableGeneration = '09007199254740993';
  assert.equal(inspectXssProfileOrigin(input).valid, false);
});

function bindStoredLlm(input, childGeneration = '7') {
  input.execution.scopeBinding = Object.freeze({
    runId:input.execution.runId, ownerId:input.platformUserId,
    ownerKey:input.execution.ownerKey, scopeKey:'stored_llm',
    parentGeneration:String(input.execution.durableGeneration), childGeneration,
  });
  return input;
}

test('scoped origin v2 is bound to the exact current stored_llm child generation', () => {
  const input = bindStoredLlm(fixture());
  Object.assign(input.snapshot.origin, {
    version:'xss-profile-origin-v2', scopeKey:'stored_llm', childGeneration:'7',
  });
  assert.equal(inspectXssProfileOrigin(input).valid, true);
  input.execution.scopeBinding = Object.freeze({ ...input.execution.scopeBinding, childGeneration:'8' });
  assert.equal(inspectXssProfileOrigin(input).reason, 'scope_generation_mismatch');
});

test('legacy v1 cannot qualify scoped execution and v2 cannot qualify unscoped execution', () => {
  const scopedV1 = bindStoredLlm(fixture());
  assert.equal(inspectXssProfileOrigin(scopedV1).reason, 'scope_generation_mismatch');
  const unscopedV2 = fixture();
  Object.assign(unscopedV2.snapshot.origin, {
    version:'xss-profile-origin-v2', scopeKey:'stored_llm', childGeneration:'0',
  });
  assert.equal(inspectXssProfileOrigin(unscopedV2).reason, 'scope_generation_mismatch');
});

test('scoped validation rejects foreign, malformed and non-stored_llm bindings', () => {
  const changes = [
    binding => { binding.runId = randomUUID(); },
    binding => { binding.ownerId = 18; },
    binding => { binding.ownerKey = '["XSS","18"]'; },
    binding => { binding.scopeKey = 'stored_user'; },
    binding => { binding.parentGeneration = '5'; },
    binding => { binding.childGeneration = '07'; },
    binding => { binding.extra = true; },
  ];
  for (const change of changes) {
    const input = bindStoredLlm(fixture());
    Object.assign(input.snapshot.origin, {
      version:'xss-profile-origin-v2', scopeKey:'stored_llm', childGeneration:'7',
    });
    const binding = { ...input.execution.scopeBinding };
    change(binding);
    input.execution.scopeBinding = binding;
    assert.equal(inspectXssProfileOrigin(input).valid, false);
  }
});
