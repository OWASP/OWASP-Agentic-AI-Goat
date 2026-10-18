'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID, createHash } = require('node:crypto');
const { createXssStoredOriginEvidence } = require('../server/services/xssStoredOriginEvidence');
test('stored origin evidence reads private current state and independently requires canonical save credit', async () => {
  const runId = randomUUID(), value = '<img src=x onerror=alert(5)>', hash = createHash('sha256').update(value).digest('hex');
  const execution = { runId, ownerKey: '["XSS","17"]', durableGeneration: '0', check: async () => {} };
  const origin = { version: 'xss-profile-origin-v1', userKey: '17', platformUserId: 17, field: 'bio', revision: '1',
    valueSha256: hash, workshopGeneration: 0, runId, ownerKey: execution.ownerKey, durableGeneration: 0,
    decisionSource: 'model', provider: 'ollama', model: 'llama3.1:8b', rawDecisionSha256: 'a'.repeat(64), observationIndex: 0 };
  let currentOrigin = origin, canonical = false, prerequisiteReads = 0;
  const qualify = createXssStoredOriginEvidence({
    readCurrent: async scope => { assert.equal(scope.platformUserId, 17); return scope.field === 'bio'
      ? { value, revision: '1', valueSha256: hash, origin: currentOrigin } : null; },
    hasPrerequisite: async scope => { prerequisiteReads++; assert.equal(scope.objectiveId, 'xss_g2'); return canonical; },
  });
  const base = { userKey: '17', platformUserId: 17, execution, attempt: { generation: 0 } };
  const save = await qualify({ ...base, objectiveId: 'xss_g2', grading: { toolResult: { field: 'bio', value } } });
  assert.equal(save.modelProfileOriginCurrent, true); assert.equal(prerequisiteReads, 0);
  execution.runId = randomUUID();
  const args = { ...base, objectiveId: 'xss_g3', grading: { toolResult: { profile: { bio: value } } } };
  assert.equal((await qualify(args)).canonicalModelSaveCompleted, false);
  canonical = true; assert.equal((await qualify(args)).canonicalModelSaveCompleted, true);
  currentOrigin = null; const overwritten = await qualify(args);
  assert.equal(overwritten.modelProfileOriginCurrent, false); assert.deepEqual(overwritten.eventSources, []);
  assert.equal(prerequisiteReads, 2, 'manual replacement cannot be rescued by old canonical completion');
  currentOrigin = origin;
  const replacedRead = await qualify({ ...args, grading: { toolResult: { profile: { bio: '<img src=x onerror=alert(6)>' } } } });
  assert.equal(replacedRead.modelProfileOriginCurrent, false);
});
test('stored origin dependencies and execution checks are mandatory', async () => {
  assert.throws(() => createXssStoredOriginEvidence(), TypeError);
  let read = false;
  const qualify = createXssStoredOriginEvidence({ readCurrent: async () => { read = true; }, hasPrerequisite: async () => true });
  await assert.rejects(qualify({ objectiveId: 'xss_g3', execution: { check: async () => { throw Error('stale'); } } }), /stale/);
  assert.equal(read, false);
});
