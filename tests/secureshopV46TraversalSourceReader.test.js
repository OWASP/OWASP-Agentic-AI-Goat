'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash, randomUUID } = require('node:crypto');
const { createSceneBinding } = require('../server/services/secureshopSceneBinding');
const { createV46TraversalSourceReader } = require('../server/services/secureshopV46TraversalSourceReader');

const bytes = Buffer.from('owned-v46-source');
const digest = createHash('sha256').update(bytes).digest('hex');
function fixture() {
  const scope = {
    launchId: randomUUID(), scenarioId: randomUUID(), generation: 1,
    platformOwnerId: 2, platformSessionId: 3
  };
  const persona = { id: 4, role: 'customer' };
  const personaSession = { sessionId: randomUUID(), authorityVersion: '1' };
  const scene = {
    sceneId: randomUUID(), sceneGeneration: 1, grantId: randomUUID(),
    execution: scope, withLease: work => work()
  };
  const target = createSceneBinding({ ...scope, targetId: randomUUID() }, scene);
  const mode = {
    version: 1, featureId: 'uploads', policyVersion: 'test', mode: 'vuln',
    generation: 0, modeStamp: 'a'.repeat(64)
  };
  const operationId = randomUUID(), effectId = randomUUID(), storageKey = randomUUID();
  const admission = {
    operationId, uploadRequestId: randomUUID(), storageKey,
    bindingSha256: 'b'.repeat(64), requestSha256: 'c'.repeat(64),
    scope: {
      ...scope, targetId: target.targetId, sceneId: scene.sceneId,
      sceneGeneration: scene.sceneGeneration, grantId: scene.grantId,
      shopUserId: persona.id, personaSessionId: personaSession.sessionId,
      personaAuthorityVersion: personaSession.authorityVersion,
      mode: mode.mode, modeGeneration: mode.generation, modeStamp: mode.modeStamp
    },
    request: {
      kind: 'avatar', scopeId: persona.id, originalFilename: '....//escaped-v46.txt',
      declaredMime: 'text/plain', public: false, byteCount: bytes.length, bodySha256: digest
    }
  };
  const effect = {
    operationId, effectId, outcome: 'completed', effectSha256: 'd'.repeat(64),
    file: {
      storageKey, originalFilename: admission.request.originalFilename,
      cleanedFilename: '../escaped-v46.txt', declaredMime: 'text/plain',
      byteCount: bytes.length, bodySha256: digest,
      baseVirtualPath: `operations/${storageKey}/avatars/${persona.id}`,
      resolvedVirtualPath: `operations/${storageKey}/avatars/${persona.id}/../escaped-v46.txt`,
      storedVirtualPath: `operations/${storageKey}/avatars/escaped-v46.txt`, isTraversal: true
    }
  };
  return { scope, persona, personaSession, target, mode, operationId, effectId, admission, effect };
}

test('V46 source reader joins current authority to an exact physical traversal reread', async () => {
  const f = fixture();
  let checks = 0, reads = 0;
  const reader = createV46TraversalSourceReader({
    assets: { async lookup(claim) {
      assert.deepEqual(claim, {
        effectId: f.effectId, operationId: f.operationId, targetId: f.target.targetId,
        generation: 1, sceneId: f.target.scene.sceneId, sceneGeneration: 1,
        mode: 'vuln', modeGeneration: 0, modeStamp: f.mode.modeStamp
      });
      return { admission: f.admission, effect: f.effect };
    } },
    async assertCurrent(value) { assert.equal(value, f.admission); checks++; },
    async read(receipt) {
      assert.deepEqual(receipt, {
        storedVirtualPath: f.effect.file.storedVirtualPath,
        responseByteCount: bytes.length, responseSha256: digest
      });
      reads++;
      return Buffer.from(bytes);
    }
  });
  const value = await reader.read({ ...f, signal: new AbortController().signal });
  assert.equal(value.readback.bodySha256, digest);
  assert.equal(checks, 2);
  assert.equal(reads, 1);
});

test('V46 source reader denies fixed, stale, foreign and changed-byte evidence before qualification', async () => {
  const f = fixture();
  let reads = 0;
  const make = found => createV46TraversalSourceReader({
    assets: { async lookup() { return found; } },
    async assertCurrent() {},
    async read() { reads++; return Buffer.from('changed'); }
  });
  assert.equal(await make(null).read({ ...f, signal: new AbortController().signal }), null);
  assert.equal(await make({ admission: f.admission, effect: f.effect }).read({
    ...f, mode: { ...f.mode, mode: 'fixed' }, signal: new AbortController().signal
  }), null);
  await assert.rejects(make({ admission: { ...f.admission,
    scope: { ...f.admission.scope, shopUserId: 99 } }, effect: f.effect }).read({
    ...f, signal: new AbortController().signal
  }), { code: 'UPLOAD_SOURCE_UNAVAILABLE' });
  await assert.rejects(make({ admission: f.admission, effect: f.effect }).read({
    ...f, signal: new AbortController().signal
  }), { code: 'UPLOAD_SOURCE_UNAVAILABLE' });
  assert.equal(reads, 1);
});
