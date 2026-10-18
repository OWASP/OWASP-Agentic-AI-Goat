'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash, randomUUID } = require('node:crypto');
const { normalizeAdmission, normalizeEffect } = require('../server/services/secureshopBoundUploadReceipt');
const { createSecureShopV46TraversalApplication } = require('../server/services/secureshopV46TraversalApplication');

const digest = bytes => createHash('sha256').update(bytes).digest('hex');
function admission(bytes = Buffer.from('owned-v46')) {
  return normalizeAdmission({
    operationId: randomUUID(), uploadRequestId: randomUUID(), storageKey: randomUUID(),
    scope: {
      targetId: randomUUID(), launchId: randomUUID(), scenarioId: randomUUID(), generation: 1,
      platformOwnerId: 2, platformSessionId: 3, sceneId: randomUUID(), sceneGeneration: 1,
      grantId: randomUUID(), shopUserId: 4, personaSessionId: randomUUID(),
      personaAuthorityVersion: '1', mode: 'vuln', modeGeneration: 0, modeStamp: 'a'.repeat(64)
    },
    request: {
      kind: 'avatar', scopeId: 4, originalFilename: '....//escaped-v46.txt',
      declaredMime: 'text/plain', public: false, byteCount: bytes.length, bodySha256: digest(bytes)
    }
  });
}
const execution = { signal: new AbortController().signal, async check() {} };

test('V46 application fixed mode persists exact denial before invoking the writer', async () => {
  const a = admission();
  let writes = 0;
  const application = createSecureShopV46TraversalApplication({
    effects: { async find() { return null; } },
    writer: { async writeAndReadBack() { writes++; throw Error('must not write'); } },
    journal: { async recordEffect(raw, value) { return normalizeEffect(value, raw); } }
  });
  const result = await application.execute({
    admission: a, file: { bytes: Buffer.from('owned-v46'), filename: a.request.originalFilename,
      mime: a.request.declaredMime }, mode: 'fixed', execution, effectId: randomUUID()
  });
  assert.equal(result.effect.outcome, 'denied');
  assert.equal(result.effect.denialCode, 'PATH_TRAVERSAL_DENIED');
  assert.equal(writes, 0);
});

test('V46 application recovers a lost effect acknowledgement without repeating the sink', async () => {
  const bytes = Buffer.from('owned-v46'), a = admission(bytes);
  let effect = null, writes = 0;
  const application = createSecureShopV46TraversalApplication({
    effects: { async find() { return effect; } },
    writer: { async writeAndReadBack() {
      writes++;
      return {
        cleanedFilename: '../escaped-v46.txt', byteCount: bytes.length, bodySha256: digest(bytes),
        baseVirtualPath: `operations/${a.storageKey}/avatars/4`,
        resolvedVirtualPath: `operations/${a.storageKey}/avatars/4/../escaped-v46.txt`,
        storedVirtualPath: `operations/${a.storageKey}/avatars/escaped-v46.txt`, isTraversal: true
      };
    } },
    journal: { async recordEffect(raw, value) {
      effect = normalizeEffect(value, raw);
      throw Error('lost acknowledgement');
    } }
  });
  const input = {
    admission: a, file: { bytes, filename: a.request.originalFilename, mime: a.request.declaredMime },
    mode: 'vuln', execution, effectId: randomUUID()
  };
  assert.equal((await application.execute(input)).effect.outcome, 'completed');
  assert.equal((await application.execute(input)).replayed, true);
  assert.equal(writes, 1);
});

test('V46 application rejects a replayed normal upload or changed fixed denial', async () => {
  const a = admission(), effectId = randomUUID();
  for (const prior of [
    normalizeEffect({ effectId, outcome: 'completed', file: {
      storageKey: a.storageKey, originalFilename: a.request.originalFilename,
      cleanedFilename: 'escaped-v46.txt', declaredMime: a.request.declaredMime,
      byteCount: a.request.byteCount, bodySha256: a.request.bodySha256,
      baseVirtualPath: `operations/${a.storageKey}/avatars/4`,
      resolvedVirtualPath: `operations/${a.storageKey}/avatars/4/escaped-v46.txt`,
      storedVirtualPath: `operations/${a.storageKey}/avatars/4/escaped-v46.txt`, isTraversal: false
    }, denialCode: null, quarantineRequired: false }, a),
    normalizeEffect({ effectId, outcome: 'denied', file: null,
      denialCode: 'PROHIBITED_EXTENSION', quarantineRequired: false }, a)
  ]) {
    const application = createSecureShopV46TraversalApplication({
      effects: { async find() { return prior; } },
      writer: { async writeAndReadBack() { throw Error('must not write'); } },
      journal: { async recordEffect() { throw Error('must not journal'); } }
    });
    await assert.rejects(application.execute({
      admission: a, file: { bytes: Buffer.from('owned-v46'), filename: a.request.originalFilename,
        mime: a.request.declaredMime }, mode: 'vuln', execution, effectId
    }), { code: 'BOUND_UPLOAD_EFFECT_MISMATCH' });
  }
});
