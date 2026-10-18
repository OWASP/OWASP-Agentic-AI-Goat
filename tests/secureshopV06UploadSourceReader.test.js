'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  randomUUID
} = require('node:crypto');
const {
  createV06UploadSourceReader
} = require('../server/services/secureshopV06UploadSourceReader');
function fixture() {
  const scope = {
    launchId: randomUUID(),
    scenarioId: randomUUID(),
    generation: 2,
    platformOwnerId: 3,
    platformSessionId: 4
  };
  const persona = {
      id: 5,
      role: 'customer'
    },
    personaSession = {
      sessionId: randomUUID(),
      authorityVersion: '1'
    };
  const target = {
    targetId: randomUUID(),
    scene: {
      sceneId: randomUUID(),
      sceneGeneration: 2,
      grantId: randomUUID()
    }
  };
  const mode = {
    featureId: 'uploads',
    mode: 'vuln',
    generation: 2,
    modeStamp: 'a'.repeat(64)
  };
  const input = {
    scope,
    persona,
    personaSession,
    target,
    mode,
    operationId: randomUUID(),
    effectId: randomUUID()
  };
  let found = {
    admission: {
      operationId: input.operationId,
      scope: {
        ...scope,
        targetId: target.targetId,
        sceneId: target.scene.sceneId,
        sceneGeneration: 2,
        grantId: target.scene.grantId,
        shopUserId: 5,
        personaSessionId: personaSession.sessionId,
        personaAuthorityVersion: '1',
        mode: 'vuln',
        modeGeneration: 2,
        modeStamp: mode.modeStamp
      }
    },
    effect: {
      effectId: input.effectId,
      outcome: 'completed',
      file: {
        isTraversal: false,
        storedVirtualPath: 'private-owned-path',
        byteCount: 4,
        bodySha256: 'b'.repeat(64)
      }
    },
    canonicalServe: {
      serveSha256: 'c'.repeat(64)
    }
  };
  let reads = 0,
    checks = 0;
  const reader = createV06UploadSourceReader({
    assets: {
      async lookup() {
        return found;
      }
    },
    async assertCurrent() {
      checks++;
    },
    async read(value) {
      reads++;
      assert.equal(value.storedVirtualPath, 'private-owned-path');
    }
  });
  return {
    reader,
    input,
    get: () => found,
    set: value => {
      found = value;
    },
    counts: () => ({
      reads,
      checks
    })
  };
}
test('source reader rereads bytes with current authority on both sides', async () => {
  const f = fixture(),
    result = await f.reader.read(f.input);
  assert.ok(result.serve);
  assert.deepEqual(f.counts(), {
    reads: 1,
    checks: 2
  });
});
test('missing serve and fixed mode never read physical bytes', async () => {
  for (const kind of ['serve', 'fixed']) {
    const f = fixture();
    if (kind === 'serve') delete f.get().canonicalServe;else f.input.mode.mode = 'fixed';
    assert.equal(await f.reader.read(f.input), null);
    assert.deepEqual(f.counts(), {
      reads: 0,
      checks: 0
    });
  }
});
for (const key of ['platformOwnerId', 'platformSessionId', 'generation', 'sceneId', 'grantId', 'personaSessionId', 'modeStamp']) test(`source reader rejects changed ${key} before physical read`, async () => {
  const f = fixture();
  f.get().admission.scope[key] = 'changed';
  await assert.rejects(f.reader.read(f.input));
  assert.equal(f.counts().reads, 0);
});
test('preabort never selects original evidence', async () => {
  const f = fixture();
  const c = new AbortController();
  c.abort();
  await assert.rejects(f.reader.read({
    ...f.input,
    signal: c.signal
  }));
  assert.deepEqual(f.counts(), {
    reads: 0,
    checks: 0
  });
});
