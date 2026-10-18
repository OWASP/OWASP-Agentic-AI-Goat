'use strict';

const test = require('node:test'),
  assert = require('node:assert/strict');
const {
  createSecureShopBoundUploadRepository
} = require('../server/database/postgres/secureshopBoundUploadRepository');
const {
  normalizeAdmission,
  normalizeEffect
} = require('../server/services/secureshopBoundUploadReceipt');
const id = n => `0000000${n}-0000-4000-8000-00000000000${n}`;
const raw = {
  operationId: id(1),
  uploadRequestId: id(2),
  storageKey: id(3),
  scope: {
    targetId: id(4),
    launchId: id(5),
    scenarioId: id(6),
    generation: 8,
    platformOwnerId: 9,
    platformSessionId: 99,
    sceneId: id(7),
    sceneGeneration: 2,
    grantId: id(8),
    shopUserId: 10,
    personaSessionId: id(9),
    personaAuthorityVersion: '1',
    mode: 'vuln',
    modeGeneration: 0,
    modeStamp: 'a'.repeat(64)
  },
  request: {
    kind: 'avatar',
    scopeId: 10,
    originalFilename: 'x.html',
    declaredMime: 'text/html',
    public: true,
    byteCount: 1,
    bodySha256: 'b'.repeat(64)
  }
};
for (const orphan of [true, false]) test(`repository ${orphan ? 'orphan' : 'unresolved'} uses birth cleanup authority without altering immutable execution digests`, async () => {
  const a = normalizeAdmission(raw),
    scope = {
      ...a.scope,
      launchId: id(2),
      generation: 2,
      platformSessionId: 11
    };
  let calls = 0,
    queries = 0;
  const client = {
    async query(sql, args) {
      if (!sql.includes('reconcile_bound_upload')) return {
        rows: []
      };
      queries++;
      assert.equal(args[0], a.operationId);
      assert.equal(args[5].toString('hex'), a.bindingSha256);
      assert.equal(args[6].toString('hex'), a.requestSha256);
      return {
        rows: [{
          operation_id: a.operationId,
          receipt_sha256: Buffer.from('c'.repeat(64), 'hex'),
          replayed: false
        }]
      };
    },
    release() {}
  };
  const repo = createSecureShopBoundUploadRepository({
    query: client.query,
    async connect() {
      return client;
    }
  }, {
    checkCurrent: async () => {
      throw Error('active authority forbidden');
    },
    assertSceneGrant: async () => {
      throw Error('active authority forbidden');
    },
    checkCleanupAuthority: async (s, op) => {
      calls++;
      assert.deepEqual(s, scope);
      assert.equal(op, id(6));
    }
  });
  const opts = {
      cleanupOperationId: id(6),
      cleanupScope: scope
    },
    receipt = {
      action: 'quarantined',
      receiptSha256: 'c'.repeat(64)
    },
    unresolved = normalizeEffect({
      effectId: id(7),
      outcome: 'unresolved',
      file: null,
      denialCode: null,
      quarantineRequired: true
    }, a);
  if (orphan) await repo.reconcileOrphan(raw, receipt, opts);else await repo.reconcile(raw, unresolved, receipt, opts);
  assert.equal(queries, 1);
  assert.equal(calls, 3);
  for (const foreign of [{
    ...scope,
    targetId: id(9)
  }, {
    ...scope,
    platformOwnerId: 12
  }]) await assert.rejects(repo.reconcileOrphan(raw, receipt, {
    ...opts,
    cleanupScope: foreign
  }), e => e.code === 'BOUND_UPLOAD_MISMATCH');
  assert.equal(queries, 1);
});
