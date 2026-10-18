'use strict';

const test = require('node:test'),
  assert = require('node:assert/strict'),
  fs = require('node:fs/promises'),
  os = require('node:os'),
  path = require('node:path'),
  crypto = require('node:crypto');
const {
  createSecureShopBoundUploadAssetRepository
} = require('../server/database/postgres/secureshopBoundUploadAssetRepository');
const {
  createSecureShopUploadAssetReader
} = require('../server/services/secureshopUploadAssetReader');
const claim = {
  effectId: '00000001-0000-4000-8000-000000000001',
  operationId: '00000002-0000-4000-8000-000000000002',
  targetId: '00000003-0000-4000-8000-000000000003',
  generation: 2,
  sceneId: '00000004-0000-4000-8000-000000000004',
  sceneGeneration: 3,
  mode: 'vuln',
  modeGeneration: 4,
  modeStamp: 'a'.repeat(64)
};
test('lookup binds exact operation target scene and mode while excluding retired evidence', async () => {
  let query;
  const repo = createSecureShopBoundUploadAssetRepository({
    async query(sql, args) {
      query = {
        sql,
        args
      };
      return {
        rows: []
      };
    }
  });
  assert.equal(await repo.lookup(claim), null);
  assert.deepEqual(query.args, [claim.effectId, claim.operationId, claim.targetId, 2, claim.sceneId, 3, 'vuln', 4, claim.modeStamp]);
  assert.match(query.sql, /t\.lifecycle='active'/);
  assert.match(query.sql, /assert_scene_execution_grant/);
  assert.match(query.sql, /r\.operation_id IS NULL AND c\.target_id IS NULL/);
});
