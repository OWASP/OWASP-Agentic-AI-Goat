'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { normalizeAdmission, normalizeEffect } = require('../server/services/secureshopBoundUploadReceipt');
const { createSecureShopV46TraversalRepository } = require('../server/database/postgres/secureshopV46TraversalRepository');

const id = n => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const sha = value => createHash('sha256').update(value).digest('hex');
const claim = {
  effectId: id(1), operationId: id(2), targetId: id(3), generation: 2,
  sceneId: id(4), sceneGeneration: 3, mode: 'vuln', modeGeneration: 4, modeStamp: 'a'.repeat(64)
};
function fixture() {
  const bytes = Buffer.from('owned-v46');
  const admission = normalizeAdmission({
    operationId: claim.operationId,
    uploadRequestId: id(5),
    storageKey: id(6),
    scope: {
      targetId: claim.targetId, launchId: id(7), scenarioId: id(8), generation: claim.generation,
      platformOwnerId: 9, platformSessionId: 10, sceneId: claim.sceneId,
      sceneGeneration: claim.sceneGeneration, grantId: id(11), shopUserId: 12,
      personaSessionId: id(13), personaAuthorityVersion: '1', mode: claim.mode,
      modeGeneration: claim.modeGeneration, modeStamp: claim.modeStamp
    },
    request: {
      kind: 'avatar', scopeId: 12, originalFilename: '....//escaped-v46.txt',
      declaredMime: 'text/plain', public: false, byteCount: bytes.length, bodySha256: sha(bytes)
    }
  });
  const effect = normalizeEffect({
    effectId: claim.effectId,
    outcome: 'completed',
    file: {
      storageKey: admission.storageKey, originalFilename: admission.request.originalFilename,
      cleanedFilename: '../escaped-v46.txt', declaredMime: 'text/plain',
      byteCount: bytes.length, bodySha256: sha(bytes),
      baseVirtualPath: `operations/${admission.storageKey}/avatars/12`,
      resolvedVirtualPath: `operations/${admission.storageKey}/avatars/12/../escaped-v46.txt`,
      storedVirtualPath: `operations/${admission.storageKey}/avatars/escaped-v46.txt`,
      isTraversal: true
    },
    denialCode: null,
    quarantineRequired: false
  }, admission);
  const row = {
    binding_sha256: Buffer.from(admission.bindingSha256, 'hex'),
    request_sha256: Buffer.from(admission.requestSha256, 'hex'),
    effect_sha256: Buffer.from(effect.effectSha256, 'hex'),
    operation_id: admission.operationId, upload_request_id: admission.uploadRequestId,
    admission_storage_key: admission.storageKey, target_id: admission.scope.targetId,
    launch_id: admission.scope.launchId, scenario_id: admission.scope.scenarioId,
    generation: String(admission.scope.generation), platform_owner_id: admission.scope.platformOwnerId,
    platform_session_id: admission.scope.platformSessionId, scene_id: admission.scope.sceneId,
    scene_generation: String(admission.scope.sceneGeneration), grant_id: admission.scope.grantId,
    shop_user_id: admission.scope.shopUserId, persona_session_id: admission.scope.personaSessionId,
    persona_authority_version: admission.scope.personaAuthorityVersion, mode: admission.scope.mode,
    mode_generation: String(admission.scope.modeGeneration), mode_stamp: Buffer.from(admission.scope.modeStamp, 'hex'),
    kind: admission.request.kind, scope_id: admission.request.scopeId,
    admission_original_filename: admission.request.originalFilename,
    admission_declared_mime: admission.request.declaredMime, is_public: admission.request.public,
    admission_byte_count: admission.request.byteCount, admission_body_sha256: Buffer.from(admission.request.bodySha256, 'hex'),
    effect_id: effect.effectId, outcome: effect.outcome, effect_storage_key: effect.file.storageKey,
    effect_original_filename: effect.file.originalFilename, cleaned_filename: effect.file.cleanedFilename,
    effect_declared_mime: effect.file.declaredMime, effect_byte_count: effect.file.byteCount,
    effect_body_sha256: Buffer.from(effect.file.bodySha256, 'hex'), base_virtual_path: effect.file.baseVirtualPath,
    resolved_virtual_path: effect.file.resolvedVirtualPath, stored_virtual_path: effect.file.storedVirtualPath,
    is_traversal: true
  };
  return { admission, effect, row };
}

test('V46 repository returns only exact non-serving same-operation traversal evidence', async () => {
  const f = fixture();
  let query;
  const repository = createSecureShopV46TraversalRepository({ async query(sql, args) {
    query = { sql, args };
    return { rows: [f.row] };
  } });
  const value = await repository.lookup(claim);
  assert.deepEqual(value.admission, f.admission);
  assert.deepEqual(value.effect, f.effect);
  assert.equal(value.canonicalServe, undefined);
  assert.equal(value.storedVirtualPath, f.effect.file.storedVirtualPath);
  assert.match(query.sql, /e\.is_traversal=TRUE/);
  assert.match(query.sql, /NOT EXISTS \(SELECT 1 FROM secureshop_review\.bound_upload_serves/);
  assert.deepEqual(query.args, [claim.effectId, claim.operationId, claim.targetId, 2,
    claim.sceneId, 3, 'vuln', 4, claim.modeStamp]);
});

test('V46 repository rejects changed, under-avatar and sibling-operation paths', async () => {
  for (const change of [
    { stored_virtual_path: `operations/${id(99)}/avatars/escaped-v46.txt` },
    { stored_virtual_path: `operations/${id(6)}/avatars/12/escaped-v46.txt` },
    { resolved_virtual_path: `operations/${id(6)}/avatars/12/../../escaped-v46.txt` },
    { cleaned_filename: 'escaped-v46.txt' },
    { effect_original_filename: 'escaped-v46.txt' }
  ]) {
    const f = fixture();
    Object.assign(f.row, change);
    const repository = createSecureShopV46TraversalRepository({ async query() { return { rows: [f.row] }; } });
    await assert.rejects(repository.lookup(claim), /(?:Invalid bound upload receipt|BOUND_UPLOAD_(?:TRAVERSAL|RECEIPT)_CHANGED)/);
  }
});

test('V46 repository returns null for absent, retired or cleaned evidence', async () => {
  const repository = createSecureShopV46TraversalRepository({ async query(sql) {
    assert.match(sql, /t\.lifecycle='active'/);
    assert.match(sql, /r\.operation_id IS NULL AND c\.target_id IS NULL/);
    return { rows: [] };
  } });
  assert.equal(await repository.lookup(claim), null);
});
