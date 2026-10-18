'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID, createHash } = require('node:crypto');
const { normalizeAdmission, normalizeEffect } = require('../server/services/secureshopBoundUploadReceipt');
const { createSecureShopBoundUploadSavedOperation } = require('../server/services/secureshopBoundUploadSavedOperation');

const bytes = Buffer.from('owned-v46');
const digest = createHash('sha256').update(bytes).digest('hex');
function fixture() {
  const admission = normalizeAdmission({
    operationId: randomUUID(), uploadRequestId: randomUUID(), storageKey: randomUUID(),
    scope: { targetId: randomUUID(), launchId: randomUUID(), scenarioId: randomUUID(), generation: 1,
      platformOwnerId: 2, platformSessionId: 3, sceneId: randomUUID(), sceneGeneration: 1,
      grantId: randomUUID(), shopUserId: 46, personaSessionId: randomUUID(),
      personaAuthorityVersion: '1', mode: 'vuln', modeGeneration: 0, modeStamp: 'a'.repeat(64) },
    request: { kind: 'avatar', scopeId: 46, originalFilename: '....//escaped.txt',
      declaredMime: 'text/plain', public: false, byteCount: bytes.length, bodySha256: digest }
  });
  const effect = normalizeEffect({ effectId: randomUUID(), outcome: 'completed', file: {
    storageKey: admission.storageKey, originalFilename: admission.request.originalFilename,
    cleanedFilename: '../escaped.txt', declaredMime: admission.request.declaredMime,
    byteCount: bytes.length, bodySha256: digest,
    baseVirtualPath: `operations/${admission.storageKey}/avatars/46`,
    resolvedVirtualPath: `operations/${admission.storageKey}/avatars/46/../escaped.txt`,
    storedVirtualPath: `operations/${admission.storageKey}/avatars/escaped.txt`, isTraversal: true
  }, denialCode: null, quarantineRequired: false }, admission);
  const s = admission.scope, r = admission.request;
  const row = { operation_id: admission.operationId, upload_request_id: admission.uploadRequestId,
    storage_key: admission.storageKey, target_id: s.targetId, launch_id: s.launchId,
    scenario_id: s.scenarioId, generation: String(s.generation), platform_owner_id: s.platformOwnerId,
    platform_session_id: s.platformSessionId, scene_id: s.sceneId, scene_generation: String(s.sceneGeneration),
    grant_id: s.grantId, shop_user_id: s.shopUserId, persona_session_id: s.personaSessionId,
    persona_authority_version: s.personaAuthorityVersion, mode: s.mode,
    mode_generation: String(s.modeGeneration), mode_stamp: Buffer.from(s.modeStamp, 'hex'),
    kind: r.kind, scope_id: r.scopeId, original_filename: r.originalFilename,
    declared_mime: r.declaredMime, is_public: r.public, byte_count: r.byteCount,
    body_sha256: Buffer.from(r.bodySha256, 'hex'), binding_sha256: Buffer.from(admission.bindingSha256, 'hex'),
    request_sha256: Buffer.from(admission.requestSha256, 'hex') };
  return { admission, effect, row };
}

test('V46 saved GET rereads bytes and projects the same safe operation-relative destination', async () => {
  const { admission, effect, row } = fixture();
  let reads = 0, mints = 0;
  const saved = createSecureShopBoundUploadSavedOperation({
    pool: { async query() { return { rows: [row] }; } }, assertCurrent: async () => {},
    effects: { async find() { return effect; } }, read: async () => assert.fail('normal reader'),
    readTraversal: async receipt => { reads++; assert.equal(receipt.storedVirtualPath, effect.file.storedVirtualPath); },
    capability: { mint() { mints++; } }, assetOrigin: 'http://[::1]:9083'
  });
  const result = await saved.read({ scope: admission.scope, persona: { id: 46, role: 'customer' },
    personaSession: { sessionId: admission.scope.personaSessionId, authorityVersion: '1' },
    uploadRequestId: admission.uploadRequestId });
  assert.equal(reads, 1); assert.equal(mints, 0);
  assert.deepEqual(result, { operationId: admission.operationId, uploadRequestId: admission.uploadRequestId,
    status: 'completed', filename: admission.request.originalFilename, byteCount: bytes.length,
    bodySha256: digest, traversal: true, operationRelativePath: 'avatars/escaped.txt',
    escapedAvatarSubdirectory: true });
});

test('V46 saved GET rejects a changed stored destination after physical reread', async () => {
  const { admission, effect, row } = fixture();
  const changed = { ...effect, file: { ...effect.file, storedVirtualPath: `operations/${admission.storageKey}/foreign.txt` } };
  const saved = createSecureShopBoundUploadSavedOperation({
    pool: { async query() { return { rows: [row] }; } }, assertCurrent: async () => {},
    effects: { async find() { return changed; } }, read: async () => {}, readTraversal: async () => {},
    capability: { mint() {} }, assetOrigin: 'http://[::1]:9083'
  });
  await assert.rejects(saved.read({ scope: admission.scope, persona: { id: 46, role: 'customer' },
    personaSession: { sessionId: admission.scope.personaSessionId, authorityVersion: '1' },
    uploadRequestId: admission.uploadRequestId }), { code: 'BOUND_UPLOAD_EFFECT_MISMATCH' });
});
