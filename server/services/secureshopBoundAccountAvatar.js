'use strict';

const { createHash } = require('node:crypto');
const { createLaunchScope } = require('./secureshopConversationBinding');
const { executionScope, withSceneLease } = require('./secureshopSceneBinding');
const { normalizeAdmission } = require('./secureshopBoundUploadReceipt');
const { createSecureShopBoundUploadApplication } = require('./secureshopBoundUploadApplication');
const { createSecureShopV46TraversalApplication } = require('./secureshopV46TraversalApplication');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const ROLES = new Set(['customer', 'merchant', 'admin']);
const MAX_BYTES = 20 * 1024 * 1024;
const fail = code => Object.assign(new Error('Bound account avatar unavailable'), { code, executionBoundary: true });
const derive = (label, parts) => {
  const hash = createHash('sha256').update(JSON.stringify([label, ...parts])).digest('hex');
  return `${hash.slice(0, 8)}-${hash.slice(8, 12)}-5${hash.slice(13, 16)}-a${hash.slice(17, 20)}-${hash.slice(20, 32)}`;
};
const sameExecution = (left, right) => ['launchId', 'scenarioId', 'generation',
  'platformOwnerId', 'platformSessionId'].every(key => left[key] === right[key]);

function createSecureShopBoundAccountAvatar({ pool, launches, resolveTarget, personaAuthority,
  modeAuthority, journal, effects, writer, traversalWriter,
  read = require('./secureshopUploadAssetReader').createSecureShopUploadAssetReader(),
  readTraversal = require('./secureshopV46TraversalAssetReader').createSecureShopV46TraversalAssetReader() } = {}) {
  if (typeof pool?.query !== 'function' || typeof launches?.assertCurrent !== 'function'
      || typeof resolveTarget !== 'function' || typeof personaAuthority?.capture !== 'function'
      || typeof modeAuthority?.capture !== 'function' || typeof modeAuthority?.assertToken !== 'function'
      || typeof journal?.claim !== 'function' || typeof journal?.recordEffect !== 'function'
      || typeof effects?.find !== 'function' || typeof writer?.writeAndReadBack !== 'function'
      || typeof traversalWriter?.writeAndReadBack !== 'function' || typeof read !== 'function'
      || typeof readTraversal !== 'function') throw new TypeError('Bound account avatar dependencies required');

  const ordinary = createSecureShopBoundUploadApplication({ effects, writer, journal });
  const traversal = createSecureShopV46TraversalApplication({ effects, writer: traversalWriter, journal });

  function identity(input) {
    const scope = createLaunchScope(input.scope), persona = input.persona,
      session = input.personaSession;
    if (!ROLES.has(persona?.role) || !Number.isSafeInteger(persona?.id) || persona.id < 1
        || !UUID.test(input.requestId || '') || !UUID.test(session?.sessionId || '')
        || !/^[1-9][0-9]*$/.test(String(session?.authorityVersion))) throw fail('SHOP_AUTH_INVALID');
    return { scope, persona, session };
  }

  async function authority(input) {
    input.signal?.throwIfAborted();
    const { scope, persona, session } = identity(input);
    await launches.assertCurrent(scope);
    const target = await resolveTarget(scope), current = executionScope(target);
    if (!target?.scene || !sameExecution(current, scope) || !UUID.test(target.targetId || '')
        || !UUID.test(target.scene.sceneId || '') || !UUID.test(target.scene.grantId || '')) throw fail('SHOP_SCENE_STALE');
    const modeToken = modeAuthority.assertToken(await modeAuthority.capture(scope, 'uploads'));
    const mode = modeToken.snapshot;
    if (!['vuln', 'fixed'].includes(mode?.mode) || !Number.isSafeInteger(mode.generation)
        || !/^[a-f0-9]{64}$/.test(mode.modeStamp || '')) throw fail('SHOP_MODE_CHANGED');
    const fence = await personaAuthority.capture({ scope, personaId: persona.id, role: persona.role,
      sessionId: session.sessionId, authorityVersion: session.authorityVersion });
    const binding = fence?.binding;
    if (!binding || !sameExecution(binding, scope) || binding.personaId !== persona.id
        || binding.role !== persona.role || binding.sessionId !== session.sessionId
        || String(binding.authorityVersion) !== String(session.authorityVersion)
        || typeof fence.assertRemoteAdmission !== 'function') throw fail('SHOP_AUTH_INVALID');
    await modeToken.assertCurrent();
    await fence.assertRemoteAdmission();
    await modeToken.assertCurrent();
    input.signal?.throwIfAborted();
    return { scope, persona, session, target, mode };
  }

  async function assertCurrent(input, admitted) {
    const current = await authority(input), s = admitted.scope;
    if (!sameExecution(current.scope, s) || current.target.targetId !== s.targetId
        || current.target.scene.sceneId !== s.sceneId
        || current.target.scene.sceneGeneration !== s.sceneGeneration
        || current.target.scene.grantId !== s.grantId
        || current.persona.id !== s.shopUserId || current.session.sessionId !== s.personaSessionId
        || String(current.session.authorityVersion) !== s.personaAuthorityVersion
        || current.mode.mode !== s.mode || current.mode.generation !== s.modeGeneration
        || current.mode.modeStamp !== s.modeStamp) throw fail('SHOP_AUTH_INVALID');
    return current;
  }

  const internalRequestId = (current, requestId) => derive('bound-account-avatar-request-v1',
    [current.scope, current.target.targetId, current.persona.role, current.persona.id,
      current.session.sessionId, requestId]);

  function result(admitted, effect, requestId, replayed) {
    const status = effect?.outcome || 'uncertain';
    return Object.freeze({ ok: status === 'completed', kind: 'avatar',
      scope_id: String(admitted.scope.shopUserId), requestId, status,
      operationId: admitted.operationId, filename: admitted.request.originalFilename,
      mime: admitted.request.declaredMime, size_bytes: admitted.request.byteCount,
      public: admitted.request.public, is_traversal: effect?.file?.isTraversal === true,
      replayed: replayed === true,
      ...(status === 'denied' ? { denialCode: effect.denialCode } : {}) });
  }

  async function readEffect(input, admitted) {
    await assertCurrent(input, admitted);
    const effect = await effects.find(admitted);
    if (effect?.outcome === 'completed') await (effect.file.isTraversal ? readTraversal : read)({
      storedVirtualPath: effect.file.storedVirtualPath,
      responseByteCount: effect.file.byteCount,
      responseSha256: effect.file.bodySha256
    });
    await assertCurrent(input, admitted);
    return effect;
  }

  return Object.freeze({
    async upload(input) {
      const current = await authority(input);
      const bytes = input.bytes, filename = input.filename, mime = input.mime;
      if (!Buffer.isBuffer(bytes) || bytes.length < 1 || bytes.length > MAX_BYTES
          || typeof filename !== 'string' || !filename || !filename.isWellFormed()
          || Buffer.byteLength(filename) > 4096 || /[\0\r\n\\]/.test(filename)
          || typeof mime !== 'string' || !mime || Buffer.byteLength(mime) > 1024
          || /[\0\r\n]/.test(mime) || typeof input.public !== 'boolean'
          || input.scopeId !== current.persona.id) throw fail('INVALID_ARGUMENT');
      const crafted = filename.includes('....//');
      if (!crafted && filename.includes('/')) throw fail('INVALID_ARGUMENT');
      const requestId = internalRequestId(current, input.requestId);
      const bodySha256 = createHash('sha256').update(bytes).digest('hex');
      const operationId = derive('bound-account-avatar-operation-v1',
        [requestId, filename, mime, input.public, bodySha256]);
      const rawAdmission = {
        operationId, uploadRequestId: requestId,
        storageKey: derive('bound-account-avatar-storage-v1', [operationId]),
        scope: {
          targetId: current.target.targetId, ...current.scope,
          sceneId: current.target.scene.sceneId,
          sceneGeneration: current.target.scene.sceneGeneration,
          grantId: current.target.scene.grantId,
          shopUserId: current.persona.id, personaSessionId: current.session.sessionId,
          personaAuthorityVersion: String(current.session.authorityVersion),
          mode: current.mode.mode, modeGeneration: current.mode.generation,
          modeStamp: current.mode.modeStamp
        },
        request: { kind: 'avatar', scopeId: current.persona.id, originalFilename: filename,
          declaredMime: mime, public: input.public, byteCount: bytes.length, bodySha256 }
      };
      await assertCurrent(input, normalizeAdmission(rawAdmission));
      const admitted = await journal.claim(rawAdmission);
      await assertCurrent(input, admitted);
      const execution = { signal: input.signal, check: () => assertCurrent(input, admitted) };
      const app = crafted ? traversal : ordinary;
      const applied = await withSceneLease(current.target, () => app.execute({ admission: admitted,
        file: { bytes, filename, mime }, mode: current.mode.mode, execution,
        effectId: derive('bound-account-avatar-effect-v1', [operationId, current.mode.mode]) }));
      const effect = await readEffect(input, admitted);
      if (!effect || effect.effectSha256 !== applied.effect.effectSha256) throw fail('BOUND_UPLOAD_EFFECT_MISMATCH');
      return result(admitted, effect, input.requestId, admitted.replayed || applied.replayed);
    },
    async read(input) {
      const current = await authority(input), requestId = internalRequestId(current, input.requestId);
      const rows = (await pool.query(`SELECT a.* FROM secureshop_review.bound_upload_admissions a
        LEFT JOIN secureshop_review.bound_upload_cleanup_receipts c ON c.target_id=a.target_id
        WHERE a.upload_request_id=$1 AND a.target_id=$2 AND a.launch_id=$3
          AND a.scenario_id=$4 AND a.generation=$5 AND a.platform_owner_id=$6
          AND a.platform_session_id=$7 AND a.shop_user_id=$8 AND a.persona_session_id=$9
          AND a.persona_authority_version=$10 AND c.target_id IS NULL`,
      [requestId, current.target.targetId, current.scope.launchId, current.scope.scenarioId,
        current.scope.generation, current.scope.platformOwnerId, current.scope.platformSessionId,
        current.persona.id, current.session.sessionId, String(current.session.authorityVersion)])).rows;
      await authority(input);
      if (rows.length > 1) throw fail('BOUND_UPLOAD_EFFECT_MISMATCH');
      if (!rows.length) return Object.freeze({ ok: false, kind: 'avatar',
        scope_id: String(current.persona.id), requestId: input.requestId, status: 'uncertain',
        operationId: null, filename: '', mime: '', size_bytes: 0, public: false,
        is_traversal: false, replayed: false });
      const row = rows[0];
      const admitted = normalizeAdmission({ operationId: row.operation_id,
        uploadRequestId: row.upload_request_id, storageKey: row.storage_key,
        scope: { targetId: row.target_id, launchId: row.launch_id, scenarioId: row.scenario_id,
          generation: Number(row.generation), platformOwnerId: row.platform_owner_id,
          platformSessionId: row.platform_session_id, sceneId: row.scene_id,
          sceneGeneration: Number(row.scene_generation), grantId: row.grant_id,
          shopUserId: row.shop_user_id, personaSessionId: row.persona_session_id,
          personaAuthorityVersion: row.persona_authority_version, mode: row.mode,
          modeGeneration: Number(row.mode_generation), modeStamp: row.mode_stamp.toString('hex') },
        request: { kind: row.kind, scopeId: row.scope_id,
          originalFilename: row.original_filename, declaredMime: row.declared_mime,
          public: row.is_public, byteCount: row.byte_count,
          bodySha256: row.body_sha256.toString('hex') } });
      if (admitted.uploadRequestId !== requestId
          || admitted.bindingSha256 !== row.binding_sha256.toString('hex')
          || admitted.requestSha256 !== row.request_sha256.toString('hex')
          || admitted.operationId !== derive('bound-account-avatar-operation-v1',
            [requestId, admitted.request.originalFilename, admitted.request.declaredMime,
              admitted.request.public, admitted.request.bodySha256])
          || admitted.storageKey !== derive('bound-account-avatar-storage-v1', [admitted.operationId]))
        throw fail('BOUND_UPLOAD_EFFECT_MISMATCH');
      const effect = await readEffect(input, admitted);
      return result(admitted, effect, input.requestId, true);
    }
  });
}

module.exports = { createSecureShopBoundAccountAvatar };
