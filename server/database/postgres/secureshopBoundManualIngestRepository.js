'use strict';

const { withTransaction } = require('./index');
const { randomUUID, createHash } = require('node:crypto');
const { copySceneBinding, executionScope, assertSceneGrant, withSceneLease }
  = require('../../services/secureshopSceneBinding');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA256 = /^[0-9a-f]{64}$/;
const BINDING_KEYS = Object.freeze(['targetId', 'launchId', 'scenarioId', 'generation',
  'platformOwnerId', 'platformSessionId']);
const FILE_KEYS = Object.freeze(['targetId', 'launchId', 'scenarioId', 'generation',
  'platformOwnerId', 'platformSessionId', 'virtualPath', 'bytes', 'sha256']);
const INPUT_KEYS = Object.freeze(['operationId', 'productId', 'merchantId', 'fileReceipt',
  'filename', 'mime', 'isPublic', 'extractor', 'extractionSha256', 'embeddingModel',
  'embeddingDimension', 'chunks', 'expectedRuntimeFingerprint']);

function failure(code, message) { return Object.assign(new Error(message), { code }); }
function plain(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && [Object.prototype, null].includes(Object.getPrototypeOf(value));
}
function exact(value, keys, message) {
  const descriptors = plain(value) ? Object.getOwnPropertyDescriptors(value) : null;
  if (!descriptors || Reflect.ownKeys(descriptors).length !== keys.length
      || keys.some(key => !Object.hasOwn(descriptors, key)
        || !Object.hasOwn(descriptors[key], 'value'))) {
    throw failure('INVALID_ARGUMENT', message);
  }
}
function uuid(value, name) {
  if (typeof value !== 'string' || !UUID.test(value)) {
    throw failure('INVALID_ARGUMENT', `${name} is invalid`);
  }
  return value.toLowerCase();
}
function integer(value, name, min = 1, max = 2147483647) {
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw failure('INVALID_ARGUMENT', `${name} is invalid`);
  }
  return value;
}
function text(value, name, maxBytes) {
  if (typeof value !== 'string' || !value || Buffer.byteLength(value, 'utf8') > maxBytes) {
    throw failure('INVALID_ARGUMENT', `${name} is invalid`);
  }
  return value;
}
function hash(value, name) {
  if (typeof value !== 'string' || !SHA256.test(value)) {
    throw failure('INVALID_ARGUMENT', `${name} is invalid`);
  }
  return value;
}
function binding(value) {
  exact(value, value && Object.hasOwn(value, 'scene') ? [...BINDING_KEYS, 'scene'] : BINDING_KEYS,
    'product target binding is invalid');
  return copySceneBinding(value, { targetId: uuid(value.targetId, 'targetId'),
    launchId: uuid(value.launchId, 'launchId'), scenarioId: uuid(value.scenarioId, 'scenarioId'),
    generation: integer(value.generation, 'generation', 1, Number.MAX_SAFE_INTEGER),
    platformOwnerId: integer(value.platformOwnerId, 'platformOwnerId'),
    platformSessionId: integer(value.platformSessionId, 'platformSessionId') });
}
function bindingValues(value) {
  return [value.targetId, value.launchId, value.scenarioId, value.generation,
    value.platformOwnerId, value.platformSessionId];
}
function fileReceipt(value, scope, productId, operationId) {
  exact(value, FILE_KEYS, 'file receipt is invalid');
  const receipt = Object.freeze({ targetId: uuid(value.targetId, 'file targetId'),
    launchId: uuid(value.launchId, 'file launchId'),
    scenarioId: uuid(value.scenarioId, 'file scenarioId'),
    generation: integer(value.generation, 'file generation', 1, Number.MAX_SAFE_INTEGER),
    platformOwnerId: integer(value.platformOwnerId, 'file platformOwnerId'),
    platformSessionId: integer(value.platformSessionId, 'file platformSessionId'),
    virtualPath: text(value.virtualPath, 'virtualPath', 4096),
    bytes: integer(value.bytes, 'bytes', 1, 20 * 1024 * 1024),
    sha256: hash(value.sha256, 'file sha256') });
  const expectedPath = `/uploads/product_manuals/${productId}/${operationId}-manual`;
  const current = executionScope(scope);
  if (receipt.targetId === scope.targetId || receipt.launchId !== current.launchId
      || receipt.scenarioId !== current.scenarioId || receipt.generation !== current.generation
      || receipt.platformOwnerId !== current.platformOwnerId
      || receipt.platformSessionId !== current.platformSessionId
      || receipt.virtualPath !== expectedPath) {
    throw failure('INVALID_ARGUMENT', 'file receipt does not match product target authority');
  }
  return receipt;
}
function chunks(value, dimension) {
  if (!Array.isArray(value) || value.length < 1 || value.length > 129) {
    throw failure('INVALID_ARGUMENT', 'manual chunks are invalid');
  }
  return Object.freeze(value.map((chunk, index) => {
    exact(chunk, ['text', 'embedding'], `manual chunk ${index} is invalid`);
    const body = text(chunk.text, `manual chunk ${index} text`, 65536);
    if (!Array.isArray(chunk.embedding) || chunk.embedding.length !== dimension
        || chunk.embedding.some(number => typeof number !== 'number' || !Number.isFinite(number))
        || !chunk.embedding.some(number => number !== 0)) {
      throw failure('INVALID_ARGUMENT', `manual chunk ${index} embedding is invalid`);
    }
    return Object.freeze({ text: body, embedding: Object.freeze([...chunk.embedding]) });
  }));
}
function normalizeInput(value, scope) {
  exact(value, INPUT_KEYS, 'manual ingest input is invalid');
  const operationId = uuid(value.operationId, 'operationId');
  const productId = integer(value.productId, 'productId');
  const merchantId = integer(value.merchantId, 'merchantId');
  const embeddingDimension = integer(value.embeddingDimension, 'embeddingDimension', 1, 4096);
  return Object.freeze({ operationId, productId, merchantId, expectedRuntimeFingerprint: hash(value.expectedRuntimeFingerprint, 'expectedRuntimeFingerprint'),
    fileReceipt: fileReceipt(value.fileReceipt, scope, productId, operationId),
    filename: text(value.filename, 'filename', 4096), mime: text(value.mime, 'mime', 1024),
    isPublic: typeof value.isPublic === 'boolean' ? value.isPublic
      : (() => { throw failure('INVALID_ARGUMENT', 'isPublic is invalid'); })(),
    extractor: text(value.extractor, 'extractor', 128),
    extractionSha256: hash(value.extractionSha256, 'extractionSha256'),
    embeddingModel: text(value.embeddingModel, 'embeddingModel', 256), embeddingDimension,
    chunks: chunks(value.chunks, embeddingDimension) });
}
function number(row, name, min, max = Number.MAX_SAFE_INTEGER) {
  const value = Number(row?.[name]);
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw failure('BOUND_MANUAL_INGEST_MISMATCH', 'manual ingest receipt is invalid');
  }
  return value;
}
function rowHash(row, name) {
  if (!Buffer.isBuffer(row?.[name]) || row[name].length !== 32) {
    throw failure('BOUND_MANUAL_INGEST_MISMATCH', 'manual ingest receipt is invalid');
  }
  return row[name].toString('hex');
}
function receipt(row, scope, expectedOperationId, replayed) {
  const current = executionScope(scope);
  const version = row?.receipt_version == null ? 1 : number(row, 'receipt_version', 1, 2);
  if (!row || row.receipt_valid !== true || row.operation_id !== expectedOperationId
      || row.target_id !== scope.targetId || row.launch_id !== scope.launchId
      || row.scenario_id !== scope.scenarioId
      || number(row, 'generation', 1) !== scope.generation
      || number(row, 'original_platform_owner_id', 1, 2147483647) !== scope.platformOwnerId
      || number(row, 'original_platform_session_id', 1, 2147483647) !== scope.platformSessionId
      || typeof row.is_public !== 'boolean') {
    throw failure('BOUND_MANUAL_INGEST_MISMATCH', 'manual ingest receipt does not match');
  }
  if ((scope.scene === undefined && version !== 1)
      || (scope.scene !== undefined && version !== 2)
      || (version === 2 && (row.scene_id !== scope.scene.sceneId
        || number(row, 'scene_generation', 1) !== scope.scene.sceneGeneration
        || row.scene_grant_id !== scope.scene.grantId
        || row.execution_launch_id !== current.launchId
        || row.execution_scenario_id !== current.scenarioId
        || number(row, 'execution_generation', 1) !== current.generation
        || number(row, 'execution_platform_owner_id', 1, 2147483647) !== current.platformOwnerId
        || number(row, 'execution_platform_session_id', 1, 2147483647) !== current.platformSessionId))) {
    throw failure('BOUND_MANUAL_INGEST_MISMATCH', 'manual ingest execution receipt does not match');
  }
  const manualSourceId = number(row, 'manual_source_id', 1);
  const documentCount = number(row, 'document_count', 1, 129);
  const productId = number(row, 'product_id', 1, 2147483647);
  const completed = new Date(row.completed_at);
  if (!Number.isFinite(completed.getTime())) {
    throw failure('BOUND_MANUAL_INGEST_MISMATCH', 'manual ingest receipt is invalid');
  }
  const virtualPath = text(row.virtual_path, 'virtualPath', 4096);
  const filename = text(row.filename, 'filename', 4096);
  const mime = text(row.mime, 'mime', 1024);
  const extractor = text(row.extractor, 'extractor', 128);
  const embeddingModel = text(row.embedding_model, 'embeddingModel', 256);
  const file = Object.freeze({ targetId: uuid(row.file_target_id, 'file targetId'),
    launchId: uuid(row.file_launch_id, 'file launchId'),
    scenarioId: uuid(row.file_scenario_id, 'file scenarioId'),
    generation: number(row, 'file_generation', 1),
    platformOwnerId: number(row, 'file_platform_owner_id', 1, 2147483647),
    platformSessionId: number(row, 'file_platform_session_id', 1, 2147483647),
    virtualPath, bytes: number(row, 'byte_count', 1, 20 * 1024 * 1024),
    sha256: rowHash(row, 'file_sha256') });
  if (file.launchId !== current.launchId || file.scenarioId !== current.scenarioId
      || file.generation !== current.generation || file.platformOwnerId !== current.platformOwnerId
      || file.platformSessionId !== current.platformSessionId || file.targetId === scope.targetId
      || file.virtualPath !== `/uploads/product_manuals/${productId}/${expectedOperationId}-manual`) {
    throw failure('BOUND_MANUAL_INGEST_MISMATCH', 'manual ingest file receipt does not match');
  }
  const runtimeFingerprint = row.runtime_fingerprint == null ? null : rowHash(row, 'runtime_fingerprint');
  if (runtimeFingerprint !== null && row.runtime_receipt_valid !== true) throw failure('BOUND_MANUAL_INGEST_MISMATCH', 'manual runtime receipt is invalid');
  return Object.freeze({ runtimeFingerprint, operationId: expectedOperationId, manualSourceId,
    ...Object.fromEntries(BINDING_KEYS.map(key => [key, scope[key]])),
    ...(version === 2 ? { execution: current, sceneId: scope.scene.sceneId,
      sceneGeneration: scope.scene.sceneGeneration, sceneGrantId: scope.scene.grantId } : {}),
    productId, merchantId: number(row, 'merchant_id', 1, 2147483647), fileReceipt: file,
    filename, mime, isPublic: row.is_public, extractor,
    extractionSha256: rowHash(row, 'extraction_sha256'), embeddingModel,
    embeddingDimension: number(row, 'embedding_dimension', 1, 4096),
    documentDigest: rowHash(row, 'document_digest'), documentCount,
    receiptSha256: rowHash(row, 'receipt_sha256'), completedAt: completed.toISOString(),
    replayed: Boolean(replayed),
    chunkIds: Object.freeze(Array.from({ length: documentCount },
      (_unused, index) => `manual:${manualSourceId}:${index}`)) });
}

const RECEIPT_SELECT = `SELECT i.*,r.runtime_fingerprint,
  (r.original_receipt_sha256=i.receipt_sha256 AND r.receipt_sha256=secureshop_review.manual_runtime_receipt_digest(r.operation_id,r.runtime_fingerprint,r.original_receipt_sha256)) AS runtime_receipt_valid,
  i.receipt_sha256=CASE WHEN i.receipt_version=2 THEN
    secureshop_review.product_manual_scene_receipt_digest(i)
  WHEN i.receipt_version=1 THEN secureshop_review.product_manual_ingest_receipt_digest(
    i.operation_id,i.manual_source_id,i.target_id,i.launch_id,i.scenario_id,i.generation,
    i.original_platform_owner_id,i.original_platform_session_id,i.product_id,i.merchant_id,
    i.file_target_id,i.file_launch_id,i.file_scenario_id,i.file_generation,
    i.file_platform_owner_id,i.file_platform_session_id,i.virtual_path,i.byte_count,
    i.file_sha256,i.filename,i.mime,i.is_public,i.extractor,i.extraction_sha256,
    i.embedding_model,i.embedding_dimension,i.document_digest,i.document_count
  ) ELSE NULL END AS receipt_valid
  FROM secureshop_review.product_target_manual_ingests i
  LEFT JOIN secureshop_review.product_target_manual_runtime_receipts r USING(operation_id)
  WHERE i.operation_id=$1 AND i.target_id=$2 AND i.launch_id=$3 AND i.scenario_id=$4
    AND i.generation=$5 AND i.original_platform_owner_id=$6
    AND i.original_platform_session_id=$7`;

// Private V26 provenance stores the canonical upload preimage in the migration-owned
// immutable snapshot table. Turn metadata receives this compact reference only.
const PREIMAGE_CAPTURE = `SELECT operation_id,target_id,document_digest,receipt_sha256,runtime_receipt_sha256
 FROM secureshop_review.capture_product_manual_preimage($1::uuid,$2::uuid,$3::jsonb)`;
const PRIVATE_PREIMAGE_CAPTURE = `SELECT operation_id,target_id,document_digest,receipt_sha256,runtime_receipt_sha256
 FROM secureshop_review.capture_private_product_manual_preimage($1::uuid,$2::uuid,$3::jsonb)`;
const ineligible = reason => Object.freeze({ eligible: false, reason });
function digest(row, name) {
  return Buffer.isBuffer(row?.[name]) && row[name].length === 32 ? row[name].toString('hex') : null;
}
async function captureManualLineage(client, scope, input, accepted, privateSource = false) {
  if (!scope.scene) return ineligible('legacy_receipt');
  // A replay must preserve its already-saved producer metadata; it must never
  // fabricate a historical preimage from float vectors or a current head.
  if (accepted.replayed) return ineligible('replayed_without_original');
  if (accepted.isPublic !== !privateSource) return ineligible(privateSource ? 'public_manual' : 'private_manual');
  const rows = (await client.query(privateSource ? PRIVATE_PREIMAGE_CAPTURE : PREIMAGE_CAPTURE,
    [input.operationId, scope.targetId, JSON.stringify(input.chunks)])).rows;
  if (rows.length !== 1) return ineligible('missing_original');
  const row = rows[0];
  const documentDigest = digest(row, 'document_digest');
  const receiptSha256 = digest(row, 'receipt_sha256');
  const runtimeReceiptSha256 = digest(row, 'runtime_receipt_sha256');
  if (row.operation_id !== input.operationId || row.target_id !== scope.targetId
      || documentDigest !== accepted.documentDigest || receiptSha256 !== accepted.receiptSha256
      || !runtimeReceiptSha256) return ineligible('capture_mismatch');
  return Object.freeze({ eligible: true, version: 2, preimageRef: Object.freeze({
    version: 1, operationId: input.operationId, targetId: scope.targetId,
    documentDigest, receiptSha256, runtimeReceiptSha256,
  }) });
}

function createSecureShopBoundManualIngestRepository(pool, { checkCurrent, auditStore, getRuntimeFingerprint } = {}) {
  if (typeof pool?.query !== 'function' || typeof pool?.connect !== 'function'
      || typeof checkCurrent !== 'function') {
    throw failure('BOUND_MANUAL_INGEST_UNAVAILABLE', 'manual ingest authority unavailable');
  }
  if (auditStore && typeof auditStore.append !== 'function') throw new TypeError('Audit store required');
  async function read(client, scope, operationId, replayed) {
    const row = (await client.query(RECEIPT_SELECT,
      [operationId, ...bindingValues(scope)])).rows[0];
    if (!row) throw failure('BOUND_MANUAL_INGEST_RECEIPT_UNAVAILABLE', 'manual ingest receipt unavailable');
    return receipt(row, scope, operationId, replayed);
  }
  async function appendManual(value, requested, options = {}, capture = false) {
      const timeout = options.effectTimeoutMs;
      if (timeout !== undefined && (!Number.isInteger(timeout) || timeout < 100 || timeout > 10000)) throw new TypeError('Invalid effect timeout');
      const scope = binding(value);
      const current = executionScope(scope);
      const input = normalizeInput(requested, scope);
      const trusted = async () => { const fingerprint = await getRuntimeFingerprint?.(); if (typeof fingerprint !== 'string' || !SHA256.test(fingerprint) || fingerprint !== input.expectedRuntimeFingerprint) throw failure('EMBEDDING_FINGERPRINT_UNAVAILABLE', 'Verified manual embedding runtime changed or is unavailable'); return fingerprint; };
      await trusted();
      await checkCurrent(current);
      return withSceneLease(scope, () => withTransaction(pool, async client => {
        if (timeout !== undefined) await client.query("SELECT set_config('statement_timeout',$1,true),set_config('lock_timeout',$1,true)", [String(timeout)]);
        await assertSceneGrant(client, scope);
        const f = input.fileReceipt;
        const result = (await client.query(scope.scene ? `SELECT *
          FROM secureshop_review.append_product_manual_retrieval_attested_scene(
            ${Array.from({length:35}, (_, index) => `$${index + 1}${index === 33 ? '::jsonb' : ''}`).join(',')})` : `SELECT *
          FROM secureshop_review.append_product_manual_retrieval_attested(
            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,
            $19,$20,$21,$22,$23,$24,$25,$26::jsonb,$27)`, [input.operationId,
          ...bindingValues(scope), ...(scope.scene ? [scope.scene.sceneId,
            scope.scene.sceneGeneration, scope.scene.grantId, current.launchId,
            current.scenarioId, current.generation, current.platformOwnerId,
            current.platformSessionId] : []), input.productId, input.merchantId,
          f.targetId, f.launchId, f.scenarioId, f.generation, f.platformOwnerId,
          f.platformSessionId, f.virtualPath, f.bytes, Buffer.from(f.sha256, 'hex'),
          input.filename, input.mime, input.isPublic, input.extractor,
          Buffer.from(input.extractionSha256, 'hex'), input.embeddingModel,
          input.embeddingDimension, JSON.stringify(input.chunks), Buffer.from(input.expectedRuntimeFingerprint, 'hex')])).rows[0];
        if (!result || typeof result.replayed !== 'boolean'
            || result.operation_id !== input.operationId
            || number(result, 'manual_source_id', 1) < 1
            || number(result, 'document_count', 1, 129) !== input.chunks.length) {
          throw failure('BOUND_MANUAL_INGEST_MISMATCH', 'manual ingest append result is invalid');
        }
        const accepted = await read(client, scope, input.operationId, result.replayed);
        if (accepted.manualSourceId !== Number(result.manual_source_id)
            || accepted.documentCount !== Number(result.document_count)
            || accepted.documentDigest !== rowHash(result, 'document_digest')
            || accepted.receiptSha256 !== rowHash(result, 'receipt_sha256')
            || accepted.productId !== input.productId || accepted.merchantId !== input.merchantId
            || BINDING_KEYS.some(key => accepted.fileReceipt[key] !== input.fileReceipt[key])
            || accepted.fileReceipt.virtualPath !== input.fileReceipt.virtualPath
            || accepted.fileReceipt.bytes !== input.fileReceipt.bytes
            || accepted.fileReceipt.sha256 !== input.fileReceipt.sha256
            || accepted.filename !== input.filename || accepted.mime !== input.mime
            || accepted.isPublic !== input.isPublic || accepted.extractor !== input.extractor
            || accepted.extractionSha256 !== input.extractionSha256
            || accepted.embeddingModel !== input.embeddingModel
            || accepted.embeddingDimension !== input.embeddingDimension
            || accepted.runtimeFingerprint !== input.expectedRuntimeFingerprint) {
          throw failure('BOUND_MANUAL_INGEST_MISMATCH', 'manual ingest append receipt changed');
        }
        if (auditStore && !result.replayed) await auditStore.append(client, {
          eventId: randomUUID(), scope: current, persona: { id: input.merchantId, role: 'merchant' },
          actor: 'merchant', action: 'manual_ingest', target: String(accepted.manualSourceId),
          paramsJson: JSON.stringify({ operationId: input.operationId, productId: input.productId,
            filename: accepted.filename, mime: accepted.mime, bytes: accepted.fileReceipt.bytes,
            fileSha256: accepted.fileReceipt.sha256, documentCount: accepted.documentCount,
            documentDigest: accepted.documentDigest, receiptSha256: accepted.receiptSha256,
            storageTargetId: scope.targetId,
            ...(scope.scene ? { sceneId: scope.scene.sceneId,
              sceneGeneration: scope.scene.sceneGeneration, sceneGrantId: scope.scene.grantId } : {}) }),
          outcome: 'completed', sourceKind: 'manual_ingest', sourceId: input.operationId,
        });
        const lineage = capture ? await captureManualLineage(client, scope, input, accepted) : null;
        const protectedLineage = capture === 'protected' && accepted.isPublic === false
          ? await captureManualLineage(client, scope, input, accepted, true) : null;
        await assertSceneGrant(client, scope);
        await checkCurrent(current);
        await trusted();
        return capture ? Object.freeze({ receipt: accepted, lineage,
          ...(protectedLineage ? {protectedLineage} : {}) }) : accepted;
      }));
  }
  return Object.freeze({
    appendManual: (value, requested, options) => appendManual(value, requested, options, false),
    appendManualWithLineage: (value, requested, options) => appendManual(value, requested, options, true),
    appendManualWithProtectedLineage: (value, requested, options) => appendManual(value, requested, options, 'protected'),
    async readReceipt(value, requested = {}) {
      const scope = binding(value);
      const current = executionScope(scope);
      exact(requested, ['operationId'], 'manual ingest receipt request is invalid');
      const operationId = uuid(requested.operationId, 'operationId');
      await checkCurrent(current);
      return withSceneLease(scope, () => withTransaction(pool, async client => {
        await assertSceneGrant(client, scope);
        const accepted = await read(client, scope, operationId, true);
        await assertSceneGrant(client, scope);
        await checkCurrent(current);
        return accepted;
      }));
    },
  });
}

module.exports = { createSecureShopBoundManualIngestRepository };
