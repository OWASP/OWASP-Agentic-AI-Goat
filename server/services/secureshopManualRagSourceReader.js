'use strict';

// This reader is deliberately narrower than product retrieval.  It consumes
// only producer-captured canonical JSONB preimages or immutable references from completed turns; it
// must never regenerate provenance from the mutable retrieval head or float8
// vectors.  Missing or oversized capture is an ordinary ineligible source.
const { isDeepStrictEqual: equal } = require('node:util');
const { executionScope } = require('./secureshopSceneBinding');
const { validateManualRagSourceContract, VERSION, resolveProductSimilarObservation } = require('./secureshopManualRagSourceContract');
const { SECURESHOP_CONVERSATION_PURPOSES: PURPOSES } = require('./secureshopConversationPurpose');

const MAX_LINEAGE_BYTES = 64 * 1024;
const MAX_CAPTURE_BYTES = 48 * 1024;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][0-9a-f]{3}-[a-f0-9]{12}$/i;
const SHA = /^[a-f0-9]{64}$/;
const fail = () => Object.assign(new Error('Manual RAG source unavailable'),
  { code: 'MANUAL_RAG_SOURCE_UNAVAILABLE' });
const plain = value => value !== null && typeof value === 'object'
  && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
const exact = (value, keys) => plain(value) && Reflect.ownKeys(value).length === keys.length
  && keys.every(key => Object.hasOwn(value, key)
    && Object.hasOwn(Object.getOwnPropertyDescriptor(value, key), 'value'));
const bytes = value => Buffer.byteLength(JSON.stringify(value), 'utf8');
const frozen = value => Object.freeze(value);

function targetProjection(target) {
  const execution = executionScope(target);
  return frozen({ targetId: target.targetId, launchId: target.launchId,
    scenarioId: target.scenarioId, generation: target.generation,
    platformOwnerId: target.platformOwnerId, platformSessionId: target.platformSessionId,
    scene: frozen({ sceneId: target.scene.sceneId, sceneGeneration: target.scene.sceneGeneration,
      grantId: target.scene.grantId, execution }) });
}

function origin(value, kind) {
  const keys = kind === 'upload'
    ? ['version', 'binding', 'personaSession', 'source', 'runId', 'traceEventIds', 'target', 'receipt', 'lineage']
    : ['version', 'binding', 'personaSession', 'source', 'runId', 'traceEventIds', 'execution', 'productId', 'target', 'lineage'];
  if (!exact(value, keys) || value.version !== 1 || !plain(value.source)
      || !exact(value.source, ['sessionId', 'requestId'])
      || !UUID.test(value.source.sessionId || '') || !UUID.test(value.source.requestId || '')
      || !UUID.test(value.runId || '') || !Array.isArray(value.traceEventIds)
      || !value.traceEventIds.every(id => UUID.test(id || '')) || new Set(value.traceEventIds).size !== value.traceEventIds.length
      || !plain(value.lineage) || typeof value.lineage.eligible !== 'boolean') throw fail();
  return value;
}

const UPLOAD_FIELDS = ['documentsJson', 'normalizedChunksJson', 'manualFieldsJson',
  'sceneReceiptJson', 'runtimeReceiptJson', 'runtimeReceiptSha256'];
function uploadPreimages(value) {
  if (typeof value.documentsJson !== 'string' || Buffer.byteLength(value.documentsJson) > 4 * 1024 * 1024
      || !Array.isArray(value.normalizedChunksJson) || value.normalizedChunksJson.length < 1
      || value.normalizedChunksJson.length > 129
      || value.normalizedChunksJson.some(item => typeof item !== 'string' || Buffer.byteLength(item) > 131072)
      || ['manualFieldsJson', 'sceneReceiptJson', 'runtimeReceiptJson', 'runtimeReceiptSha256']
        .some(key => typeof value[key] !== 'string')) throw fail();
  return value;
}
function eligibleUpload(value) {
  if (!exact(value, ['eligible', 'version', ...UPLOAD_FIELDS]) || value.eligible !== true
      || value.version !== 1 || bytes(value) > MAX_CAPTURE_BYTES) throw fail();
  return uploadPreimages(value);
}
function uploadReference(value) {
  if (!exact(value, ['eligible', 'version', 'preimageRef']) || value.eligible !== true || value.version !== 2
      || !exact(value.preimageRef, ['version', 'operationId', 'targetId', 'documentDigest', 'receiptSha256', 'runtimeReceiptSha256'])
      || value.preimageRef.version !== 1 || !UUID.test(value.preimageRef.operationId || '')
      || !UUID.test(value.preimageRef.targetId || '')
      || ['documentDigest', 'receiptSha256', 'runtimeReceiptSha256'].some(key => !SHA.test(value.preimageRef[key] || ''))
      || bytes(value) > MAX_CAPTURE_BYTES) throw fail();
  return value.preimageRef;
}
/* Inline v1 capture retains its original admission bound. Only privately
 * resolved v2 payloads can exceed that metadata bound; the pure contract still
 * validates every original digest and keeps the final semantic output bounded. */
function searchReference(value) {
  if (!exact(value, ['eligible', 'version', 'revision', 'selected', 'manualSources', 'preimageRef'])
      || value.eligible !== true || value.version !== 2 || !plain(value.revision)
      || !Array.isArray(value.selected) || !Array.isArray(value.manualSources)
      || !exact(value.preimageRef, ['version', 'revisionId', 'sourceSetDigest', 'vectorDigest'])
      || value.preimageRef.version !== 1 || !UUID.test(value.preimageRef.revisionId || '')
      || !SHA.test(value.preimageRef.sourceSetDigest || '') || !SHA.test(value.preimageRef.vectorDigest || '')
      || value.preimageRef.revisionId !== value.revision.revisionId
      || value.preimageRef.sourceSetDigest !== value.revision.sourceSetDigest
      || value.preimageRef.vectorDigest !== value.revision.vectorDigest
      || bytes(value) > MAX_CAPTURE_BYTES) throw fail();
  return value;
}

function eligibleSearch(value) {
  if (!exact(value, ['eligible', 'version', 'revision', 'sourceSetJson', 'vectorsJson', 'selected', 'manualSources'])
      || value.eligible !== true || value.version !== 1 || !plain(value.revision)
      || typeof value.sourceSetJson !== 'string' || typeof value.vectorsJson !== 'string'
      || !Array.isArray(value.selected) || !Array.isArray(value.manualSources)
      || bytes(value) > MAX_CAPTURE_BYTES) throw fail();
  return value;
}

function findSelection(original, lineage) {
  const context = resolveProductSimilarObservation(original?.result?.taskMetadata?.productAssist, original?.result)?.retrieved_context;
  if (!Array.isArray(context)) throw fail();
  const candidates = context.filter(item => item?.sourceKind === 'manual');
  if (candidates.length !== 1) throw fail();
  const selected = lineage.selected.filter(item => item?.sourceKind === 'manual'
    && item.sourceId === candidates[0].sourceId && item.chunkIndex === candidates[0].chunkIndex
    && item.text === candidates[0].text && item.score === candidates[0].score);
  if (selected.length !== 1) throw fail();
  const source = lineage.manualSources.filter(item => item?.sourceId === selected[0].sourceId
    && item.productId === original?.result?.taskMetadata?.productAssist?.productId);
  if (source.length !== 1 || !UUID.test(source[0].operationId || '')) throw fail();
  return frozen({ selected: selected[0], manual: source[0] });
}

function assertOriginal(originValue, original, target, kind) {
  if (!plain(original) || original.sessionId !== originValue.source.sessionId
      || original.requestId !== originValue.source.requestId || original.run?.run_id !== originValue.runId
      || !equal(original.traceEventIds, originValue.traceEventIds)
      || !equal(original.binding, originValue.binding)
      || !equal(original.personaSession, originValue.personaSession)) throw fail();
  if (kind === 'consumer' && (!equal(originValue.target, targetProjection(target))
      || original.binding?.role !== 'customer')) throw fail();
  if (kind === 'upload') {
    const execution = originValue.target?.scene?.execution;
    if (original.binding?.role !== 'merchant' || originValue.target?.targetId !== target.targetId
        || ['launchId', 'scenarioId', 'generation', 'platformOwnerId', 'platformSessionId']
          .some(key => originValue.target?.[key] !== target[key])
        || !equal(execution, { launchId: originValue.binding.launchId,
          scenarioId: originValue.binding.scenarioId, generation: originValue.binding.generation,
          platformOwnerId: originValue.binding.platformOwnerId,
          platformSessionId: originValue.binding.platformSessionId })) throw fail();
  }
}

function createManualRagSourceReader({ current, readConsumer, readUploader, readReceipt, readRevision,
  readRevisionPreimage, readManualPreimage, qualifyModel } = {}) {
  for (const dependency of [current, readConsumer, readUploader, readReceipt, readRevision, qualifyModel]) {
    if (typeof dependency !== 'function') throw new TypeError('Manual RAG source reader dependencies required');
  }
  for (const dependency of [readRevisionPreimage, readManualPreimage]) {
    if (dependency !== undefined && typeof dependency !== 'function') throw new TypeError('Manual RAG preimage reader must be a function');
  }
  return async function readManualRagSource(context, request = {}) {
    try {
      if (!exact(request, ['sessionId', 'requestId']) || !UUID.test(request.sessionId || '')
          || !UUID.test(request.requestId || '')) throw fail();
      const state = await current(context);
      if (!plain(state) || typeof state.check !== 'function' || !state.target?.scene
          || state.binding?.role !== 'customer' || state.persona?.role !== 'customer') throw fail();
      const checked = async work => { await state.check(); const value = await work(); await state.check(); return value; };
      const consumer = await checked(() => readConsumer({ state, request, purpose: PURPOSES.productAssist }));
      const consumerOrigin = origin(consumer?.origin, 'consumer');
      assertOriginal(consumerOrigin, consumer?.original, state.target, 'consumer');
      if (!equal(consumerOrigin.binding, state.binding) || !equal(consumerOrigin.personaSession, state.personaSession)
          || !equal(consumerOrigin.execution, state.execution)) throw fail();
      if (consumerOrigin.lineage.eligible !== true) throw fail();
      let search = consumerOrigin.lineage.version === 2 ? searchReference(consumerOrigin.lineage)
        : eligibleSearch(consumerOrigin.lineage);
      const selection = findSelection(consumer.original, search);
      const uploader = await checked(() => readUploader({ state, operationId: selection.manual.operationId,
        manualSource: selection.manual, purpose: PURPOSES.productManualIngest }));
      const uploadOrigin = origin(uploader?.origin, 'upload');
      assertOriginal(uploadOrigin, uploader?.original, state.target, 'upload');
      if (uploadOrigin.lineage.eligible !== true || uploadOrigin.receipt?.operationId !== selection.manual.operationId
          || uploadOrigin.receipt?.receiptSha256 !== selection.manual.receiptSha256
          || uploadOrigin.target?.scene?.grantId !== uploadOrigin.receipt?.sceneGrantId
          || uploadOrigin.target?.scene?.sceneId !== uploadOrigin.receipt?.sceneId
          || uploadOrigin.target?.scene?.sceneGeneration !== uploadOrigin.receipt?.sceneGeneration
          || !equal(uploadOrigin.target?.scene?.execution, uploadOrigin.receipt?.execution)) throw fail();
      let upload = uploadOrigin.lineage.version === 2 ? uploadReference(uploadOrigin.lineage)
        : eligibleUpload(uploadOrigin.lineage);
      // This is the persisted metadata budget, not the transient SQL payload.
      if (bytes({ upload: uploadOrigin.lineage, search: consumerOrigin.lineage }) > MAX_LINEAGE_BYTES) throw fail();
      const receipt = await checked(() => readReceipt({ state, operationId: selection.manual.operationId }));
      const revision = await checked(() => readRevision({ state, revisionId: selection.selected.revisionId }));
      if (!equal(receipt, uploadOrigin.receipt) || !equal(revision, search.revision)) throw fail();
      if (consumerOrigin.lineage.version === 2) {
        if (typeof readRevisionPreimage !== 'function') throw fail();
        const captured = await checked(() => readRevisionPreimage({ state, revisionId: search.preimageRef.revisionId }));
        if (!exact(captured, ['revision', 'sourceSetJson', 'vectorsJson']) || !equal(captured.revision, revision)
            || typeof captured.sourceSetJson !== 'string' || typeof captured.vectorsJson !== 'string') throw fail();
        search = { ...search, sourceSetJson: captured.sourceSetJson, vectorsJson: captured.vectorsJson };
      }
      if (uploadOrigin.lineage.version === 2) {
        if (typeof readManualPreimage !== 'function' || upload.operationId !== receipt.operationId
            || upload.targetId !== state.target.targetId || upload.targetId !== receipt.targetId
            || upload.documentDigest !== receipt.documentDigest || upload.receiptSha256 !== receipt.receiptSha256) throw fail();
        const captured = await checked(() => readManualPreimage({ state, operationId: upload.operationId }));
        if (!exact(captured, ['receipt', ...UPLOAD_FIELDS]) || !equal(captured.receipt, receipt)
            || captured.runtimeReceiptSha256 !== upload.runtimeReceiptSha256) throw fail();
        upload = uploadPreimages(captured);
      }
      const chunk = upload.normalizedChunksJson[selection.selected.chunkIndex];
      if (typeof chunk !== 'string') throw fail();
      const proof = frozen({ version: VERSION,
        birth: { launchId: state.target.launchId, scenarioId: state.target.scenarioId,
          generation: state.target.generation, platformOwnerId: state.target.platformOwnerId,
          platformSessionId: state.target.platformSessionId },
        uploader: { binding: uploadOrigin.binding, personaSession: uploadOrigin.personaSession,
          grantId: uploadOrigin.target.scene.grantId, original: uploader.original },
        consumer: { binding: consumerOrigin.binding, personaSession: consumerOrigin.personaSession,
          grantId: consumerOrigin.target.scene.grantId, execution: consumerOrigin.execution,
          original: consumer.original },
        receipt, revision, selected: selection.selected, documentsJson: upload.documentsJson,
        normalizedChunkJson: chunk,
        integrity: { manualFieldsJson: upload.manualFieldsJson, sceneReceiptJson: upload.sceneReceiptJson,
          runtimeReceiptJson: upload.runtimeReceiptJson, runtimeReceiptSha256: upload.runtimeReceiptSha256,
          sourceSetJson: search.sourceSetJson, vectorsJson: search.vectorsJson } });
      const result = validateManualRagSourceContract({ target: state.target, proof, qualifyModel });
      await state.check();
      return result;
    } catch (error) {
      // Invalid historical provenance is ordinary V26 ineligibility.  Current
      // authority, cancellation, and database failures are operational
      // failures and must retain their original code for the caller.
      if (error?.code === 'MANUAL_RAG_SOURCE_INVALID') throw fail();
      throw error;
    }
  };
}

module.exports = { createManualRagSourceReader, MAX_CAPTURE_BYTES, MAX_LINEAGE_BYTES };
