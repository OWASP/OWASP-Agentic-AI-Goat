'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createManualRagSourceReader } = require('../server/services/secureshopManualRagSourceReader');
const { fixture } = require('./secureshopManualRagSourceContract.test');

const clone = value => structuredClone(value);
function projected(target) {
  return { targetId: target.targetId, launchId: target.launchId, scenarioId: target.scenarioId,
    generation: target.generation, platformOwnerId: target.platformOwnerId,
    platformSessionId: target.platformSessionId, scene: { sceneId: target.scene.sceneId,
      sceneGeneration: target.scene.sceneGeneration, grantId: target.scene.grantId,
      execution: clone(target.scene.execution) } };
}
function uploadTarget(source, target) {
  return { targetId: target.targetId, launchId: target.launchId, scenarioId: target.scenarioId,
    generation: target.generation, platformOwnerId: target.platformOwnerId,
    platformSessionId: target.platformSessionId, scene: { sceneId: source.receipt.sceneId,
      sceneGeneration: source.receipt.sceneGeneration, grantId: source.uploader.grantId,
      execution: clone(source.receipt.execution) } };
}
function setup(mutate = () => {}, { compact = false, catalogCount = 0, extraChunks = 0 } = {}) {
  const source = fixture({ catalogCount, extraChunks });
  const proof = clone(source.proof);
  const calls = [];
  const consumerOrigin = { version: 1, binding: clone(proof.consumer.binding),
    personaSession: clone(proof.consumer.personaSession),
    source: { sessionId: proof.consumer.original.sessionId, requestId: proof.consumer.original.requestId },
    runId: proof.consumer.original.run.run_id, traceEventIds: clone(proof.consumer.original.traceEventIds),
    execution: clone(proof.consumer.execution), productId: proof.consumer.original.result.taskMetadata.productAssist.productId,
    target: projected(source.target), lineage: { eligible: true, version: 1,
      revision: clone(proof.revision), sourceSetJson: proof.integrity.sourceSetJson,
      vectorsJson: proof.integrity.vectorsJson, selected: [clone(proof.selected)],
      manualSources: [{ sourceId: proof.receipt.manualSourceId, operationId: proof.receipt.operationId,
        productId: proof.receipt.productId, merchantId: proof.receipt.merchantId,
        receiptSha256: proof.receipt.receiptSha256 }] } };
  const uploadOrigin = { version: 1, binding: clone(proof.uploader.binding),
    personaSession: clone(proof.uploader.personaSession),
    source: { sessionId: proof.uploader.original.sessionId, requestId: proof.uploader.original.requestId },
    runId: proof.uploader.original.run.run_id, traceEventIds: clone(proof.uploader.original.traceEventIds),
    target: uploadTarget(proof, source.target), receipt: clone(proof.receipt),
    lineage: { eligible: true, version: 1, documentsJson: proof.documentsJson,
      normalizedChunksJson: source.normalizedChunksJson, manualFieldsJson: proof.integrity.manualFieldsJson,
      sceneReceiptJson: proof.integrity.sceneReceiptJson, runtimeReceiptJson: proof.integrity.runtimeReceiptJson,
      runtimeReceiptSha256: proof.integrity.runtimeReceiptSha256 } };
  const consumerOriginal = clone(proof.consumer.original);
  const state = { binding: clone(proof.consumer.binding), persona: { id: proof.consumer.binding.shopUserId, role: 'customer' },
    personaSession: clone(proof.consumer.personaSession), target: source.target,
    execution: clone(proof.consumer.execution), async check() { calls.push('check'); } };
  const revisionPreimage = { revision: clone(proof.revision), sourceSetJson: proof.integrity.sourceSetJson,
    vectorsJson: proof.integrity.vectorsJson };
  const { eligible, version, ...rawUpload } = clone(uploadOrigin.lineage);
  const manualPreimage = { receipt: clone(proof.receipt), ...rawUpload };
  if (compact) {
    const { sourceSetJson, vectorsJson, ...savedSearch } = consumerOrigin.lineage;
    consumerOrigin.lineage = { ...savedSearch, version: 2, preimageRef: { version: 1,
      revisionId: proof.revision.revisionId, sourceSetDigest: proof.revision.sourceSetDigest,
      vectorDigest: proof.revision.vectorDigest } };
    uploadOrigin.lineage = { eligible: true, version: 2, preimageRef: { version: 1,
      operationId: proof.receipt.operationId, targetId: proof.receipt.targetId, documentDigest: proof.receipt.documentDigest,
      receiptSha256: proof.receipt.receiptSha256, runtimeReceiptSha256: proof.integrity.runtimeReceiptSha256 } };
  }
  const deps = {
    async current() { calls.push('current'); return state; },
    async readConsumer(input) { calls.push(['consumer', input]); return { origin: consumerOrigin, original: consumerOriginal }; },
    async readUploader(input) { calls.push(['uploader', input]); return { origin: uploadOrigin, original: clone(proof.uploader.original) }; },
    async readReceipt(input) { calls.push(['receipt', input]); return clone(proof.receipt); },
    async readRevision(input) { calls.push(['revision', input]); return clone(proof.revision); },
    ...(compact ? {
      async readRevisionPreimage(input) { calls.push(['revisionPreimage', input]); return clone(revisionPreimage); },
      async readManualPreimage(input) { calls.push(['manualPreimage', input]); return clone(manualPreimage); },
    } : {}),
    qualifyModel: source.qualifyModel,
  };
  mutate({ source, proof, state, consumerOrigin, uploadOrigin, consumerOriginal, revisionPreimage, manualPreimage, deps });
  const reader = createManualRagSourceReader(deps);
  return { reader, source, proof, calls, state, consumerOrigin, uploadOrigin };
}

test('reader uses only completed protected origins and captured canonical preimages', async () => {
  const { reader, proof, calls } = setup();
  const result = await reader({}, { sessionId: proof.consumer.original.sessionId,
    requestId: proof.consumer.original.requestId });
  assert.equal(result.sourceDigest.length, 64);
  assert.equal(result.lineage.receipt.operationId, proof.receipt.operationId);
  assert.deepEqual(calls.filter(item => Array.isArray(item)).map(item => item[0]),
    ['consumer', 'uploader', 'receipt', 'revision']);
  assert.equal(calls.filter(item => item === 'check').length, 9);
  assert.equal(calls.find(item => Array.isArray(item) && item[0] === 'consumer')[1].purpose,
    'secureshop_product_assist');
  assert.equal(calls.find(item => Array.isArray(item) && item[0] === 'uploader')[1].purpose,
    'secureshop_product_manual_ingest');
});

test('reader rejects absent, ineligible, oversized, or current-head-substituted producer lineage', async () => {
  const cases = [
    value => { value.consumerOrigin.lineage = { eligible: false, reason: 'historical_missing' }; },
    value => { value.uploadOrigin.lineage = { eligible: false, reason: 'metadata_limit' }; },
    value => { value.uploadOrigin.lineage.documentsJson += 'x'.repeat(64 * 1024); },
    value => { value.consumerOrigin.lineage.revision.revisionId = '10000000-0000-4000-8000-0000000000aa'; },
  ];
  for (const mutate of cases) {
    const value = setup(mutate);
    await assert.rejects(value.reader({}, { sessionId: value.proof.consumer.original.sessionId,
      requestId: value.proof.consumer.original.requestId }), { code: 'MANUAL_RAG_SOURCE_UNAVAILABLE' });
  }
});

test('reader rejects changed consumer authority, uploader receipt, and selection before a source is returned', async () => {
  const cases = [
    value => { value.state.execution.mode = 'fixed'; },
    value => { value.uploadOrigin.receipt.receiptSha256 = 'a'.repeat(64); },
    value => { value.consumerOrigin.lineage.selected[0].text = 'substituted'; },
  ];
  for (const mutate of cases) {
    const value = setup(mutate);
    await assert.rejects(value.reader({}, { sessionId: value.proof.consumer.original.sessionId,
      requestId: value.proof.consumer.original.requestId }), { code: 'MANUAL_RAG_SOURCE_UNAVAILABLE' });
  }
});

test('reader preserves authority and storage failures instead of classifying them as missing provenance', async () => {
  const authority = setup();
  authority.reader = createManualRagSourceReader({
    async current() { throw Object.assign(new Error('revoked'), { code: 'PERSONA_SESSION_REVOKED' }); },
    async readConsumer() { throw Error('unreachable'); }, async readUploader() { throw Error('unreachable'); },
    async readReceipt() { throw Error('unreachable'); }, async readRevision() { throw Error('unreachable'); },
    qualifyModel: authority.source.qualifyModel,
  });
  await assert.rejects(authority.reader({}, { sessionId: authority.proof.consumer.original.sessionId,
    requestId: authority.proof.consumer.original.requestId }), { code: 'PERSONA_SESSION_REVOKED' });
  const storage = setup();
  storage.reader = createManualRagSourceReader({
    async current() { return storage.state; }, async readConsumer() { throw Object.assign(new Error('database'), { code: 'DB_UNAVAILABLE' }); },
    async readUploader() { throw Error('unreachable'); }, async readReceipt() { throw Error('unreachable'); },
    async readRevision() { throw Error('unreachable'); }, qualifyModel: storage.source.qualifyModel,
  });
  await assert.rejects(storage.reader({}, { sessionId: storage.proof.consumer.original.sessionId,
    requestId: storage.proof.consumer.original.requestId }), { code: 'DB_UNAVAILABLE' });
});

test('protected reader accepts only the exact immutable v2 consumer hop, with v1 uploader unchanged', async () => {
  const {canonicalDigest}=require('../server/services/mcp/protocolContext');
  const asV2 = ({consumerOriginal}) => {
    const old=consumerOriginal.result.taskMetadata.productAssist;
    consumerOriginal.result.taskMetadata.productAssist={version:2,operation:'similar',productId:old.productId,
      provider:old.provider,model:old.model,observationHop:{step:consumerOriginal.result.hops[0].step,
        observationSha256:canonicalDigest(consumerOriginal.result.hops[0].result)}};
  };
  const good=setup(asV2);
  const answer=await good.reader({}, {sessionId:good.proof.consumer.original.sessionId,requestId:good.proof.consumer.original.requestId});
  assert.equal(answer.lineage.selected.text,good.proof.selected.text);
  for(const mutate of [o=>o.result.taskMetadata.productAssist.observationHop.step=4,
    o=>o.result.taskMetadata.productAssist.observationHop.observationSha256='a'.repeat(64),
    o=>o.result.hops[0].result.content[0].text+=' changed']){
    const bad=setup(value=>{asV2(value);mutate(value.consumerOriginal);});
    await assert.rejects(bad.reader({}, {sessionId:bad.proof.consumer.original.sessionId,
      requestId:bad.proof.consumer.original.requestId}),{code:'MANUAL_RAG_SOURCE_UNAVAILABLE'});
  }
});

test('compact references resolve exact immutable 125-product revision and large original upload outside turn metadata', async () => {
  const value = setup(() => {}, { compact: true, catalogCount: 125, extraChunks: 3 });
  assert.ok(Buffer.byteLength(value.proof.integrity.vectorsJson) > 200000);
  assert.ok(Buffer.byteLength(value.proof.documentsJson) > 48000);
  assert.ok(Buffer.byteLength(JSON.stringify({upload:value.uploadOrigin.lineage,search:value.consumerOrigin.lineage})) < 4096);
  const answer = await value.reader({}, {sessionId:value.proof.consumer.original.sessionId,
    requestId:value.proof.consumer.original.requestId});
  assert.equal(answer.lineage.revision.documentCount,129);
  assert.equal(answer.lineage.receipt.documentCount,4);
  assert.ok(Buffer.byteLength(JSON.stringify(answer)) < 65536);
  assert.equal(Object.hasOwn(answer.lineage,'vectorsJson'),false);
  assert.equal(Object.hasOwn(answer.lineage,'documentsJson'),false);
  assert.equal(answer.semantic.observation.mcp.content[0].text,
    value.proof.consumer.original.result.hops[0].result.content[0].text);
  assert.deepEqual(value.calls.filter(Array.isArray).map(c=>c[0]),
    ['consumer','uploader','receipt','revision','revisionPreimage','manualPreimage']);
  const reads=value.calls.filter(Array.isArray);
  assert.equal(reads.at(-2)[1].revisionId,value.proof.revision.revisionId);
  assert.equal(reads.at(-1)[1].operationId,value.proof.receipt.operationId);
  assert.equal(reads.at(-1)[1].state,value.state);
  assert.equal(value.calls.filter(c=>c==='check').length,13);
});

test('compact source references cannot substitute revision/head, upload/receipt, raw bytes, or absent preimages', async () => {
  const mutations = [
    v=>v.consumerOrigin.lineage.preimageRef.revisionId='10000000-0000-4000-8000-0000000000aa',
    v=>v.consumerOrigin.lineage.preimageRef.sourceSetDigest='a'.repeat(64),
    v=>v.consumerOrigin.lineage.preimageRef.vectorDigest='a'.repeat(64),
    v=>v.uploadOrigin.lineage.preimageRef.operationId='10000000-0000-4000-8000-0000000000aa',
    v=>v.uploadOrigin.lineage.preimageRef.targetId='10000000-0000-4000-8000-0000000000aa',
    v=>v.uploadOrigin.lineage.preimageRef.documentDigest='a'.repeat(64),
    v=>v.uploadOrigin.lineage.preimageRef.receiptSha256='a'.repeat(64),
    v=>v.uploadOrigin.lineage.preimageRef.runtimeReceiptSha256='a'.repeat(64),
    v=>v.revisionPreimage.revision.platformOwnerId++,
    v=>v.revisionPreimage.sourceSetJson+=' ',
    v=>v.revisionPreimage.vectorsJson+=' ',
    v=>v.manualPreimage.receipt.generation++,
    v=>v.manualPreimage.documentsJson+=' ',
    v=>v.manualPreimage.normalizedChunksJson[0]+=' ',
    v=>v.manualPreimage.runtimeReceiptJson+=' ',
    v=>delete v.deps.readRevisionPreimage,
    v=>delete v.deps.readManualPreimage,
    v=>v.deps.readRevisionPreimage=async()=>null,
    v=>v.deps.readManualPreimage=async()=>null,
  ];
  for (const mutate of mutations) {
    const value=setup(mutate,{compact:true});
    await assert.rejects(value.reader({}, {sessionId:value.proof.consumer.original.sessionId,
      requestId:value.proof.consumer.original.requestId}),{code:'MANUAL_RAG_SOURCE_UNAVAILABLE'});
  }
});

test('compact preimage reads preserve reset, aborted, and storage failures at current authority boundaries', async () => {
  for (const code of ['STALE_LAUNCH','ABORT_ERR','DB_UNAVAILABLE']) {
    const value=setup(v=>{
      v.deps.readRevisionPreimage=async()=>{throw Object.assign(new Error('controlled failure'),{code});};
    },{compact:true});
    await assert.rejects(value.reader({}, {sessionId:value.proof.consumer.original.sessionId,
      requestId:value.proof.consumer.original.requestId}),{code});
    assert.equal(value.calls.some(c=>Array.isArray(c)&&c[0]==='manualPreimage'),false);
  }
  const value=setup(v=>{
    const original=v.deps.readManualPreimage;
    v.deps.readManualPreimage=async input=>{
      const result=await original(input);
      v.state.check=async()=>{throw Object.assign(new Error('retired during read'),{code:'STALE_LAUNCH'});};
      return result;
    };
  },{compact:true});
  await assert.rejects(value.reader({}, {sessionId:value.proof.consumer.original.sessionId,
    requestId:value.proof.consumer.original.requestId}),{code:'STALE_LAUNCH'});
});
