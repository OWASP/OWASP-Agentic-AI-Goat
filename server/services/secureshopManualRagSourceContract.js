'use strict';

const { createHash } = require('node:crypto');
const { isDeepStrictEqual: equal } = require('node:util');
const { createConversationBinding, createLaunchScope } = require('./secureshopConversationBinding');
const { executionScope } = require('./secureshopSceneBinding');
const { createTurnRequest } = require('./secureshopTurnRequest');
const { isQualifiedSecureShopModelTrace } = require('./secureshopRealModelTrace');
const { canonicalDigest } = require('./mcp/protocolContext');

const VERSION = 'secureshop-manual-rag-source-v1';
const PROTECTED_VERSION = 'secureshop-protected-manual-source-v1';
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const SHA = /^[a-f0-9]{64}$/;
const SCOPE = ['launchId','scenarioId','generation','platformOwnerId','platformSessionId'];
const sha = value => createHash('sha256').update(value, 'utf8').digest('hex');
const failure = () => Object.assign(Error('Manual RAG source contract unavailable'), { code: 'MANUAL_RAG_SOURCE_INVALID' });
const need = value => { if (!value) throw failure(); };
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && equal(Reflect.ownKeys(value).sort(), [...keys].sort())
  && keys.every(k => Object.hasOwn(Object.getOwnPropertyDescriptor(value, k), 'value'));
const positive = n => Number.isSafeInteger(n) && n > 0;
const decimal = (value, zero = false) => typeof value === 'string' && (zero ? /^(0|[1-9]\d*)$/ : /^[1-9]\d*$/).test(value)
  && BigInt(value) <= 9223372036854775807n;
const text = (value, max) => typeof value === 'string' && !!value && value.isWellFormed()
  && !value.includes('\0') && Buffer.byteLength(value) <= max;
const parse = value => { need(typeof value === 'string'); try { return JSON.parse(value); } catch { throw failure(); } };
function freeze(value) {
  if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); }
  return value;
}
function scope(value) { need(exact(value, SCOPE) && equal(value, createLaunchScope(value))); }
function credential(value) {
  need(exact(value, ['sessionId','authorityVersion']) && UUID.test(value.sessionId || '') && decimal(value.authorityVersion));
}
function original(side, tool, productId, qualifyModel) {
  const o = side.original;
  need(exact(o, ['binding','personaSession','sessionId','requestId','message','requestVersion','requestHash',
    'status','traceEventIds','traces','result','run','effect'])
    && equal(o.binding, side.binding) && equal(o.personaSession, side.personaSession)
    && UUID.test(o.sessionId || '') && UUID.test(o.requestId || '') && o.requestVersion === 1
    && o.status === 'completed' && text(o.message, 65536)
    && o.requestHash === createTurnRequest({ ...o, binding: side.binding, version: o.requestVersion }).hash);
  const rows = o.traces, ids = o.traceEventIds, result = o.result;
  need(Array.isArray(rows) && rows.length >= 4 && rows.length <= 4096 && Array.isArray(ids)
    && equal(rows.map(r => r.event_id), ids) && new Set(ids).size === ids.length
    && ids.every(id => UUID.test(id || '')) && rows.every((r, i) => r.session_id === o.sessionId
      && decimal(String(r.id)) && (!i || BigInt(r.id) > BigInt(rows[i-1].id)))
    && result?.stopReason === 'end_turn' && text(result.text, 16384)
    && Number.isSafeInteger(result.steps) && result.steps >= 1 && result.steps <= 4 && Array.isArray(result.hops)
    && Buffer.byteLength(JSON.stringify(result)) <= 262144);
  const hops = result.hops.filter(h => h.tool === tool);
  need(hops.length === 1 && hops[0].error === null && hops[0].policyViolation === null
    && exact(hops[0].params, ['product_id']) && hops[0].params.product_id === productId);
  const hop = hops[0], [ns, name] = tool.split('.');
  const decisions = rows.filter(r => r.kind === 'model_decision' && r.actor === 'supervisor'
    && r.step === hop.step && parse(r.params_json || 'null')?.decision === 'tool_use');
  const calls = rows.filter(r => r.kind === 'local_tool_call' && r.actor === 'supervisor→task'
    && r.step === hop.step && r.agent_ns === ns && r.tool_name === name);
  const results = rows.filter(r => r.kind === 'local_tool_result' && r.actor === 'task→supervisor'
    && r.step === hop.step && r.agent_ns === ns && r.tool_name === name);
  need(decisions.length === 1 && calls.length === 1 && results.length === 1
    && isQualifiedSecureShopModelTrace(decisions[0], qualifyModel));
  const selected = parse(decisions[0].params_json).toolCalls;
  need(Array.isArray(selected) && selected.length === 1 && exact(selected[0], ['id','name','args'])
    && text(selected[0].id, 128) && selected[0].name === tool && equal(selected[0].args, hop.params)
    && calls[0].policy_violation === null && results[0].policy_violation === null
    && equal(parse(calls[0].params_json), hop.params) && equal(parse(results[0].result_json), hop.result)
    && BigInt(decisions[0].id) < BigInt(calls[0].id) && BigInt(calls[0].id) < BigInt(results[0].id));
  const terminal = rows.at(-1), terminalMeta = parse(terminal.result_json || 'null');
  const finals = rows.filter(r => r.kind === 'model_decision' && parse(r.result_json || 'null')?.decision === 'final');
  need(finals.length === 1 && isQualifiedSecureShopModelTrace(finals[0], qualifyModel)
    && parse(finals[0].result_json).text === result.text && BigInt(finals[0].id) > BigInt(results[0].id)
    && BigInt(finals[0].id) < BigInt(terminal.id) && rows.filter(r => r.kind === 'terminal').length === 1
    && terminal.kind === 'terminal' && terminal.actor === 'supervisor'
    && isQualifiedSecureShopModelTrace(terminal, qualifyModel) && terminalMeta.stopReason === 'end_turn'
    && terminalMeta.steps === result.steps && terminalMeta.hops === result.hops.length
    && [finals[0], terminal].every(r => r.provider === decisions[0].provider
      && parse(r.result_json).model === parse(decisions[0].result_json).model));
  const run = o.run, effect = o.effect, ownerKey = JSON.stringify(['SecureShopBoundConversation', o.sessionId]);
  need(exact(run, ['run_id','owner_key','generation','status']) && UUID.test(run.run_id || '')
    && run.owner_key === ownerKey && decimal(run.generation, true) && run.status === 'completed'
    && exact(effect, ['run_id','owner_key','generation','effect_key','status'])
    && effect.run_id === run.run_id && effect.owner_key === ownerKey && effect.generation === run.generation
    && effect.status === 'completed'
    && effect.effect_key === `${o.requestId}:${JSON.stringify([hop.step,selected[0].id,tool])}`);
  const mcp = hop.result;
  need(exact(mcp, ['content']) && Array.isArray(mcp.content) && mcp.content.length === 1
    && exact(mcp.content[0], ['type','text']) && mcp.content[0].type === 'text');
  return { value: parse(mcp.content[0].text), mcp, reference: { sessionId: o.sessionId, requestId: o.requestId,
    requestHash: o.requestHash, runId: run.run_id, step: hop.step, callId: selected[0].id,
    traceEventIds: [...ids], chainDigest:canonicalDigest({traces:rows,result,run,effect}), observationSha256: sha(JSON.stringify(mcp)), responseSha256: sha(result.text) } };
}

// v2 removes duplicate metadata text only; the complete original MCP text
// remains in its immutable hop. Canonical hashing ignores JSONB object key order
// while retaining exact content strings, array order and selected tool arguments.
function resolveProductSimilarObservation(metadata, result) {
  need(metadata?.operation === 'similar' && positive(metadata.productId));
  if (metadata.version === 1) { need(metadata.observation && Object.getPrototypeOf(metadata.observation) === Object.prototype); return metadata.observation; }
  need(exact(metadata, ['version','operation','productId','provider','model','observationHop']) && metadata.version === 2
    && exact(metadata.observationHop, ['step','observationSha256'])
    && Number.isSafeInteger(metadata.observationHop.step) && metadata.observationHop.step >= 1 && metadata.observationHop.step <= 4
    && SHA.test(metadata.observationHop.observationSha256 || '') && Array.isArray(result?.hops));
  const matches = result.hops.filter(h => h.tool === 'product-search.similar' && h.step === metadata.observationHop.step);
  need(matches.length === 1 && matches[0].error === null && matches[0].policyViolation === null
    && exact(matches[0].params, ['product_id']) && matches[0].params.product_id === metadata.productId
    && result.hops.filter(h => h.tool === 'product-search.similar' && h.error === null && h.policyViolation === null).length === 1);
  const observation = matches[0].result;
  need(exact(observation, ['content']) && Array.isArray(observation.content) && observation.content.length === 1
    && exact(observation.content[0], ['type','text']) && observation.content[0].type === 'text'
    && canonicalDigest(observation) === metadata.observationHop.observationSha256);
  const value = parse(observation.content[0].text);
  need(value && Object.getPrototypeOf(value) === Object.prototype && value.seed?.id === metadata.productId);
  return value;
}

// Pure coherence validation, never authority admission, adoption, a Judge verdict
// or credit. The protected reader must independently fetch these exact original
// rows and perform current scene/session/mode checks before and after every read.
// JSON strings below are PostgreSQL jsonb::text projections, not JS re-encodings.
function validateSource({ target, proof, qualifyModel } = {}, protectedSource = false) {
  try {
    need(target?.scene && typeof qualifyModel === 'function');
    const current = executionScope(target); // Reject spread/JSON forged capabilities.
    need(exact(proof, ['version','birth','uploader','consumer','receipt','revision','selected',
      'documentsJson','normalizedChunkJson','integrity', ...(protectedSource ? ['query'] : [])])
      && proof.version === (protectedSource ? PROTECTED_VERSION : VERSION));
    const { birth, uploader, consumer, receipt: r, revision, selected: selectedRow } = proof;
    scope(birth); need(SCOPE.every(k => birth[k] === target[k]));
    for (const [side, role] of [[uploader, 'merchant'], [consumer, 'customer']]) {
      need(exact(side, ['binding','personaSession','grantId','original', ...(role === 'customer' ? ['execution'] : [])])
        && side.binding?.role === role && equal(side.binding, createConversationBinding(side.binding,
          { id: side.binding.shopUserId, role })) && UUID.test(side.grantId || '')
        && side.binding.platformOwnerId === birth.platformOwnerId);
      credential(side.personaSession);
    }
    need(equal(createLaunchScope(consumer.binding), current) && consumer.grantId === target.scene.grantId
      && uploader.personaSession.sessionId !== consumer.personaSession.sessionId);
    const mode = consumer.execution;
    need(exact(mode, ['version','featureId','policyVersion','mode','generation','modeStamp','scope'])
      && mode.version === 1 && mode.featureId === 'product_assist'
      && mode.policyVersion === 'bounded-product-data-and-catalog-neighbors-v1' && mode.mode === 'vuln'
      && Number.isSafeInteger(mode.generation) && mode.generation >= 0 && SHA.test(mode.modeStamp || '')
      && equal(mode.scope, current));
    const receiptKeys = ['runtimeFingerprint','operationId','manualSourceId',...SCOPE,'targetId','execution',
      'sceneId','sceneGeneration','sceneGrantId','productId','merchantId','fileReceipt','filename','mime','isPublic',
      'extractor','extractionSha256','embeddingModel','embeddingDimension','documentDigest','documentCount',
      'receiptSha256','completedAt','replayed','chunkIds'];
    need(exact(r, receiptKeys) && SCOPE.every(k => r[k] === birth[k]) && r.targetId === target.targetId
      && r.sceneId === target.scene.sceneId && r.sceneGeneration === target.scene.sceneGeneration
      && r.sceneGrantId === uploader.grantId && equal(r.execution, createLaunchScope(uploader.binding))
      && UUID.test(r.operationId || '') && positive(r.manualSourceId) && positive(r.productId)
      && r.productId <= 2147483647 && r.merchantId === uploader.binding.shopUserId && r.isPublic === !protectedSource
      && ['runtimeFingerprint','extractionSha256','documentDigest','receiptSha256'].every(k => SHA.test(r[k] || ''))
      && text(r.filename, 4096) && text(r.mime, 1024) && text(r.extractor, 128) && text(r.embeddingModel, 256)
      && positive(r.embeddingDimension) && r.embeddingDimension <= 4096 && positive(r.documentCount)
      && r.documentCount <= 129 && typeof r.replayed === 'boolean'
      && typeof r.completedAt === 'string' && new Date(r.completedAt).toISOString() === r.completedAt
      && equal(r.chunkIds, Array.from({length:r.documentCount}, (_, i) => `manual:${r.manualSourceId}:${i}`)));
    const f = r.fileReceipt;
    need(exact(f, ['targetId',...SCOPE,'virtualPath','bytes','sha256'])
      && SCOPE.every(k => f[k] === r.execution[k]) && UUID.test(f.targetId || '') && f.targetId !== r.targetId
      && f.virtualPath === `/uploads/product_manuals/${r.productId}/${r.operationId}-manual`
      && positive(f.bytes) && f.bytes <= 20 * 1024 * 1024 && SHA.test(f.sha256 || ''));
    need(exact(revision, ['revisionId','targetId',...SCOPE,'runtimeFingerprint','sourceSetDigest','vectorDigest','documentCount'])
      && UUID.test(revision.revisionId || '') && revision.targetId === r.targetId
      && SCOPE.every(k => revision[k] === birth[k]) && positive(revision.documentCount)
      && SHA.test(revision.vectorDigest || '') && revision.runtimeFingerprint === r.runtimeFingerprint
      && SHA.test(revision.sourceSetDigest || '')
      && exact(selectedRow, ['sourceKind','sourceId','chunkIndex','text','score','textSha256','sourceSha256','revisionId'])
      && selectedRow.sourceKind === 'manual' && selectedRow.sourceId === r.manualSourceId
      && Number.isSafeInteger(selectedRow.chunkIndex) && selectedRow.chunkIndex >= 0
      && selectedRow.chunkIndex < r.documentCount && selectedRow.revisionId === revision.revisionId
      && text(selectedRow.text, 32768) && selectedRow.textSha256 === sha(selectedRow.text)
      && SHA.test(selectedRow.sourceSha256 || '') && Number.isFinite(selectedRow.score)
      && selectedRow.score >= -1 && selectedRow.score <= 1);
    need(text(proof.documentsJson, 4 * 1024 * 1024) && text(proof.normalizedChunkJson, 131072));
    const documents = parse(proof.documentsJson), normalized = parse(proof.normalizedChunkJson);
    need(Array.isArray(documents) && documents.length === r.documentCount && documents.every(d =>
      exact(d, ['text','embedding']) && text(d.text, 32768) && Array.isArray(d.embedding)
      && d.embedding.length === r.embeddingDimension && d.embedding.every(Number.isFinite)
      && d.embedding.some(n => n !== 0)) && sha(proof.documentsJson) === r.documentDigest
      && sha(documents.map(d => d.text).join('')) === r.extractionSha256
      && Buffer.byteLength(documents.map(d => d.text).join('')) <= 200000
      && equal(normalized, { sourceKind:'manual', sourceId:r.manualSourceId, chunkIndex:selectedRow.chunkIndex,
        text:selectedRow.text, embedding:documents[selectedRow.chunkIndex].embedding })
      && documents[selectedRow.chunkIndex].text === selectedRow.text
      && sha(proof.normalizedChunkJson) === selectedRow.sourceSha256);
    const i = proof.integrity;
    need(exact(i, ['manualFieldsJson','sceneReceiptJson','runtimeReceiptJson','runtimeReceiptSha256','sourceSetJson','vectorsJson'])
      && ['manualFieldsJson','sceneReceiptJson','runtimeReceiptJson','sourceSetJson','vectorsJson'].every(k => text(i[k], 4 * 1024 * 1024))
      && SHA.test(i.runtimeReceiptSha256 || ''));
    const manualFields = {version:1,kind:'product_manual_ingest',operationId:r.operationId,manualSourceId:r.manualSourceId,
      targetId:r.targetId,...birth,productId:r.productId,merchantId:r.merchantId,fileTargetId:f.targetId,
      fileLaunchId:f.launchId,fileScenarioId:f.scenarioId,fileGeneration:f.generation,
      filePlatformOwnerId:f.platformOwnerId,filePlatformSessionId:f.platformSessionId,virtualPath:f.virtualPath,
      bytes:f.bytes,fileSha256:f.sha256,filename:r.filename,mime:r.mime,isPublic:r.isPublic,extractor:r.extractor,
      extractionSha256:r.extractionSha256,embeddingModel:r.embeddingModel,embeddingDimension:r.embeddingDimension,
      documentDigest:r.documentDigest,documentCount:r.documentCount};
    need(equal(parse(i.manualFieldsJson), manualFields));
    need(equal(parse(i.sceneReceiptJson), {kind:'product_manual_ingest',version:2,manualFieldsSha256:sha(i.manualFieldsJson),
      sceneId:r.sceneId,sceneGeneration:r.sceneGeneration,sceneGrantId:r.sceneGrantId,
      executionLaunchId:r.execution.launchId,executionScenarioId:r.execution.scenarioId,
      executionGeneration:r.execution.generation,executionPlatformOwnerId:r.execution.platformOwnerId,
      executionPlatformSessionId:r.execution.platformSessionId}) && sha(i.sceneReceiptJson) === r.receiptSha256
      && equal(parse(i.runtimeReceiptJson), {version:1,kind:'manual_embedding_runtime',operationId:r.operationId,
        runtimeFingerprint:r.runtimeFingerprint,originalReceiptSha256:r.receiptSha256})
      && sha(i.runtimeReceiptJson) === i.runtimeReceiptSha256);
    const sources = parse(i.sourceSetJson), vectors = parse(i.vectorsJson);
    const kinds = ['product','listing','review','manual','policy'];
    const key = row => JSON.stringify([row.sourceKind,row.sourceId,row.chunkIndex]);
    need(Array.isArray(sources) && Array.isArray(vectors) && sources.length === revision.documentCount
      && vectors.length === sources.length && sources.every(d => exact(d, ['sourceKind','sourceId','chunkIndex','text','sourceSha256'])
        && kinds.includes(d.sourceKind) && decimal(d.sourceId) && Number.isSafeInteger(Number(d.sourceId))
        && Number.isSafeInteger(d.chunkIndex) && d.chunkIndex >= 0 && text(d.text, 65536) && SHA.test(d.sourceSha256 || ''))
      && new Set(sources.map(key)).size === sources.length
      && vectors.every(d => exact(d, ['sourceKind','sourceId','chunkIndex','sourceSha256','embedding'])
        && Array.isArray(d.embedding) && d.embedding.length === 384 && d.embedding.every(Number.isFinite)
        && d.embedding.some(n => n !== 0) && sources.some(s => key(s) === key(d) && s.sourceSha256 === d.sourceSha256))
      && new Set(vectors.map(key)).size === vectors.length
      && sha(i.sourceSetJson) === revision.sourceSetDigest && sha(i.vectorsJson) === revision.vectorDigest
      && sources.some(d => d.sourceKind === 'manual' && d.sourceId === String(r.manualSourceId)
        && d.chunkIndex === selectedRow.chunkIndex && d.text === selectedRow.text && d.sourceSha256 === selectedRow.sourceSha256));
    const upload = original(uploader, 'uploads.upload_product_manual', r.productId, qualifyModel);
    const read = original(consumer, 'product-search.similar', r.productId, qualifyModel);
    need(uploader.original.message === `Store and index this manual for product ${r.productId}. File metadata: ${JSON.stringify({filename:r.filename,mime:r.mime,bytes:f.bytes,sha256:f.sha256})}`
      && consumer.original.message === `Find products similar to product ${r.productId}.`
      && upload.value.ok === true && upload.value.kind === 'product_manual' && upload.value.scope_id === r.productId
      && upload.value.operationId === r.operationId && upload.value.size_bytes === f.bytes
      && upload.value.relative_path === f.virtualPath && upload.value.filename === r.filename && upload.value.mime === r.mime
      && upload.value.chunk_count === r.documentCount && equal(upload.value.chunk_ids, r.chunkIds)
      && upload.value.extractor === r.extractor && upload.value.indexed_corpus === 'manuals'
      && upload.value.extractor_error === null && upload.value.is_traversal === false
      && upload.value.extracted_bytes === Buffer.byteLength(documents.map(d => d.text).join(''))
      && read.value.seed?.id === r.productId && Array.isArray(read.value.retrieved_context)
      && ['manuals','mixed'].includes(read.value.mode));
    need(equal(uploader.original.result.taskMetadata?.productManualIngest?.observation, upload.value)
      && uploader.original.result.taskMetadata.productManualIngest.operationId === r.operationId
      && equal(resolveProductSimilarObservation(consumer.original.result.taskMetadata?.productAssist, consumer.original.result), read.value)
      && consumer.original.result.taskMetadata.productAssist.operation === 'similar'
      && consumer.original.result.taskMetadata.productAssist.productId === r.productId
      && equal(consumer.original.result.modeCapability, {version:1,featureId:mode.featureId,policyVersion:mode.policyVersion,
        effectiveMode:mode.mode,scope:{kind:'launch_feature',id:mode.featureId}})
      && read.value.count === read.value.results?.length && read.value.retrieved_context.length <= 5
      && read.value.mode === (read.value.retrieved_context.some(c => c.sourceKind !== 'manual') ? 'mixed' : 'manuals'));
    const context = read.value.retrieved_context.filter(c => c.sourceKind === 'manual'
      && c.sourceId === selectedRow.sourceId && c.chunkIndex === selectedRow.chunkIndex);
    need(context.length === 1 && equal(context[0], {sourceKind:'manual',sourceId:selectedRow.sourceId,
      chunkIndex:selectedRow.chunkIndex,text:selectedRow.text,score:selectedRow.score}));
    if (protectedSource) {
      const q = proof.query;
      need(exact(q, ['version','kind','productId','name','description','text','sha256','runtimeFingerprint'])
        && q.version === 1 && q.kind === 'product_name_description' && q.productId === r.productId
        && text(q.name,32768) && typeof q.description === 'string'
        && text(q.text,32768) && q.text === `${q.name}\n${q.description}` && sha(q.text) === q.sha256
        && q.runtimeFingerprint === revision.runtimeFingerprint
        && read.value.seed.name === q.name
        && equal(consumer.original.result.taskMetadata?.protectedManualConsumerOrigin?.query, q));
    }
    const lineage = { version:protectedSource ? PROTECTED_VERSION : VERSION, birth, scene:{sceneId:r.sceneId,sceneGeneration:r.sceneGeneration,targetId:r.targetId},
      uploader:{binding:uploader.binding,personaSession:uploader.personaSession,grantId:uploader.grantId,original:upload.reference},
      consumer:{binding:consumer.binding,personaSession:consumer.personaSession,grantId:consumer.grantId,
        execution:mode,original:read.reference}, receipt:r, revision, selected:selectedRow,
      ...(protectedSource ? {query:proof.query} : {}) };
    need(Buffer.byteLength(JSON.stringify(lineage)) <= 65536);
    // Derived solely from the same already-verified original turn/hop; neither
    // a latest query nor a supplied response can enter this semantic bundle.
    const semantic = { version: 1, task: { kind: 'server_original_request', text: consumer.original.message },
      response: { text: consumer.original.result.text, sha256: read.reference.responseSha256 },
      observation: { mcp: read.mcp, sha256: read.reference.observationSha256 } };
    const output = { sourceDigest:canonicalDigest(lineage), lineage:structuredClone(lineage), semantic:structuredClone(semantic) };
    need(Buffer.byteLength(JSON.stringify(output)) <= 65536);
    return freeze(output);
  } catch { throw failure(); }
}
// Closed entrypoints: callers cannot relax V26's public-source requirement.
const validateManualRagSourceContract = input => validateSource(input, false);
const validateProtectedManualSourceContract = input => validateSource(input, true);
module.exports = { VERSION, PROTECTED_VERSION, validateManualRagSourceContract,
  validateProtectedManualSourceContract, resolveProductSimilarObservation };
