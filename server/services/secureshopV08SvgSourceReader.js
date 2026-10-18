'use strict';

const { createHash } = require('node:crypto');
const { isDeepStrictEqual: equal } = require('node:util');
const { posix: path } = require('node:path');
const { createV06UploadSourceReader } = require('./secureshopV06UploadSourceReader');
const { readQualifiedUploadSource } = require('./secureshopV06UploadEvidence');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const MARKER = /dvaia-v08-[a-f0-9]{32}/g;
const hash = value => createHash('sha256').update(value).digest('hex');
const fail = () => Object.assign(Error('SVG upload source unavailable'), {
  code: 'SVG_UPLOAD_SOURCE_UNAVAILABLE', executionBoundary: true,
});

function createV08SvgSourceReader({ identityPool, conversationRepository, journal, assets,
  assertCurrent, read, capability, assetOrigin, qualifyModel } = {}) {
  for (const fn of [identityPool?.query, conversationRepository?.getTraceEvents,
    journal?.readUploadRequest, assets?.lookup, assertCurrent, read, capability?.mint, qualifyModel]) {
    if (typeof fn !== 'function') throw new TypeError('SVG upload source dependencies required');
  }
  let origin;
  try { origin = new URL(assetOrigin); } catch { throw new TypeError('Exact upload asset origin required'); }
  if (origin.origin !== assetOrigin || origin.pathname !== '/' || origin.search || origin.hash) {
    throw new TypeError('Exact upload asset origin required');
  }
  const retainedReader = createV06UploadSourceReader({ assets, assertCurrent, read });
  const verified = new WeakMap();
  async function current(check, signal) { signal?.throwIfAborted(); await check(); signal?.throwIfAborted(); }
  return Object.freeze({
    async read(input) {
      const { binding, personaSession, target, mode, sessionId, requestId, check, signal } = input;
      if (!UUID.test(sessionId || '') || !UUID.test(requestId || '') || typeof check !== 'function'
          || mode?.mode !== 'vuln' || mode?.featureId !== 'uploads') return null;
      await current(check, signal);
      const row = await journal.readUploadRequest({ sessionId, requestId, binding,
        purpose: 'secureshop_avatar_upload' });
      await current(check, signal);
      const meta = row?.result_json?.taskMetadata?.boundUpload;
      if (row?.status !== 'completed' || !UUID.test(meta?.operationId || '')
          || !UUID.test(meta?.effectId || '') || meta.uploadRequestId !== requestId
          || !Array.isArray(meta.traceEventIds) || meta.traceEventIds.length < 4 || meta.traceEventIds.length > 128) return null;
      const retained = await retainedReader.read({ scope: binding, persona: { id: binding.shopUserId, role: 'customer' },
        personaSession, operationId: meta.operationId, effectId: meta.effectId, target, mode, signal });
      await current(check, signal);
      if (!retained) return null;
      const graphReceipt = meta.graphEffect;
      const rows = (await identityPool.query(`SELECT e.run_id,e.owner_key,e.generation::text AS generation,
        e.effect_key,e.status,r.status AS run_status,o.generation::text AS live_generation
        FROM graph_runtime.effects e
        JOIN graph_runtime.runs r ON r.run_id=e.run_id AND r.owner_key=e.owner_key AND r.generation=e.generation
        JOIN graph_runtime.owners o ON o.owner_key=e.owner_key
        WHERE e.run_id=$1 AND e.owner_key=$2 AND e.generation=$3 AND e.effect_key=$4 LIMIT 2`,
      [graphReceipt?.runId,graphReceipt?.ownerKey,graphReceipt?.generation,graphReceipt?.effectKey])).rows;
      await current(check, signal);
      if (rows.length !== 1) throw fail();
      const traces = await conversationRepository.getTraceEvents(sessionId, binding, meta.traceEventIds,
        'secureshop_avatar_upload');
      await current(check, signal);
      const provenance = readQualifiedUploadSource({ binding, personaSession, row, traces, retained,
        graphEffect: rows[0], qualifyModel });
      if (!provenance) return null;
      const { admission, effect, serve } = provenance;
      if (path.extname(admission.request.originalFilename).toLowerCase() !== '.svg'
          || effect.file.byteCount > 256 * 1024
          || admission.request.declaredMime !== 'image/svg+xml' || admission.request.public !== true
          || effect.file.declaredMime !== 'image/svg+xml' || serve.status !== 200
          || serve.contentType !== 'image/svg+xml' || serve.responseByteCount !== effect.file.byteCount
          || serve.responseSha256 !== effect.file.bodySha256) return null;
      const bytes = await read({ storedVirtualPath: effect.file.storedVirtualPath,
        responseByteCount: effect.file.byteCount, responseSha256: effect.file.bodySha256 });
      await current(check, signal);
      const text = bytes.toString('utf8'), markers = text.match(MARKER) || [];
      if (!Buffer.from(text, 'utf8').equals(bytes) || markers.length !== 1) return null;
      const selected = traces.find(trace => trace.kind === 'model_decision' && trace.step === 1);
      let selectedValue;
      try { selectedValue = JSON.parse(selected?.result_json); } catch { return null; }
      if (typeof selected?.provider !== 'string' || Buffer.byteLength(selected.provider) > 64
          || typeof selectedValue?.model !== 'string' || Buffer.byteLength(selectedValue.model) > 256) return null;
      const proof = Object.freeze({ sessionId, requestId, operationId: admission.operationId,
        effectId: effect.effectId, originalEnvelopeSha256: hash(provenance.meta.originalEnvelope),
        requestHash: row.request_hash, bindingSha256: admission.bindingSha256,
        uploadRequestSha256: admission.requestSha256,
        tool: Object.freeze({ name:'uploads.upload_avatar', args:Object.freeze({}) }),
        qualifiedModel: Object.freeze({ provider:selected.provider, model:selectedValue.model }),
        file: Object.freeze({ originalFilename:effect.file.originalFilename,
          declaredMime:effect.file.declaredMime, public:admission.request.public,
          outcome:effect.outcome, byteCount:effect.file.byteCount, bodySha256:effect.file.bodySha256 }),
        serve: Object.freeze({ status:serve.status, contentType:serve.contentType,
          responseByteCount:serve.responseByteCount, responseSha256:serve.responseSha256 }),
        fileSha256: effect.file.bodySha256, byteCount: effect.file.byteCount,
        serveSha256: serve.serveSha256, markerSha256: hash(markers[0]) });
      const source = Object.freeze({ sourceDigest: hash(JSON.stringify(proof)), proof, provenance });
      verified.set(source, Object.freeze({ storedVirtualPath:effect.file.storedVirtualPath,
        byteCount:effect.file.byteCount, bodySha256:effect.file.bodySha256, marker:markers[0],
        scope:Object.freeze({...admission.scope}), operationId:admission.operationId,
        effectId:effect.effectId }));
      return source;
    },
    async mint(source, { check, signal } = {}) {
      const state = verified.get(source);
      if (!state || typeof check !== 'function') throw fail();
      await current(check, signal);
      const bytes = await read({ storedVirtualPath:state.storedVirtualPath,
        responseByteCount:state.byteCount, responseSha256:state.bodySha256 });
      await current(check, signal);
      const text = bytes.toString('utf8');
      if (!Buffer.from(text, 'utf8').equals(bytes)
          || (text.match(MARKER) || []).length !== 1 || !text.includes(state.marker)) throw fail();
      const scope = state.scope;
      const token = capability.mint({ effectId:state.effectId, operationId:state.operationId,
        targetId:scope.targetId, generation:scope.generation, sceneId:scope.sceneId,
        sceneGeneration:scope.sceneGeneration, mode:scope.mode,
        modeGeneration:scope.modeGeneration, modeStamp:scope.modeStamp });
      if (!token || typeof token.path !== 'string' || !Number.isSafeInteger(token.expiresAt)
          || token.expiresAt <= Date.now()) throw fail();
      return Object.freeze({ assetUrl:`${assetOrigin}${token.path}`,
        expected:Object.freeze({ byteCount:state.byteCount, bodySha256:state.bodySha256,
          contentType:'image/svg+xml', contentSecurityPolicy:'sandbox allow-scripts', marker:state.marker }) });
    },
  });
}
module.exports = { createV08SvgSourceReader };
