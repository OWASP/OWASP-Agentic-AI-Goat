'use strict';

const { createHash } = require('node:crypto');
const HASH = /^[a-f0-9]{64}$/;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const PIPELINE = Object.freeze({ version: 1, encoding: 'utf8-fatal', units: 'unicode-codepoints',
  window: 500, overlap: 50, trim: 'ecmascript-whitespace', minimum: 20, shortDocument: 'whole-trimmed' });
const sha256 = value => createHash('sha256').update(value).digest('hex');
const CHUNK_PIPELINE_FINGERPRINT = sha256(JSON.stringify(PIPELINE));
const fail = (code, message) => Object.assign(new Error(message), { code, statusCode: 503 });
const invalid = () => { throw new TypeError('Invalid durable RAG input'); };
const uuid = value => typeof value === 'string' && UUID.test(value);

// Exact source bytes survive trimming/chunking; ranges refer to the original
// UTF-8 buffer and never split a Unicode code point. No content sanitization.
function prepareWorkshopRagDocument(buffer) {
  if (!Buffer.isBuffer(buffer) || !buffer.length || buffer.length > 1048576) invalid();
  const sourceBuffer = Buffer.from(buffer);
  let text;
  try { text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(sourceBuffer); }
  catch { invalid(); }
  if (!text.trim() || text.includes('\0') || !Buffer.from(text, 'utf8').equals(sourceBuffer)) invalid();
  const points = Array.from(text), offsets = [0];
  for (const point of points) offsets.push(offsets.at(-1) + Buffer.byteLength(point));
  const chunks = [];
  const range = (start, end) => {
    while (start < end && !points[start].trim()) start++;
    while (end > start && !points[end - 1].trim()) end--;
    return { start, end };
  };
  for (let start = 0; start < points.length; start += PIPELINE.window - PIPELINE.overlap) {
    const end = Math.min(start + PIPELINE.window, points.length), trimmed = range(start, end);
    if (trimmed.end - trimmed.start >= PIPELINE.minimum) chunks.push({ startByte: offsets[trimmed.start], endByte: offsets[trimmed.end] });
    if (end === points.length) break;
  }
  if (!chunks.length) { const trimmed = range(0, points.length); chunks.push({ startByte: offsets[trimmed.start], endByte: offsets[trimmed.end] }); }
  if (chunks.length > 4096) invalid();
  return Object.freeze({ sourceBuffer, sourceSha256: sha256(sourceBuffer),
    chunks: Object.freeze(chunks.map(Object.freeze)), chunkPipelineSha256: CHUNK_PIPELINE_FINGERPRINT });
}

/** Staged durable orchestration. No configured singleton, pool, Map or fallback.
 * revisions must atomically verify source/head/runtime/lifecycle and, for
 * publishAndSelect, both prior selection ID AND monotonic selection version.
 * The candidate source-only repository alone cannot activate this service.
 */
function createWorkshopRagStore({ repository, revisions, embedder, checkCurrent, maxConcurrent = 2, embeddingBudget } = {}) {
  for (const method of ['read', 'readDocument', 'ingest']) if (typeof repository?.[method] !== 'function') throw new TypeError('Durable source repository required');
  for (const method of ['snapshot', 'publish', 'publishAndSelect', 'search', 'findIngestReplay']) if (typeof revisions?.[method] !== 'function') throw new TypeError('Durable vector revision repository required');
  if (typeof embedder?.embed !== 'function' || typeof embedder?.getRuntimeFingerprint !== 'function' || typeof checkCurrent !== 'function'
      || (embeddingBudget !== undefined && typeof embeddingBudget !== 'function') || !Number.isInteger(maxConcurrent) || maxConcurrent < 1 || maxConcurrent > 8) throw new TypeError('Trusted RAG inference dependencies required');
  let active = 0;
  const fingerprint = () => { const f = embedder.getRuntimeFingerprint(); if (f === null) return null;
    if (!f || !HASH.test(f.fingerprint)) throw fail('RAG_RUNTIME_UNAVAILABLE', 'Verified embedding runtime unavailable'); return f.fingerprint; };
  const bounded = async operation => { if (embeddingBudget) return embeddingBudget(operation); if (active >= maxConcurrent) throw fail('RAG_EMBEDDING_BUSY', 'Embedding capacity is busy; retry');
    active++; try { return await operation(); } finally { active--; } };
  function bind(inputScope, { signal } = {}) {
    // Scope is supplied by authenticated admission, never model/tool arguments.
    if (!inputScope || !Number.isSafeInteger(inputScope.ownerId) || inputScope.ownerId < 1
        || !Number.isSafeInteger(inputScope.platformSessionId) || inputScope.platformSessionId < 1
        || !((inputScope.family === 'RAG' && inputScope.slot === 'current')
          || (inputScope.family === 'CSRF' && ['clean', 'poison'].includes(inputScope.slot)))) invalid();
    const scope = Object.freeze({ ...inputScope });
    const check = async () => { signal?.throwIfAborted(); await checkCurrent(scope); signal?.throwIfAborted(); };
    const validateDocument = document => {
      if (!document || document.ownerId !== scope.ownerId || document.family !== scope.family || document.slot !== scope.slot
          || String(document.resourceGeneration) !== String(scope.resourceGeneration) || !uuid(document.documentId) || !HASH.test(document.sourceSha256)
          || !HASH.test(document.chunkManifestSha256) || !HASH.test(document.chunkPipelineSha256)
          || typeof document.sourceText !== 'string' || sha256(Buffer.from(document.sourceText, 'utf8')) !== document.sourceSha256
          || !Array.isArray(document.chunks) || !document.chunks.length || document.chunks.length > 4096) throw fail('RAG_SOURCE_INVALID', 'Durable document integrity failed');
      const bytes = Buffer.from(document.sourceText, 'utf8');
      if (bytes.length !== document.sourceBytes || bytes.length > 1048576) throw fail('RAG_SOURCE_INVALID', 'Durable document integrity failed');
      return Object.freeze({ ...document, chunks: Object.freeze(document.chunks.map((chunk, index) => {
        if (chunk.chunkIndex !== index || !Number.isInteger(chunk.startByte) || !Number.isInteger(chunk.endByte)
            || chunk.startByte < 0 || (index > 0 && chunk.startByte <= document.chunks[index - 1].startByte) || chunk.endByte <= chunk.startByte || chunk.endByte > bytes.length
            || typeof chunk.text !== 'string' || !chunk.text.trim() || Buffer.byteLength(chunk.text) > 65536
            || !Buffer.from(chunk.text).equals(bytes.subarray(chunk.startByte, chunk.endByte)) || sha256(chunk.text) !== chunk.sha256) throw fail('RAG_SOURCE_INVALID', 'Durable chunk integrity failed');
        return Object.freeze({ ...chunk });
      })) });
    };
    const vector = encoded => {
      if (encoded?.embeddingDimension !== 384 || !Array.isArray(encoded.embedding) || encoded.embedding.length !== 384
          || !encoded.embedding.every(Number.isFinite) || !encoded.embedding.some(n => n !== 0)) throw fail('RAG_EMBEDDING_INVALID', 'Embedding pipeline returned invalid output');
      return Object.freeze([...encoded.embedding]);
    };
    const validateReceipt = (receipt, document, runtime, authority = scope) => {
      if (!receipt || !uuid(receipt.revisionId) || receipt.documentId !== document.documentId
          || receipt.sourceSha256 !== document.sourceSha256 || receipt.chunkManifestSha256 !== document.chunkManifestSha256
          || receipt.chunkPipelineSha256 !== document.chunkPipelineSha256 || receipt.runtimeFingerprint !== runtime
          || receipt.ownerId !== scope.ownerId || receipt.family !== scope.family || receipt.slot !== scope.slot
          || String(receipt.resourceGeneration) !== String(scope.resourceGeneration)
          || String(receipt.graphGeneration) !== String(authority.graphGeneration) || receipt.runId !== authority.runId) {
        throw fail('RAG_RECEIPT_INVALID', 'Durable embedding receipt does not match admitted document');
      }
      return Object.freeze({ ...receipt });
    };
    async function prepareRevision(document, operationId, selection) {
      await check();
      const snapshot = await revisions.snapshot(scope, { documentId: document.documentId });
      if (!snapshot || snapshot.sourceSha256 !== document.sourceSha256 || snapshot.chunkManifestSha256 !== document.chunkManifestSha256
          || snapshot.chunkPipelineSha256 !== document.chunkPipelineSha256 || !(snapshot.expectedHead === null || uuid(snapshot.expectedHead))) throw fail('RAG_SOURCE_CHANGED', 'Document changed before embedding');
      let runtime = fingerprint(); const vectors = [];
      for (const chunk of document.chunks) {
        await check(); const encoded = await embedder.embed(chunk.text, { signal }); await check();
        const current = fingerprint();
        if (!current || (runtime !== null && runtime !== current)) throw fail('RAG_RUNTIME_CHANGED', 'Embedding runtime changed during preparation');
        runtime = current;
        vectors.push(Object.freeze({ chunkIndex: chunk.chunkIndex, sourceSha256: chunk.sha256, embedding: vector(encoded) }));
      }
      await check();
      if (fingerprint() !== runtime) throw fail('RAG_RUNTIME_CHANGED', 'Embedding runtime changed before publication');
      const input = Object.freeze({ operationId, documentId: document.documentId,
        sourceSha256: document.sourceSha256, chunkManifestSha256: document.chunkManifestSha256,
        chunkPipelineSha256: document.chunkPipelineSha256, expectedHead: snapshot.expectedHead,
        expectedRuntimeFingerprint: runtime, vectors: Object.freeze(vectors), ...(selection ? { selection } : {}) });
      const receipt = await (selection ? revisions.publishAndSelect(scope, input) : revisions.publish(scope, input));
      return validateReceipt(receipt, document, runtime);
    }
    return Object.freeze({
      async state() { await check(); const value = await repository.read(scope); await check(); return value; },
      async ingestAndSelect({ documentId, operationId, sourceBuffer, filename, ingestionKind }) {
        if (!uuid(documentId) || !uuid(operationId) || typeof filename !== 'string' || !filename || Buffer.byteLength(filename) > 512) invalid();
        return bounded(async () => {
          const prepared = prepareWorkshopRagDocument(sourceBuffer);
          await check();
          const replay = await revisions.findIngestReplay(scope, { documentId, operationId, filename, ingestionKind,
            sourceSha256: prepared.sourceSha256, chunkPipelineSha256: CHUNK_PIPELINE_FINGERPRINT, chunks: prepared.chunks });
          await check();
          if (replay !== null) {
            const document = validateDocument(replay.document), observation = replay.observation;
            if (document.documentId !== documentId || document.sourceSha256 !== prepared.sourceSha256 || document.chunkPipelineSha256 !== CHUNK_PIPELINE_FINGERPRINT || typeof replay.currentlySelected !== 'boolean' || !observation ||
                ['ownerId', 'platformSessionId', 'family', 'slot', 'runId'].some(key => observation[key] !== scope[key]) ||
                ['resourceGeneration', 'graphGeneration'].some(key => String(observation[key]) !== String(scope[key])) ||
                !uuid(replay.receipt?.runId) || !/^(0|[1-9][0-9]*)$/.test(String(replay.receipt.graphGeneration)) ||
                !HASH.test(replay.receipt?.runtimeFingerprint || '')) throw fail('RAG_RECEIPT_INVALID', 'Invalid completed ingestion replay observation');
            const receipt = validateReceipt(replay.receipt, document, replay.receipt.runtimeFingerprint, replay.receipt);
            return Object.freeze({ chunksStored: document.chunks.length, documentId, receipt,
              replayed: true, currentlySelected: replay.currentlySelected, observation: Object.freeze({ ...observation }) });
          }
          const prior = await repository.read(scope); await check();
          if (!prior || !(prior.documentId === null || uuid(prior.documentId)) || !/^(0|[1-9][0-9]*)$/.test(prior.selectionVersion)) throw fail('RAG_SELECTION_INVALID', 'Durable selection unavailable');
          const selection = Object.freeze({ expectedSelection: prior.documentId, expectedSelectionVersion: prior.selectionVersion });
          // Persist original bytes first. Embedding failure leaves this staged
          // source under quota, with the previous selected document unchanged.
          const document = validateDocument(await repository.ingest(scope, { documentId, operationId, ingestionKind, filename,
            sourceBuffer: prepared.sourceBuffer, chunks: prepared.chunks, expectedChunkPipelineFingerprint: CHUNK_PIPELINE_FINGERPRINT }));
          if (document.chunks.length !== prepared.chunks.length || document.chunks.some((chunk, i) => chunk.startByte !== prepared.chunks[i].startByte || chunk.endByte !== prepared.chunks[i].endByte) || document.sourceSha256 !== prepared.sourceSha256 || document.chunkPipelineSha256 !== CHUNK_PIPELINE_FINGERPRINT) throw fail('RAG_SOURCE_INVALID', 'Published source differs from upload');
          const receipt = await prepareRevision(document, operationId, selection); await check();
          return Object.freeze({ chunksStored: document.chunks.length, documentId, receipt, replayed: false, currentlySelected: true });
        });
      },
      async search({ documentId, question, limit = 5, operationId }) {
        if (!uuid(documentId) || !uuid(operationId) || typeof question !== 'string' || !question.trim() || Buffer.byteLength(question) > 65536
            || !Number.isInteger(limit) || limit < 1 || limit > 20) invalid();
        return bounded(async () => {
          await check(); const document = validateDocument(await repository.readDocument(scope, { documentId }));
          const before = fingerprint(); const encoded = await embedder.embed(question, { signal }); await check(); const runtime = fingerprint();
          if (!runtime || (before !== null && before !== runtime)) throw fail('RAG_RUNTIME_CHANGED', 'Embedding runtime changed during query');
          const query = Object.freeze({ documentId, embedding: vector(encoded), expectedRuntimeFingerprint: runtime, limit });
          let result;
          try { result = await revisions.search(scope, query); }
          catch (error) {
            if (!['EMBEDDING_REINDEX_REQUIRED', 'EMBEDDING_RUNTIME_MISMATCH'].includes(error?.code)) throw error;
            await prepareRevision(document, operationId, null);
            if (fingerprint() !== runtime) throw fail('RAG_RUNTIME_CHANGED', 'Embedding runtime changed during rebuild');
            result = await revisions.search(scope, query);
          }
          await check();
          if (fingerprint() !== runtime) throw fail('RAG_RUNTIME_CHANGED', 'Embedding runtime changed during retrieval');
          if (!result || !Array.isArray(result.chunks) || !result.receipt || result.chunks.length > limit) throw fail('RAG_RETRIEVAL_INVALID', 'Durable retrieval receipt unavailable');
          const chunks = result.chunks.map(row => { const source = document.chunks[row.chunkIndex];
            if (!source || row.text !== source.text || !Number.isFinite(row.score) || row.score < -1 || row.score > 1) throw fail('RAG_RETRIEVAL_INVALID', 'Retrieved chunk differs from source');
            return Object.freeze({ text: row.text, score: row.score, chunkIndex: row.chunkIndex }); });
          return Object.freeze({ chunks: Object.freeze(chunks), receipt: validateReceipt(result.receipt, document, runtime) });
        });
      },
    });
  }
  return Object.freeze({ bind });
}
module.exports = { createWorkshopRagStore, prepareWorkshopRagDocument, CHUNK_PIPELINE_FINGERPRINT, WORKSHOP_RAG_CHUNK_PIPELINE: PIPELINE };
