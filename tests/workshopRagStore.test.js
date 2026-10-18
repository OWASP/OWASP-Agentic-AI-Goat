'use strict';
const { controlledObjectiveGraph } = require('./helpers/controlledObjectiveBoundary');
// Contract adapters below are controlled unit doubles, not PostgreSQL proof.
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID, createHash } = require('node:crypto');
const { createWorkshopRagStore, prepareWorkshopRagDocument, CHUNK_PIPELINE_FINGERPRINT } = require('../server/services/workshopRagStore');
const hash = value => createHash('sha256').update(value).digest('hex');
const failure = code => Object.assign(new Error(code), { code });
const vector = () => ({ embeddingDimension: 384, embedding: Array(384).fill(0).map((_, i) => i === 0 ? 1 : 0) });
function fixture() {
  const scope = { ownerId: 1, platformSessionId: 2, family: 'RAG', slot: 'current', graphGeneration: '0', resourceGeneration: '0', runId: randomUUID() };
  const state = { documents: new Map(), heads: new Map(), completed: new Map(), selection: null, version: 0, runtime: 'a'.repeat(64), current: true, calls: 0, publications: 0, searchError: null };
  const checkCurrent = async () => { if (!state.current) throw failure('RUN_INVALIDATED'); };
  const receipt = (document, revisionId) => ({ ...scope, documentId: document.documentId, revisionId,
    sourceSha256: document.sourceSha256, chunkManifestSha256: document.chunkManifestSha256,
    chunkPipelineSha256: document.chunkPipelineSha256, runtimeFingerprint: state.runtime });
  const repository = {
    async read() { return { generation: '0', documentId: state.selection, selectionVersion: String(state.version), document: state.documents.get(state.selection) || null }; },
    async readDocument(_, { documentId }) { return state.documents.get(documentId); },
    async ingest(_, input) {
      const document = { ...scope, documentId: input.documentId, operationId: input.operationId, filename: input.filename, ingestionKind: input.ingestionKind, sourceText: input.sourceBuffer.toString('utf8'), sourceSha256: hash(input.sourceBuffer),
        sourceBytes: input.sourceBuffer.length, chunkManifestSha256: hash(JSON.stringify(input.chunks)), chunkPipelineSha256: input.expectedChunkPipelineFingerprint,
        chunks: input.chunks.map((part, chunkIndex) => { const text = input.sourceBuffer.subarray(part.startByte, part.endByte).toString('utf8');
          return { ...part, chunkIndex, text, sha256: hash(text) }; }) };
      state.documents.set(document.documentId, document); return document;
    },
  };
  async function publish(_, input) {
    await checkCurrent();
    if (input.selection && (state.selection !== input.selection.expectedSelection || String(state.version) !== input.selection.expectedSelectionVersion)) throw failure('SELECTION_CONFLICT');
    if (input.expectedRuntimeFingerprint !== state.runtime) throw failure('RUNTIME_CONFLICT');
    const prior = state.heads.get(input.documentId);
    if ((prior?.revisionId || null) !== input.expectedHead) throw failure('HEAD_CONFLICT');
    const result = receipt(state.documents.get(input.documentId), randomUUID());
    state.heads.set(input.documentId, result); state.completed.set(input.operationId, result); state.publications++;
    if (input.selection) { state.selection = input.documentId; state.version++; }
    return result;
  }
  const revisions = {
    async findIngestReplay(observation, input) {
      const result = state.completed.get(input.operationId); if (!result) return null;
      const document = state.documents.get(result.documentId);
      if (document.documentId !== input.documentId || document.filename !== input.filename || document.ingestionKind !== input.ingestionKind || document.sourceSha256 !== input.sourceSha256 || document.chunkPipelineSha256 !== input.chunkPipelineSha256 || JSON.stringify(document.chunks.map(({startByte,endByte})=>({startByte,endByte}))) !== JSON.stringify(input.chunks)) throw failure('REPLAY_CONFLICT');
      return { document, receipt: result, observation, currentlySelected: state.selection === document.documentId };
    },
    async snapshot(_, { documentId }) { const d = state.documents.get(documentId); return { sourceSha256: d.sourceSha256,
      chunkManifestSha256: d.chunkManifestSha256, chunkPipelineSha256: d.chunkPipelineSha256, expectedHead: state.heads.get(documentId)?.revisionId || null }; },
    publish, publishAndSelect: publish,
    async search(_, { documentId, expectedRuntimeFingerprint, limit }) {
      if (state.searchError) throw state.searchError;
      const head = state.heads.get(documentId); if (!head) throw failure('EMBEDDING_REINDEX_REQUIRED');
      if (head.runtimeFingerprint !== expectedRuntimeFingerprint) throw failure('EMBEDDING_RUNTIME_MISMATCH');
      return { chunks: state.documents.get(documentId).chunks.slice(0, limit).map(c => ({ ...c, score: 1 })), receipt: { ...head, ...scope } };
    },
  };
  const embedder = { getRuntimeFingerprint: () => ({ fingerprint: state.runtime }), async embed() { state.calls++; return vector(); } };
  const create = options => createWorkshopRagStore({ repository, revisions, embedder, checkCurrent, ...options }).bind(scope);
  const upload = (text = 'Actual owned untrusted source with sufficient content for a meaningful chunk.') => ({ documentId: randomUUID(), operationId: randomUUID(), sourceBuffer: Buffer.from(text), filename: 'owned.txt', ingestionKind: 'upload' });
  return { state, scope, repository, revisions, embedder, create, upload };
}
test('chunk preparation preserves exact UTF8 including BOM and makes safe Unicode byte ranges', () => {
  const original = Buffer.from('\ufeff \n' + '😀abc '.repeat(250) + '\n'); const p = prepareWorkshopRagDocument(original);
  assert.deepEqual(p.sourceBuffer, original); assert.equal(p.sourceSha256, hash(original)); assert.equal(p.chunkPipelineSha256, CHUNK_PIPELINE_FINGERPRINT);
  assert.ok(p.chunks.length > 1); for (const c of p.chunks) assert.doesNotThrow(() => new TextDecoder('utf8', { fatal: true }).decode(original.subarray(c.startByte, c.endByte)));
  original.fill(0); assert.notDeepEqual(p.sourceBuffer, original);
  for (const value of [Buffer.from([0xff]), Buffer.from('a\0b'), Buffer.alloc(1048577), Buffer.from(' \n')]) assert.throws(() => prepareWorkshopRagDocument(value));
});
test('requires durable vector adapter; no memory fallback or source-only activation', () => {
  const f = fixture(); assert.throws(() => f.create({ revisions: {} }), /Durable vector/);
});
test('ingests immutable source then publishes and selects, retrieval repeats without reindex', async () => {
  const f = fixture(), store = f.create(), input = f.upload(); const result = await store.ingestAndSelect(input);
  assert.equal(result.chunksStored, 1); assert.equal(f.state.selection, input.documentId); assert.equal(f.state.publications, 1);
  assert.equal(f.state.documents.get(input.documentId).sourceText, input.sourceBuffer.toString());
  const request = { documentId: input.documentId, question: 'What is in this source?', operationId: randomUUID() };
  const first = await store.search(request); const second = await store.search({ ...request, operationId: randomUUID() });
  assert.equal(first.chunks[0].text, input.sourceBuffer.toString()); assert.deepEqual(second.receipt, first.receipt); assert.equal(f.state.publications, 1);
});
test('embedding failure preserves staged exact source and prior selected document', async () => {
  const f = fixture(), store = f.create(); const original = f.upload(); await store.ingestAndSelect(original);
  f.embedder.embed = async () => { throw failure('MODEL_UNAVAILABLE'); }; const next = f.upload('New source retained even though its embedding provider is currently unavailable.');
  await assert.rejects(store.ingestAndSelect(next), { code: 'MODEL_UNAVAILABLE' });
  assert.equal(f.state.selection, original.documentId); assert.equal(f.state.documents.get(next.documentId).sourceText, next.sourceBuffer.toString()); assert.equal(f.state.publications, 1);
});
test('runtime mismatch rebuilds exact saved chunks once, preserving source and selection', async () => {
  const f = fixture(), store = f.create(), input = f.upload(); await store.ingestAndSelect(input);
  const before = JSON.stringify(f.state.documents.get(input.documentId)); f.state.runtime = 'b'.repeat(64);
  const result = await store.search({ documentId: input.documentId, question: 'Explain', operationId: randomUUID() });
  assert.equal(result.receipt.runtimeFingerprint, f.state.runtime); assert.equal(f.state.publications, 2); assert.equal(f.state.selection, input.documentId);
  assert.equal(JSON.stringify(f.state.documents.get(input.documentId)), before);
});
test('database retrieval outage propagates without reindex, empty success or memory fallback', async () => {
  const f = fixture(), store = f.create(), input = f.upload(); await store.ingestAndSelect(input); f.state.searchError = failure('DB_DOWN');
  await assert.rejects(store.search({ documentId: input.documentId, question: 'Explain', operationId: randomUUID() }), { code: 'DB_DOWN' }); assert.equal(f.state.publications, 1);
});
test('reset during inference rejects late publication and retains staged source without selection', async () => {
  const f = fixture(), store = f.create(), input = f.upload(); f.embedder.embed = async () => { f.state.current = false; return vector(); };
  await assert.rejects(store.ingestAndSelect(input), { code: 'RUN_INVALIDATED' }); assert.equal(f.state.selection, null); assert.equal(f.state.publications, 0); assert.ok(f.state.documents.has(input.documentId));
});
test('runtime change during multi-chunk inference prevents publication', async () => {
  const f = fixture(), store = f.create(), input = f.upload('full source text '.repeat(100)); let calls = 0;
  f.embedder.embed = async () => { if (++calls === 2) f.state.runtime = 'c'.repeat(64); return vector(); };
  await assert.rejects(store.ingestAndSelect(input), { code: 'RAG_RUNTIME_CHANGED' }); assert.equal(f.state.publications, 0);
});
test('slower upload cannot overwrite newer selected document; CAS preserves both sources', async () => {
  const f = fixture(), store = f.create(); let release, reached;
  const waiting = new Promise(resolve => { reached = resolve; }); const pending = new Promise(resolve => { release = resolve; });
  f.embedder.embed = async text => { if (text.startsWith('Slow')) { reached(); await pending; } return vector(); };
  const slow = f.upload('Slow older document reaches inference first but must not overwrite a newer selection.');
  const fast = f.upload('Fast newer document completes first and becomes the selected durable document.');
  const oldPromise = store.ingestAndSelect(slow); await waiting; await store.ingestAndSelect(fast); release();
  await assert.rejects(oldPromise, { code: 'SELECTION_CONFLICT' }); assert.equal(f.state.selection, fast.documentId); assert.equal(f.state.documents.size, 2);
});
test('bounded inference rejects excess work before staging extra source', async () => {
  const f = fixture(), store = f.create({ maxConcurrent: 1 }); let release, reached;
  const waiting = new Promise(resolve => { reached = resolve; }); const pending = new Promise(resolve => { release = resolve; });
  f.embedder.embed = async () => { reached(); await pending; return vector(); }; const active = store.ingestAndSelect(f.upload()); await waiting;
  await assert.rejects(store.ingestAndSelect(f.upload()), { code: 'RAG_EMBEDDING_BUSY' }); assert.equal(f.state.documents.size, 1); release(); await active;
});
test('wrong-scope publication receipt and altered retrieved source cannot become evidence', async () => {
  const f = fixture(), store = f.create(), input = f.upload(); const publish = f.revisions.publishAndSelect;
  f.revisions.publishAndSelect = async (...args) => ({ ...await publish(...args), ownerId: 99 });
  await assert.rejects(store.ingestAndSelect(input), { code: 'RAG_RECEIPT_INVALID' });
  const search = f.revisions.search; f.revisions.search = async (...args) => { const result = await search(...args); result.chunks[0].text = 'substituted'; return result; };
  await assert.rejects(store.search({ documentId: input.documentId, question: 'Explain', operationId: randomUUID() }), { code: 'RAG_RETRIEVAL_INVALID' });
});
test('ingestion graph uses atomic durable publication and passes receipt to Judge without Map calls', async () => {
  const { runRagIngestGraph: runRagIngestGraphRuntime } = require('../server/agent-runtime/ragIngestGraph');
  const runRagIngestGraph = controlledObjectiveGraph(runRagIngestGraphRuntime);
  const f = fixture(), input = f.upload(), packets = []; const bound = f.create();
  const result = await runRagIngestGraph({ userKey: '1', sessionId: input.documentId, buffer: input.sourceBuffer, filename: input.filename, displayFilename: input.filename }, {
    durableRagStore: bound, execution: { runId: f.scope.runId, check: async () => {} },
    ragVectorStore: new Proxy({}, { get() { throw Error('Unexpected memory store use'); } }),
    objectiveJudge: async packet => { assert.equal(f.state.selection, input.documentId); packets.push(packet); return { verdict: 'fail' }; },
    markRagObjectiveComplete: async () => { throw Error('Unexpected credit'); },
  });
  assert.equal(result.document_receipt.documentId, input.documentId); assert.equal(packets.length, 2);
  assert.ok(packets.every(packet => packet.evidence.some(item => item.id === 'document_receipt')));
});
test('durable aborted ingestion does not delete staged source or call Judge', async () => {
  const { runRagIngestGraph: runRagIngestGraphRuntime } = require('../server/agent-runtime/ragIngestGraph');
  const runRagIngestGraph = controlledObjectiveGraph(runRagIngestGraphRuntime);
  let judges = 0; const aborted = Object.assign(new Error('reset'), { name: 'AbortError' });
  await assert.rejects(runRagIngestGraph({ userKey: '1', sessionId: randomUUID(), buffer: Buffer.from('source'), filename: 'owned.txt', displayFilename: 'owned.txt' }, {
    durableRagStore: { ingestAndSelect: async () => { throw aborted; } },
    ragVectorStore: new Proxy({}, { get() { throw Error('Unexpected memory cleanup'); } }),
    objectiveJudge: async () => { judges++; }, markRagObjectiveComplete: async () => {},
  }), { name: 'AbortError' }); assert.equal(judges, 0);
});
test('selection version prevents ABA overwrite even when previous document ID is restored', async () => {
  const f = fixture(), store = f.create(); const original = f.upload(); await store.ingestAndSelect(original);
  const embed = f.embedder.embed; f.embedder.embed = async (...args) => { f.state.version += 2; return embed(...args); };
  await assert.rejects(store.ingestAndSelect(f.upload()), { code: 'SELECTION_CONFLICT' }); assert.equal(f.state.selection, original.documentId);
});
test('source corruption and wrong family are rejected before query inference', async () => {
  for (const mutate of [d => { d.sourceText += 'changed'; }, d => { d.family = 'CSRF'; }, d => { d.chunks[0].sha256 = 'f'.repeat(64); }]) {
    const f = fixture(), store = f.create(), input = f.upload(); await store.ingestAndSelect(input); const calls = f.state.calls;
    mutate(f.state.documents.get(input.documentId));
    await assert.rejects(store.search({ documentId: input.documentId, question: 'Explain', operationId: randomUUID() }), { code: 'RAG_SOURCE_INVALID' }); assert.equal(f.state.calls, calls);
  }
});
test('a provider without actual runtime provenance cannot publish a revision', async () => {
  const f = fixture(), store = f.create(); f.embedder.getRuntimeFingerprint = () => null;
  await assert.rejects(store.ingestAndSelect(f.upload()), { code: 'RAG_RUNTIME_CHANGED' }); assert.equal(f.state.publications, 0);
});
test('completed logical-operation replay preserves original receipt and does not alter newer selection or grade', async () => {
  const { runRagIngestGraph: runRagIngestGraphRuntime } = require('../server/agent-runtime/ragIngestGraph');
  const runRagIngestGraph = controlledObjectiveGraph(runRagIngestGraphRuntime);
  const f = fixture(), store = f.create(), original = f.upload(), newer = f.upload('Newer selected source remains selected when an older completed operation is retried.');
  const completed = await store.ingestAndSelect(original); await store.ingestAndSelect(newer); const calls = f.state.calls, publications = f.state.publications;
  const replay = await store.ingestAndSelect(original); assert.equal(replay.replayed, true); assert.equal(replay.currentlySelected, false);
  assert.deepEqual(replay.receipt, completed.receipt); assert.equal(f.state.calls, calls); assert.equal(f.state.publications, publications); assert.equal(f.state.selection, newer.documentId);
  await assert.rejects(store.ingestAndSelect({ ...original, filename: 'changed.txt' }), { code: 'REPLAY_CONFLICT' });
  let judges = 0, credits = 0;
  const out = await runRagIngestGraph({ userKey: '1', sessionId: original.documentId, buffer: original.sourceBuffer, filename: original.filename, displayFilename: original.filename }, {
    durableRagStore: { ingestAndSelect: async () => replay }, objectiveJudge: async () => { judges++; }, markRagObjectiveComplete: async () => { credits++; },
  });
  assert.equal(judges, 0); assert.equal(credits, 0); assert.deepEqual(out.judgments, []); assert.equal(out.currently_selected, false); assert.deepEqual(out.document_receipt, completed.receipt);
});
