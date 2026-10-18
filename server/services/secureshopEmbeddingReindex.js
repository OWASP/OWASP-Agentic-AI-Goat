'use strict';

const { createLaunchScope } = require('./secureshopConversationBinding');
const { copySceneBinding, executionScope } = require('./secureshopSceneBinding');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HASH = /^[a-f0-9]{64}$/;
const KINDS = new Set(['product', 'listing', 'review', 'manual', 'policy']);
const CORPORA = Object.freeze({ products: Object.freeze(['product','listing']), reviews: Object.freeze(['review']), manuals: Object.freeze(['manual']), policies: Object.freeze(['policy']) });
const failure = (code, message) => Object.assign(new Error(message), { code });
const invalid = () => failure('EMBEDDING_REINDEX_INVALID', 'Invalid embedding revision source');

// Internal orchestration only: no HTTP route or automatic upgrade is exposed.
// Publication independently checks the source snapshot, lifecycle and trusted
// runtime fingerprint inside the repository's transaction.
function createSecureShopEmbeddingReindex({ repository, embedder, checkCurrent } = {}) {
  if (typeof repository?.snapshot !== 'function' || typeof repository?.publish !== 'function'
      || typeof embedder?.embed !== 'function' || typeof embedder?.getRuntimeFingerprint !== 'function'
      || typeof checkCurrent !== 'function') throw new TypeError('Embedding reindex dependencies required');
  let busy = false;
  return Object.freeze({
    async reindex({ scope: inputScope, binding: inputBinding, operationId, signal, personaEffect, beforeEffect } = {}) {
      require('./secureshopPersonaProductEffect').assertPersonaProductEffect(personaEffect);
      if (beforeEffect !== undefined && typeof beforeEffect !== 'function') throw invalid();
      const scope = createLaunchScope(inputScope);
      if (typeof operationId !== 'string' || !UUID.test(operationId)
          || typeof inputBinding?.targetId !== 'string' || !UUID.test(inputBinding.targetId)
          || Object.keys(scope).some(key => executionScope(inputBinding)[key] !== scope[key])) throw invalid();
      const binding = copySceneBinding(inputBinding, { targetId: inputBinding.targetId.toLowerCase(),
        launchId: inputBinding.launchId, scenarioId: inputBinding.scenarioId,
        generation: inputBinding.generation, platformOwnerId: inputBinding.platformOwnerId,
        platformSessionId: inputBinding.platformSessionId });
      if (busy) throw failure('EMBEDDING_REINDEX_BUSY', 'An embedding revision is already being prepared');
      busy = true;
      const check = async () => { signal?.throwIfAborted(); await checkCurrent(scope);await personaEffect?.check(scope); await beforeEffect?.(); signal?.throwIfAborted(); };
      const fingerprint = () => {
        const value = embedder.getRuntimeFingerprint();
        if (value === null) return null;
        if (!value || !HASH.test(value.fingerprint)) throw failure('EMBEDDING_FINGERPRINT_UNAVAILABLE', 'Verified embedding runtime is unavailable');
        return value.fingerprint;
      };
      try {
        await check();
        const snapshot = await repository.snapshot(binding);
        await check();
        if (!snapshot || !HASH.test(snapshot.sourceSetDigest) ||
            !(snapshot.expectedHead === null || (typeof snapshot.expectedHead === 'string' && UUID.test(snapshot.expectedHead))) ||
            !Array.isArray(snapshot.documents) || snapshot.documents.length < 1 || snapshot.documents.length > 4096) throw invalid();
        // Copy the authoritative snapshot before yielding to inference. Never
        // regenerate catalog defaults or re-extract original uploaded files.
        const seen = new Set();
        const sources = snapshot.documents.map(row => {
          if (!row || !KINDS.has(row.sourceKind) || typeof row.sourceId !== 'string' || !/^[1-9][0-9]{0,15}$/.test(row.sourceId) || !Number.isSafeInteger(Number(row.sourceId))
              || !Number.isSafeInteger(row.chunkIndex) || row.chunkIndex < 0 || row.chunkIndex > 128
              || !HASH.test(row.sourceSha256) || typeof row.text !== 'string' || !row.text.trim()
              || Buffer.byteLength(row.text, 'utf8') > 65536) throw invalid();
          const key = `${row.sourceKind}:${row.sourceId}:${row.chunkIndex}`;
          if (seen.has(key)) throw invalid(); seen.add(key);
          return Object.freeze({ sourceKind: row.sourceKind, sourceId: row.sourceId,
            chunkIndex: row.chunkIndex, text: row.text, sourceSha256: row.sourceSha256 });
        });
        const expectedHead = snapshot.expectedHead, sourceSetDigest = snapshot.sourceSetDigest;
        let runtime = fingerprint();
        const documents = [];
        for (const row of sources) {
          await check();
          const encoded = await embedder.embed(row.text, { signal });
          await check();
          const current = fingerprint();
          if (!current || (runtime !== null && runtime !== current)) {
            throw failure('EMBEDDING_RUNTIME_CHANGED', 'Embedding runtime changed during revision preparation');
          }
          runtime = current;
          if (encoded?.embeddingDimension !== 384 || !Array.isArray(encoded.embedding)
              || encoded.embedding.length !== 384 || !encoded.embedding.every(Number.isFinite)
              || !encoded.embedding.some(value => value !== 0)) throw invalid();
          documents.push(Object.freeze({ sourceKind: row.sourceKind, sourceId: row.sourceId,
            chunkIndex: row.chunkIndex, sourceSha256: row.sourceSha256,
            embedding: Object.freeze([...encoded.embedding]) }));
        }
        await check();
        if (fingerprint() !== runtime) throw failure('EMBEDDING_RUNTIME_CHANGED', 'Embedding runtime changed before publication');
        // The expected fingerprint is a concurrency constraint, never authority:
        // repository.publish compares it with its own trusted runtime getter.
        const publication=Object.freeze({ operationId: operationId.toLowerCase(),
          sourceSetDigest, expectedHead, expectedRuntimeFingerprint: runtime,
          documents: Object.freeze(documents) });
        return personaEffect?await personaEffect.publish(repository,binding,publication):await repository.publish(binding,publication);
      } finally { busy = false; }
    },
    async reindexSelective({ scope: inputScope, binding: inputBinding, operationId, corpus, signal, personaEffect } = {}) {
      require('./secureshopPersonaProductEffect').assertPersonaProductEffect(personaEffect);
      const sourceKinds = typeof corpus === 'string' && Object.hasOwn(CORPORA, corpus) ? CORPORA[corpus] : null;
      if (!sourceKinds) throw failure('EMBEDDING_REINDEX_UNSUPPORTED', 'Embedding corpus is unsupported');
      if (typeof repository.snapshotSelective !== 'function') throw failure('EMBEDDING_REINDEX_UNAVAILABLE', 'Selective embedding snapshot unavailable');
      const scope = createLaunchScope(inputScope);
      if (typeof operationId !== 'string' || !UUID.test(operationId)
          || typeof inputBinding?.targetId !== 'string' || !UUID.test(inputBinding.targetId)
          || Object.keys(scope).some(key => executionScope(inputBinding)[key] !== scope[key])) throw invalid();
      const binding = copySceneBinding(inputBinding, { targetId: inputBinding.targetId.toLowerCase(),
        launchId: inputBinding.launchId, scenarioId: inputBinding.scenarioId,
        generation: inputBinding.generation, platformOwnerId: inputBinding.platformOwnerId,
        platformSessionId: inputBinding.platformSessionId });
      if (busy) throw failure('EMBEDDING_REINDEX_BUSY', 'An embedding revision is already being prepared');
      busy = true;
      const check = async () => { signal?.throwIfAborted(); await checkCurrent(scope); await personaEffect?.check(scope); signal?.throwIfAborted(); };
      const fingerprint = () => { const value = embedder.getRuntimeFingerprint(); if (value === null) return null; if (!value || !HASH.test(value.fingerprint)) throw failure('EMBEDDING_FINGERPRINT_UNAVAILABLE', 'Verified embedding runtime is unavailable'); return value.fingerprint; };
      try {
        await check();
        const snapshot = await repository.snapshotSelective(binding, { sourceKinds: [...sourceKinds] });
        await check();
        if (!snapshot || !HASH.test(snapshot.sourceSetDigest) || !(snapshot.expectedHead === null || (typeof snapshot.expectedHead === 'string' && UUID.test(snapshot.expectedHead)))
            || typeof snapshot.currentRuntimeFingerprint !== 'string' || !HASH.test(snapshot.currentRuntimeFingerprint) || snapshot.currentRuntimeFingerprint !== fingerprint() || !Array.isArray(snapshot.documents) || !snapshot.documents.length) throw failure('EMBEDDING_REINDEX_STALE_SOURCE', 'Selective embedding snapshot is stale');
        if (snapshot.documents.length > 4096) throw failure('EMBEDDING_REINDEX_STALE_SOURCE', 'Selective embedding snapshot is stale');
        const seen = new Set(); let selected = 0;
        const rows = snapshot.documents.map(row => {
          if (!row || !KINDS.has(row.sourceKind) || typeof row.sourceId !== 'string' || !/^[1-9][0-9]{0,15}$/.test(row.sourceId) || !Number.isSafeInteger(Number(row.sourceId)) || !Number.isInteger(row.chunkIndex) || row.chunkIndex < 0 || row.chunkIndex > 128 || !HASH.test(row.sourceSha256) || typeof row.text !== 'string' || !row.text.trim() || Buffer.byteLength(row.text,'utf8') > 65536) throw failure('EMBEDDING_REINDEX_STALE_SOURCE', 'Selective embedding sibling is invalid');
          const key=`${row.sourceKind}:${row.sourceId}:${row.chunkIndex}`;if(seen.has(key))throw invalid();seen.add(key);const chosen=sourceKinds.includes(row.sourceKind);if(chosen)selected+=1;
          if (!chosen && (!Array.isArray(row.embedding) || row.embedding.length !== 384 || row.embedding.some(n=>typeof n !== 'number'||!Number.isFinite(n)) || !row.embedding.some(n=>n!==0))) throw failure('EMBEDDING_REINDEX_STALE_SOURCE', 'Selective embedding sibling is invalid');
          return { sourceKind:row.sourceKind,sourceId:row.sourceId,chunkIndex:row.chunkIndex,sourceSha256:row.sourceSha256,text:row.text,embedding:chosen?null:[...row.embedding] };
        });
        if (!selected) throw failure('EMBEDDING_REINDEX_NO_SOURCE', 'Selective embedding corpus has no source documents');
        const runtime = snapshot.currentRuntimeFingerprint;
        const sourceSetDigest = snapshot.sourceSetDigest, expectedHead = snapshot.expectedHead;
        for (const row of rows) if (row.embedding === null) { await check(); const encoded = await embedder.embed(row.text,{signal}); await check(); const current=fingerprint(); if(!current||current!==runtime)throw failure('EMBEDDING_RUNTIME_CHANGED','Embedding runtime changed during revision preparation'); if(encoded?.embeddingDimension!==384||!Array.isArray(encoded.embedding)||encoded.embedding.length!==384||!encoded.embedding.every(Number.isFinite)||!encoded.embedding.some(value=>value!==0))throw invalid(); row.embedding=[...encoded.embedding]; }
        await check(); if(fingerprint()!==runtime)throw failure('EMBEDDING_RUNTIME_CHANGED','Embedding runtime changed before publication');
        const publication=Object.freeze({operationId:operationId.toLowerCase(),sourceSetDigest,expectedHead,expectedRuntimeFingerprint:runtime,documents:Object.freeze(rows.map(row=>Object.freeze({sourceKind:row.sourceKind,sourceId:row.sourceId,chunkIndex:row.chunkIndex,sourceSha256:row.sourceSha256,embedding:Object.freeze([...row.embedding])}))) });
        return personaEffect?await personaEffect.publish(repository,binding,publication):await repository.publish(binding,publication);
      } finally { busy=false; }
    },
  });
}
module.exports = { createSecureShopEmbeddingReindex };
