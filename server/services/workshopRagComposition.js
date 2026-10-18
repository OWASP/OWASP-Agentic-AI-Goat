'use strict';
const { randomUUID } = require('node:crypto');
const { readBearerAuthorization } = require('../middleware/bearerToken');
const { canonicalDurableGeneration } = require('../agent-runtime/durableGeneration');
const { createWorkshopRagStore, CHUNK_PIPELINE_FINGERPRINT } = require('./workshopRagStore');
const { createWorkshopRagRepository } = require('../database/postgres/workshopRagRepository');
const { createWorkshopRagRevisionRepository } = require('../database/postgres/workshopRagRevisionRepository');
const failure = (code, message, statusCode = 503) => Object.assign(new Error(message), { code, statusCode });
const positive = value => Number.isSafeInteger(Number(value)) && Number(value) > 0;
const slotsFor = family => family === 'RAG' ? ['current'] : family === 'CSRF' ? ['clean', 'poison'] : [];

// Explicit construction/injection only until migration, lifecycle and route
// readiness promote together. Never chooses a memory store or loads .env.
function createWorkshopRagComposition({ pool, identityAdapter, embedder, assertReady,
  sourceFactory = createWorkshopRagRepository, revisionFactory = createWorkshopRagRevisionRepository,
  maxConcurrent = 2 } = {}) {
  if (!pool || typeof identityAdapter?.validateSession !== 'function' || typeof assertReady !== 'function'
      || typeof embedder?.embed !== 'function' || !Number.isInteger(maxConcurrent) || maxConcurrent < 1 || maxConcurrent > 8) throw new TypeError('Durable RAG composition dependencies required');
  let ready = false, initialization = null, active = 0;
  const embeddingBudget = async operation => {
    if (active >= maxConcurrent) throw failure('RAG_EMBEDDING_BUSY', 'Embedding capacity is busy; retry');
    active++; try { return await operation(); } finally { active--; }
  };
  const requireReady = () => { if (!ready) throw failure('RAG_STORAGE_NOT_READY', 'Durable document storage is unavailable'); };
  function repositories(check) {
    const sources = sourceFactory(pool, { checkCurrent: check, checkResetCurrent: check, getChunkPipelineFingerprint: () => CHUNK_PIPELINE_FINGERPRINT });
    const revisions = revisionFactory(pool, { checkCurrent: check, getRuntimeFingerprint: () => embedder.getRuntimeFingerprint()?.fingerprint });
    return { sources, revisions };
  }
  return Object.freeze({
    async initialize() {
      if (!initialization) initialization = Promise.resolve().then(() => assertReady(pool)).then(() => { ready = true; }).catch(error => { initialization = null; ready = false; throw failure('RAG_STORAGE_NOT_READY', 'Durable document storage failed readiness'); });
      await initialization;
    },
    isReady: () => ready,
    isEmbeddingReady: () => Boolean(embedder.getRuntimeFingerprint?.()?.fingerprint),
    async resolveRequest(req) {
      requireReady();
      const token = readBearerAuthorization(req).token;
      const ownerId = Number(req?.user?.id), platformSessionId = Number(req?.identitySession?.id);
      if (!token || !positive(ownerId) || !positive(platformSessionId)) throw failure('RAG_AUTH_REQUIRED', 'A verified platform session is required', 401);
      const checkIdentity = async () => {
        requireReady();
        let found;
        try { found = await identityAdapter.validateSession(token); } catch(error) {
          if(['JsonWebTokenError','TokenExpiredError','NotBeforeError','AccountLocked'].includes(error.name)) throw failure('RAG_AUTH_REQUIRED','The platform session is no longer current',401);
          throw failure('RAG_AUTH_UNAVAILABLE','Platform session validation is unavailable');
        }
        if (Number(found?.user?.id) !== ownerId || Number(found?.session?.id) !== platformSessionId
            || Number(found?.session?.user_id) !== ownerId) throw failure('RAG_AUTH_REQUIRED', 'The platform session is no longer current', 401);
      };
      await checkIdentity();
      const coordinate = (family, slot) => { if (!slotsFor(family).includes(slot)) throw new TypeError('Invalid RAG family/slot'); return Object.freeze({ ownerId, platformSessionId, family, slot }); };
      const forExecution = execution => {
        if (typeof execution?.check !== 'function') throw failure('RAG_RUN_REQUIRED', 'Admitted RAG execution required');
        const check = async () => { await execution.check(); await checkIdentity(); await execution.check(); };
        return { check, ...repositories(check) };
      };
      return Object.freeze({
        ownerId, platformSessionId, check: checkIdentity,
        async read({ family = 'RAG', slot = 'current' } = {}) {
          await checkIdentity(); const result = await repositories(checkIdentity).sources.read(coordinate(family, slot)); await checkIdentity(); return result;
        },
        async bind(execution, { family = 'RAG', slot = 'current' } = {}) {
          const identity = coordinate(family, slot);
          if (execution?.ownerKey !== JSON.stringify([family, String(ownerId)]) || typeof execution?.runId !== 'string') throw failure('RAG_RUN_REQUIRED', 'Execution owner does not match authenticated resource');
          const graphGeneration = canonicalDurableGeneration(execution.durableGeneration);
          const { check, sources, revisions } = forExecution(execution); await check();
          const current = await sources.read(identity);
          const scope = Object.freeze({ ...identity, graphGeneration, runId: execution.runId,
            resourceGeneration: canonicalDurableGeneration(current.resourceGeneration) });
          const bound = createWorkshopRagStore({ repository: sources, revisions, embedder, checkCurrent: check, embeddingBudget }).bind(scope, { signal: execution.signal });
          return Object.freeze({ ...bound, scope, selectedDocumentId: current.documentId,
            async document(documentId) {
              await check();
              let value;
              try { value = await sources.readDocument(scope, { documentId }); }
              catch (error) {
                // read_slot represents an owner who has never uploaded as an
                // empty generation-zero selection without creating a slot.
                // read_document cannot find that slot. Recheck authority and
                // the empty snapshot; a real reset must retain its stale error.
                await check();
                if (error.code === '55000' && error.message === 'RAG document unavailable') {
                  throw failure('RAG_DOCUMENT_NOT_FOUND', 'Owned document unavailable', 404);
                }
                if (error.code === '55000' && error.message === 'RAG resource generation stale'
                    && scope.resourceGeneration === '0' && current.selectionVersion === '0'
                    && current.documentId === null && current.document === null) {
                  const fresh = await sources.read(identity);
                  await check();
                  if (fresh.resourceGeneration === '0' && fresh.selectionVersion === '0'
                      && fresh.documentId === null && fresh.document === null) {
                    throw failure('RAG_DOCUMENT_NOT_FOUND', 'Owned document unavailable', 404);
                  }
                }
                throw error;
              }
              await check();
              return value;
            } });
        },
        async retireDocument(execution, { family = 'RAG', slot = 'current', documentId, operationId }) {
          if(execution?.ownerKey!==JSON.stringify([family,String(ownerId)]))throw failure('RAG_RESET_REQUIRED','Reset owner mismatch');
          const {check,sources}=forExecution(execution);await check();const identity=coordinate(family,slot),current=await sources.read(identity);
          return sources.retireDocument({...identity,graphGeneration:canonicalDurableGeneration(execution.durableGeneration),resourceGeneration:current.resourceGeneration},{documentId,operationId});
        },
        async reset(execution, { family = 'RAG', slots = slotsFor(family), operationId, targetOwnerId = ownerId, afterErase } = {}) {
          if (!positive(targetOwnerId) || execution?.ownerKey !== JSON.stringify([family, String(targetOwnerId)])) throw failure('RAG_RESET_REQUIRED', 'Reset owner does not match authenticated resource');
          const graphGeneration = canonicalDurableGeneration(execution.durableGeneration);
          if (!Array.isArray(slots) || !slots.length || new Set(slots).size !== slots.length || slots.some(slot => !slotsFor(family).includes(slot))) throw new TypeError('Invalid reset slots');
          const { check, sources } = forExecution(execution);const leaseToken=randomUUID();
          const binding={actorOwnerId:ownerId,actorSessionId:platformSessionId,ownerId:targetOwnerId,family,graphGeneration};
          await check();const journal=await sources.beginReset(binding,{operationId,leaseToken,slots});await check();
          const result=await sources.applyReset(binding,{operationId,leaseToken});await check();
          if(journal.state!=='completed'){
            if(afterErase!==undefined){if(typeof afterErase!=='function')throw new TypeError('Reset continuation required');await afterErase();await check();}
            await sources.finishReset(binding,{operationId,leaseToken});await check();
          }
          return result;
        },
      });
    },
    async deleteOwner(binding) {
      requireReady();
      // SQL requires the canonical running deletion job and current lease.
      const sources = sourceFactory(pool, { checkCurrent: async () => {}, getChunkPipelineFingerprint: () => CHUNK_PIPELINE_FINGERPRINT });
      return sources.deleteOwner(binding);
    },
  });
}
module.exports = { createWorkshopRagComposition };
