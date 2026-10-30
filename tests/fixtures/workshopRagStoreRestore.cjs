'use strict';
// Owned native qualification child: no application singleton, dotenv or model provider.
const assert = require('node:assert/strict'), fs = require('node:fs'), path = require('node:path');
const { randomUUID, createHash } = require('node:crypto');
const { Pool } = require('pg');
(async () => {
  assert.equal(process.env.PG_TEST_DISPOSABLE, 'yes');
  assert.equal(fs.realpathSync(process.cwd()), fs.realpathSync(process.env.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE));
  const input = JSON.parse(process.argv[2]);
  const url = new URL(process.env.WORKSHOP_RAG_RUNTIME_URL); assert.equal(url.hostname, '127.0.0.1');
  assert.equal(url.username, 'dvaia_identity_runtime'); assert.match(url.pathname, /^\/owasp_ai_goat_test_workshop_rag_[a-f0-9]+$/);
  const pool = new Pool({ connectionString: url.href, max: 2, statement_timeout: 10000 });
  try {
    const { createWorkshopRagStore, CHUNK_PIPELINE_FINGERPRINT } = require('../../server/services/workshopRagStore');
    const checkCurrent = async () => {};
    let embedder;
    if (process.env.WORKSHOP_RAG_ACTUAL_EMBEDDING === '1') {
      assert.equal(process.env.HF_HUB_OFFLINE, '1'); assert.equal(process.env.TRANSFORMERS_OFFLINE, '1');
      assert.ok(fs.realpathSync(process.env.XENOVA_CACHE).startsWith(fs.realpathSync(process.cwd()) + path.sep));
      embedder = require('../../server/services/secureshopProductEmbedder').createSecureShopProductEmbedder();
    } else {
      assert.match(input.runtimeFingerprint, /^[a-f0-9]{64}$/);
      embedder = { getRuntimeFingerprint: () => ({ fingerprint: input.runtimeFingerprint }), embed: async () => ({ embeddingDimension: 384, embedding: Array.from({ length: 384 }, (_, i) => i === 0 ? 1 : 0) }) };
    }
    const repository = require('../../server/database/postgres/workshopRagRepository').createWorkshopRagRepository(pool, { checkCurrent, getChunkPipelineFingerprint: () => CHUNK_PIPELINE_FINGERPRINT });
    const revisions = require('../../server/database/postgres/workshopRagRevisionRepository').createWorkshopRagRevisionRepository(pool, { checkCurrent, getRuntimeFingerprint: () => embedder.getRuntimeFingerprint()?.fingerprint });
    const bound = createWorkshopRagStore({ repository, revisions, embedder, checkCurrent }).bind(input.scope);
    const restored = await bound.state(); assert.equal(restored.documentId, input.documentId);
    const result = await bound.search({ documentId: input.documentId, question: 'What is the policy?', operationId: randomUUID() });
    assert.equal(result.receipt.revisionId, input.revisionId);
    console.log(JSON.stringify({ kind: 'independent-process-restore', pid: process.pid, documentId: restored.documentId,
      sourceSha256: createHash('sha256').update(restored.document.sourceText).digest('hex'), revisionId: result.receipt.revisionId,
      chunkCount: result.chunks.length, runtimeFingerprint: embedder.getRuntimeFingerprint().fingerprint }));
  } finally { await pool.end(); }
})().catch(error => { console.error(JSON.stringify({ name: error.name, code: error.code || null })); process.exitCode = 1; });
