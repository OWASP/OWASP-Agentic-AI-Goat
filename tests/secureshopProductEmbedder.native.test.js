'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createSecureShopProductEmbedder } = require('../server/services/secureshopProductEmbedder');
const { RagVectorStore } = require('../server/services/ragVectorStore');

test('product embeddings use the actual cached CPU pipeline without accessing document stores', {
  skip: process.env.RUN_PRODUCT_EMBEDDER_NATIVE !== '1', timeout: 120000,
}, async () => {
  assert.equal(process.env.HF_HUB_OFFLINE, '1', 'qualification must use the installed cache offline');
  assert.ok(process.env.XENOVA_CACHE, 'installed embedding cache is required');
  const store = new RagVectorStore();
  const poison = () => { throw new Error('Product embedder accessed shared document state'); };
  for (const key of ['sessions', 'sessionMetadata', 'lastSessionByUser']) {
    Object.defineProperty(store, key, { get: poison });
  }
  try {
    const embedder = createSecureShopProductEmbedder({ store });
    const first = await embedder.embed('Insulated steel travel mug with a spill-resistant lid.');
    const second = await embedder.embed('Wireless keyboard with rechargeable battery.');
    assert.equal(first.embeddingDimension, 384);
    assert.equal(first.embeddingModel, embedder.identity.embeddingModel);
    assert.equal(first.embedding.length, 384);
    assert.ok(first.embedding.every(Number.isFinite));
    const norm = Math.sqrt(first.embedding.reduce((sum, value) => sum + value * value, 0));
    assert.ok(Math.abs(norm - 1) < 0.001);
    assert.notDeepEqual(first.embedding, second.embedding);
    const again = await embedder.embed('Insulated steel travel mug with a spill-resistant lid.');
    assert.deepEqual(again.embedding, first.embedding);
  } finally {
    await store.embedder?.dispose?.();
  }
});
