'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const { createSecureShopProductEmbedder } = require('../server/services/secureshopProductEmbedder');
test('product embedding uses only pure pipeline output and preserves stable model identity', async () => {
  const vector = new Float32Array(384); vector[0] = 1;
  let input;
  const store = { init: async () => {}, embedText: async value => { input = value; return vector; },
    get sessions() { throw Error('document session access forbidden'); } };
  const embedder = createSecureShopProductEmbedder({ store });
  const result = await embedder.embed('authentic owned manual text');
  assert.equal(input, 'authentic owned manual text'); assert.deepEqual(result.embedding, Array.from(vector));
  assert.equal(result.embeddingModel, embedder.identity.embeddingModel);
  vector[0] = 0; assert.equal(result.embedding[0], 1);
});
test('malformed model output never receives a fabricated embedding fallback', async () => {
  for (const value of [new Float32Array(384), new Float32Array(3), Array(384).fill(1), new Float32Array(384).fill(NaN)]) {
    const embedder = createSecureShopProductEmbedder({ store: { init: async () => {}, embedText: async () => value } });
    await assert.rejects(embedder.embed('text'), { code: 'EMBEDDING_UNAVAILABLE' });
  }
});
test('cancellation drains active inference and rejects its result', async () => {
  const controller = new AbortController(); let release, entered;
  const started = new Promise(resolve => { entered = resolve; });
  const store = { init: async () => {}, embedText: async () => { entered(); return new Promise(resolve => { release = resolve; }); } };
  const pending = createSecureShopProductEmbedder({ store }).embed('text', { signal: controller.signal });
  await started; controller.abort(); release(new Float32Array(384).fill(1));
  await assert.rejects(pending, { name: 'AbortError' });
});

test('reindex accepts exact stored-body byte limit without truncation and rejects overflow', async () => {
  const text = 'é'.repeat(32768);
  let received;
  const store = { init: async () => {}, embedText: async value => { received = value; return new Float32Array(384).fill(1); } };
  const embedder = createSecureShopProductEmbedder({ store });
  await embedder.embed(text);
  assert.equal(received, text);
  assert.equal(Buffer.byteLength(received), 65536);
  await assert.rejects(embedder.embed(text + 'a'), /65536 UTF-8 bytes/);
  assert.equal(received, text);
});
