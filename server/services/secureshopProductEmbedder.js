'use strict';

const IDENTITY = Object.freeze({ embeddingModel: 'Xenova/all-MiniLM-L6-v2:q8:mean:l2:v1', embeddingDimension: 384 });

// Share the installer-verified CPU pipeline, but never access the RAG store's
// documents or session maps. Cancellation drains inference before returning.
function createSecureShopProductEmbedder({ store } = {}) {
  store ||= require('./ragVectorStore');
  if (typeof store.init !== 'function' || typeof store.embedText !== 'function') {
    throw new TypeError('Product embedding pipeline required');
  }
  return Object.freeze({ identity: IDENTITY,
    getRuntimeFingerprint: () => typeof store.getRuntimeFingerprint === 'function' ? store.getRuntimeFingerprint() : null,
    async embed(text, { signal } = {}) {
      if (typeof text !== 'string' || !text.trim() || Buffer.byteLength(text, 'utf8') > 65536) {
        throw new TypeError('Embedding text must contain 1 to 65536 UTF-8 bytes');
      }
      signal?.throwIfAborted();
      await store.init();
      signal?.throwIfAborted();
      const vector = await store.embedText(text);
      signal?.throwIfAborted();
      if (!(vector instanceof Float32Array) || vector.length !== IDENTITY.embeddingDimension
          || !vector.every(Number.isFinite) || !vector.some(value => value !== 0)) {
        throw Object.assign(new Error('Product embedding pipeline returned invalid output'), { code: 'EMBEDDING_UNAVAILABLE' });
      }
      return Object.freeze({ ...IDENTITY, embedding: Object.freeze(Array.from(vector)) });
    },
  });
}
module.exports = { createSecureShopProductEmbedder, PRODUCT_EMBEDDING_IDENTITY: IDENTITY };
