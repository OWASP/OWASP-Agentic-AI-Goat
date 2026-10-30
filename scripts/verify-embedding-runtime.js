'use strict';

const path = require('node:path');
const fs = require('node:fs/promises');

async function prepareEmbeddingCache(cacheDirectory) {
  if (typeof cacheDirectory !== 'string' || !path.isAbsolute(cacheDirectory) || cacheDirectory.includes('\0')) {
    throw new Error('An absolute embedding cache directory is required');
  }
  await fs.mkdir(cacheDirectory, { recursive: true, mode: 0o700 });
  const canonical = await fs.realpath(cacheDirectory);
  const original = await fs.stat(canonical);
  if (!original.isDirectory()) throw new Error('Embedding cache must be a directory');
  return Object.freeze({ directory: canonical, async check() {
    const current = await fs.stat(canonical);
    if (await fs.realpath(cacheDirectory) !== canonical || !current.isDirectory()
        || current.dev !== original.dev || current.ino !== original.ino) {
      throw new Error('Embedding cache changed during verification');
    }
  } });
}

async function verifyEmbeddingRuntime({ cacheDirectory, createStore } = {}) {
  if (process.env.NODE_TLS_REJECT_UNAUTHORIZED === '0') throw new Error('TLS verification is required');
  const cache = await prepareEmbeddingCache(cacheDirectory);
  const previousCache = process.env.XENOVA_CACHE;
  process.env.XENOVA_CACHE = cache.directory;
  let store;
  try {
    store = createStore ? createStore() : new (require('../server/services/ragVectorStore').RagVectorStore)();
    await store.init();
    const vector = await store.embedText('OWASP-AI-GOAT installation verifies local document retrieval.');
    if (!(vector instanceof Float32Array) || vector.length !== 384 || !vector.every(Number.isFinite)
        || !vector.some(value => value !== 0)) throw new Error('Embedding output is invalid');
    await cache.check();
    return Object.freeze({ model: 'Xenova/all-MiniLM-L6-v2', dtype: 'q8', dimensions: 384, cacheDirectory: cache.directory });
  } finally {
    if (previousCache === undefined) delete process.env.XENOVA_CACHE;
    else process.env.XENOVA_CACHE = previousCache;
    await store?.embedder?.dispose?.();
  }
}

if (require.main === module) {
  const args = process.argv.slice(2);
  if (args.length !== 2 || args[0] !== '--cache-dir') {
    console.error('Usage: node --use-system-ca scripts/verify-embedding-runtime.js --cache-dir ABSOLUTE_PATH');
    process.exitCode = 1;
  } else verifyEmbeddingRuntime({ cacheDirectory: args[1] }).then(result => {
    console.log(JSON.stringify(result));
  }).catch(() => {
    console.error('Embedding model verification failed. Check the model cache, download access and trusted system certificates. TLS verification must remain enabled.');
    process.exitCode = 1;
  });
}

module.exports = { verifyEmbeddingRuntime, prepareEmbeddingCache };
