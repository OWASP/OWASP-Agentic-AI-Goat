'use strict';

const { createHash } = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');
const { createRequire } = require('node:module');
const { constants } = require('node:fs');

const MODEL = 'Xenova/all-MiniLM-L6-v2';
const ASSETS = Object.freeze(['config.json', 'onnx/model_quantized.onnx', 'tokenizer.json', 'tokenizer_config.json']);
const unavailable = () => Object.assign(new Error('Embedding runtime provenance is unavailable'), { code: 'EMBEDDING_FINGERPRINT_UNAVAILABLE' });

async function loadInstalledRuntime() {
  const transformers = await import('@huggingface/transformers');
  // Resolve ONNX from the actual Transformers entry, including nested installs.
  const fromTransformers = createRequire(require.resolve('@huggingface/transformers'));
  const onnx = fromTransformers('onnxruntime-node');
  const tokenizerEntry = fromTransformers.resolve('@huggingface/tokenizers');
  const tokenizerPackage = JSON.parse(await fs.readFile(
    path.resolve(path.dirname(tokenizerEntry), '../package.json'), 'utf8'));
  if (tokenizerPackage.name !== '@huggingface/tokenizers') throw unavailable();
  return { transformersVersion: transformers.env.version,
    tokenizersVersion: tokenizerPackage.version,
    onnxVersion: onnx.env.versions.node,
    cacheDirectory: process.env.XENOVA_CACHE || process.env.TRANSFORMERS_CACHE || transformers.env.cacheDir };
}

function deepFreeze(value) {
  for (const child of Object.values(value)) if (child && typeof child === 'object') deepFreeze(child);
  return Object.freeze(value);
}

// Internal composition dependency only. No request input or caller-provided
// fingerprint is accepted by snapshot(). This records files observed now; future
// pipeline integration must bracket loading with matching snapshots before using
// it as an attestation of the assets actually loaded into a session.
function createEmbeddingRuntimeFingerprinter({ loadRuntime = loadInstalledRuntime } = {}) {
  if (typeof loadRuntime !== 'function') throw new TypeError('Runtime loader required');
  return Object.freeze({
    async snapshot(...args) {
      if (args.length) throw new TypeError('Embedding provenance accepts no request arguments');
      try {
        const runtime = await loadRuntime();
        if (!runtime || !['transformersVersion', 'tokenizersVersion', 'onnxVersion'].every(key =>
          typeof runtime[key] === 'string' && /^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$/.test(runtime[key]))
          || typeof runtime.cacheDirectory !== 'string' || !path.isAbsolute(runtime.cacheDirectory)) throw unavailable();
        const root = await fs.realpath(path.join(runtime.cacheDirectory, MODEL));
        const assets = [];
        for (const name of ASSETS) {
          const filename = await fs.realpath(path.join(root, name));
          if (!filename.startsWith(root + path.sep)) throw unavailable();
          const handle = await fs.open(filename, constants.O_RDONLY | constants.O_NOFOLLOW);
          try {
            const before = await handle.stat({ bigint: true });
            if (!before.isFile() || before.size < 1n || before.size > 67108864n) throw unavailable();
            const data = await handle.readFile();
            const after = await handle.stat({ bigint: true });
            if (before.size !== BigInt(data.length) || before.size !== after.size
              || before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs) throw unavailable();
            assets.push({ path: name, bytes: data.length, sha256: createHash('sha256').update(data).digest('hex') });
          } finally { await handle.close(); }
        }
        // Fixed property/asset order is the canonical encoding; paths and cache
        // locations are deliberately absent so relocations do not change identity.
        const description = { schemaVersion: 2, model: MODEL, dimension: 384,
          dtype: 'q8', pooling: 'mean', normalization: 'l2', backend: 'onnxruntime-node:cpu',
          transformersVersion: runtime.transformersVersion, tokenizersVersion: runtime.tokenizersVersion,
          onnxVersion: runtime.onnxVersion,
          platform: process.platform, architecture: process.arch, assets };
        return deepFreeze({ fingerprint: createHash('sha256').update(JSON.stringify(description)).digest('hex'), description });
      } catch (error) {
        if (error.code === 'EMBEDDING_FINGERPRINT_UNAVAILABLE') throw error;
        throw unavailable(); // Do not expose cache/host paths to consumers.
      }
    },
  });
}

module.exports = { createEmbeddingRuntimeFingerprinter };
