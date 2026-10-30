'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { createEmbeddingRuntimeFingerprinter } = require('../server/services/embeddingRuntimeFingerprint');

async function fixture(t) {
  const cacheDirectory = await fs.mkdtemp(path.join(os.tmpdir(), 'owasp-ai-goat-embedding-fingerprint-'));
  t.after(() => fs.rm(cacheDirectory, { recursive: true, force: true }));
  const model = path.join(cacheDirectory, 'Xenova/all-MiniLM-L6-v2');
  await fs.mkdir(path.join(model, 'onnx'), { recursive: true });
  for (const name of ['config.json', 'tokenizer.json', 'tokenizer_config.json', 'onnx/model_quantized.onnx']) await fs.writeFile(path.join(model, name), `fictional:${name}`);
  const runtime = { cacheDirectory, transformersVersion: '4.2.0', tokenizersVersion: '0.1.3', onnxVersion: '1.24.3' };
  return { runtime, model, reader: createEmbeddingRuntimeFingerprinter({ loadRuntime: async () => runtime }) };
}

test('canonical snapshot is deterministic, deeply immutable and cache-location independent', async t => {
  const a = await fixture(t), b = await fixture(t);
  const first = await a.reader.snapshot();
  assert.deepEqual(first, await a.reader.snapshot());
  assert.deepEqual(first, await b.reader.snapshot());
  assert.match(first.fingerprint, /^[a-f0-9]{64}$/);
  assert.equal(first.description.platform, process.platform);
  assert.equal(first.description.architecture, process.arch);
  assert.equal(first.description.backend, 'onnxruntime-node:cpu');
  assert.equal(first.description.assets.length, 4);
  assert.equal(first.description.schemaVersion, 2);
  assert.equal(first.description.tokenizersVersion, '0.1.3');
  assert.throws(() => { first.description.assets[0].sha256 = 'forged'; }, TypeError);
  assert.ok(!JSON.stringify(first).includes(a.runtime.cacheDirectory));
});

test('runtime and asset changes produce new fingerprints without stale caching', async t => {
  const { reader, runtime, model } = await fixture(t);
  const fingerprints = [(await reader.snapshot()).fingerprint];
  runtime.transformersVersion = '4.3.0'; fingerprints.push((await reader.snapshot()).fingerprint);
  runtime.onnxVersion = '1.30.0'; fingerprints.push((await reader.snapshot()).fingerprint);
  runtime.tokenizersVersion = '0.2.0'; fingerprints.push((await reader.snapshot()).fingerprint);
  await fs.writeFile(path.join(model, 'onnx/model_quantized.onnx'), 'changed fictional weights');
  fingerprints.push((await reader.snapshot()).fingerprint);
  assert.equal(new Set(fingerprints).size, 5);
});

test('missing assets and unavailable runtime metadata fail closed without host paths', async t => {
  const { reader, model, runtime } = await fixture(t);
  await fs.unlink(path.join(model, 'tokenizer.json'));
  await assert.rejects(reader.snapshot(), error => error.code === 'EMBEDDING_FINGERPRINT_UNAVAILABLE' && !error.message.includes(model));
  runtime.transformersVersion = 'unknown';
  await assert.rejects(reader.snapshot(), { code: 'EMBEDDING_FINGERPRINT_UNAVAILABLE' });
});

test('snapshot rejects request-supplied metadata before invoking the runtime loader', async () => {
  let calls = 0;
  const reader = createEmbeddingRuntimeFingerprinter({ loadRuntime: async () => { calls++; } });
  await assert.rejects(reader.snapshot({ fingerprint: 'forged', cacheDirectory: '/private' }), TypeError);
  assert.equal(calls, 0);
});

test('asset links escaping the owned model tree fail closed', async t => {
  const a = await fixture(t), b = await fixture(t);
  const asset = path.join(a.model, 'tokenizer.json');
  await fs.unlink(asset); await fs.symlink(path.join(b.model, 'tokenizer.json'), asset);
  await assert.rejects(a.reader.snapshot(), { code: 'EMBEDDING_FINGERPRINT_UNAVAILABLE' });
});
