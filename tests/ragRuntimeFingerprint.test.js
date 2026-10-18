'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { RagVectorStore } = require('../server/services/ragVectorStore');
const { createSecureShopProductEmbedder } = require('../server/services/secureshopProductEmbedder');
const snapshot = fingerprint => Object.freeze({ fingerprint, description: Object.freeze({}) });
function setup(values, { disposeFailure = false } = {}) {
  const events = [];
  const store = new RagVectorStore({ runtimeFingerprinter: { snapshot: async () => {
    events.push('snapshot'); const value = values.shift(); if (value instanceof Error) throw value; return value;
  } }, loadTransformers: async () => ({ env: {}, pipeline: async (_task, _model, options) => {
    events.push(options.local_files_only ? 'offline' : 'download');
    const pipeline = async () => ({ data: new Float32Array(384).fill(1) });
    pipeline.dispose = async () => { events.push('dispose'); if (disposeFailure) throw Error('disposal failed'); };
    return pipeline;
  } }) });
  return { store, events };
}
test('stable verified session exposes immutable metadata without changing legacy embedding contract', async () => {
  const { store, events } = setup([snapshot('same'), snapshot('same')]);
  const embedder = createSecureShopProductEmbedder({ store });
  assert.equal(embedder.getRuntimeFingerprint(), null);
  await Promise.all([store.init(), store.init()]);
  const first = embedder.getRuntimeFingerprint(); await store.init();
  assert.equal(embedder.getRuntimeFingerprint(), first);
  assert.deepEqual(events, ['snapshot', 'offline', 'snapshot']);
  const result = await embedder.embed('fictional text');
  assert.deepEqual(Object.keys(result).sort(), ['embedding', 'embeddingDimension', 'embeddingModel']);
});
test('changed assets or runtime dispose rejected pipeline and never claim readiness', async () => {
  const { store, events } = setup([snapshot('before'), snapshot('after')]);
  await assert.rejects(store.init(), { code: 'EMBEDDING_FINGERPRINT_CHANGED' });
  assert.equal(store.modelReady, false); assert.equal(store.embedder, null);
  assert.equal(store.getRuntimeFingerprint(), null);
  assert.deepEqual(events, ['snapshot', 'offline', 'snapshot', 'dispose']);
});
test('first download drains before stable offline reload', async t => {
  const keys = ['HF_HUB_OFFLINE', 'TRANSFORMERS_OFFLINE'];
  const previous = keys.map(key => process.env[key]);
  t.after(() => keys.forEach((key, index) => { if (previous[index] === undefined) delete process.env[key]; else process.env[key] = previous[index]; }));
  keys.forEach(key => { delete process.env[key]; });
  const missing = Object.assign(Error('missing'), { code: 'EMBEDDING_FINGERPRINT_UNAVAILABLE' });
  const { store, events } = setup([missing, snapshot('same'), snapshot('same')]);
  await store.init();
  assert.deepEqual(events, ['snapshot', 'download', 'dispose', 'snapshot', 'offline', 'snapshot']);
  assert.equal(store.getRuntimeFingerprint().fingerprint, 'same');
});
test('failed disposal prevents retry from overlapping a leaked allocation', async () => {
  const { store, events } = setup([snapshot('before'), snapshot('after')], { disposeFailure: true });
  await assert.rejects(store.init(), /disposal failed/);
  await assert.rejects(store.init(), /disposal failed/);
  assert.equal(events.filter(x => x === 'offline').length, 1);
  assert.equal(store.getRuntimeFingerprint(), null);
});
test('injected fixture pipeline remains unverified without an explicit internal hook', async () => {
  const store = new RagVectorStore({ loadTransformers: async () => ({ env: {}, pipeline: async () => async () => ({ data: [1] }) }) });
  await store.init(); assert.equal(store.getRuntimeFingerprint(), null);
});

test('offline startup with missing attested assets never attempts a download', async t => {
  const previous = process.env.HF_HUB_OFFLINE;
  t.after(() => { if (previous === undefined) delete process.env.HF_HUB_OFFLINE; else process.env.HF_HUB_OFFLINE = previous; });
  process.env.HF_HUB_OFFLINE = '1';
  const missing = Object.assign(Error('missing'), { code: 'EMBEDDING_FINGERPRINT_UNAVAILABLE' });
  const { store, events } = setup([missing]);
  await assert.rejects(store.init(), { code: 'EMBEDDING_FINGERPRINT_UNAVAILABLE' });
  assert.deepEqual(events, ['snapshot']);
  assert.equal(store.getRuntimeFingerprint(), null);
});
