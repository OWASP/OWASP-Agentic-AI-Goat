'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { RagVectorStore } = require('../server/services/ragVectorStore');

test('embedding initialization is shared and retains model, quantization, pooling and normalization', async () => {
  let loads = 0;
  const store = new RagVectorStore({ loadTransformers: async () => ({ env: {}, pipeline: async (task, model, options) => {
    loads++;
    assert.equal(task, 'feature-extraction');
    assert.equal(model, 'Xenova/all-MiniLM-L6-v2');
    assert.equal(options.dtype, 'q8');
    assert.equal(options.device, 'cpu');
    return async (_text, config) => {
      assert.deepEqual(config, { pooling: 'mean', normalize: true });
      return { data: Float32Array.from([1, 0]) };
    };
  } }) });
  await Promise.all([store.init(), store.init(), store.init()]);
  assert.equal(loads, 1);
  assert.deepEqual(await store.embedText('fixture'), Float32Array.from([1, 0]));
});

test('failed embedding initialization can retry without claiming readiness', async () => {
  let attempts = 0;
  const store = new RagVectorStore({ loadTransformers: async () => {
    if (++attempts === 1) throw new Error('temporary load failure');
    return { env: {}, pipeline: async () => async () => ({ data: Float32Array.from([1]) }) };
  } });
  await assert.rejects(store.init(), /temporary load failure/);
  assert.equal(store.modelReady, false);
  await store.init();
  assert.equal(store.modelReady, true);
});

test('startup recovery shares one bounded retry sequence and becomes ready after transient failure',async()=>{
 let calls=0;const waits=[];
 const store=new RagVectorStore({loadTransformers:async()=>{if(++calls<3)throw Error('temporary');return{env:{},pipeline:async()=>async()=>({data:[1]})};}});
 const options={delayMs:5,delay:async ms=>{waits.push(ms);}};
 await Promise.all([store.initWithRetry(options),store.initWithRetry(options)]);
 assert.equal(calls,3);assert.deepEqual(waits,[5,5]);assert.equal(store.modelReady,true);
});
test('permanent failure exhausts three attempts and pending load never starts a duplicate',async()=>{
 let calls=0,release;
 const store=new RagVectorStore({loadTransformers:async()=>{calls++;throw Error('unavailable');}});
 await assert.rejects(store.initWithRetry({delay:async()=>{}}),/unavailable/);assert.equal(calls,3);assert.equal(store.modelReady,false);
 const pending=new RagVectorStore({loadTransformers:()=>{calls++;return new Promise(resolve=>{release=()=>resolve({env:{},pipeline:async()=>async()=>({data:[1]})});});}});
 const before=calls,a=pending.initWithRetry(),b=pending.initWithRetry();await Promise.resolve();assert.equal(calls,before+1);release();await Promise.all([a,b]);assert.equal(pending.modelReady,true);
});
