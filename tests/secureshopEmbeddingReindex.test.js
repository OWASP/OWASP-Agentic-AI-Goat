'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createSecureShopEmbeddingReindex } = require('../server/services/secureshopEmbeddingReindex');
const id = '11111111-1111-4111-8111-111111111111';
const scope = { launchId:id,scenarioId:id,generation:1,platformOwnerId:1,platformSessionId:2 };
const binding = {...scope,targetId:id};
const hash = 'a'.repeat(64), other = 'b'.repeat(64);
function fixture(options={}) {
  const calls = [], state = { runtime: options.initialRuntime === undefined ? hash : options.initialRuntime };
  const documents = ['product','manual'].map((sourceKind,index)=>({sourceKind,sourceId:String(index+1),chunkIndex:0,text:index ? 'Actual retained poisoned manual instruction' : 'Instructor-edited product text',sourceSha256:hash}));
  const snapshot = {sourceSetDigest:hash,expectedHead:null,documents};
  const repository = { snapshot:async()=>snapshot, publish:async(_binding,input)=>{calls.push(input);return {revisionId:input.operationId};} };
  const embedder = {getRuntimeFingerprint:()=>state.runtime===null ? null : {fingerprint:state.runtime},embed:async(text)=>{state.runtime ||= hash;return {embeddingDimension:384,embedding:Array(384).fill(1)};}};
  const service = createSecureShopEmbeddingReindex({repository,embedder,checkCurrent:async()=>{if(state.retired)throw Error('retired');}});
  return {service,repository,embedder,state,calls,snapshot,input:{scope,binding,operationId:id}};
}
test('reindex retains original product/manual bodies and binds all vectors to one attested runtime',async()=>{
 const f=fixture({initialRuntime:null}), seen=[];const embed=f.embedder.embed;f.embedder.embed=async text=>{seen.push(text);return embed(text);};
 assert.deepEqual(await f.service.reindex(f.input),{revisionId:id});
 assert.deepEqual(seen,f.snapshot.documents.map(r=>r.text));assert.equal(f.calls.length,1);
 assert.equal(f.calls[0].expectedRuntimeFingerprint,hash);assert.equal(f.calls[0].sourceSetDigest,hash);
 assert.deepEqual(f.calls[0].documents.map(r=>r.sourceKind),['product','manual']);assert.ok(Object.isFrozen(f.calls[0].documents[0].embedding));
});
test('runtime change between source embeddings never publishes mixed vectors',async()=>{
 const f=fixture();let n=0;f.embedder.embed=async()=>{if(++n===2)f.state.runtime=other;return {embeddingDimension:384,embedding:Array(384).fill(1)};};
 await assert.rejects(f.service.reindex(f.input),{code:'EMBEDDING_RUNTIME_CHANGED'});assert.equal(f.calls.length,0);
});
test('cancelled inference drains and owner retirement prevents late publication',async()=>{
 for(const mode of ['abort','retire']){const f=fixture(),controller=new AbortController();f.embedder.embed=async()=>{mode==='abort'?controller.abort():f.state.retired=true;return {embeddingDimension:384,embedding:Array(384).fill(1)};};
 await assert.rejects(f.service.reindex({...f.input,signal:controller.signal}));assert.equal(f.calls.length,0);}
});
test('stale publication rejection is propagated without source rewrites or retry',async()=>{
 const f=fixture();let attempts=0;f.repository.publish=async()=>{attempts++;throw Object.assign(Error('stale'),{code:'STALE_SOURCE'});};
 await assert.rejects(f.service.reindex(f.input),{code:'STALE_SOURCE'});assert.equal(attempts,1);assert.equal(f.snapshot.documents[1].text,'Actual retained poisoned manual instruction');
});
test('bounded admission rejects concurrent work and releases after failure',async()=>{
 const f=fixture();let release;f.repository.snapshot=()=>new Promise(resolve=>{release=resolve;});const running=f.service.reindex(f.input);await new Promise(resolve=>setImmediate(resolve));
 await assert.rejects(f.service.reindex(f.input),{code:'EMBEDDING_REINDEX_BUSY'});release({});await assert.rejects(running,{code:'EMBEDDING_REINDEX_INVALID'});
 f.repository.snapshot=async()=>f.snapshot;await f.service.reindex(f.input);assert.equal(f.calls.length,1);
});
test('foreign binding, duplicate sources, unattested runtime and invalid vectors fail closed',async()=>{
 for(const kind of ['foreign','duplicate','unattested','vector']){const f=fixture();if(kind==='foreign')f.input.binding={...binding,platformOwnerId:3};if(kind==='duplicate')f.snapshot.documents.push(f.snapshot.documents[0]);if(kind==='unattested')f.embedder.getRuntimeFingerprint=()=>null;if(kind==='vector')f.embedder.embed=async()=>({embeddingDimension:384,embedding:Array(384).fill(NaN)});
 await assert.rejects(f.service.reindex(f.input));assert.equal(f.calls.length,0);}
});
test('abort keeps admission occupied until the underlying embedding settles',async()=>{
 const f=fixture(),controller=new AbortController();let release;f.embedder.embed=()=>new Promise(resolve=>{release=resolve;});
 const running=f.service.reindex({...f.input,signal:controller.signal});const rejected=assert.rejects(running,{name:'AbortError'});
 await new Promise(resolve=>setImmediate(resolve));controller.abort();
 await assert.rejects(f.service.reindex(f.input),{code:'EMBEDDING_REINDEX_BUSY'});assert.equal(f.calls.length,0);
 release({embeddingDimension:384,embedding:Array(384).fill(1)});await rejected;assert.equal(f.calls.length,0);
});
test('selective products re-embeds product and preserves manual sibling vector',async()=>{
 const f=fixture();let snapshot={...f.snapshot, expectedHead:id, currentRuntimeFingerprint:hash, documents:f.snapshot.documents.map((row,index)=>({...row,embedding:Array(384).fill(index+2)}))};let published;
 f.repository.snapshotSelective=async(_binding,input)=>{assert.deepEqual(input.sourceKinds,['product','listing']);return snapshot;};f.repository.publish=async(_binding,input)=>{for(const row of input.documents)assert.deepEqual(Object.keys(row).sort(),['embedding','sourceId','sourceKind','sourceSha256','chunkIndex'].sort());published=input;return {revisionId:id};};
 await f.service.reindexSelective({...f.input,corpus:'products'});assert.deepEqual(published.documents.map(row=>row.sourceKind),['product','manual']);assert.equal(published.documents[1].embedding[0],3);assert.equal(published.documents[0].embedding[0],1);
});
test('selective rejects unknown corpora, empty selection, stale sibling and runtime mismatch',async()=>{
 const f=fixture();f.repository.snapshotSelective=async()=>({...f.snapshot,expectedHead:id,currentRuntimeFingerprint:hash,documents:f.snapshot.documents.map(row=>({...row,embedding:Array(384).fill(1)}))});
 await assert.rejects(f.service.reindexSelective({...f.input,corpus:'analytics'}),{code:'EMBEDDING_REINDEX_UNSUPPORTED'});
 f.repository.snapshotSelective=async()=>({...f.snapshot,expectedHead:id,currentRuntimeFingerprint:hash,documents:f.snapshot.documents.map(row=>({...row,sourceKind:'manual',embedding:Array(384).fill(1)}))});await assert.rejects(f.service.reindexSelective({...f.input,corpus:'products'}),{code:'EMBEDDING_REINDEX_NO_SOURCE'});
 f.repository.snapshotSelective=async()=>({...f.snapshot,expectedHead:id,currentRuntimeFingerprint:other,documents:f.snapshot.documents.map(row=>({...row,embedding:Array(384).fill(1)}))});await assert.rejects(f.service.reindexSelective({...f.input,corpus:'products'}),{code:'EMBEDDING_REINDEX_STALE_SOURCE'});
});

test('trusted optional original-scene callback fences async embedding and publication without replacing authority', async () => {
 const f=fixture();let stale=false,checks=0;const embed=f.embedder.embed;
 f.embedder.embed=async text=>{const result=await embed(text);stale=true;return result;};
 await assert.rejects(f.service.reindex({...f.input,beforeEffect:async()=>{checks++;if(stale)throw Object.assign(Error('scene changed'),{code:'SCENE_CHANGED'});}}),{code:'SCENE_CHANGED'});
 assert.ok(checks>=2);assert.equal(f.calls.length,0);
 const g=fixture();await g.service.reindex({...g.input,beforeEffect:async()=>{}});assert.equal(g.calls.length,1);
 await assert.rejects(g.service.reindex({...g.input,beforeEffect:'not trusted code'}),{code:'EMBEDDING_REINDEX_INVALID'});
});
