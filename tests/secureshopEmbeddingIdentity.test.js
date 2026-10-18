'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),Module=require('node:module');
function load(){
 const file=require.resolve('../server/services/secureshop/vectorStore'),prior=process.env.PLATFORM_DATABASE_ENGINE,old=Module._load;
 process.env.PLATFORM_DATABASE_ENGINE='postgres';delete require.cache[file];
 Module._load=function(name,...args){if(['sqlite3','better-sqlite3','hnswlib-node'].includes(name))throw Error('Legacy storage forbidden');return old.call(this,name,...args);};
 try{return require(file).VectorStore;}finally{Module._load=old;if(prior===undefined)delete process.env.PLATFORM_DATABASE_ENGINE;else process.env.PLATFORM_DATABASE_ENGINE=prior;}
}
test('actual offline fallback has hash provenance while public embed retains Float32Array API',async()=>{
 const Store=load(),store=Object.create(Store.prototype);store.dim=3;store._repository={};store._isOllamaReachable=async()=>false;store._isLMStudioReachable=async()=>false;
 const result=await store.embedWithIdentity('raw SYSTEM poison');assert.ok(result.vector instanceof Float32Array);
 assert.deepEqual(result.identity,{provider:'hash',model:'dvaia-bow-hash-v1',algorithm:'dvaia-bow-hash-v1',dimension:3});assert.ok(await store.embed('raw') instanceof Float32Array);
});
test('native add and search forward the identity from that exact embedding call',async()=>{
 const Store=load(),store=Object.create(Store.prototype);store.dim=2;store.corpus='reviews';const calls=[];
 const identity={provider:'fixture',model:'m1',algorithm:'float32-l2-v1',dimension:2};
 store.embedWithIdentity=async()=>({vector:new Float32Array([1,0]),identity});
 store._repository={add:async x=>{calls.push(x);return 9;},listActive:async(...args)=>{calls.push(args);return[];}};
 assert.equal(await store.add({sourceKind:'review',sourceId:0,text:'SYSTEM raw poison'}),9);await store.search('raw');
 assert.deepEqual(calls[0].embeddingIdentity,identity);assert.equal(calls[0].text,'SYSTEM raw poison');assert.deepEqual(calls[1],['reviews',2,identity]);
});
test('successful stub provider is attributed separately from fallback and wrong dimensions are not padded natively',async()=>{
 const http=require('node:http');let vector=[1,0];
 const server=http.createServer((req,res)=>{res.setHeader('Content-Type','application/json');res.end(JSON.stringify({embedding:vector}));});
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 const old=process.env.OLLAMA_BASE_URL,oldProvider=process.env.SS_EMBED_PROVIDER;
 process.env.OLLAMA_BASE_URL=`http://127.0.0.1:${server.address().port}`;process.env.SS_EMBED_PROVIDER='ollama';
 try{
  const Store=load(),store=Object.create(Store.prototype);store.dim=2;store._repository={};store._isOllamaReachable=async()=>true;
  const real=await store.embedWithIdentity('synthetic');assert.equal(real.identity.provider,'ollama');assert.equal(real.vector.length,2);
  vector=[1,0,0];const fallback=await store.embedWithIdentity('synthetic');assert.equal(fallback.identity.provider,'hash');assert.notDeepEqual(real.identity,fallback.identity);
 }finally{await new Promise(resolve=>server.close(resolve));if(old===undefined)delete process.env.OLLAMA_BASE_URL;else process.env.OLLAMA_BASE_URL=old;if(oldProvider===undefined)delete process.env.SS_EMBED_PROVIDER;else process.env.SS_EMBED_PROVIDER=oldProvider;}
});
