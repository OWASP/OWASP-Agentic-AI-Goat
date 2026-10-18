'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {RagVectorStore}=require('../server/services/ragVectorStore');
test('uninitialized real embedding store exposes actionable service readiness error',async()=>{
 const store=new RagVectorStore({loadTransformers:()=>{throw Error('must not load model');}});
 await assert.rejects(store.embedText('synthetic'),error=>error.code==='RAG_EMBEDDING_NOT_READY'&&error.status===503&&/health/.test(error.message));
});
test('explicit offline flags disable remote model loading before pipeline construction',async()=>{
 const previous={HF_HUB_OFFLINE:process.env.HF_HUB_OFFLINE,TRANSFORMERS_OFFLINE:process.env.TRANSFORMERS_OFFLINE};
 try {
  for(const flag of Object.keys(previous)){
   delete process.env.HF_HUB_OFFLINE;delete process.env.TRANSFORMERS_OFFLINE;process.env[flag]='1';
   const env={allowRemoteModels:true};let calls=0;
   const store=new RagVectorStore({loadTransformers:async()=>({env,pipeline:async()=>{
    calls++;assert.equal(env.allowRemoteModels,false);return async()=>[];
   }})});
   await store.init();assert.equal(calls,1);assert.equal(store.modelReady,true);
  }
 } finally {
  for(const [key,value]of Object.entries(previous)){
   if(value===undefined)delete process.env[key];else process.env[key]=value;
  }
 }
});
