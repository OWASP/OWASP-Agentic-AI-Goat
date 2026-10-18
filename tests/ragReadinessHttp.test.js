'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),Module=require('node:module'),path=require('node:path');
const express=require('express'),routePath=path.resolve(__dirname,'../server/routes/ragInjection.js'),load=Module._load;
let failure=null;let runs=0;let provider='openai';let providerStatus={available:false};
const ai={getActiveProviderInfo:()=>({provider,model:'fixture'}),verifyProviderConnection:async name=>{assert.equal(name,provider);return providerStatus;}};
Module._load=function(name,parent,...rest){
 if(/authDb|sqlite|database\/postgres/.test(name))throw Error('Database import forbidden');
 if(parent?.filename===routePath){
  if(name==='../middleware/adminAuth')return{authenticateToken:(req,res,next)=>{req.user={id:1};next();}};
  if(name==='../agent-runtime/runCoordinator')return{createRunCoordinator:()=>({run:async()=>{runs++;if(failure)throw failure;return{success:true};}})};
  if(name==='../services/ragVectorStore')return{modelReady:true,getActiveSessionsCount:()=>0,getSessionInfo:()=>({exists:true,filename:'fixture.txt'})};
  if(name==='../services/multiProviderAIService')return ai;
  if(name==='../services/ragProgressStore')return{createDefaultRagProgressStore:()=>({})};
 }
 return load.call(this,name,parent,...rest);
};
const router=require(routePath);
test.after(()=>{Module._load=load;});
test('RAG upload and query map only typed embedding readiness failures to 503',async()=>{
 const app=express();app.use(express.json());app.use(router);const server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});const base=`http://127.0.0.1:${server.address().port}`;
 try{for(const endpoint of ['upload','query'])for(const kind of ['ready','unready','ordinary']){
  failure=kind==='ready'?null:Object.assign(new Error(kind==='unready'?'RAG embedding model is not ready. Check RAG health and retry after initialization completes.':'fixture failure'),kind==='unready'?{code:'RAG_EMBEDDING_NOT_READY'}:{});
  let body,headers={};if(endpoint==='upload'){body=new FormData();body.append('document',new Blob(['synthetic policy']),'fixture.txt');}else{headers['content-type']='application/json';body=JSON.stringify({session_id:'123e4567-e89b-42d3-a456-426614174000',question:'policy?'});}
  const response=await fetch(base+'/'+endpoint,{method:'POST',headers,body}),data=await response.json();assert.equal(response.status,kind==='ready'?200:kind==='unready'?503:500);assert.equal(data.code,kind==='unready'?'RAG_EMBEDDING_NOT_READY':undefined);assert.equal(data.stack,undefined);
 }}finally{await new Promise(resolve=>server.close(resolve));}
});

test('RAG blank queries are rejected before agent execution',async()=>{
 const app=express();app.use(express.json());app.use(router);
 const server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});
 const before=runs;
 try {for(const question of ['', '  ', '\n\t', null, 42]) {
  const response=await fetch(`http://127.0.0.1:${server.address().port}/query`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({session_id:'123e4567-e89b-42d3-a456-426614174000',question})});
  assert.equal(response.status,400);await response.json();
 }assert.equal(runs,before);} finally {await new Promise(resolve=>server.close(resolve));}
});

test('RAG health verifies cloud readiness and never reports mock as a working LLM',async()=>{
 const app=express();app.use(router);const server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});
 try {for(const [name,status,ready] of [['openai',{available:false},false],['openai',{available:true},true],['mock',{available:true,mocked:true},false]]) {
 provider=name;providerStatus=status;
 const response=await fetch(`http://127.0.0.1:${server.address().port}/health`);const body=await response.json();
 assert.equal(body.embeddingReady,true);assert.equal(body.llmReady,ready);assert.equal(body.status,ready?'ok':'degraded');
 }}finally{await new Promise(resolve=>server.close(resolve));}
});

test('RAG rejects non-text uploads before execution and accepts UTF-8 txt with browser MIME types',async()=>{
 const app=express();app.use(router);const server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});failure=null;
 try{
  for(const [name,type,bytes,status] of [
   ['payload.pdf','text/plain',Buffer.from('%PDF-1.7'),400],
   ['binary.txt','text/plain',Buffer.from([0xff,0xfe,0x61]),400],
   ['nul.txt','text/plain',Buffer.from('hello\0world'),400],
   ['policy.TXT','application/octet-stream',Buffer.from('Remboursement café — vendredi.'),200],
   ['policy.txt','text/plain',Buffer.from('Ordinary policy.'),200]
  ]){
   const before=runs,body=new FormData();body.append('document',new Blob([bytes],{type}),name);
   const response=await fetch(`http://127.0.0.1:${server.address().port}/upload`,{method:'POST',body});await response.json();
   assert.equal(response.status,status,name);assert.equal(runs-before,status===200?1:0,name);
  }
 }finally{await new Promise(resolve=>server.close(resolve));}
});
