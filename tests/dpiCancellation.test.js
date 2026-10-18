'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),Module=require('node:module');
test('DPI reset cancellation returns stable409 without provider hints or error logging',async()=>{
 const original=Module._load,file=require.resolve('../server/routes/promptInjectionWorkshop'),prior=process.env.PLATFORM_DATABASE_ENGINE;process.env.PLATFORM_DATABASE_ENGINE='postgres';delete require.cache[file];let logged=0,runs=0;
 Module._load=function(name,...args){
  if(name==='../services/promptInjectionWorkshop'||name==='../services/multiProviderAIService')return{};
  if(name==='../utils/contextLogger')return{error:()=>logged++};
  if(name==='../services/promptInjectionProgressService')return{createDefaultPromptInjectionProgressService:()=>({})};
  if(name==='../agent-runtime/runCoordinator')return{createRunCoordinator:()=>({})};
  if(['sqlite3','better-sqlite3'].includes(name)||/authDb$/.test(name))throw Error('Database load forbidden');
  return original.call(this,name,...args);
 };
 let server;try{
  const {createPromptInjectionWorkshopRouter}=require(file),express=require('express'),app=express();app.use(express.json());app.use((req,res,next)=>{req.user={id:1};req.identitySession={id:7};next();});
  app.use(createPromptInjectionWorkshopRouter({validateSession:async token=>{assert.equal(token,'controlled-session');return{user:{id:1},session:{id:7,user_id:1}};},progressService:{},runCoordinator:{run:async()=>{runs++;throw Object.assign(Error('private abort detail'),{name:'AbortError'});}},logger:{error:()=>logged++},aiService:{getActiveProviderInfo:()=>{assert.fail('Cancelled run must not be classified as provider outage');}}}));
  server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});
  const response=await fetch(`http://127.0.0.1:${server.address().port}/chat`,{method:'POST',headers:{'content-type':'application/json',authorization:'Bearer controlled-session'},body:JSON.stringify({userMessage:'AWS'})});assert.equal(response.status,409);
  assert.deepEqual(await response.json(),{success:false,code:'AGENT_RUN_CANCELLED',error:'Agent run was cancelled.',response:null,completedObjectiveId:null});assert.equal(logged,0);assert.equal(runs,1);
  const missing=await fetch(`http://127.0.0.1:${server.address().port}/chat`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({userMessage:'AWS'})});assert.equal(missing.status,401);assert.equal(runs,1);
 }finally{if(server)await new Promise(resolve=>server.close(resolve));Module._load=original;delete require.cache[file];if(prior===undefined)delete process.env.PLATFORM_DATABASE_ENGINE;else process.env.PLATFORM_DATABASE_ENGINE=prior;}
});
