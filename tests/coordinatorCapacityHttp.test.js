'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),Module=require('node:module'),express=require('express');
const {createPostgresAdminAuth}=require('../server/middleware/postgresAdminAuth');
const fixtureAdminAuth=createPostgresAdminAuth({repository:{},jwtSecret:'coordinator-capacity-fixture-key-2026',validateSession:async token=>token==='controlled-session'?{user:{id:1,username:'student-1',role:'student',admin_level:0},session:{id:7,user_id:1}}:null});
const busy=()=>Object.assign(Error('private capacity detail'),{code:'GRAPH_RUN_CAPACITY_EXCEEDED',statusCode:503});
async function mounted(t,router){const app=express();app.use(express.json());app.use((req,res,next)=>{if(req.headers.authorization){req.user={id:1};req.identitySession={id:7};}next();});app.use(router);const server=await new Promise(r=>{const s=app.listen(0,'127.0.0.1',()=>r(s));});t.after(()=>new Promise(r=>server.close(r)));return async(path,auth=true)=>{const response=await fetch('http://127.0.0.1:'+server.address().port+path,{method:'POST',headers:{'content-type':'application/json',...(auth?{authorization:'Bearer controlled-session'}:{})},body:JSON.stringify({userMessage:'AWS',referenceKey:'owned'})});return{status:response.status,body:await response.json()};};}
test('mounted sensitive lookup uses shared wrapper: busy503, cancel409, session401 and ordinary500',async t=>{
 let error=busy(),calls=0;const router=require('../server/routes/postgres/sensitiveLookup')({store:{},filesDir:'/nonexistent-controlled',aiService:{},authenticate:(req,res,next)=>req.user?next():res.status(401).json({error:'Authentication required'}),coordinator:{run:async()=>{calls++;throw error;}}});
 const post=await mounted(t,router);let r=await post('/mysql/path-traversal');assert.equal(r.status,503);assert.equal(r.body.code,'GRAPH_RUN_CAPACITY_EXCEEDED');assert.equal(r.body.error,'Agent capacity is unavailable.');
 error=Object.assign(Error('cancel detail'),{name:'AbortError'});assert.equal((await post('/mysql/path-traversal')).status,409);
 error=Object.assign(Error('revoked detail'),{code:'SESSION_REVOKED'});assert.equal((await post('/mysql/path-traversal')).status,401);
 error=Error('ordinary controlled failure');assert.equal((await post('/mysql/path-traversal')).status,500);
 assert.equal((await post('/mysql/path-traversal',false)).status,401);assert.equal(calls,4);
});
test('mounted DPI capacity keeps null result and preserves cancellation/auth/unrelated errors',async t=>{
 const original=Module._load,file=require.resolve('../server/routes/promptInjectionWorkshop'),prior=process.env.PLATFORM_DATABASE_ENGINE;process.env.PLATFORM_DATABASE_ENGINE='postgres';delete require.cache[file];
 Module._load=function(name,...args){if(['../services/promptInjectionWorkshop','../services/multiProviderAIService'].includes(name))return{};if(name==='../utils/contextLogger')return{error(){}};if(name==='../services/promptInjectionProgressService')return{createDefaultPromptInjectionProgressService:()=>({})};if(name==='../agent-runtime/runCoordinator')return{createRunCoordinator:()=>({})};if(['sqlite3','better-sqlite3'].includes(name)||/authDb$/.test(name))throw Error('Database forbidden');return original.call(this,name,...args);};
 let factory;try{factory=require(file).createPromptInjectionWorkshopRouter;}finally{Module._load=original;delete require.cache[file];if(prior===undefined)delete process.env.PLATFORM_DATABASE_ENGINE;else process.env.PLATFORM_DATABASE_ENGINE=prior;}
 let error=busy(),calls=0;const post=await mounted(t,factory({validateSession:async()=>({user:{id:1},session:{id:7,user_id:1}}),progressService:{},runCoordinator:{run:async()=>{calls++;throw error;}},logger:{error(){}},aiService:{getActiveProviderInfo:()=>({provider:'controlled'})}}));
 let r=await post('/chat');assert.equal(r.status,503);assert.deepEqual(r.body,{success:false,code:'GRAPH_RUN_CAPACITY_EXCEEDED',error:'Agent capacity is unavailable.',response:null,completedObjectiveId:null});
 error=Object.assign(Error('cancel'),{name:'AbortError'});r=await post('/chat');assert.equal(r.status,409);assert.equal(r.body.code,'AGENT_RUN_CANCELLED');error=Error('ordinary');assert.equal((await post('/chat')).status,500);assert.equal((await post('/chat',false)).status,401);assert.equal(calls,3);
});
test('mounted MCP transport capacity503 preserves existing unrelated/cancel500 and missing auth401',async t=>{
 const original=Module._load,file=require.resolve('../server/routes/mcpWorkshop'),prior=process.env.PLATFORM_DATABASE_ENGINE;process.env.PLATFORM_DATABASE_ENGINE='postgres';delete require.cache[file];let error=busy(),calls=0;
 Module._load=function(name,...args){
  if(name==='../agent-runtime/runCoordinator')return{createRunCoordinator:()=>({run:async()=>{calls++;throw error;}})};
  if(name==='../utils/progressSync')return Object.fromEntries(['syncObjectiveComplete','checkAndMarkWorkshopComplete','resetWorkshopProgress','syncWorkshopStarted','getUserWorkshopProgress'].map(k=>[k,async()=>[]]));
  if(name==='../database/mcpWorkshopDb')return{engine:'controlled'};
  if(name==='../database/postgres/mcpResourceRepository')return{createMcpResourceRepository:()=>({})};
  if(name==='../services/multiProviderAIService'||name==='../multiProviderAIService')return{provider:'controlled'};
  if(name==='../services/workshopConfigService')return{createWorkshopConfigService:()=>({})};
  if(name==='../services/mcpObjectiveGrader')return{createMcpObjectiveGrader:()=>({})};
  if(name==='../middleware/adminAuth')return fixtureAdminAuth;
  if(name==='../middleware/rateLimiter')return{generalRateLimiter:(_req,_res,next)=>next()};
  if(/(?:^|\/)(?:database|multiProviderAIService)(?:\/|\.js|$)/.test(name))throw Error('Unsafe database dependency forbidden');
  return original.call(this,name,...args);
 };
 let router;try{router=require(file);}finally{Module._load=original;delete require.cache[file];if(prior===undefined)delete process.env.PLATFORM_DATABASE_ENGINE;else process.env.PLATFORM_DATABASE_ENGINE=prior;}
 const post=await mounted(t,router);let r=await post('/mcp');assert.equal(r.status,503);assert.deepEqual(r.body,{error:'Agent capacity is unavailable.',code:'GRAPH_RUN_CAPACITY_EXCEEDED'});
 error=Object.assign(Error('controlled abort'),{name:'AbortError'});assert.equal((await post('/mcp')).status,500);error=Error('controlled unrelated');assert.equal((await post('/mcp')).status,500);assert.equal((await post('/mcp',false)).status,401);assert.equal(calls,3);
});
