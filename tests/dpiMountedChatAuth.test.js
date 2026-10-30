'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');

test('full-app DPI chat mounts canonical session authentication without closing public status',async t=>{
 const envKeys=['PLATFORM_DATABASE_ENGINE','WORKSHOP_DATABASE_ENGINE','JWT_SECRET','IDENTITY_DATABASE_URL'];
 const prior=Object.fromEntries(envKeys.map(key=>[key,process.env[key]]));
 Object.assign(process.env,{PLATFORM_DATABASE_ENGINE:'postgres',WORKSHOP_DATABASE_ENGINE:'postgres',JWT_SECRET:require('node:crypto').randomBytes(48).toString('base64url'),IDENTITY_DATABASE_URL:'postgresql://fixture@127.0.0.1:1/owasp_ai_goat_test_dpi_mounted'});
 const Module=require('node:module'),originalLoad=Module._load;
 const controlledAi={getActiveProviderInfo:()=>({provider:'controlled',providerName:'Controlled fixture',model:'no-model'}),verifyProviderConnectionLite:async()=>({available:true,healthy:true,configured:true})};
 Module._load=function(name,parent,isMain){
  if(/(?:^|\/)(?:authDb|sqlite|sqlite3|better-sqlite3)(?:\.js)?$/.test(name))throw Error('Legacy database import forbidden in mounted DPI test');
  if(name==='../services/multiProviderAIService'||name==='./multiProviderAIService')return controlledAi;
  return originalLoad.call(this,name,parent,isMain);
 };
 t.after(()=>{Module._load=originalLoad;for(const [key,value]of Object.entries(prior))if(value===undefined)delete process.env[key];else process.env[key]=value;});
 const source=fs.readFileSync(path.join(__dirname,'../server/applicationServer.js'),'utf8');
 const authMount="app.post('/api/workshop/prompt-injection/chat', authenticateToken);";
 const routerMount="app.use('/api/workshop/prompt-injection', require('./routes/promptInjectionWorkshop'));";
 assert.ok(source.indexOf(authMount)>0&&source.indexOf(authMount)<source.indexOf(routerMount),'Chat authentication must precede production router mount');
 const express=require('express');
 const {createPostgresAdminAuth}=require('../server/middleware/postgresAdminAuth');
 const {createPromptInjectionWorkshopRouter}=require('../server/routes/promptInjectionWorkshop');
 const current={user:{id:7,username:'owner',role:'student'},session:{id:9,user_id:7}};
 let live=true,actorCalls=0,validations=0;
 const validateSession=async token=>{validations++;return live&&token==='owned-current-token'?current:null;};
 const auth=createPostgresAdminAuth({repository:{},validateSession});
 const app=express();app.use(express.json());
 app.post('/api/workshop/prompt-injection/chat',auth.authenticateToken);
 app.use('/api/workshop/prompt-injection',createPromptInjectionWorkshopRouter({
  aiService:controlledAi,
  validateSession,progressService:{assertObjectiveEnabled:async()=>{},getProgress:async()=>({objectives:{}})},
  completionService:{beginAttempt:async()=>null},runCoordinator:{run:async(_owner,_options,work)=>work({check:async()=>{},trace:async()=>{}})},
  workshopService:{chat:async()=>{actorCalls++;return{response:'Owned controlled response',judgment:{verdict:'fail'}};}},
 }));
 const server=app.listen(0,'127.0.0.1');await new Promise(resolve=>server.once('listening',resolve));t.after(()=>new Promise(resolve=>server.close(resolve)));
 const base=`http://127.0.0.1:${server.address().port}/api/workshop/prompt-injection`;
 const chat=token=>fetch(base+'/chat',{method:'POST',headers:{'content-type':'application/json',...(token?{authorization:'Bearer '+token}:{})},body:JSON.stringify({userMessage:'Explain AWS',activeObjectiveId:'system_prompt'})});
 assert.equal((await fetch(base+'/health')).status,200,'Public health contract remains reachable');
 assert.equal((await chat(null)).status,401);assert.equal((await chat('stale-token')).status,401);assert.equal(actorCalls,0);
 const accepted=await chat('owned-current-token');assert.equal(accepted.status,200);assert.equal((await accepted.json()).response,'Owned controlled response');assert.equal(actorCalls,1);assert.ok(validations>=3,'Canonical middleware and route fence both validated the owned token');
 live=false;assert.equal((await chat('owned-current-token')).status,401);assert.equal(actorCalls,1);
});
