'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),Module=require('node:module');
test('mounted Excessive Agency route binds exact platform session through controlled graph/effect/history/publication',async()=>{
 const original=Module._load;let live=true,phase='normal',entered,release,effects=0,saves=0,labChecks=0;
 const pause=()=>{entered();return new Promise(resolve=>release=resolve);};
 const ownerApi=require('../server/agent-runtime/ownerWorkflowRoutes');
 const execution={signal:new AbortController().signal,check:async()=>{},trace:async()=>{},effect:async function(key,work){if(phase==='admission')await pause();return work();}};
 const coordinator={run:async(_owner,_options,work)=>work(execution)};
 const state={conversations:{get:async()=>[],set:async()=>{saves++;}},database:{getUserProgress:async()=>({})},toolRouter:{}};
 const stubs={
  '../agent-runtime/runCoordinator':{createRunCoordinator:()=>coordinator},
  '../middleware/adminAuth':{authenticateToken:(req,res,next)=>{req.user={id:41};req.identitySession={id:19};next();}},
  '../services/postgresIdentityAdapter':{getPostgresIdentityAdapter:()=>({validateSession:async()=>live?{user:{id:41},session:{id:19,user_id:41}}:null})},
  '../services/excessiveAgencyAttendeeLabStore':{excessiveAgencyAttendeeLabStore:{resolveSession:async()=>{labChecks++;return{labUser:{userId:'alice'},state};},getOrCreate:async()=>state}},
  '../services/multiProviderAIService':{},'../utils/contextLogger':{},
  '../services/workshopModeService':{getMode:async()=> 'vuln'},
  '../services/workshopModeHandlers':{createWorkshopModeHandlers:()=>({get(){},set(){}})},
  '../services/workshopConfigService':{createWorkshopConfigService:()=>({getSnapshot:async()=>({exercises:{excessive_agency:{objectives:{}}}})})},
  '../utils/progressSync':{syncObjectiveComplete:async()=>{},checkAndMarkWorkshopComplete:async()=>{},resetWorkshopProgress:async()=>{},getUserWorkshopProgress:async()=>[]},
  '../agent-runtime/excessiveAgencyGraph':{runExcessiveAgencyGraph:async()=>{
   const run=ownerApi.getOwnerExecution();if(phase==='provider')await pause();
   await run.effect('owned',async()=>{effects++;});
   if(phase==='publication')await pause();
   return{finalResponse:'PRIVATE_EA_HELD',toolObservations:[],judgments:[],completedObjectiveIds:[],projectionPending:[]};
  }},
 };
 Module._load=function(name,parent,main){if(Object.hasOwn(stubs,name))return stubs[name];if(/(?:^|\/)authDb(?:\.js)?$/.test(name))throw Error('Legacy database forbidden');return original.call(this,name,parent,main);};
 const routePath=require.resolve('../server/routes/excessiveAgencyLab');delete require.cache[routePath];let server;
 try{
  const app=require('express')();app.use(require('express').json());app.use(require(routePath));server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});
  const send=()=>fetch('http://127.0.0.1:'+server.address().port+'/chat',{method:'POST',headers:{authorization:'Bearer private','content-type':'application/json','x-lab-session':'intentional-lab-session'},body:JSON.stringify({message:'Read my notes'})});
  let response=await send();assert.equal(response.status,200);assert.equal((await response.json()).response,'PRIVATE_EA_HELD');assert.equal(saves,1);
  for(const kind of ['provider','admission','publication']){phase=kind;live=true;const before=effects,saved=saves;const waiting=new Promise(resolve=>entered=resolve),pending=send();await waiting;live=false;release();response=await pending;const body=await response.json();assert.equal(response.status,401);assert.equal(body.code,'SESSION_REVOKED');assert.equal(JSON.stringify(body).includes('PRIVATE_EA_HELD'),false);assert.equal(effects,before+(kind==='publication'?1:0));assert.equal(saves,saved);}
  assert.equal(labChecks,4,'existing lab session resolution remains in use');
 }finally{release?.();if(server)await new Promise(resolve=>server.close(resolve));Module._load=original;delete require.cache[routePath];}
});
