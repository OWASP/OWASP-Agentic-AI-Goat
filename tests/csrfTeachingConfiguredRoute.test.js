'use strict';
// Evaluate a copied route source with explicit inert dependency seams. No route
// module import, configured database, browser process, or model is started.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const express = require('express');
const owners = require('../server/agent-runtime/ownerWorkflowRoutes');
function loadRoute(effects, cleared, modeState={mode:null,stamp:'default'}) {
  const sandbox = { ready: async()=>{}, flush: async()=>{}, getState:()=>({}),tab:()=>({agentChatEnabled:true}),getTabState:()=>({}) };
  const mocks = {
    '../agent-runtime/postgresRunLedger': {configuredRunLedger:()=>null},
    '../utils/progressSync': {syncWorkshopStarted:async()=>{}}, '../database/csrfWorkshopDb': {engine:'postgres',clearActivity:async owner=>cleared.push(owner)},
    '../services/workshopModeService':{getMode:async()=>modeState.mode,setMode:async({mode})=>{modeState.mode=mode;modeState.stamp='updated';return mode;}},
    '../services/postgresPlatformStores':{getPostgresPlatformStores:()=>({progress:{getEvaluationScope:async()=>({generation:0,mode:modeState.mode,modeStamp:modeState.stamp})}})},
    '../services/multiProviderAIService': {}, '../services/csrfWorkshopAgent': {chat:async()=>{throw modeState.chatError||Error('Unexpected chat');}},
    '../services/csrfVictimSandbox': {TABS:{get:{objectives:[]}},TAB_IDS:['get'],ALL_OBJECTIVES:[],getOrCreateSandbox:()=>sandbox},
    '../utils/contextLogger': {}, '../services/xssMailProvider': {}, '../services/csrfEmailDispatch': {},
    '../services/csrfInboxScope': {createCsrfInboxScope:()=>({})},
    '../services/ragVectorStore': {forFamily:()=>({})},
    '../services/workshopConfigService': {createWorkshopConfigService:()=>({})},
    '../services/csrfBrowserExecutor': {createCsrfBrowserExecutor:()=>({execute:async()=>{},close:async()=>{}})},
    '../services/csrfBrowserWorkflow': {createCsrfBrowserWorkflow:()=>({})},
    '../services/csrfClassifiedEmailBrowserWorkflow': {createCsrfClassifiedEmailBrowserWorkflow:()=>({run:async()=>{},inspect:async()=>{}})},
    '../services/csrfProgressProjection': {createCsrfProgressProjection:()=>({})},
    '../services/csrfObjectiveGrader': {createCsrfObjectiveGrader:()=>({begin:async()=>({generation:0,mode:modeState.mode,modeStamp:modeState.stamp})})},
    '../services/csrfBrowserController': {createCsrfBrowserController:()=>()=>{}},
    '../middleware/adminAuth': {authenticateToken:(q,s,n)=>{if(q.headers.authorization!=='Bearer valid')return s.sendStatus(401);q.user={id:17};q.identitySession={id:31};n();}},
    '../services/csrfRagResources': {createCsrfRagResources:()=>({})},
    '../services/csrfActionHandler': {createCsrfActionHandler:deps=>async(req,res)=>{
      const execution=owners.getOwnerExecution();
      await execution.check();
      await execution.withTeachingEffect(async()=>effects.push({owner:deps.getUserId(req),key:deps.getUserKey(req)}));
      await modeState.afterEffect?.();
      res.json({owner:deps.getUserId(req)});
    }},
  };
  const safe = new Set(['../services/csrfRuntimeBudget','../services/csrfEmailMode','../middleware/bearerToken','express','express-rate-limit','node:crypto','path','fs','../agent-runtime/ownerWorkflowRoutes','../agent-runtime/ownerWorkflowHttpError','../agent-runtime/runCoordinator','../services/csrfBrowserReceipt','../services/csrfGadgetBrowserReceipt','../data/csrfEmailPayloads','../data/csrfRagPayloads','../services/csrfTeachingAuthority','../services/csrfTeachingSinkMount','../agent-runtime/csrfSelectedEffect']);
  const filename=path.resolve(__dirname,'../server/routes/csrfWorkshop.js');
  const localRequire=require('node:module').createRequire(filename);
  const module={exports:{}};
  vm.runInNewContext(fs.readFileSync(filename,'utf8'),{module,exports:module.exports,__dirname:path.dirname(filename),process:{env:{PLATFORM_DATABASE_ENGINE:'postgres'}},console,Buffer,URL,setInterval,clearInterval,setTimeout,clearTimeout,require:name=>{
    if(Object.hasOwn(mocks,name))return mocks[name];
    assert.ok(safe.has(name),`Unreviewed route dependency: ${name}`);return localRequire(name);
  }},{filename});
  return module.exports;
}
test('configured CSRF route keeps cookie sink private owner authority and ordinary bearer boundary',async t=>{
 const effects=[];let valid=true;let leases=0;
 const cleared=[];const route=loadRoute(effects,cleared);
 const check=async()=>{if(!valid)throw Object.assign(new Error('revoked'),{statusCode:401});};
 const authority=()=>({ownerId:17,sessionId:'canonical',check});
 const runtime={bindBearer:async req=>{if(req.headers.authorization!=='Bearer valid')throw Object.assign(new Error('invalid'),{statusCode:401});return authority();},resolveAuthority:async(_req,{allowCookie})=>{if(!allowCookie)throw Object.assign(new Error('bearer required'),{statusCode:401});return authority();},store:{withAuthority:async(_sid,binding,work)=>{assert.equal(binding.ownerId,17);await check();leases++;return work();}}};
 const app=express();app.use(express.json());app.use((req,_res,next)=>{req.sessionID='teaching';req.session={userId:999};if(req.headers['x-stale-user'])req.user={id:999};next();});
 app.use(route.configureTeachingSessions(runtime));
 assert.throws(()=>route.configureTeachingSessions(runtime),/already configured/);
 app.use('/api/workshop',(req,res,next)=>req.headers.authorization==='Bearer valid'?next():res.status(401).json({error:'umbrella'}));
 app.use('/api/workshop/csrf',route);
 app.use((_req,res)=>res.sendStatus(404));
 const server=app.listen(0,'127.0.0.1');await new Promise(resolve=>server.once('listening',resolve));t.after(()=>new Promise(resolve=>server.close(resolve)));
 const base=`http://127.0.0.1:${server.address().port}/api/workshop/csrf`;
 const request=(suffix,opts={})=>fetch(base+suffix,{...opts,signal:AbortSignal.timeout(3000)});
 for(const method of ['GET','POST']) {const res=await request('/agent-action',{method});assert.equal(res.status,200);assert.equal((await res.json()).owner,17);}
 assert.deepEqual(effects,[{owner:17,key:'17'},{owner:17,key:'17'}]);assert.equal(leases,4); // Each request fences its effect and final persistence separately.
 for(const opts of [{headers:{authorization:'Bearer invalid'}},{headers:{'x-stale-user':'yes'}},{method:'HEAD'}])assert.ok([401,405].includes((await request('/agent-action',opts)).status));
 for(const suffix of ['/victim-state','/agent-action/child'])assert.equal((await request(suffix)).status,401);
 assert.equal((await request('/victim-state',{headers:{authorization:'Bearer valid'}})).status,200);
 assert.equal((await request('/activity',{method:'DELETE'})).status,401);
 assert.equal((await request('/activity',{method:'DELETE',headers:{authorization:'Bearer valid'}})).status,200);assert.deepEqual(cleared,['17']);
 valid=false;assert.equal((await request('/agent-action')).status,401);assert.equal(effects.length,2);assert.equal((await request('/activity',{method:'DELETE',headers:{authorization:'Bearer valid'}})).status,401);assert.deepEqual(cleared,['17']);
});
test('mounted mode endpoints preserve null default and admit fixed owner actions',async t=>{
 const effects=[],state={mode:null,stamp:'default'},route=loadRoute(effects,[],state);let valid=true;const check=async()=>{if(!valid)throw Object.assign(Error('revoked'),{statusCode:401});};
 const runtime={bindBearer:async()=>({ownerId:17,sessionId:'31',check}),resolveAuthority:async()=>({ownerId:17,sessionId:'31',check}),store:{withAuthority:async(_id,_binding,work)=>{await check();return work();}}};
 const app=express();app.use(express.json());app.use((req,_res,next)=>{req.sessionID='teaching';req.session={};next();});app.use(route.configureTeachingSessions(runtime));app.use('/api/workshop/csrf',route);
 const server=app.listen(0,'127.0.0.1');await new Promise(r=>server.once('listening',r));t.after(()=>new Promise(r=>server.close(r)));
 const base=`http://127.0.0.1:${server.address().port}/api/workshop/csrf`,request=(path,body)=>fetch(base+path,{method:body?'POST':'GET',headers:{authorization:'Bearer valid','content-type':'application/json'},...(body?{body:JSON.stringify(body)}:{}),signal:AbortSignal.timeout(3000)});
 let response=await request('/mode');assert.equal(response.status,200);assert.equal((await response.json()).mode,null);assert.equal(state.stamp,'default');
 response=await request('/mode',{mode:'fixed',owner:99});assert.equal(response.status,400);assert.equal(state.mode,null);
 response=await request('/mode',{mode:'fixed'});assert.equal(response.status,200);assert.equal((await response.json()).effectiveMode,'fixed');
 response=await request('/agent-action',{tab:'get'});assert.equal(response.status,200);assert.equal((await response.json()).owner,17);
 assert.deepEqual(effects,[{owner:17,key:'17'}]);response=await request('/mode',{mode:null});assert.equal(response.status,400);response=await request('/mode',{mode:'vuln'});assert.equal(response.status,200);
 for (const status of [401,423,503]) {state.chatError=new (require('../server/agent-runtime/ownerWorkflowHttpError').OwnerWorkflowHttpError)(status,'Teaching session authority unavailable');response=await request('/chat',{tab:'get',message:'inspect'});assert.equal(response.status,status);assert.equal((await response.json()).error,'Teaching session authority unavailable');}
 state.chatError={code:'SESSION_REVOKED'};response=await request('/chat',{tab:'get',message:'inspect'});assert.equal(response.status,401);assert.equal((await response.json()).code,'SESSION_REVOKED');state.chatError={code:'MODE_MISMATCH'};response=await request('/chat',{tab:'get',message:'inspect'});assert.equal(response.status,409);
});

test('configured outer publication preserves canonical revoked-session denial and does not relabel outages',async t=>{
 for (const outage of [false,true]) {
  let current=true; const effects=[],state={afterEffect:async()=>{current=false;}};
  const route=loadRoute(effects,[],state);
  const resolve=require('../server/services/teachingSessionAuthority').createTeachingSessionAuthority({validateSession:async()=>{
   if(!current){if(outage)throw Object.assign(Error('database unavailable'),{code:'08006'});return null;}
   return {user:{id:17},session:{id:31,user_id:17}};
  },assertBinding:async()=>{}});
  const runtime={bindBearer:req=>resolve(req),resolveAuthority:req=>resolve(req),store:{withAuthority:async(_id,_binding,work)=>work()}};
  const app=express();app.use(express.json());app.use((req,_res,next)=>{req.sessionID='teaching';req.session={};next();});app.use(route.configureTeachingSessions(runtime));app.use('/api/workshop/csrf',route);
  const server=app.listen(0,'127.0.0.1');await new Promise(r=>server.once('listening',r));
  try {const response=await fetch(`http://127.0.0.1:${server.address().port}/api/workshop/csrf/agent-action`,{headers:{authorization:'Bearer valid'},signal:AbortSignal.timeout(3000)});
   assert.equal(response.status,outage?503:401);assert.equal(effects.length,1);assert.equal((await response.json()).owner,undefined);
  }finally{await new Promise(r=>server.close(r));}
 }
});
test('configured CSRF teaching effect and publication leases preserve only typed public denials',async()=>{
 for(const phase of ['effect','publication'])for(const status of [401,423,503,418,419]){
  const effects=[],route=loadRoute(effects,[]);let leases=0;
  const runtime={bindBearer:async()=>({ownerId:17,sessionId:31,check:async()=>{}}),resolveAuthority:async()=>({ownerId:17,sessionId:31,check:async()=>{}}),store:{withAuthority:async(_sid,_binding,work)=>{
   leases++;if(leases===(phase==='effect'?1:2))throw Object.assign(Error('private lease details'),{code:status===418?'UNEXPECTED':'TEACHING_SESSION_AUTHORITY_UNAVAILABLE',statusCode:status});return work();
  }}};
  const app=express();app.use(express.json());app.use((req,_res,next)=>{req.sessionID='teaching';req.session={};next();});app.use(route.configureTeachingSessions(runtime));app.use('/api/workshop/csrf',route);
  const server=app.listen(0,'127.0.0.1');await new Promise(r=>server.once('listening',r));
  try{const response=await fetch(`http://127.0.0.1:${server.address().port}/api/workshop/csrf/agent-action`,{headers:{authorization:'Bearer valid'},signal:AbortSignal.timeout(3000)});assert.equal(response.status,status>=418&&status<423?500:status);const body=await response.json();assert.equal(body.owner,undefined);if([401,423,503].includes(status))assert.equal(body.error,'Teaching session authority unavailable');assert.equal(effects.length,phase==='effect'?0:1);}finally{await new Promise(r=>server.close(r));}
 }
});
