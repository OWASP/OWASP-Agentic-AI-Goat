'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),Module=require('node:module');
test('all mounted EA reset routes fence admission, partial mutation and final publication',async()=>{
 const original=Module._load;let live=true,phase='normal',route,entered,release,labChecks=0,changes=[],rows;
 const pause=()=>{entered();return new Promise(resolve=>release=resolve);};
 const execution={check:async()=>{}};
 const coordinator={reset:async(_owner,work)=>{if(phase==='admission')await pause();await work(execution);if(phase==='publication')await pause();}};
 const state={conversations:{delete:async()=>{rows.get(41).history=[];changes.push('history');if(phase==='mutation')await pause();}},database:{getStats:async()=>({}),getUserProgress:async()=>({})},toolRouter:{}};
 const stubs={
  '../agent-runtime/runCoordinator':{createRunCoordinator:()=>coordinator},
  '../middleware/adminAuth':{authenticateToken:(req,res,next)=>{req.user={id:41};req.identitySession={id:19};next();}},
  '../services/postgresIdentityAdapter':{getPostgresIdentityAdapter:()=>({validateSession:async()=>live?{user:{id:41},session:{id:19,user_id:41}}:null})},
  '../services/excessiveAgencyAttendeeLabStore':{excessiveAgencyAttendeeLabStore:{resolveSession:async()=>{labChecks++;return{labUser:{userId:'alice'},state};},getOrCreate:async()=>state,resetAttendee:async id=>{rows.get(id).local=false;changes.push('local');if(phase==='mutation'&&route==='/reset')await pause();return state;}}},
  '../services/multiProviderAIService':{},'../utils/contextLogger':{},
  '../services/workshopModeService':{getMode:async()=> 'vuln'},
  '../services/workshopModeHandlers':{createWorkshopModeHandlers:()=>({get(){},set(){}})},
  '../services/workshopConfigService':{createWorkshopConfigService:()=>({getSnapshot:async()=>({exercises:{excessive_agency:{objectives:{}}}})})},
  '../utils/progressSync':{syncObjectiveComplete:async()=>{},checkAndMarkWorkshopComplete:async()=>{},resetWorkshopProgress:async id=>{rows.get(id).credit=false;changes.push('progress');if(phase==='mutation')await pause();},getUserWorkshopProgress:async()=>[]},
 };
 Module._load=function(name,parent,main){if(Object.hasOwn(stubs,name))return stubs[name];if(/(?:^|\/)authDb(?:\.js)?$/.test(name))throw Error('Legacy database forbidden');return original.call(this,name,parent,main);};
 const routePath=require.resolve('../server/routes/excessiveAgencyLab');delete require.cache[routePath];let server;
 try{
  const app=require('express')();app.use(require('express').json());app.use(require(routePath));server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});
  for(route of ['/reset','/progress/reset','/conversation/reset'])for(phase of ['normal','admission','mutation','publication']){
   live=true;changes=[];rows=new Map([[41,{history:['owner'],credit:true,local:true}],[42,{history:['sibling'],credit:true,local:true}]]);
   const waiting=new Promise(resolve=>entered=resolve);
   const pending=fetch('http://127.0.0.1:'+server.address().port+route,{method:'POST',headers:{authorization:'Bearer private','content-type':'application/json','x-lab-session':'intentional-lab-session'},body:'{}'});
   if(phase!=='normal'){await waiting;live=false;release();}
   const response=await pending,body=await response.json();assert.equal(response.status,phase==='normal'?200:401,route+':'+phase);if(phase!=='normal')assert.equal(body.code,'SESSION_REVOKED');
   const full=route==='/reset'?['local']:route==='/progress/reset'?['progress','local']:['history'];
   assert.deepEqual(changes,phase==='admission'?[]:phase==='mutation'?full.slice(0,1):full);
   assert.deepEqual(rows.get(42),{history:['sibling'],credit:true,local:true});
  }
  assert.equal(labChecks,8,'progress/conversation routes retain teaching lab-session checks');
 }finally{release?.();if(server)await new Promise(resolve=>server.close(resolve));Module._load=original;delete require.cache[routePath];}
});
