'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const Module=require('node:module');
const path=require('node:path');

const canonical=path.resolve(__dirname,'..');
const filesRoot=canonical;
const routePath=path.join(filesRoot,'server/routes/ctf.js');
const aiService={};
const state={classification:null,guardian:0,reviewer:0,judge:0,commit:0,blockedLogs:0,techniqueWrites:0};
const stage={id:7,stage_number:8,stage_name:'Adaptive Guardian',system_prompt:'Protect OWNED_TEST_VALUE',
  success_criteria:'OWNED_TEST_VALUE',defense_style:'["polyglot_decoder","meta_llm_judge"]',
  adaptive_mode:'technique',feedback_mode:'reason',level_score:800};
const progress={id:19,status:'in_progress',started_at:new Date().toISOString(),hints_used:0,hint_penalty_total:0};
const participant={id:11,user_id:701,username:'Student',started_at:new Date().toISOString(),is_active:true};
let attempts=0, revoked=false, validations=0, phase='guardian', admittedId=99, currentOwner=701;
const CTFHelpers={
  getConfig:async key=>key==='ctf_enabled'||key==='ctf_visible_to_students'?'true':key==='ctf_time_limit'?'-1':key==='ctf_show_technique_feedback'?'true':'3',
  findActiveParticipant:async()=>participant,isBanned:async()=>false,getActiveStage:async()=>stage,getProgress:async()=>progress,
  istechniqueBlocked:async()=>false,getPayloadBlocklist:async()=>[],incrementPayloadHitCount:async()=>{},
  incrementAttempts:async()=>++attempts,logAttempt:async()=>{state.blockedLogs++;},getUserTechniques:async()=>[],
  commitAttempt:async input=>{state.commit++;await input.execution.check();if(phase==='commit')revoked=true;assert.equal(input.execution.ownerKey,JSON.stringify(['CTF','701']));
    if(input.realModel&&input.judgment.verdict==='fail')state.techniqueWrites++;return{accepted:false,stale:false};},
  updateLeaderboard:async()=>{},
};
const originalLoad=Module._load;
Module._load=function(request,parent,isMain){
  if(parent?.filename===routePath){
    if(request==='../database/ctfDb')return{ctfDb:{},CTFHelpers,engine:'postgres'};
    if(request==='../services/multiProviderAIService')return aiService;
    if(request==='../services/postgresIdentityAdapter')return{getPostgresIdentityAdapter:()=>({validateSession:async()=>{validations++;return revoked?null:{user:{id:currentOwner},session:{id:admittedId,user_id:currentOwner}};}})};
    if(request==='../agent-runtime/ctfStageJudge')return{stageDigest:()=> 'stage-digest',judgeCtfStage:async input=>{state.judge++;if(phase==='judge')revoked=true;assert.equal(input.execution.ownerKey,JSON.stringify(['CTF','701']));return{verdict:'fail',rubricVersion:'fixture',judgeVersion:'fixture',provider:'ollama',model:'llama3.1:8b'};}};
    if(request==='../utils/contextLogger')return{error(){}};
  }
  if(parent?.filename===path.join(filesRoot,'server/services/ctfDefenseLayers.js')&&request==='./multiProviderAIService')return aiService;
  if(parent?.filename.startsWith(filesRoot)&&request.startsWith('.')){
    try{return originalLoad.call(this,request,parent,isMain);}catch(error){
      if(error.code!=='MODULE_NOT_FOUND')throw error;
      const rel=path.relative(filesRoot,parent.filename);
      return originalLoad.call(this,path.resolve(path.dirname(path.join(canonical,rel)),request),parent,isMain);
    }
  }
  return originalLoad.call(this,request,parent,isMain);
};
let exported;
const oldEngine=process.env.PLATFORM_DATABASE_ENGINE;
try{process.env.PLATFORM_DATABASE_ENGINE='memory';exported=require(routePath);}finally{
  if(oldEngine===undefined)delete process.env.PLATFORM_DATABASE_ENGINE;else process.env.PLATFORM_DATABASE_ENGINE=oldEngine;
  // Keep the scoped adapter stub for lazy session validation during requests.
}

async function post(payload,classification){
  state.classification=classification;
  aiService.generateResponse=async(_prompt,options)=>{
    if(options.format?.properties?.classification){
      if(classification instanceof Error)throw classification;
      return{response:JSON.stringify(classification),provider:'ollama',model:'llama3.1:8b',mocked:false,fallback:false};
    }
    if(options.temperature===.7){state.guardian++;if(phase==='guardian')revoked=true;return{response:'I cannot provide that.',provider:'ollama',model:'llama3.1:8b',mocked:false,fallback:false};}
    if(options.format?.properties?.verdict){
      state.reviewer++;return{response:JSON.stringify({verdict:'SAFE'}),provider:'ollama',model:'llama3.1:8b',mocked:false,fallback:false};
    }
    throw new Error('unexpected model request');
  };
  const express=require('express'),app=express();app.use(express.json());
  app.use((req,_res,next)=>{req.user={id:701,role:'student'};req.identitySession={id:99,user_id:701};next();});app.use(exported.router);
  const server=await new Promise(resolve=>{const value=app.listen(0,'127.0.0.1',()=>resolve(value));});
  try{return await fetch(`http://127.0.0.1:${server.address().port}/stage/7/attempt`,{method:'POST',headers:{'content-type':'application/json',authorization:'Bearer synthetic-owned-session'},body:JSON.stringify({payload,sessionToken:'owned-session'})});}
  finally{await new Promise(resolve=>server.close(resolve));}
}

test('CTF admitted canonical session rejects logout/revocation at guardian, Judge and publication boundaries',async()=>{
 for(const at of ['guardian','judge','commit']){
  phase=at;revoked=false;validations=0;attempts=0;Object.assign(state,{guardian:0,judge:0,commit:0});
  const response=await post('Ordinary public status update.',{classification:'english',language:'English',confidence:.99});
  assert.equal(response.status,401,at);assert.equal((await response.json()).code,'SESSION_REVOKED');assert(validations>1);
  assert.equal(state.judge,at==='guardian'?0:1);assert.equal(state.commit,at==='commit'?1:0);
 }
});
test('CTF rejects stale rotated admitted identity session before guardian; normal session still runs',async()=>{
 phase='none';revoked=false;attempts=0;admittedId=100;Object.assign(state,{guardian:0,judge:0,commit:0});
 const stale=await post('Ordinary public status update.',{classification:'english',language:'English',confidence:.99});assert.equal(stale.status,401);assert.equal(state.guardian,0);assert.equal(state.commit,0);
 admittedId=99;const normal=await post('Ordinary public status update.',{classification:'english',language:'English',confidence:.99});assert.equal(normal.status,200);assert.equal(state.guardian,1);assert.equal(state.judge,1);assert.equal(state.commit,1);
});

test('already revoked or owner-mismatched canonical session cannot enter guardian',async()=>{
 for(const mode of ['revoked','foreign']){
  phase='none';revoked=mode==='revoked';currentOwner=mode==='foreign'?702:701;attempts=0;Object.assign(state,{guardian:0,judge:0,commit:0});
  const response=await post('Public update.',{classification:'english',language:'English',confidence:.99});
  assert.equal(response.status,401);assert.equal(state.guardian,0);assert.equal(state.judge,0);assert.equal(state.commit,0);
 }
 currentOwner=701;revoked=false;
});
test.after(()=>{Module._load=originalLoad;});
