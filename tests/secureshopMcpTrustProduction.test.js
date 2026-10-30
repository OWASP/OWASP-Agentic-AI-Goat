'use strict';
const test=require('node:test');const assert=require('node:assert/strict');const express=require('express');
const {buildSecureShopMcpTrustTask,assertSecureShopMcpTrustReadiness,createScenarioLaunches,createSecureShopMcpTrustCoordinator,createSecureShopMcpTrustProduction}
  =require('../server/services/secureshopMcpTrustProduction');
const {createBoundMcpTrustRouter}=require('../server/routes/secureshop/boundMcpTrust');
const {findPacketInvocation}=require('./postgres/secureshopMcpTrustQualifierSchema');
const {createTurnRequest}=require('../server/services/secureshopTurnRequest');
const {createTurnRequestsRepository}=require('../server/database/postgres/secureshopTurnRequestsRepository');
const scope=Object.freeze({launchId:'10000000-0000-4000-8000-000000000001',scenarioId:'20000000-0000-4000-8000-000000000001',
  generation:1,platformOwnerId:7,platformSessionId:8});
const requestId='30000000-0000-4000-8000-000000000001',bearer='p'.repeat(43);

test('qualifier links the nested current invocation rather than a prior baseline',()=>{
  const evidence={runId:'run-current',requestId:'request-current',callId:'call-current',targetId:'target-current',
    remoteReceiptSha256:'a'.repeat(64),resultSha256:'b'.repeat(64),
    currentInvocation:{invocationId:'invocation-current',operationId:'operation-current'}};
  const current={invocation_id:'invocation-current',operation_id:'operation-current',run_id:'run-current',
    request_id:'request-current',call_id:'call-current',target_id:'target-current',
    remote_receipt_sha256:'a'.repeat(64),result_sha256:'b'.repeat(64)};
  const prior={...current,invocation_id:'invocation-prior',operation_id:'operation-prior',run_id:'run-prior'};
  assert.equal(findPacketInvocation(evidence,[prior,current]),current);
  assert.equal(findPacketInvocation({...evidence,currentInvocation:null},[current]),null);
  assert.equal(findPacketInvocation(evidence,[current,{...current}]),null,'ambiguous duplicate linkage must fail');
});
function setup({lookupRequest,capturePersonaAuthority,modeEpochForFence}={}){const calls=[];let visible=true;const enabled={rogue_registration:true,rug_pull:true};
  const availability={async read(){return{registered:true,visible,enabled:{...enabled}};},async assertScenario(value){calls.push(['available',value]);
    if(!visible||!enabled[value])throw Object.assign(new Error('hidden'),{code:'BOUND_MCP_UNAVAILABLE'});}};
  const launches={async assertCurrent(value){calls.push(['current',value]);},async resolveCapability(value){return value===bearer?scope:null;}};
  const conversations={async assertOwned(id,scope,persona,purpose){calls.push(['owned',id,scope,persona,purpose]);},
    async create(value,persona,purpose){calls.push(['conversation',value,persona,purpose]);return{id:purpose==='mcp_rogue_registration'
    ?'40000000-0000-4000-8000-000000000001':'40000000-0000-4000-8000-000000000002'};}};
  const schemas={rogue_registration:{serverIdentity:'secureshop-rogue-weather-lab',version:1,schemaSha256:'a'.repeat(64)},
    rug_pull:{serverIdentity:'secureshop-weather-lab',version:1,schemaSha256:'b'.repeat(64)}};
  const features={rogue_registration:{ready:true,application:{async initialize(){calls.push(['discover','rogue_registration']);return schemas.rogue_registration;}}},
    rug_pull:{ready:true,application:{async initialize(){calls.push(['discover','rug_pull']);return schemas.rug_pull;},async rotate(){calls.push(['rotate']);
      schemas.rug_pull={...schemas.rug_pull,version:2,schemaSha256:'c'.repeat(64)};return schemas.rug_pull;}}}};
  let afterRun;const createRunner=(feature,schema)=>({async run(input){calls.push(['run',feature,schema,input]);await afterRun?.();return{text:'Observed.',stopReason:'end_turn',replayed:false};}});
  const checkCurrent=async value=>{await launches.assertCurrent(value);await availability.assertScenario(value.trustScenario);};
  const application=createSecureShopMcpTrustCoordinator({launches,conversations,availability,features,createRunner,checkCurrent,
    lookupRequest,capturePersonaAuthority,modeEpochForFence});
  return{application,calls,enabled,hide(){visible=false;},afterRun(value){afterRun=value;}};}

test('production composition stays inert when its explicit feature gate is off',()=>{
  assert.deepEqual(createSecureShopMcpTrustProduction(),{ready:false});
  assert.throws(()=>createSecureShopMcpTrustProduction({enabled:'true'}),{code:'BOUND_MCP_UNAVAILABLE'});
});

test('structural readiness ignores mutable visibility while requiring both objective and target capabilities',async()=>{
  const agentsPool={async query(sql,args){if(sql.includes('information_schema.columns'))return{rows:[{ready:true}]};
    return{rows:args[0].map(value=>({value,ready:true}))};}};
  const identityPool={async query(sql,args){
    if(sql.includes('FROM pg_constraint'))return{rows:args[0].map(conname=>({conname,ready:true}))};
    if(sql.includes('workshop_platform.objectives'))return{rows:args[1].map(objective_id=>({objective_id,catalog_active:true,is_enabled:false}))};
    if(sql.includes('workshop_platform.exercises'))return{rows:[{catalog_active:true,is_visible:false}]};
    throw new Error('unexpected query');
  }};
  assert.equal(await assertSecureShopMcpTrustReadiness({identityPool,agentsPool}),true);
  const missing={async query(sql,args){if(sql.includes('information_schema.columns'))return{rows:[{ready:true}]};
    return{rows:args[0].slice(1).map(value=>({value,ready:true}))};}};
  await assert.rejects(assertSecureShopMcpTrustReadiness({identityPool,agentsPool:missing}),{code:'BOUND_MCP_UNAVAILABLE'});
});

test('scenario-bound launch reservations recheck mutable objective availability around the durable reservation',async()=>{
  const calls=[];let checks=0;const availability={async assertScenario(value){calls.push(['available',value]);checks++;
    if(checks===3)throw Object.assign(new Error('hidden'),{code:'BOUND_MCP_UNAVAILABLE'});}};
  const launches={async assertCurrent(value){calls.push(['current',value]);},async reserveMcpTarget(value,valueScenario){
    calls.push(['reserve',value,valueScenario]);return{targetId:'50000000-0000-4000-8000-000000000001'};}};
  const bound=createScenarioLaunches(launches,availability,'rug_pull');await bound.assertCurrent(scope);
  await assert.rejects(bound.reserveMcpTarget({launchId:scope.launchId},'rug_pull'),{code:'BOUND_MCP_UNAVAILABLE'});
  assert.deepEqual(calls.map(row=>row[0]),['current','available','available','reserve','available']);
  await assert.rejects(bound.reserveMcpTarget({},'rogue_registration'),{code:'BOUND_MCP_UNAVAILABLE'});
  assert.equal(calls.filter(row=>row[0]==='reserve').length,1);
});

test('coordinator exposes no target while hidden and requires the authenticated admin persona',async()=>{
  const f=setup();f.hide();assert.deepEqual(await f.application.status({scope,persona:{id:13,role:'admin'}}),
    {ready:false,scenarios:{rogue_registration:true,rug_pull:true}});
  assert.equal(f.calls.some(row=>row[0]==='discover'),false);
  await assert.rejects(f.application.discover({scope,persona:{id:13,role:'admin'},trustScenario:'rogue_registration'}),{code:'BOUND_MCP_UNAVAILABLE'});
  assert.equal(f.calls.some(row=>row[0]==='discover'),false);
  await assert.rejects(f.application.discover({scope,persona:{id:12,role:'merchant'},trustScenario:'rogue_registration'}),{code:'OWNER_MISMATCH'});
});

test('coordinator uses server-owned replay-stable tasks and rejects a hide-after-run result',async()=>{
  const f=setup();const first=await f.application.run({scope,persona:{id:13,role:'admin'},trustScenario:'rogue_registration',requestId});
  assert.equal(first.ok,true);const run=f.calls.find(row=>row[0]==='run')[3];
  assert.equal(run.message,buildSecureShopMcpTrustTask('rogue_registration',1,requestId));
  assert.equal(run.requestId,requestId);assert.doesNotMatch(run.message,/approved|unapproved|protected|export/i);
  f.afterRun(()=>f.hide());await assert.rejects(f.application.run({scope,persona:{id:13,role:'admin'},trustScenario:'rug_pull',
    requestId:'30000000-0000-4000-8000-000000000002'}),{code:'BOUND_MCP_UNAVAILABLE'});
});

test('coordinator isolates rogue and rug histories with stable server-owned purposes',async()=>{
  const f=setup(),persona={id:13,role:'admin'};
  await f.application.run({scope,persona,trustScenario:'rogue_registration',requestId});
  await f.application.run({scope,persona,trustScenario:'rug_pull',requestId:'30000000-0000-4000-8000-000000000002'});
  await f.application.run({scope,persona,trustScenario:'rogue_registration',requestId:'30000000-0000-4000-8000-000000000003'});
  const conversations=f.calls.filter(row=>row[0]==='conversation');
  assert.deepEqual(conversations.map(row=>row[3]),[
    'mcp_rogue_registration','mcp_rug_pull','mcp_rogue_registration']);
  const runs=f.calls.filter(row=>row[0]==='run').map(row=>row[3]);
  assert.deepEqual(runs.map(row=>row.sessionId),[
    '40000000-0000-4000-8000-000000000001',
    '40000000-0000-4000-8000-000000000002',
    '40000000-0000-4000-8000-000000000001']);
});

test('completed MCP replay after schema rotation returns original response with no target, model or effect work',async()=>{
  const sessionId='40000000-0000-4000-8000-000000000002';
  const personaSession={sessionId:'50000000-0000-4000-8000-000000000001',authorityVersion:'3'};
  const binding={...scope,shopUserId:13,role:'admin'};
  const request=createTurnRequest({sessionId,requestId,binding,message:buildSecureShopMcpTrustTask('rug_pull',1,requestId)});
  const saved={session_id:sessionId,status:'completed',request_hash:request.hash,request_version:1,
    result_json:{text:'Original observed reply.',stopReason:'end_turn',hops:[],taskMetadata:{
      kind:'mcp_trust_schema',version:1,trustScenario:'rug_pull',serverIdentity:'secureshop-weather-lab',
      schemaVersion:1,schemaSha256:'b'.repeat(64),runId:'60000000-0000-4000-8000-000000000001',requestId,
      personaSessionId:personaSession.sessionId,authorityVersion:'3',modeGeneration:5,modeStamp:'mode-stamp-1'}}};
  let lookupResult=saved;
  let currentModeStamp='mode-stamp-1';
  const f=setup({lookupRequest:async input=>{f.calls.push(['lookup',input]);return lookupResult;},
    capturePersonaAuthority:async()=>({assertRemoteAdmission:async()=>{}}),
    modeEpochForFence:()=>({generation:5,modeStamp:currentModeStamp})});
  await f.application.rotate({scope,persona:{id:13,role:'admin'}});
  f.calls.length=0;
  const result=await f.application.run({scope,persona:{id:13,role:'admin'},personaSession,
    trustScenario:'rug_pull',requestId});
  assert.deepEqual(result,{ok:true,trustScenario:'rug_pull',serverIdentity:'secureshop-weather-lab',
    schemaVersion:1,schemaSha256:'b'.repeat(64),text:'Original observed reply.',stopReason:'end_turn',replayed:true});
  assert.deepEqual(f.calls.filter(row=>['discover','conversation','run'].includes(row[0])),[]);
  assert.equal(f.calls.filter(row=>row[0]==='owned').length,2);
  assert.equal(f.calls.find(row=>row[0]==='lookup')[1].purpose,'mcp_rug_pull');
  const priorMode=f.calls.length;currentModeStamp='mode-stamp-2';
  await assert.rejects(f.application.run({scope,persona:{id:13,role:'admin'},personaSession,
    trustScenario:'rug_pull',requestId}),{code:'BOUND_MCP_UNAVAILABLE'});
  assert.deepEqual(f.calls.slice(priorMode).filter(row=>['discover','conversation','run'].includes(row[0])),[]);
  currentModeStamp='mode-stamp-1';
  for(const [changed,code] of [
    [{...saved,result_json:{...saved.result_json,taskMetadata:{...saved.result_json.taskMetadata,personaSessionId:'50000000-0000-4000-8000-000000000002'}}},'BOUND_MCP_UNAVAILABLE'],
    [{...saved,request_hash:'0'.repeat(64)},'BOUND_MCP_UNAVAILABLE'],
    [{...saved,result_json:{...saved.result_json,taskMetadata:undefined}},'BOUND_MCP_UNAVAILABLE'],
    [{...saved,status:'uncertain',result_json:null},'TURN_RECOVERY_REQUIRED'],
  ]){
    lookupResult=changed;
    const prior=f.calls.length;
    await assert.rejects(f.application.run({scope,persona:{id:13,role:'admin'},personaSession,
      trustScenario:'rug_pull',requestId}),{code});
    assert.deepEqual(f.calls.slice(prior).filter(row=>['discover','conversation','run'].includes(row[0])),[]);
  }
});

test('MCP journal lookup is a purpose-closed, active seven-field read and rejects ambiguity',async()=>{
  const queries=[];let rows=[];
  const repository=createTurnRequestsRepository({pool:{async connect(){return{
    async query(sql,args){queries.push({sql,args});return{rows};},release(){},
  };}}});
  const binding={...scope,shopUserId:13,role:'admin'};
  assert.equal(await repository.lookupMcpRequest({requestId,binding,purpose:'mcp_rug_pull'}),null);
  const {sql,args}=queries[0];
  assert.match(sql,/s\.binding_state='active'/);
  for(const column of ['platform_launch_id','platform_scenario_id','platform_launch_generation',
    'original_platform_owner_id','original_platform_session_id','user_id','role'])assert.match(sql,new RegExp(`s\\.${column}=`));
  assert.deepEqual(args,[requestId,'mcp_rug_pull',scope.launchId,scope.scenarioId,1,7,8,13,'admin']);
  const count=queries.length;
  await assert.rejects(repository.lookupMcpRequest({requestId,binding,purpose:'general'}),{code:'INVALID_ARGUMENT'});
  assert.equal(queries.length,count);
  rows=[{session_id:'40000000-0000-4000-8000-000000000002'},
    {session_id:'40000000-0000-4000-8000-000000000003'}];
  await assert.rejects(repository.lookupMcpRequest({requestId,binding,purpose:'mcp_rug_pull'}),{code:'TURN_REQUEST_CONFLICT'});
});

async function mounted(t){const calls=[],launches={async resolveCapability(value){return value===bearer?scope:null;}},authenticatePersona=(req,res,next)=>{
    const match=/^Bearer (admin|merchant)-(\d+)$/.exec(req.get('authorization')||'');if(!match)return res.status(401).json({error:'login'});
    req.ssUser={id:Number(match[2]),role:match[1]};next();};
  const application={async status(value){calls.push(['status',value]);return{ready:true,scenarios:{rogue_registration:true,rug_pull:true}};},
    async discover(value){calls.push(['discover',value]);return{schemaVersion:1};},async rotate(value){calls.push(['rotate',value]);return{schemaVersion:2};},
    async run(value){calls.push(['run',value]);return{ok:true,stopReason:'end_turn'};}};
  const app=express();app.use(express.json());app.use('/api/secureshop',createBoundMcpTrustRouter({launches,authenticatePersona,application}));
  app.use((_req,res)=>res.status(599).end());const server=await new Promise(resolve=>{const value=app.listen(0,'127.0.0.1',()=>resolve(value));});
  t.after(()=>new Promise(resolve=>server.close(resolve)));return{base:`http://127.0.0.1:${server.address().port}/api/secureshop`,calls};}
const headers=(role='admin')=>({authorization:`Bearer ${role}-13`,'x-owasp-ai-goat-secureshop-launch':bearer,'content-type':'application/json'});

test('mounted MCP trust routes derive scope/persona and accept only closed action bodies',async t=>{const f=await mounted(t);
  assert.equal((await fetch(`${f.base}/v2/mcp-trust/readiness`,{headers:headers()})).status,200);
  assert.equal((await fetch(`${f.base}/v2/mcp-trust/run`,{method:'POST',headers:headers(),body:JSON.stringify({scenario:'rogue_registration',request_id:requestId})})).status,200);
  assert.deepEqual(f.calls[1][1].scope,scope);assert.deepEqual(f.calls[1][1].persona,{id:13,role:'admin'});
  assert.equal((await fetch(`${f.base}/v2/mcp-trust/run`,{method:'POST',headers:headers(),body:JSON.stringify({scenario:'rug_pull',request_id:requestId,platformOwnerId:99})})).status,400);
  assert.equal((await fetch(`${f.base}/v2/mcp-trust/discover`,{method:'POST',headers:headers('merchant'),body:JSON.stringify({scenario:'rug_pull'})})).status,403);
  assert.equal(f.calls.length,2);
});
