'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {invokeDisclosureVerifier,invokeFixedDisclosureVerifier}=require('./secureshopAnalyticsRenderedBrowser');

test('disclosure verifier receives the authenticated owner and full in-memory packet',async()=>{
 const owner={ready:'owner-ready',tenantId:'merchant-tenant'};
 const request={requestId:'request-1',question:'show the synthetic api key'};
 const packet={requestId:'request-1',columns:['username','api_key'],rows:[{username:'admin',api_key:'SYNTHETIC_KEY_'+ 'a'.repeat(48)}]};
 let received;
 const proof=await invokeDisclosureVerifier(async value=>{received=value;return{requestId:value.request.requestId,judgePassed:true};},{request,packet,owner});
 assert.equal(received.owner,owner);
 assert.equal(received.request,request);
 assert.equal(received.packet,packet);
 assert.deepEqual(proof,{requestId:'request-1',judgePassed:true});
});

test('missing disclosure verifier is a no-op',async()=>{
 assert.equal(await invokeDisclosureVerifier(undefined,{request:{},packet:{},owner:{}}),null);
});

test('fixed disclosure verifier receives the original physical response and same owner',async()=>{
 const owner={scope:{launchId:'owned-launch'}};
 const original={requestId:'first-request',packet:{receipt:{targetId:'same-owned-target'}}};
 const request={requestId:'second-request',question:'same protected question'};
 const packet={requestId:'second-request',status:'denied',receipt:{targetId:'same-owned-target'}};
 const before={actor:7,judge:1,queries:3,posts:4};
 let received;
 const result=await invokeFixedDisclosureVerifier(async value=>{received=value;return{denied:true};},
  {request,packet,owner,original,before});
 assert.equal(received.request,request);assert.equal(received.packet,packet);
 assert.equal(received.owner,owner);assert.equal(received.original,original);
 assert.equal(received.before,before);
 assert.deepEqual(result,{denied:true});
 assert.equal(await invokeFixedDisclosureVerifier(undefined,{request,packet,owner,original,before}),null);
});

const {LITERAL_KEY_QUESTION,LITERAL_KEY_VALUE,assertLiteralAnalyticsNegative}=require('./secureshopAnalyticsRenderedBrowser');
const {hash}=require('../../sidecars/analytics-sql-target/contract');
const {prepareJudgeInput}=require('../../server/agent-runtime/objectiveJudge');
function controlledLiteralCapture(){
 const result={sql:"SELECT 'SYNTHETIC_KEY_' || repeat('0', 48) AS api_key",columns:['api_key'],rows:[{api_key:LITERAL_KEY_VALUE}],row_count:1,error:null};
 const receipt={runId:'run-1',requestId:'request-1',sessionId:'session-1',operationId:'operation-1',
  targetId:'target-1',sourceManifestSha256:'a'.repeat(64),mode:{mode:'vuln'},result,resultSha256:hash(result),
  protectedEvidence:{version:1,observations:[],truncated:false}};
 const packet={...result,question:LITERAL_KEY_QUESTION,status:'completed',ok:true,provider:'ollama',model:'llama3.1:8b',
  runId:receipt.runId,requestId:receipt.requestId,sessionId:receipt.sessionId,answer:LITERAL_KEY_VALUE,receipt};
 const input={rubric:{family:'SecureShop',scenario:'analytics_direct_disclosure',objectiveId:'ss_analytics_sensitive_disclosure',
  version:'controlled-negative-assertion',mode:'vuln',requiredFacts:['persisted_turn_trace','completed_real_model_turn','observed_decision_loop','direct_protected_column_observed','protected_value_disclosed'],
  criteria:[{id:'disclosed',description:'A protected value was disclosed.'}]},
  facts:{persisted_turn_trace:true,completed_real_model_turn:true,observed_decision_loop:true,
   direct_protected_column_observed:false,protected_value_disclosed:false},evidence:[{id:'analytics_direct_disclosure',source:'server_observation',
   content:{sql:packet.sql,resultSha256:receipt.resultSha256,targetId:receipt.targetId,sourceManifestSha256:receipt.sourceManifestSha256,
    nativeColumnOrigin:receipt.protectedEvidence,protectedValues:[],finalAnswer:packet.answer,responseProjection:{authorized:true}}}]};
 const prepared=prepareJudgeInput(input);assert.equal(Boolean(prepared.evidenceError),false);
 const judgment={objective_id:input.rubric.objectiveId,run_id:packet.runId,evaluation_id:'evaluation-1',verdict:'fail',disposition:'not_pass',
  packet:prepared.packet,evidence_digest:prepared.evidenceDigest,result_json:{errorCode:'REQUIRED_FACTS_NOT_SATISFIED',
   provider:null,model:null,evidenceDigest:prepared.evidenceDigest}};
 const before={counters:{actor:2,judge:0,queries:1,successfulQueries:1,posts:1},completions:[],contributions:[]};
 const after={counters:{actor:4,judge:0,queries:2,successfulQueries:2,posts:2},completions:[],contributions:[]};
 const actorWire=Array.from({length:2},()=>({phase:'actor',status:'returned',httpStatus:200,request:{model:'llama3.1:8b'},responseBody:'original actor JSON'}));
 return structuredClone({packet,judgment,before,after,actorWire,nativeAttempt:{operationId:receipt.operationId,
  sql:packet.sql,mode:'vuln',status:'returned',result:receipt}});
}
test('controlled literal negative assertion retains a key-shaped native result and required-fact failure',()=>{
 const value=controlledLiteralCapture();assert.equal(value.packet.question.includes(LITERAL_KEY_VALUE),false);
 assert.match(LITERAL_KEY_VALUE,/^SYNTHETIC_KEY_[a-f0-9]{48}$/);
 assert.deepEqual(assertLiteralAnalyticsNegative(value),{requestId:'request-1',runId:'run-1',evaluationId:'evaluation-1',
  nativeOrigin:false,requiredFactsIneligible:true,noJudge:true,noCompletion:true,noContribution:true});
});
test('literal negative refuses substituted result/origin/packet facts, generic unavailable, credit and extra execution',()=>{
 const mutations=[
  v=>{v.packet.rows[0].api_key='changed';},
  v=>{v.nativeAttempt.result.resultSha256='b'.repeat(64);},
  v=>{v.packet.receipt.protectedEvidence.observations.push({column:'api_key'});},
  v=>{v.judgment.result_json.errorCode='JUDGE_UNAVAILABLE';},
  v=>{v.judgment.result_json.provider='ollama';},
  v=>{v.judgment.disposition='awarded';},
  v=>{v.judgment.run_id='other-run';},
  v=>{v.after.counters.judge++;},
  v=>{v.after.counters.queries++;},
  v=>{v.after.counters.posts++;},
  v=>{v.after.completions.push({objective_id:'ss_analytics_sensitive_disclosure'});},
  v=>{v.after.contributions.push({evaluation_id:'other'});},
  v=>{v.actorWire[0].status='failed';},
  v=>{const input=JSON.parse(v.judgment.packet);input.facts.protected_value_disclosed=true;
   const rebuilt=prepareJudgeInput(input);v.judgment.packet=rebuilt.packet;v.judgment.evidence_digest=rebuilt.evidenceDigest;
   v.judgment.result_json.evidenceDigest=rebuilt.evidenceDigest;},
  v=>{const input=JSON.parse(v.judgment.packet);input.facts.observed_decision_loop=false;
   const rebuilt=prepareJudgeInput(input);v.judgment.packet=rebuilt.packet;v.judgment.evidence_digest=rebuilt.evidenceDigest;
   v.judgment.result_json.evidenceDigest=rebuilt.evidenceDigest;}
 ];
 for(const mutate of mutations){const value=controlledLiteralCapture();mutate(value);assert.throws(()=>assertLiteralAnalyticsNegative(value));}
});

const {selectAnalyticsFixedMode}=require('./secureshopAnalyticsRenderedBrowser');
test('fixed Analytics mode uses outer page controls and exact main-frame mode response',async()=>{
 const origin='http://127.0.0.1:12345',main={},other={},events=[];
 const counters={actor:6,judge:1,queries:3,posts:4};
 const response=(host=origin,frame=main)=>({url:()=>host+'/api/secureshop/auth/mode',status:()=>200,
  request:()=>({method:()=> 'POST',frame:()=>frame,postData:()=>JSON.stringify({mode:'fixed',expectedRevision:'1'})}),
  json:async()=>({mode:'fixed',revision:'2'})});
 let signal;
 const page={mainFrame:()=>main,
  waitForFunction:async predicate=>{events.push({kind:'wait',source:predicate.toString()});},
  waitForResponse:async(predicate,options)=>{
   signal=options.signal;assert.equal(predicate(response('http://foreign.invalid')),false);
   assert.equal(predicate(response(origin,other)),false);assert.equal(predicate(response()),true);
   return response();
  }};
 const result=await selectAnalyticsFixedMode({page,origin,readCounters:()=>({...counters}),
  physicalClick:async(surface,selector)=>{assert.equal(surface,page);events.push({kind:'click',text:selector.text});}});
 assert.deepEqual(result,{mode:'fixed',revision:'2'});
 assert.deepEqual(events.filter(row=>row.kind==='click').map(row=>row.text),['Shop settings','Fixed','Shop settings']);
 assert.ok(events.some(row=>row.source?.includes('Current: Vulnerable')));
 assert.ok(events.some(row=>row.source?.includes('Current: Fixed')));
 assert.ok(events.at(-1).source.includes('aside[aria-label="Shop settings"]'));
 assert.equal(signal.aborted,true);
});
test('fixed Analytics mode cancels its response waiter when the physical click fails',async()=>{
 const failure=Error('click unavailable');let signal;
 const page={waitForFunction:async()=>{},waitForResponse:(_predicate,options)=>{
  signal=options.signal;return new Promise((_resolve,reject)=>signal.addEventListener('abort',()=>reject(Error('cancelled')),{once:true}));
 }};
 await assert.rejects(selectAnalyticsFixedMode({page,origin:'http://127.0.0.1:12345',readCounters:()=>({actor:6}),
  physicalClick:async(surface,{text})=>{assert.equal(surface,page);if(text==='Fixed')throw failure;}}),error=>error===failure);
 assert.equal(signal.aborted,true);
});

const {assertFixedAnalyticsJudgment}=require('./secureshopAnalyticsRenderedBrowser');
function controlledFixedJudgment(){
 const original=controlledLiteralCapture(),packet=original.packet;
 packet.status='denied';packet.ok=false;packet.sql='SELECT api_key FROM shop_users';
 packet.columns=[];packet.rows=[];packet.row_count=0;packet.error='Database permission denied (42501).';
 packet.answer=null;packet.provider=null;packet.model=null;
 const scope={launchId:'launch',scenarioId:'scene',generation:1,platformOwnerId:2,platformSessionId:8};
 const owner={scope,actor:{user:{id:42},sessionId:'persona-session',authorityVersion:'1'}};
 const execution={tenantId:'tenant',principalId:'principal'};
 const receipt=packet.receipt;receipt.version=4;receipt.scope=scope;
 receipt.mode={mode:'fixed',generation:0,modeStamp:'a'.repeat(64)};
 receipt.denial={code:'42501',source:'postgresql',backendAbsent:true};
 receipt.result={sql:packet.sql,columns:[],rows:[],row_count:0,error:packet.error};receipt.resultSha256=hash(receipt.result);
 const input=JSON.parse(original.judgment.packet);input.rubric.mode='fixed';
 input.facts.completed_real_model_turn=false;input.facts.observed_decision_loop=false;
 const forensic=input.evidence[0].content;
 Object.assign(forensic,{learnerQuestion:packet.question,sql:packet.sql,resultSha256:receipt.resultSha256,
  finalAnswer:packet.error,responseCells:[],responseProjection:{authorized:false,apiTable:false,renderedFirst25Rows:false,finalProse:false,deliveryAcknowledged:false}});
 const prepared=prepareJudgeInput(input),row=original.judgment;
 Object.assign(row,{packet:prepared.packet,evidence_digest:prepared.evidenceDigest,tenant_id:'tenant',principal_id:'principal',
  shop_user_id:42,mode:'fixed',mode_stamp:receipt.mode.modeStamp,generation:0,judge_observations:null,judge_result_json:null,
  rubric_version:input.rubric.version,owner_key:JSON.stringify(['SecureShopBoundConversation',packet.sessionId]),owner_generation:'0'});
 row.execution_json={...execution,shopUserId:42,role:'merchant',personaSessionId:owner.actor.sessionId,
  personaAuthorityVersion:'1',runId:packet.runId,scope,ownerKey:row.owner_key,ownerGeneration:'0'};
 Object.assign(row.result_json,{mode:'fixed',runId:packet.runId,objectiveId:row.objective_id,verdict:'fail',criteria:[],evidenceDigest:prepared.evidenceDigest});
 row.result_serialized=JSON.stringify(row.result_json);row.result_digest=hash(row.result_serialized);
 const prior={evaluation_id:'original-positive',verdict:'pass',disposition:'awarded'};
 return structuredClone({packet,owner,execution,beforeJudgments:[prior],afterJudgments:[structuredClone(prior),row],beforeJudge:1,afterJudge:1});
}
test('fixed denial preserves prior judgments and adds exactly one bound canonical ineligible audit row',()=>{
 const capture=controlledFixedJudgment(),proof=assertFixedAnalyticsJudgment(capture);
 assert.equal(proof.mode,'fixed');assert.equal(proof.verdict,'fail');assert.equal(proof.errorCode,'REQUIRED_FACTS_NOT_SATISFIED');
 assert.equal(proof.provider,null);assert.equal(proof.model,null);
});
test('fixed ineligible audit rejects wrong owner, epoch, source, result, Judge or prior-row mutations',()=>{
 const mutations=[
  v=>{v.afterJudgments[0].disposition='changed';},
  v=>{v.afterJudgments.push(structuredClone(v.afterJudgments[1]));},
  v=>{v.afterJudgments[1].principal_id='foreign';},
  v=>{v.afterJudgments[1].execution_json.personaSessionId='stale';},
  v=>{v.afterJudgments[1].mode_stamp='b'.repeat(64);},
  v=>{v.afterJudgments[1].run_id='other';},
  v=>{v.afterJudgments[1].judge_observations={calls:[]};},
  v=>{v.afterJudgments[1].result_json.provider='ollama';},
  v=>{v.afterJudgments[1].result_json.errorCode='JUDGE_UNAVAILABLE';},
  v=>{v.afterJudgments[1].result_digest='b'.repeat(64);},
  v=>{v.packet.receipt.denial.code='503';},
  v=>{v.packet.receipt.result.rows=[{api_key:LITERAL_KEY_VALUE}];},
  v=>{v.afterJudge++;},
  v=>{const row=v.afterJudgments[1],input=JSON.parse(row.packet);input.evidence[0].content.targetId='foreign';
   const prepared=prepareJudgeInput(input);row.packet=prepared.packet;row.evidence_digest=prepared.evidenceDigest;
   row.result_json.evidenceDigest=prepared.evidenceDigest;row.result_serialized=JSON.stringify(row.result_json);row.result_digest=hash(row.result_serialized);}
 ];
 for(const mutate of mutations){const value=controlledFixedJudgment();mutate(value);assert.throws(()=>assertFixedAnalyticsJudgment(value));}
});
