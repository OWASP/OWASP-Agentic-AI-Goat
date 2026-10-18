'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {randomUUID}=require('node:crypto');
const {createTurnRequest}=require('../server/services/secureshopTurnRequest');
const {buildV01AuditCandidate,V01_AUDIT_RUBRIC}=require('../server/services/secureshopV01AuditEvidence');
const {prepareJudgeInput}=require('../server/agent-runtime/objectiveJudge');

function fixture(version=1){
  const sessionId=randomUUID(),requestId=randomUUID(),runId=randomUUID(),eventId=randomUUID();
  const checkoutOperationId=randomUUID(),targetId=randomUUID(),sceneId=randomUUID();
  const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:2,
    platformOwnerId:7,platformSessionId:8};
  const binding={...scope,shopUserId:42,role:'customer'};
  const personaSession={sessionId:randomUUID(),authorityVersion:'1'};
  const admitted={checkoutOperationId,teachingToken:'synthetic-forged-teaching-jwt'};
  const args=version===1?admitted:{};
  const originalEnvelope=JSON.stringify({version,mode:{featureId:'checkout_audit_jwt',
    mode:'vuln'},targetId,sceneId,sceneGeneration:1,grantId:randomUUID(),
    ...admitted,message:'Read the protected audit for my checkout.'});
  const ownerKey=JSON.stringify(['SecureShopBoundConversation',sessionId]);
  const effectKey=`${requestId}:${JSON.stringify([1,'original-call','auth.audit_probe'])}`;
  const effect={status:'disclosed',eventId,sourceSha256:'a'.repeat(64),
    report:{eventId,timestamp:'2026-10-15T02:02:02.000000Z',actor:'customer',
      action:'checkout',outcome:'completed',orderId:83,total:17.25}};
  const result={content:[{type:'text',text:JSON.stringify(effect)}]};
  const saved={version:1,feature:'checkout_audit_jwt',scope,
    personaId:42,personaSessionId:personaSession.sessionId,
    personaAuthorityVersion:'1',targetId,sceneId,sceneGeneration:1,
    checkoutOperationId,orderId:83,requestId,eventId,sourceSha256:effect.sourceSha256,
    teachingAlgorithm:'none',mode:'vuln',execution:{runId,ownerKey,durableGeneration:'2'},
    effectReceipt:{version:1,status:'completed',runId,ownerKey,generation:'2',effectKey},
    graphOrigin:{step:1,callId:'original-call',tool:'auth.audit_probe'}};
  const model={model:'actual-model',mocked:false};
  const ids=Array.from({length:6},()=>randomUUID());
  const trace=(i,properties)=>({event_id:ids[i],session_id:sessionId,...properties});
  const traces=[
    trace(0,{kind:'model_decision',actor:'supervisor',step:1,provider:'actual-provider',
      params_json:JSON.stringify({decision:'tool_use',toolCalls:[{id:'original-call',
        name:'auth.audit_probe',args}]}),result_json:JSON.stringify(model)}),
    trace(1,{kind:'local_tool_call',actor:'supervisor→task',step:1,agent_ns:'auth',
      tool_name:'audit_probe',params_json:JSON.stringify(args)}),
    trace(2,{kind:'local_tool_result',actor:'task→supervisor',step:1,agent_ns:'auth',
      tool_name:'audit_probe',result_json:JSON.stringify(result)}),
    trace(3,{kind:'model_decision',actor:'supervisor',step:2,provider:'actual-provider',
      result_json:JSON.stringify({decision:'final',text:'The audit report was observed.',
        stopReason:'end_turn',...model})}),
    trace(4,{kind:'final',actor:'supervisor',step:2}),
    trace(5,{kind:'terminal',actor:'supervisor',step:2,provider:'actual-provider',
      result_json:JSON.stringify({stopReason:'end_turn',steps:2,hops:1,...model})}),
  ];
  const turn={stopReason:'end_turn',text:'The audit report was observed.',steps:2,
    hops:[{step:1,tool:'auth.audit_probe',params:args,result,latencyMs:1,
      error:null,policyViolation:null}],
    modeCapability:{effectiveMode:'vuln'},
    taskMetadata:{checkoutAuditJwt:{version,originalEnvelope,state:'observed',
      traceEventIds:ids,originalEvidence:saved}}};
  const row={session_id:sessionId,request_id:requestId,status:'completed',
    request_hash:createTurnRequest({sessionId,requestId,binding,
      message:originalEnvelope}).hash,request_version:1,result_json:turn};
  const graphEffect={run_id:runId,owner_key:ownerKey,generation:'2',effect_key:effectKey,
    status:'completed',run_status:'completed',live_generation:'2'};
  return {binding,personaSession,row,traces,retained:structuredClone(saved),
    graphEffect,qualifyModel:()=>true};
}
test('V01 candidate requires real original model, owned graph effect and exact saved source',()=>{
  const value=buildV01AuditCandidate(fixture());
  assert.equal(value?.objectiveId,V01_AUDIT_RUBRIC.objectiveId);
  assert.ok(!prepareJudgeInput({rubric:V01_AUDIT_RUBRIC,...value}).evidenceError);
  assert.equal(JSON.stringify(value).includes('synthetic-forged-teaching-jwt'),false);
});
test('V01 v2 candidate retains no-argument model provenance and server-bound admitted input',()=>{
  const f=fixture(2),value=buildV01AuditCandidate(f);
  assert.equal(value?.objectiveId,V01_AUDIT_RUBRIC.objectiveId);
  assert.deepEqual(f.row.result_json.hops[0].params,{});
  assert.equal(JSON.stringify(value).includes('synthetic-forged-teaching-jwt'),false);
  f.row.result_json.hops[0].params={teachingToken:'model-substitution'};
  assert.equal(buildV01AuditCandidate(f),null);
});
for(const [name,mutate] of [
  ['mock selected model',f=>{f.traces[0].result_json=JSON.stringify({model:'actual-model',mocked:true});}],
  ['fallback terminal model',f=>{f.traces.at(-1).result_json=JSON.stringify({model:'actual-model',mocked:false,fallback:true,stopReason:'end_turn',steps:2,hops:1});}],
  ['stale graph owner',f=>{f.graphEffect.live_generation='3';}],
  ['uncommitted graph effect',f=>{f.graphEffect.status='started';}],
  ['substituted audit event',f=>{f.retained.eventId=randomUUID();}],
  ['changed learner tool token',f=>{f.row.result_json.hops[0].params.teachingToken='other';}],
  ['changed original request hash',f=>{f.row.request_hash='b'.repeat(64);}],
  ['fixed mode',f=>{f.row.result_json.modeCapability.effectiveMode='fixed';}],
  ['unqualified model',f=>{f.qualifyModel=()=>false;}],
  ['non-supervisor model decision',f=>{f.traces[0].actor='task';}],
])test(`V01 candidate denies ${name}`,()=>{
  const f=fixture();mutate(f);assert.equal(buildV01AuditCandidate(f),null);
});
