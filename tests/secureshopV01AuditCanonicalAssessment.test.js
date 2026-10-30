'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {randomUUID,createHash}=require('node:crypto');
const {createSecureShopV01AuditChat}=require('../server/services/secureshopV01AuditChat');
const {createV01AuditAssessment,assessmentRequestId}=require('../server/services/secureshopV01AuditAssessment');
const {createTurnRequest}=require('../server/services/secureshopTurnRequest');
const {createLaunchScope}=require('../server/services/secureshopConversationBinding');
const {prepareJudgeInput}=require('../server/agent-runtime/objectiveJudge');
const {POLICIES}=require('../server/services/secureshopFeatureModeAuthority');

const sha=value=>createHash('sha256').update(value).digest('hex');
async function fixture({verdict='fail',modelArgs={},modelDecision='tool'}={}){
  const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:2,
    platformOwnerId:19,platformSessionId:23},persona={id:41,role:'customer'};
  const binding={...scope,shopUserId:41,role:'customer'};
  const personaSession={sessionId:randomUUID(),authorityVersion:'2'};
  const sessionId=randomUUID(),requestId=randomUUID(),assessmentSessionId=randomUUID();
  const sourceRunId=randomUUID(),assessmentRunId=randomUUID();
  const checkoutOperationId=randomUUID(),eventId=randomUUID();
  const target={...scope,targetId:randomUUID(),scene:{sceneId:randomUUID(),
    sceneGeneration:1,grantId:randomUUID()}};
  const report={eventId,timestamp:'2026-10-15T02:02:02.000000Z',actor:'customer',
    action:'checkout',outcome:'completed',orderId:83,total:17.25};
  const publicResult={content:[{type:'text',text:JSON.stringify({status:'disclosed',
    eventId,report,sourceSha256:'a'.repeat(64)})}]};
  const weak=new WeakMap(),messages=[],traces=[],sourceEffects=[];
  let sourceRow=null,assessmentRow=null,canonicalRow=null,judgeCalls=0,
    modelCalls=0,toolCalls=0,protectedReads=0,assessmentEffects=0,
    mode='vuln',active=true;
  const check=async()=>{if(!active)throw Object.assign(Error('reset'),{code:'STALE_LAUNCH'});};
  const modeAuthority={async capture(){const snapshot={version:1,featureId:'checkout_audit_jwt',
    policyVersion:POLICIES.checkout_audit_jwt,mode,generation:2,modeStamp:'controlled',scope};
    return {snapshot,async assertCurrent(){await check();assert.equal(mode,snapshot.mode);},
      async assertCurrentAtEffect(){await check();assert.equal(mode,snapshot.mode);}};},
    assertToken(value){return value;}};
  const personaAuthority={async capture({scope:s,personaId,role,sessionId:id,authorityVersion}){
    return {binding:{...s,personaId,role,sessionId:id,authorityVersion},
      async assertRemoteAdmission(){await check();},
      async withPersonaEffect(work){await check();return work({});}};}};
  const lesson={async presentCustomerToken(){return {orderId:83,operationId:checkoutOperationId,
    token:'signed-synthetic-teaching-token'};},
    async readAudit(){toolCalls++;return structuredClone(publicResult);},
    async bindObservedEffect(input,observed){
      protectedReads++;await input.execution.check();
      assert.equal(input.checkoutOperationId,checkoutOperationId);
      assert.equal(input.teachingToken,'forged-alg-none-teaching-token');
      assert.deepEqual(observed.result,publicResult);
      const evidence={version:1,feature:'checkout_audit_jwt',scope:createLaunchScope(binding),
        personaId:41,personaSessionId:personaSession.sessionId,
        personaAuthorityVersion:'2',targetId:target.targetId,
        sceneId:target.scene.sceneId,sceneGeneration:1,checkoutOperationId,
        orderId:83,requestId,eventId,sourceSha256:'a'.repeat(64),
        teachingAlgorithm:'none',mode:'vuln',
        execution:{runId:input.execution.runId,ownerKey:input.execution.ownerKey,
          durableGeneration:String(input.execution.durableGeneration)},
        effectReceipt:observed.effectReceipt,
        graphOrigin:{step:observed.step,callId:observed.callId,tool:observed.tool}};
      weak.set(observed,evidence);return evidence;
    },evidenceFor(observed){return weak.get(observed);}};
  const session=(id,purpose)=>({id,state:'active',purpose,binding});
  const conversationRepository={async getBoundSession(id){return id===sessionId
    ?session(id,'secureshop_checkout_audit_jwt')
    :id===assessmentSessionId?session(id,'persona_inbox'):null;},
    async acquireBoundSession(){return {id:assessmentSessionId,state:'active'};},
    async appendMessage(_id,_binding,value){messages.push(value);},
    async getMessages(){return messages;},async getTokens(){return 0;},async addTokens(){},
    async appendTraces(_id,_binding,rows){traces.push(...rows);},
    async getTraceEvents(_id,_binding,ids){return ids.map(id=>traces.find(t=>t.event_id===id));}};
  const journal={async claim(input){const chosen=input.sessionId===sessionId?sourceRow:assessmentRow;
    if(chosen)return {status:chosen.status,result:chosen.result_json};
    const turn=createTurnRequest(input);
    const row={session_id:input.sessionId,request_id:input.requestId,
      request_hash:turn.hash,request_version:turn.version,status:'started',result_json:null};
    if(input.sessionId===sessionId)sourceRow=row;else assessmentRow=row;
    return {status:'claimed',claimId:randomUUID()};},
    async complete(input){const row=input.sessionId===sessionId?sourceRow:assessmentRow;
      row.status='completed';row.result_json=structuredClone(input.result);},
    async markUncertain(){},async readV01AuditRequest(){return sourceRow;}};
  const sourceOwner=JSON.stringify(['SecureShopBoundConversation',sessionId]);
  const assessmentOwner=JSON.stringify(['SecureShopBoundConversation',assessmentSessionId]);
  const graphEffect={run_id:sourceRunId,owner_key:sourceOwner,generation:'0',effect_key:null,
    status:'completed',run_status:'completed',live_generation:'0'};
  const coordinator={async run(id,options,operation){const source=id===sessionId;
    const runId=source?sourceRunId:assessmentRunId,ownerKey=source?sourceOwner:assessmentOwner;
    const boundary={runId,ownerKey,generation:'0',durableGeneration:'0',check,
      async effectWithReceipt(node,work){
        if(!source){assessmentEffects++;throw Error('assessment cannot replay source effect');}
        sourceEffects.push(node);graphEffect.effect_key=`${options.idempotencyKey}:${node}`;
        return {value:await work(),receipt:{version:1,status:'completed',runId,
          ownerKey,generation:'0',effectKey:graphEffect.effect_key}};
      }};
    return operation(boundary);
  }};
  const provider={async chat(){modelCalls++;return modelDecision==='decline'
    ?{provider:'actual-provider',model:'actual-model',mocked:false,
      stop_reason:'end_turn',text:'I cannot inspect that audit.',responseMode:'structured_final'}
    :{provider:'actual-provider',model:'actual-model',
      mocked:false,stop_reason:'tool_use',tool_uses:[{id:'actual-call',name:'auth.audit_probe',
        args:structuredClone(modelArgs)}]};},
    async finalResponse(){modelCalls++;return {provider:'actual-provider',model:'actual-model',
      mocked:false,stop_reason:'end_turn',text:'The protected audit report was observed.',
      responseMode:'structured_final'};}};
  const launches={assertCurrent:check,async resolveCapability(){return scope;}};
  const chat=createSecureShopV01AuditChat({launches,
    personaAuthority,modeAuthority,conversations:conversationRepository,journal,
    coordinator,provider,scenes:{async readExisting(){return target;}},lesson});
  const {createBoundV01AuditLessonRouter}=require('../server/routes/secureshop/boundV01AuditLesson');
  const express=require('express');
  const router=createBoundV01AuditLessonRouter({launches,
    authenticatePersona(req,_res,next){req.ssUser=persona;req.ssPersonaSession=personaSession;next();},
    runtime:chat,assessment:{async runAttempt(){throw Error('assessment unavailable during source turn');},
      async readOutcome(){throw Error('assessment unavailable during source turn');}}});
  const app=express();app.use(express.json());app.use('/api/secureshop',router);
  const server=app.listen(0);let stream;
  try{const response=await fetch(`http://127.0.0.1:${server.address().port}/api/secureshop/agents/customer/checkout-audit/chat`,{
    method:'POST',headers:{'content-type':'application/json','x-owasp-ai-goat-secureshop-launch':'a'.repeat(43)},
    body:JSON.stringify({sessionId,requestId,checkoutOperationId,
      teachingToken:'forged-alg-none-teaching-token',message:'Read my protected checkout audit.'})});
    assert.equal(response.status,200);stream=await response.text();assert.match(stream,/event: done/);
  }finally{await new Promise(resolve=>server.close(resolve));}
  const original=sourceRow.result_json;
  assert.equal(original.stopReason,'end_turn');
  assert.equal(sourceEffects.length,modelDecision==='tool'?1:0);
  assert.equal(traces.some(t=>t.kind==='model_decision'),true);
  const publication={generation:2,mode:'vuln',modeStamp:'controlled-publication'};
  const receipts={async beginEvaluation(input){
    const rubric=JSON.parse(input.recovery.packet).rubric;
    canonicalRow={tenant_id:randomUUID(),principal_id:randomUUID(),
      evaluation_id:input.evaluationId,shop_user_id:41,workshop_key:'secureshop_agent_security',
      objective_id:input.objectiveId,family:rubric.family,scenario:rubric.scenario,
      rubric_version:rubric.version,mode:'vuln',generation:2,
      mode_stamp:publication.modeStamp,owner_key:assessmentOwner,owner_generation:'0',
      live_owner_generation:'0',run_id:assessmentRunId,packet:input.recovery.packet,
      evidence_digest:sha(input.recovery.packet),child_id:null};
    Object.assign(canonicalRow,{current_tenant_id:canonicalRow.tenant_id,
      current_principal_id:canonicalRow.principal_id,current_membership_version:'1',
      execution_json:{tenantId:canonicalRow.tenant_id,principalId:canonicalRow.principal_id,
        membershipVersion:'1',scope:createLaunchScope(binding),
        personaSessionId:personaSession.sessionId,personaAuthorityVersion:'2',
        role:'customer',runId:assessmentRunId}});
    return {verdict:null};},
    async recordVerdict({result}){const serialized=JSON.stringify(result);
      Object.assign(canonicalRow,{verdict:result.verdict,
        disposition:result.verdict==='pass'?'awarded':'not_pass',
        result_json:result,result_serialized:serialized,result_digest:sha(serialized)});
      return {verdict:result.verdict,disposition:canonicalRow.disposition,result};}};
  const identityPool={async query(sql){
    if(sql.includes('identity.secureshop_authority_owners'))return {rows:[{realm:'platform',shop_tenant_id:null}]};
    if(sql.includes('workshop_platform.objectives'))return {rows:[{objective_id:'ss_auth_bypass_jwt_none'}]};
    if(sql.includes('FROM graph_runtime.effects'))return {rows:[graphEffect]};
    if(sql.includes('FROM secureshop_auth.execution_authority_state'))return {rows:canonicalRow?[canonicalRow]:[]};
    throw Error('Unexpected identity SQL');}};
  const service=createV01AuditAssessment({identityPool,agentsPool:{async query(){return {rows:assessmentRow?[assessmentRow]:[]};}},
    launches:{assertCurrent:check},conversationRepository,coordinator,journal,
    personaAuthority,personaBindings:{async capture(){return {controlled:true};}},
    scenes:{async readExisting(){return target;}},modeAuthority,lesson,receipts,
    progress:{async getGeneration(){return 2;},async getEvaluationScope(){return publication;}},
    publicationModes:{async getEvaluationScope(){return publication;}},
    async judge(input){judgeCalls++;assert.ok(prepareJudgeInput(input).packet);
      return {verdict,explanation:'Controlled independent Judge verdict',criteria:[]};},
    qualifyModel:()=>true});
  return {service,scope,persona,personaSession,sessionId,requestId,
    counts:()=>({modelCalls,toolCalls,protectedReads,assessmentEffects,judgeCalls}),
    trace:traces,graphEffect,sourceRow:()=>sourceRow,
    canonicalRow:()=>canonicalRow,revoke:()=>{active=false;},setMode:value=>{mode=value;}};
}

test('actual bound graph trace enters canonical Judge once; saved failure replays without model or effect',async()=>{
  const f=await fixture(),input={scope:f.scope,persona:f.persona,
    personaSession:f.personaSession,sessionId:f.sessionId,requestId:f.requestId};
  assert.deepEqual(await f.service.readOutcome(input),
    {completed:false,status:'unconfirmed',modelEvaluated:false});
  const outcome=await f.service.runAttempt(input);
  assert.equal(outcome.completed,false);assert.equal(outcome.judgment.verdict,'fail');
  assert.equal(f.counts().judgeCalls,1);assert.equal(f.counts().modelCalls,2);
  assert.equal(f.counts().toolCalls,1);assert.equal(f.counts().assessmentEffects,0);
  assert.equal(f.canonicalRow().run_id!==f.sourceRow().result_json.taskMetadata.checkoutAuditJwt.originalEvidence.execution.runId,true);
  assert.deepEqual(await f.service.readOutcome(input),{...outcome,replayed:true});
  assert.deepEqual(await f.service.runAttempt(input),{...outcome,replayed:true});
  assert.equal(f.counts().judgeCalls,1);assert.equal(f.counts().toolCalls,1);
  const guard=await f.service.assertRetainedPacket({...input,packet:f.canonicalRow().packet});
  await guard.assertCurrent();
});
test('controlled Judge pass commits canonical receipt and saved completion projection',async()=>{
  const f=await fixture({verdict:'pass'}),input={scope:f.scope,persona:f.persona,
    personaSession:f.personaSession,sessionId:f.sessionId,requestId:f.requestId};
  const result=await f.service.runAttempt(input);
  assert.equal(result.completed,true);assert.equal(result.judgment.verdict,'pass');
  assert.equal(f.canonicalRow().disposition,'awarded');
  assert.deepEqual(await f.service.readOutcome(input),{...result,replayed:true});
  assert.equal(f.counts().judgeCalls,1);assert.equal(f.counts().modelCalls,2);
  assert.equal(f.counts().toolCalls,1);assert.equal(f.counts().assessmentEffects,0);
});
test('v2 rejects model-supplied checkout or token arguments before the bound verifier',async()=>{
  const f=await fixture({modelArgs:{teachingToken:'mutated-model-copy'}});
  assert.equal(f.sourceRow().result_json.taskMetadata.checkoutAuditJwt.version,2);
  assert.equal(f.sourceRow().result_json.taskMetadata.checkoutAuditJwt.state,'no_effect');
  assert.equal(f.counts().toolCalls,0);assert.equal(f.counts().protectedReads,0);
  await assert.rejects(f.service.runAttempt({scope:f.scope,persona:f.persona,
    personaSession:f.personaSession,sessionId:f.sessionId,requestId:f.requestId}),
  {code:'V01_AUDIT_ASSESSMENT_UNAVAILABLE'});
  assert.equal(f.counts().judgeCalls,0);
});
test('v2 model decline through the HTTP chat route performs no protected read or grading',async()=>{
  const f=await fixture({modelDecision:'decline'});
  assert.equal(f.sourceRow().result_json.taskMetadata.checkoutAuditJwt.version,2);
  assert.equal(f.sourceRow().result_json.taskMetadata.checkoutAuditJwt.state,'no_effect');
  assert.deepEqual(f.sourceRow().result_json.hops,[]);
  assert.equal(f.counts().modelCalls,1);assert.equal(f.counts().toolCalls,0);
  assert.equal(f.counts().protectedReads,0);
  await assert.rejects(f.service.runAttempt({scope:f.scope,persona:f.persona,
    personaSession:f.personaSession,sessionId:f.sessionId,requestId:f.requestId}),
  {code:'V01_AUDIT_ASSESSMENT_UNAVAILABLE'});
  assert.equal(f.counts().judgeCalls,0);
});
test('mutated completed source effect cannot reach canonical Judge',async()=>{
  const f=await fixture(),input={scope:f.scope,persona:f.persona,
    personaSession:f.personaSession,sessionId:f.sessionId,requestId:f.requestId};
  f.graphEffect.status='started';
  assert.deepEqual(await f.service.runAttempt(input),
    {completed:false,status:'ineligible',modelEvaluated:false});
  assert.equal(f.counts().judgeCalls,0);
});
for(const [name,mutate] of [
  ['selected actor',f=>{const i=f.trace.findIndex(t=>t.kind==='model_decision');
    f.trace[i]={...f.trace[i],actor:'task'};}],
  ['final step',f=>{const i=f.trace.findLastIndex(t=>t.kind==='model_decision');
    f.trace[i]={...f.trace[i],step:99};}],
  ['terminal step',f=>{f.trace[f.trace.length-1]={...f.trace.at(-1),step:99};}],
  ['extra local call',f=>{
    const extra={...f.trace.find(t=>t.kind==='local_tool_call'),event_id:randomUUID()};
    f.trace.splice(-1,0,extra);
    f.sourceRow().result_json.taskMetadata.checkoutAuditJwt.traceEventIds.splice(-1,0,extra.event_id);
  }],
])test(`actual graph trace mutation ${name} cannot reach Judge`,async()=>{
  const f=await fixture(),input={scope:f.scope,persona:f.persona,
    personaSession:f.personaSession,sessionId:f.sessionId,requestId:f.requestId};
  mutate(f);
  assert.deepEqual(await f.service.runAttempt(input),
    {completed:false,status:'ineligible',modelEvaluated:false});
  assert.equal(f.counts().judgeCalls,0);
  assert.equal(f.counts().toolCalls,1);
});

test('actual assessment service enters POST route and saved GET with bounded canonical DTO',async()=>{
  const {EventEmitter}=require('node:events');
  const {createBoundV01AuditLessonRouter}=require('../server/routes/secureshop/boundV01AuditLesson');
  const f=await fixture({verdict:'pass'});
  const runtime=Object.fromEntries(['createSession','issueToken','readRequest','run']
    .map(name=>[name,()=>{throw Error(`Unexpected ${name}`);} ]));
  const router=createBoundV01AuditLessonRouter({launches:{resolveCapability(){}},
    authenticatePersona(_req,_res,next){next();},runtime,assessment:f.service});
  const handler=(method,path)=>{
    const row=router.stack.find(layer=>layer.route?.path===path&&layer.route.methods[method]);
    assert.ok(row);return row.route.stack.at(-1).handle;
  };
  const req=(body={},params={})=>Object.assign(new EventEmitter(),{aborted:false,
    ssLaunch:f.scope,boundPersona:f.persona,ssPersonaSession:f.personaSession,
    body,params,query:{},is:()=>true});
  const res=()=>Object.assign(new EventEmitter(),{writableEnded:false,destroyed:false,
    set(){return this;},status(code){this.statusCode=code;return this;},
    json(value){this.body=value;this.writableEnded=true;return this;}});
  const posted=res(),saved=res();
  await handler('post','/agents/customer/checkout-audit/assess')(
    req({sessionId:f.sessionId,requestId:f.requestId}),posted);
  assert.equal(posted.statusCode,200);
  assert.deepEqual(Object.keys(posted.body).sort(),['completed','judgment','replayed']);
  assert.equal(posted.body.completed,true);assert.equal(posted.body.replayed,false);
  assert.equal(posted.body.judgment.verdict,'pass');
  assert.deepEqual(Object.keys(posted.body.judgment).sort(),['canRetry','evaluationId','verdict']);
  await handler('get','/agents/customer/checkout-audit/assess/:sessionId/:requestId')(
    req({}, {sessionId:f.sessionId,requestId:f.requestId}),saved);
  assert.equal(saved.statusCode,200);
  assert.deepEqual(saved.body,{...posted.body,replayed:true});
  assert.equal(f.counts().judgeCalls,1);assert.equal(f.counts().toolCalls,1);
});
