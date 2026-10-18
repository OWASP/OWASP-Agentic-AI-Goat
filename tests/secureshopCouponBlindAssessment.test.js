'use strict';

// Controlled immutable mail graph/HTTP rows and negative Judge only. No actual model or credit.
const test=require('node:test');
const assert=require('node:assert/strict');
const {createHash}=require('node:crypto');
const {fixture:originalFixture}=require('./secureshopCouponBlindEvidence.test');
const {createCouponBlindAssessment,assessmentRequestId}=require('../server/services/secureshopCouponBlindAssessment');
const {OBJECTIVE,RUBRIC}=require('../server/services/secureshopCouponBlindEvidence');
const {createTurnRequest}=require('../server/services/secureshopTurnRequest');
const {createLaunchScope}=require('../server/services/secureshopConversationBinding');
const {prepareJudgeInput}=require('../server/agent-runtime/objectiveJudge');
const id=n=>`b0000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
const hash=value=>createHash('sha256').update(value).digest('hex');
function fixture(){
 const f=originalFixture(),qualifyModelTrace=f.qualifyModelTrace;
 const {source,privateReference}=f;
 const binding={...source.binding.scope,shopUserId:source.binding.persona.id,role:'customer'},scope=createLaunchScope(binding);
 const reference={sessionId:source.turn.sessionId,requestId:source.turn.requestId};
 const persona=source.binding.persona,session={...source.binding.personaSession};
 const p={execution:{generation:1,mode:'vuln',modeStamp:'controlled-publication'}};
 const assessmentSession=id(1),assessmentRun=id(2),owner=JSON.stringify(['SecureShopBoundConversation',assessmentSession]);
 const publication={generation:p.execution.generation,mode:p.execution.mode,modeStamp:p.execution.modeStamp};
 let active=true,enabled=true,scene=true,journalRow=null,canonicalRow=null;
 let judgeMutation=()=>{},capturedPacket=null,sourceError=null,completeError=null;
 const calls={source:0,judge:0,claim:0,complete:0,verdict:0,acquire:0,effects:0,uncertain:0};
 const check=async()=>{if(!active)throw Object.assign(Error('revoked'),{code:'SHOP_AUTH_INVALID'});};
 const identityPool={async query(sql,args){
  if(sql.includes('identity.secureshop_authority_owners'))return{rows:[{realm:'platform',shop_tenant_id:null}]};
  if(sql.includes('workshop_platform.objectives'))return{rows:enabled?[{objective_id:OBJECTIVE}]:[]};
  if(sql.includes('FROM secureshop_auth.execution_authority_state')){
   if(sql.startsWith('SELECT j.rubric_version')){
    assert.deepEqual(args,[binding.platformSessionId,binding.platformOwnerId,binding.shopUserId,canonicalRow.evaluation_id,OBJECTIVE]);
    assert.match(sql,/j.tenant_id=e.tenant_id AND j.principal_id=e.principal_id/);
   }
   if(sql.includes('j.run_id=$5')){
    assert.match(sql,/NOT EXISTS[\s\S]*retry\.child_id=j\.evaluation_id/);
    assert.deepEqual(args.slice(3),[OBJECTIVE,canonicalRow.run_id,canonicalRow.owner_key,canonicalRow.packet,canonicalRow.evidence_digest]);
   }
   return{rows:canonicalRow?[canonicalRow]:[]};
  }
  throw Error('Unexpected SQL: '+sql);
 }};
 const journal={
  async claim(input){calls.claim++;if(journalRow)return{status:journalRow.status,result:journalRow.result_json,claimId:id(3)};
   const request=createTurnRequest(input);journalRow={session_id:input.sessionId,request_id:input.requestId,
    request_hash:request.hash,request_version:request.version,status:'started',result_json:null};
   return{status:'claimed',claimId:id(3)};},
  async complete(input){await check();if(completeError)throw completeError;calls.complete++;journalRow.status='completed';journalRow.result_json=structuredClone(input.result);},
  async markUncertain(){calls.uncertain++;if(journalRow&&journalRow.status!=='completed')journalRow.status='uncertain';}};
 const conversationRepository={
  async getBoundSession(sid){return sid===assessmentSession?{id:sid,state:'active',purpose:'persona_inbox',binding}
   :sid===reference.sessionId?{id:sid,state:'active',purpose:'secureshop_coupon_probe',binding}:null;},
  async acquireBoundSession(){calls.acquire++;return{id:assessmentSession,state:'active'};}};
 const service=createCouponBlindAssessment({identityPool,agentsPool:{query:async()=>({rows:journalRow?[journalRow]:[]})},
  launches:{assertCurrent:check},conversationRepository,journal,
  coordinator:{async run(sid,options,work){const admitted=await options.admit();if(admitted.skip)return admitted.value;
   return work({runId:assessmentRun,ownerKey:owner,durableGeneration:'0',check,
    async effectWithReceipt(){calls.effects++;throw Error('No HTTP or mail effect permitted');}});}},
  personaAuthority:{capture:input=>({binding:{...createLaunchScope(input.scope),personaId:input.personaId,
   role:input.role,sessionId:input.sessionId,authorityVersion:input.authorityVersion},assertRemoteAdmission:check})},
  personaBindings:{capture:async()=>({controlled:true})},qualifyModelTrace,
  current:async()=>({state:{...source.binding,sourceBinding:source.sourceBinding},check:async()=>{await check();if(!scene)throw Error('Scene stale');}}),
  publicationModes:{getEvaluationScope:async()=>publication},progress:{getGeneration:async()=>publication.generation,getEvaluationScope:async()=>publication},
  receipts:{async beginEvaluation(input){
   const rubric=JSON.parse(input.recovery.packet).rubric;
   canonicalRow={tenant_id:id(4),principal_id:id(5),evaluation_id:input.evaluationId,shop_user_id:persona.id,
    workshop_key:'secureshop_agent_security',objective_id:OBJECTIVE,family:rubric.family,scenario:rubric.scenario,rubric_version:rubric.version,
    mode:publication.mode,generation:publication.generation,mode_stamp:publication.modeStamp,owner_key:owner,owner_generation:'0',live_owner_generation:'0',
    current_tenant_id:id(4),current_principal_id:id(5),current_membership_version:'1',run_id:assessmentRun,
    execution_json:{tenantId:id(4),principalId:id(5),membershipVersion:'1',scope,
     personaSessionId:session.sessionId,personaAuthorityVersion:session.authorityVersion,role:'customer',runId:assessmentRun},
    packet:input.recovery.packet,evidence_digest:hash(input.recovery.packet),child_id:null};
   return{verdict:null};},
   async recordVerdict({result}){calls.verdict++;const serialized=JSON.stringify(result);
    Object.assign(canonicalRow,{verdict:result.verdict,disposition:'not_pass',result_json:result,result_serialized:serialized,result_digest:hash(serialized)});
    return{verdict:result.verdict,disposition:'not_pass',result};}},
  readSource:async(context,request)=>{
   calls.source++;assert.deepEqual({sessionId:request.sessionId,requestId:request.requestId},reference);
   assert.deepEqual(context.scope,scope);await check();
   if(sourceError)throw sourceError;return structuredClone({source,privateReference});
  },
  judge:async input=>{calls.judge++;capturedPacket=prepareJudgeInput(input).packet;await judgeMutation();
   return{verdict:'fail',explanation:'Controlled negative Judge; no credit',criteria:[]};},
 });
 const input={scope,persona,personaSession:{...session,expiresAt:'2099-01-01T00:00:00Z'},...reference};
 return{source,p,service,input,calls,publication,get journalRow(){return journalRow;},get canonicalRow(){return canonicalRow;},
  get packet(){return capturedPacket;},privateReference,revoke:()=>{active=false;},disable:()=>{enabled=false;},
  setScene:value=>{scene=value;},sourceError:error=>{sourceError=error;},
  onJudge:fn=>{judgeMutation=fn;},onCompleteError:error=>{completeError=error;}};
}
test('source-bound canonical assessment invokes negative Judge once; reads/recovery have no model or effect replay',async()=>{
 const f=fixture();assert.deepEqual(await f.service.readOutcome(f.input),{completed:false,status:'unconfirmed',modelEvaluated:false});
 const value=await f.service.runAttempt(f.input);assert.equal(value.completed,false);assert.equal(value.judgment.verdict,'fail');
 assert.equal(JSON.parse(f.packet).rubric.version,RUBRIC.version);
 assert.equal(f.calls.judge,1);assert.equal(f.calls.verdict,1);assert.equal(f.calls.complete,1);assert.equal(f.calls.effects,0);
 assert.deepEqual(await f.service.readOutcome(f.input),{...value,replayed:true});
 assert.deepEqual(await f.service.runAttempt(f.input),{...value,replayed:true});
 const guard=await f.service.assertRetainedPacket({...f.input,packet:f.packet});await guard.assertCurrent();
 assert.equal(f.calls.judge,1);assert.equal(f.calls.complete,1);assert.equal(f.calls.effects,0);

});
test('fixed, disabled and unavailable historical source deny without admission; unknown store failures propagate',async()=>{
 for(const change of [f=>{f.source.sourceBinding.couponMode.mode='fixed';},f=>f.disable(),
  f=>f.sourceError(Object.assign(Error('historical unavailable'),{code:'COUPON_BLIND_SOURCE_UNAVAILABLE'}))]){
  const f=fixture();change(f);assert.deepEqual(await f.service.runAttempt(f.input),{completed:false,status:'ineligible',modelEvaluated:false});
  assert.equal(f.calls.judge,0);assert.equal(f.calls.claim,0);
 }
 const f=fixture();f.sourceError(Object.assign(Error('database offline'),{code:'57P01'}));
 await assert.rejects(f.service.runAttempt(f.input),{code:'57P01'});assert.equal(f.calls.judge,0);
});
test('foreign source authority denies before absent scene',async()=>{
 for(const method of ['runAttempt','readOutcome']){
  const f=fixture();f.setScene(null);f.input.scope={...f.input.scope,platformOwnerId:999};
  await assert.rejects(f.service[method](f.input),{code:'CONVERSATION_UNAVAILABLE'});assert.equal(f.calls.source,0);assert.equal(f.calls.claim,0);
 }

});
test('revocation, original response and publication changes during Judge prevent canonical verdict and journal writes',async()=>{
 for(const change of [f=>f.revoke(),f=>{f.source.turn.text='tampered answer';},
  f=>{f.publication.modeStamp='changed';},f=>{f.privateReference.character='b';},f=>{f.source.sourceBinding.couponMode.modeStamp='rotated';},f=>f.setScene(null),f=>f.disable()]){
  const f=fixture();f.onJudge(()=>change(f));await assert.rejects(f.service.runAttempt(f.input));
  assert.equal(f.calls.judge,1);assert.equal(f.calls.verdict,0);assert.equal(f.calls.complete,0);
 }
});
test('saved canonical parent packet, authority, execution and result tampering fail closed without new work',async()=>{
 for(const change of [r=>{r.execution_json.personaSessionId=id(77);},r=>{r.execution_json.membershipVersion='9';},
  r=>{r.owner_generation='2';r.live_owner_generation='2';},r=>{r.run_id=id(78);r.execution_json.runId=r.run_id;},
  r=>{r.packet+=' ';},r=>{r.mode_stamp='changed';},r=>{r.rubric_version='unknown';}]){
  const f=fixture();await f.service.runAttempt(f.input);change(f.canonicalRow);
  await assert.rejects(f.service.readOutcome(f.input));await assert.rejects(f.service.assertRetainedPacket({...f.input,packet:f.packet}));
  assert.equal(f.calls.judge,1);assert.equal(f.calls.complete,1);
 }
 const f=fixture();await f.service.runAttempt(f.input);f.canonicalRow.result_digest='0'.repeat(64);
 await assert.rejects(f.service.readOutcome(f.input));assert.equal(f.calls.judge,1);
});
test('retained source mutation and uncertain POST cannot replay source tools or Judge',async()=>{
 const f=fixture();await f.service.runAttempt(f.input);
 const guard=await f.service.assertRetainedPacket({...f.input,packet:f.packet});
 f.source.turn.text='tampered saved response';await assert.rejects(guard.assertCurrent());
 assert.equal(f.calls.judge,1);assert.equal(f.calls.effects,0);
 const g=fixture();g.onCompleteError(Error('Journal acknowledgement lost'));
 await assert.rejects(g.service.runAttempt(g.input));assert.equal(g.journalRow.status,'uncertain');
 await assert.rejects(g.service.runAttempt(g.input),{code:'TURN_RECOVERY_REQUIRED'});assert.equal(g.calls.judge,1);
});
test('source request identity includes both immutable original identifiers',()=>{
 assert.equal(assessmentRequestId(id(1),id(2)),assessmentRequestId(id(1),id(2)));
 assert.notEqual(assessmentRequestId(id(1),id(2)),assessmentRequestId(id(1),id(3)));
 assert.notEqual(assessmentRequestId(id(1),id(2)),assessmentRequestId(id(3),id(2)));
 assert.throws(()=>assessmentRequestId('invalid',id(2)));
});
test('saved retry joins original parent packet and fresh child creation invocation without new source effects',async()=>{
 const f=fixture();await f.service.runAttempt(f.input);const row=f.canonicalRow;
 row.result_json={verdict:'unavailable',explanation:'Controlled unavailable Judge',errorCode:'JUDGE_TIMEOUT'};
 row.verdict='unavailable';row.result_serialized=JSON.stringify(row.result_json);row.result_digest=hash(row.result_serialized);
 f.journalRow.result_json={completed:false,judgment:{...row.result_json,evaluationId:row.evaluation_id,canRetry:true}};
 const child={...structuredClone(row),evaluation_id:id(81),
  execution_json:{...structuredClone(row.execution_json),runId:id(82)},verdict:'fail',disposition:'not_pass',
  result_json:{verdict:'fail',explanation:'Controlled retry remains negative'}};
 child.result_serialized=JSON.stringify(child.result_json);child.result_digest=hash(child.result_serialized);
 row.child_id=child.evaluation_id;row.child_row=child;
 row.child_invocation={tenant_id:row.tenant_id,principal_id:row.principal_id,parent_id:row.evaluation_id,
  run_id:child.execution_json.runId,attempt:1,execution_json:structuredClone(child.execution_json)};
 assert.equal(child.run_id,row.run_id);assert.notEqual(child.execution_json.runId,row.run_id);
 const saved=await f.service.readOutcome(f.input);assert.equal(saved.judgment.evaluationId,child.evaluation_id);
 const guard=await f.service.assertRetainedPacket({...f.input,packet:row.packet});await guard.assertCurrent();
 assert.equal(f.calls.judge,1);assert.equal(f.calls.effects,0);
 for(const mutate of [r=>{r.child_row.run_id=id(88);},r=>{r.child_invocation=null;},
  r=>{r.child_invocation.execution_json.personaSessionId=id(83);},r=>{r.child_row.packet+=' ';}]){
  const original=structuredClone(row);mutate(row);await assert.rejects(f.service.readOutcome(f.input));Object.assign(row,original);
 }
 assert.equal(f.calls.judge,1);assert.equal(f.calls.complete,1);
});

