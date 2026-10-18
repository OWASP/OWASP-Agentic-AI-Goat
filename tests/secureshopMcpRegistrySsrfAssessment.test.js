'use strict';

// Controlled repositories and Judge only: these tests never qualify a model,
// executor, browser, real database, or objective completion.
const test=require('node:test');
const assert=require('node:assert/strict');
const {createHash}=require('node:crypto');
const {packet}=require('./secureshopMcpRegistrySsrfEvidence.test');
const {createMcpRegistrySsrfAssessment,assessmentRequestId}=require('../server/services/secureshopMcpRegistrySsrfAssessment');
const {validateMcpRegistrySsrfEvidence,projectMcpRegistrySsrfCandidate,RUBRIC,OBJECTIVE}=require('../server/services/secureshopMcpRegistrySsrfEvidence');
const {prepareJudgeInput}=require('../server/agent-runtime/objectiveJudge');
const {createTurnRequest}=require('../server/services/secureshopTurnRequest');
const {createLaunchScope}=require('../server/services/secureshopConversationBinding');
const {PURPOSES}=require('../server/database/postgres/secureshopRoleChatBindingRepository');
const {createTurnRequestsRepository}=require('../server/database/postgres/secureshopTurnRequestsRepository');
const id=n=>`20000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
const noop=async()=>{};
function fixture({run=false,revokeInJudge=false,journalExtras={}}={}){
 const p=packet(),scope=createLaunchScope(p.binding),admin={id:p.binding.shopUserId,role:'admin'};
 const source={sessionId:p.turn.session_id,requestId:p.turn.request_id,proposalId:p.operation.operation_id};
 const proof=validateMcpRegistrySsrfEvidence(p),candidate=projectMcpRegistrySsrfCandidate(proof);
 const prepared=prepareJudgeInput({rubric:{...RUBRIC,mode:'vuln'},...candidate});
 const publication={generation:1,mode:'vuln',modeStamp:'b'.repeat(64)};
 const assessmentSession=id(80),key=assessmentRequestId(source.sessionId,source.requestId,source.proposalId);
 const msg=JSON.stringify([OBJECTIVE,source.sessionId,source.requestId,source.proposalId,
 p.personaSession,p.modeExecution,publication]);
 const request=createTurnRequest({sessionId:assessmentSession,requestId:key,binding:p.binding,message:msg});
 const result={verdict:'fail',explanation:'Controlled negative judgment.'},evaluationId=id(81);
 let row={session_id:assessmentSession,request_id:key,status:'completed',request_hash:request.hash,request_version:request.version,
 result_json:{completed:false,judgment:{...result,evaluationId,canRetry:false}}};
 const serialized=JSON.stringify(result),tenant=id(82),principal=id(83),assessmentRun=id(84);
 let judgment={tenant_id:tenant,principal_id:principal,evaluation_id:evaluationId,shop_user_id:admin.id,
 workshop_key:'secureshop_agent_security',objective_id:OBJECTIVE,family:RUBRIC.family,scenario:RUBRIC.scenario,
 rubric_version:RUBRIC.version,mode:'vuln',generation:publication.generation,mode_stamp:publication.modeStamp,
 owner_key:JSON.stringify(['SecureShopBoundConversation',assessmentSession]),owner_generation:'1',live_owner_generation:'1',
 current_tenant_id:tenant,current_principal_id:principal,current_membership_version:'1',run_id:assessmentRun,
 execution_json:{tenantId:tenant,principalId:principal,membershipVersion:'1',scope:structuredClone(scope),
 personaSessionId:p.personaSession.sessionId,personaAuthorityVersion:p.personaSession.authorityVersion,role:'admin',runId:assessmentRun},
 packet:prepared.packet,evidence_digest:prepared.evidenceDigest,result_json:result,result_serialized:serialized,
 result_digest:createHash('sha256').update(serialized).digest('hex'),verdict:'fail',disposition:'not_pass',child_id:null};
 let processMode='vuln',active=true,qualified=true,enabled=true,scene=p.target,sourcePresent=true;
 const calls={writes:0,judge:0,registry:0,original:0,canonical:0,verdicts:0,completed:0,
  scenes:0,modes:0,catalog:0};
 // Exercise the real reader and its SQL projection against controlled rows.
 // In particular, readBoundRequest does not return request_id.
 const originalJournal=createTurnRequestsRepository({pool:{connect:async()=>({
  async query(sql,args){
   assert.deepEqual(args.slice(1),[PURPOSES.admin,scope.launchId,scope.scenarioId,
    scope.generation,scope.platformOwnerId,scope.platformSessionId,admin.id,admin.role]);
   const fields=sql.match(/SELECT (.*?)\s+FROM/s)?.[1].split(',').map(value=>value.trim().replace(/^tr\./,''));
   assert.deepEqual(fields,['session_id','status','request_hash','request_version','result_json']);
   return {rows:args[0]===source.requestId?[Object.fromEntries(fields.map(key=>[key,p.turn[key]]))]:[]};
  },release(){},
 })}});
 const write=async()=>{calls.writes++;throw Error('Read or ineligible attempt performed a write');};
 const fenceCheck=async()=>{if(!active)throw Object.assign(Error('revoked'),{code:'SHOP_AUTH_INVALID'});};
 const service=createMcpRegistrySsrfAssessment({
 identityPool:{async query(sql){
  if(sql.includes('identity.secureshop_authority_owners')){calls.catalog++;return{rows:[{realm:'platform',shop_tenant_id:null}]};}
  if(sql.includes('workshop_platform.objectives'))return{rows:enabled?[{objective_id:OBJECTIVE}]:[]};
  if(sql.includes('FROM graph_runtime.runs'))return{rows:[p.run]};
  if(sql.includes('FROM graph_runtime.effects'))return{rows:p.effects};
  if(sql.includes('FROM secureshop_auth.execution_authority_state')){calls.canonical++;return{rows:judgment?[judgment]:[]};}
  throw Error(`Unexpected controlled SQL: ${sql}`);
 }},
 agentsPool:{query:async()=>({rows:row?[row]:[]})},launches:{assertCurrent:fenceCheck},
 conversationRepository:{getBoundSession:async sid=>(sid===source.sessionId&&sourcePresent||sid===assessmentSession)
  ?{id:sid,state:'active',purpose:sid===source.sessionId?PURPOSES.admin:'persona_inbox',binding:p.binding}:null,
 getTraceEvents:async()=>p.traces,acquireBoundSession:run?async()=>({id:assessmentSession,state:'active'}):write},
 coordinator:{run:run?async(sid,options,work)=>{const admitted=await options.admit();if(admitted.skip)return admitted.value;
  return work({runId:assessmentRun,ownerKey:JSON.stringify(['SecureShopBoundConversation',sid]),durableGeneration:1,
  check:fenceCheck,effect:async(_key,fn)=>fn()});}:write},
 turnJournal:{readBoundRequest:async input=>{
  const row=await originalJournal.readBoundRequest(input);return row?{...row,...journalExtras}:row;
 },claim:run?async()=>({status:'claimed',claimId:id(85)}):write,
 complete:run?async()=>{calls.completed++;}:write,markUncertain:run?noop:write},
 bindingRepository:{read:async()=>p.boundTurn},scenes:{readExisting:async()=>{calls.scenes++;return scene;}},
 registryRepository:{readAssessmentRegistration:async()=>{calls.registry++;return{operation:p.operation,revisions:p.revisions};}},
 personaAuthority:{capture:input=>({binding:{...createLaunchScope(input.scope),personaId:input.personaId,role:input.role,
 sessionId:input.sessionId,authorityVersion:input.authorityVersion},assertRemoteAdmission:fenceCheck})},
 personaBindings:{capture:async()=>({controlled:true})},receipts:{beginEvaluation:run?async()=>({verdict:null}):write,
 recordVerdict:run?async({result})=>{calls.verdicts++;return{verdict:result.verdict,disposition:'not_pass',result};}:write},
 progress:{getGeneration:async()=>1,getEvaluationScope:async()=>publication},
 publicationModes:{getEvaluationScope:async()=>publication},judge:async input=>{calls.judge++;if(!run)throw Error('Unexpected Judge');
 assert.equal(input.rubric.objectiveId,OBJECTIVE);assert.equal(prepareJudgeInput(input).packet,prepared.packet);
 if(revokeInJudge)active=false;return{verdict:'fail',explanation:'Controlled Judge, no credit',criteria:[]};},
 qualifyModel:identity=>qualified&&p.qualifyModel(identity),
 modeAuthority:{capture:async()=>{calls.modes++;return{snapshot:p.modeExecution,assertCurrent:fenceCheck};},assertToken:v=>v},
 readRegistryMode:async()=>processMode,
 });
 const input={scope,persona:admin,personaSession:{...p.personaSession,expiresAt:'2099-01-01T00:00:00Z'},...source,
 verifyOriginal:async()=>{calls.original++;return{status:'completed',mcpRegistryProposal:{proposalId:source.proposalId,action:'register'}};}};
 return{p,service,input,calls,prepared,publication,get row(){return row;},get judgment(){return judgment;},
 setRow:v=>{row=v;},setJudgment:v=>{judgment=v;},setProcess:v=>{processMode=v;},revoke:()=>{active=false;},
 setQualified:v=>{qualified=v;},disable:()=>{enabled=false;},setScene:v=>{scene=v;},hideSource:()=>{sourcePresent=false;}};
}
test('registry discovery assessment identity includes the exact original proposal',()=>{
 assert.equal(assessmentRequestId(id(1),id(2),id(3)),assessmentRequestId(id(1),id(2),id(3)));
 for(const values of [[id(4),id(2),id(3)],[id(1),id(4),id(3)],[id(1),id(2),id(4)]])
  assert.notEqual(assessmentRequestId(...values),assessmentRequestId(id(1),id(2),id(3)));
 assert.throws(()=>assessmentRequestId(id(1),id(2),'foreign'));
});
test('foreign or missing registry discovery sources deny before optional scene and assessment availability',async()=>{
 for(const method of ['runAttempt','readOutcome']){
  for(const change of [f=>{f.input.scope={...f.input.scope,platformOwnerId:99,platformSessionId:100};},
   f=>{f.input.persona={id:99,role:'admin'};},f=>{f.input.sessionId=id(99);},f=>f.hideSource()]){
   const f=fixture({run:true});f.setScene(null);change(f);
   await assert.rejects(f.service[method](f.input),{code:'CONVERSATION_UNAVAILABLE'});
   for(const key of ['scenes','modes','catalog','original','registry','canonical','judge','writes','verdicts','completed'])
    assert.equal(f.calls[key],0,`${method} foreign source must stop before ${key}`);
  }
  const owned=fixture({run:true});owned.setScene(null);
  await assert.rejects(owned.service[method](owned.input),{code:'MCP_REGISTRY_SSRF_ASSESSMENT_UNAVAILABLE'});
  assert.equal(owned.calls.scenes,1);assert.equal(owned.calls.judge,0);
  assert.equal(owned.calls.verdicts,0);assert.equal(owned.calls.completed,0);
 }
});
test('saved registry discovery read canonicalizes route credentials and verifies the canonical immutable judgment',async()=>{
 const f=fixture();assert.deepEqual(await f.service.readOutcome(f.input),{...f.row.result_json,replayed:true});
 assert.equal(f.calls.canonical,1);assert.equal(f.calls.judge,0);assert.equal(f.calls.writes,0);
 for(const mutate of [r=>{r.request_hash='0'.repeat(64);},r=>{r.result_json.completed=true;},
 r=>{r.result_json.judgment.verdict='pass';},r=>{r.result_json.judgment.evaluationId=id(99);},
 r=>{r.result_json.extra='private';}]){
  const g=fixture();mutate(g.row);await assert.rejects(g.service.readOutcome(g.input));assert.equal(g.calls.judge,0);assert.equal(g.calls.writes,0);
 }
});
test('saved discovery read projects current fixed eligibility before an obsolete source callback, with authority fences intact',async()=>{
 const changes=[f=>f.setProcess('fixed'),f=>{f.publication.mode='fixed';},
  f=>{f.p.modeExecution.mode='fixed';}];
 for(const change of changes){
  const f=fixture();change(f);
  const before=structuredClone({row:f.row,judgment:f.judgment,turn:f.p.turn});
  f.input.verifyOriginal=async()=>{f.calls.original++;throw Object.assign(Error('old mode'),{code:'TURN_REQUEST_CONFLICT'});};
  assert.deepEqual(await f.service.readOutcome(f.input),{completed:false,status:'ineligible',modelEvaluated:false});
  for(const key of ['original','registry','canonical','judge','writes','verdicts','completed'])assert.equal(f.calls[key],0,key);
  assert.deepEqual({row:f.row,judgment:f.judgment,turn:f.p.turn},before);
  const foreign=fixture();change(foreign);foreign.input.sessionId=id(99);
  await assert.rejects(foreign.service.readOutcome(foreign.input),{code:'CONVERSATION_UNAVAILABLE'});
  const revoked=fixture();change(revoked);revoked.revoke();
  await assert.rejects(revoked.service.readOutcome(revoked.input),{code:'SHOP_AUTH_INVALID'});
 }
 for(const code of ['TURN_REQUEST_CONFLICT','ROLE_PROPOSAL_UNCONFIRMED']){
  const f=fixture(),failure=Object.assign(Error('original source denied'),{code});
  f.input.verifyOriginal=async()=>{throw failure;};
  await assert.rejects(f.service.readOutcome(f.input),error=>error===failure);
  for(const key of ['registry','canonical','judge','writes','verdicts','completed'])assert.equal(f.calls[key],0,key);
 }
});
test('saved registry discovery read rejects canonical owner, mode, packet, result and child substitutions',async()=>{
 for(const mutate of [j=>{j.execution_json.scope.generation++;},j=>{j.execution_json.personaSessionId=id(99);},
 j=>{j.execution_json.personaAuthorityVersion='99';},j=>{j.current_membership_version='99';},
 j=>{j.current_tenant_id=id(99);},j=>{j.objective_id='ss_other';},j=>{j.rubric_version='other';},
 j=>{j.mode='fixed';},j=>{j.mode_stamp='0'.repeat(64);},j=>{j.live_owner_generation='99';},
 j=>{j.packet=j.packet.replace('metadata.training','forged.training');},j=>{j.evidence_digest='0'.repeat(64);},
 j=>{j.result_digest='0'.repeat(64);},j=>{j.disposition='awarded';},j=>{j.result_json.verdict='pass';},
 j=>{j.child_id=id(90);j.child_row={};}]){
  const f=fixture();mutate(f.judgment);await assert.rejects(f.service.readOutcome(f.input));assert.equal(f.calls.judge,0);assert.equal(f.calls.writes,0);
 }
});
test('registry discovery read and run reject missing model provenance or fixed process before Judge/admission',async()=>{
 for(const change of [f=>{delete f.p.turn.result_json.taskMetadata.roleChat.mcpRegisterOrigin;},
 f=>f.setQualified(false),f=>f.setProcess('fixed'),f=>f.disable(),
 f=>{f.p.operation.state='unknown';},f=>{f.input.personaSession.authorityVersion='99';}]){
  const f=fixture();change(f);
  const result=await f.service.runAttempt(f.input);assert.deepEqual(result,{completed:false,status:'ineligible',modelEvaluated:false});
  assert.equal(f.calls.judge,0);assert.equal(f.calls.writes,0);
 }
});
test('retained registry discovery guard re-reads original evidence without replaying any registration or model',async()=>{
 const f=fixture(),guard=await f.service.assertRetainedPacket({packet:f.prepared.packet,...f.input});
 await guard.assertCurrent();assert.equal(f.calls.original,0,'recovery reads repositories directly');
 assert.equal(f.calls.writes,0);assert.equal(f.calls.judge,0);assert.ok(f.calls.registry>=2);
 f.p.operation.receipt_json.changes[0].effect.discoveryReceipt.destination.address='forged';
 await assert.rejects(guard.assertCurrent());assert.equal(f.calls.writes,0);
 const g=fixture(),current=await g.service.assertRetainedPacket({packet:g.prepared.packet,...g.input});
 g.setProcess('fixed');await assert.rejects(current.assertCurrent());
 const h=fixture(),live=await h.service.assertRetainedPacket({packet:h.prepared.packet,...h.input});
 h.revoke();await assert.rejects(live.assertCurrent());
 const m=fixture(),epoch=await m.service.assertRetainedPacket({packet:m.prepared.packet,...m.input});
 m.publication.modeStamp='0'.repeat(64);await assert.rejects(epoch.assertCurrent());
});

test('eligible registry discovery chain reaches the canonical completion service once and retains a negative controlled Judge result',async()=>{
 const f=fixture({run:true}),result=await f.service.runAttempt(f.input);
 assert.equal(result.completed,false);assert.equal(result.judgment.verdict,'fail');assert.equal(result.replayed,false);
 assert.equal(f.calls.judge,1);assert.equal(f.calls.verdicts,1);assert.equal(f.calls.completed,1);
 assert.ok(f.calls.original>=2);assert.ok(f.calls.registry>=2);
});
test('registry discovery request-ID adaptation rejects conflicting original IDs, sessions and hashes before Judge',async()=>{
 for(const change of [f=>{f.input.requestId=id(99);},
  f=>{f.p.boundTurn.request_id=id(99);},f=>{f.p.boundTurn.session_id=id(99);},
  f=>{f.p.turn.request_hash='0'.repeat(64);}]){
  const f=fixture({run:true});change(f);
  assert.deepEqual(await f.service.runAttempt(f.input),{completed:false,status:'ineligible',modelEvaluated:false});
  assert.equal(f.calls.judge,0);assert.equal(f.calls.completed,0);assert.equal(f.calls.verdicts,0);
 }
 for(const journalExtras of [{request_id:id(99)},{session_id:id(99)}]){
  const f=fixture({run:true,journalExtras});
  assert.deepEqual(await f.service.runAttempt(f.input),{completed:false,status:'ineligible',modelEvaluated:false});
  assert.equal(f.calls.judge,0);assert.equal(f.calls.completed,0);assert.equal(f.calls.verdicts,0);
 }
 const f=fixture({run:true});f.p.turn.session_id=id(99);
 await assert.rejects(f.service.runAttempt(f.input),{code:'TURN_REQUEST_CONFLICT'});
 assert.equal(f.calls.judge,0);assert.equal(f.calls.completed,0);assert.equal(f.calls.verdicts,0);
});
test('persona revocation during the Judge prevents verdict and turn publication',async()=>{
 const f=fixture({run:true,revokeInJudge:true});
 await assert.rejects(f.service.runAttempt(f.input),{code:'SHOP_AUTH_INVALID'});
 assert.equal(f.calls.judge,1);assert.equal(f.calls.verdicts,0);assert.equal(f.calls.completed,0);
});

function retryFixture(){
 const f=fixture(),parent=f.judgment;
 parent.result_json={verdict:'unavailable',explanation:'Controlled initial Judge unavailable',errorCode:'JUDGE_TIMEOUT'};
 parent.verdict='unavailable';parent.result_serialized=JSON.stringify(parent.result_json);
 parent.result_digest=createHash('sha256').update(parent.result_serialized).digest('hex');
 f.row.result_json={completed:false,judgment:{...parent.result_json,evaluationId:parent.evaluation_id,canRetry:false}};
 // Exact beginRetry DTO: original run_id is retained; execution_json records
 // the fresh child-creation execution separately in the invocation table.
 const child={...structuredClone(parent),evaluation_id:id(90),
  execution_json:{...structuredClone(parent.execution_json),runId:id(91)},
  verdict:null,disposition:null,result_json:null,result_digest:null,result_serialized:null};
 parent.child_id=child.evaluation_id;parent.child_row=child;
 parent.child_invocation={tenant_id:parent.tenant_id,principal_id:parent.principal_id,parent_id:parent.evaluation_id,
  attempt:1,run_id:child.execution_json.runId,execution_json:structuredClone(child.execution_json)};
 const finish=()=>{
  child.result_json={verdict:'fail',explanation:'Controlled retry negative; no credit'};
  child.verdict='fail';child.disposition='not_pass';child.result_serialized=JSON.stringify(child.result_json);
  child.result_digest=createHash('sha256').update(child.result_serialized).digest('hex');
 };
 return{...f,parent,child,finish};
}
test('saved registry discovery retry child retains original evidence run and verifies its fresh persisted invocation',async()=>{
 const f=retryFixture();
 assert.equal(f.child.run_id,f.parent.run_id);assert.notEqual(f.child.execution_json.runId,f.parent.run_id);
 assert.deepEqual(await f.service.readOutcome(f.input),{...f.row.result_json,replayed:true});
 f.finish();
 const completed=await f.service.readOutcome(f.input);
 assert.deepEqual(completed,{completed:false,judgment:{...f.child.result_json,evaluationId:f.child.evaluation_id,canRetry:false},replayed:true});
 for(const key of ['judge','writes','verdicts','completed'])assert.equal(f.calls[key],0,key);
});
test('saved registry discovery retry denies missing or substituted invocation, source packet and authority without replay',async()=>{
 const mutations=[
  f=>{delete f.parent.child_invocation;},
  f=>{f.parent.child_invocation.tenant_id=id(99);},f=>{f.parent.child_invocation.principal_id=id(99);},
  f=>{f.parent.child_invocation.parent_id=id(99);},f=>{f.parent.child_invocation.run_id=id(99);},
  f=>{f.parent.child_invocation.attempt=0;},f=>{f.parent.child_invocation.attempt=4;},
  f=>{f.parent.child_invocation.execution_json.personaSessionId=id(99);},
  f=>{f.child.run_id=f.child.execution_json.runId;},f=>{f.child.execution_json.runId=id(99);},
  f=>{f.child.execution_json.personaAuthorityVersion='99';},f=>{f.child.owner_generation='2';},
  f=>{f.child.packet+=' ';},f=>{f.child.evidence_digest='0'.repeat(64);},f=>{f.child.result_digest='0'.repeat(64);},
 ];
 for(const [index,mutate] of mutations.entries()){
  const f=retryFixture();f.finish();mutate(f);
  await assert.rejects(f.service.readOutcome(f.input),{code:'MCP_REGISTRY_SSRF_ASSESSMENT_UNAVAILABLE'},`mutation ${index}`);
  for(const key of ['judge','writes','verdicts','completed'])assert.equal(f.calls[key],0,`${index}: ${key}`);
 }
});

test('complete discovery proof budget rejects oversized original schema before session creation or Judge',async()=>{
 const f=fixture();
 assert.equal(f.prepared.evidenceError,undefined);
 assert.ok(Buffer.byteLength(f.prepared.packet)<24000,'ordinary full proof fits canonical packet budget');
 const {canonicalDigest}=require('../server/services/mcp/protocolContext');
 const {mcpSchemaDigest}=require('../server/services/secureshopMcpSchemaDigest');
 const revision=f.p.revisions[0],change=f.p.operation.receipt_json.changes[0];
 revision.tools_json[0].description='Owned original schema description '.repeat(1000);
 const schema=mcpSchemaDigest(revision.tools_json);
 change.schemaSha256=schema;revision.schema_sha256=Buffer.from(schema,'hex');
 change.effect.discoveryReceipt.toolsListResponse={tools:structuredClone(revision.tools_json)};
 change.effect.discoveryReceipt.toolsListResponseSha256=canonicalDigest(change.effect.discoveryReceipt.toolsListResponse);
 change.effect.discoveryReceipt.schemaSha256=schema;
 revision.effect_json={...structuredClone(change.effect),requestSha256:change.effect.discoveryReceipt.registryRequestSha256,
  bindingSha256:Buffer.from(f.p.operation.binding_sha256).toString('hex')};
 f.p.operation.receipt_sha256=Buffer.from(canonicalDigest(f.p.operation.receipt_json),'hex');
 assert.deepEqual(await f.service.runAttempt(f.input),{completed:false,status:'ineligible',modelEvaluated:false});
 assert.equal(f.calls.writes,0);assert.equal(f.calls.judge,0);assert.equal(f.calls.verdicts,0);assert.equal(f.calls.completed,0);
});
