'use strict';

// Controlled source rows, browser observation and negative Judge only. These
// controls never establish actual model/browser execution or objective credit.
const test=require('node:test');
const assert=require('node:assert/strict');
const {createHash}=require('node:crypto');
const {fixture:originalFixture}=require('./secureshopSearchEchoBrowserEvidence.test');
const {createSearchEchoBrowserAssessment,assessmentRequestId}=require('../server/services/secureshopSearchEchoBrowserAssessment');
const {OBJECTIVE,RUBRIC,RUBRIC_V2}=require('../server/services/secureshopSearchEchoBrowserEvidence');
const {createTurnRequest}=require('../server/services/secureshopTurnRequest');
const {createLaunchScope}=require('../server/services/secureshopConversationBinding');
const {prepareJudgeInput}=require('../server/agent-runtime/objectiveJudge');
const id=n=>`b0000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
const hash=value=>createHash('sha256').update(value).digest('hex');
function fixture({evidenceVersion=2}={}){
 const source=originalFixture(),p=source.proof,binding=p.binding,scope=createLaunchScope(binding);
 const persona={id:binding.shopUserId,role:'customer'},session={...p.personaSession};
 const assessmentSession=id(1),assessmentRun=id(2),owner=JSON.stringify(['SecureShopBoundConversation',assessmentSession]);
 const publication={generation:p.execution.generation,mode:p.execution.mode,modeStamp:p.execution.modeStamp};
 let active=true,enabled=true,scene=source.input.target,journalRow=null,canonicalRow=null,effectRow=null;
 let browserMutation=()=>{},judgeMutation=()=>{},capturedPacket=null,component={...source.effect.value.component};
 const calls={browser:0,judge:0,claim:0,complete:0,verdict:0,acquire:0,effects:0,uncertain:0};
 const check=async()=>{if(!active)throw Object.assign(Error('revoked'),{code:'SHOP_AUTH_INVALID'});};
 const identityPool={async query(sql,args){
  if(sql.includes('identity.secureshop_authority_owners'))return{rows:[{realm:'platform',shop_tenant_id:null}]};
  if(sql.includes('workshop_platform.objectives'))return{rows:enabled?[{objective_id:OBJECTIVE}]:[]};
  if(sql.includes('FROM secureshop_auth.execution_authority_state')){
   if(sql.includes('j.run_id=$5')){
    assert.match(sql,/NOT EXISTS[\s\S]*retry\.child_id=j\.evaluation_id/);
    assert.deepEqual(args.slice(3),[OBJECTIVE,canonicalRow.run_id,canonicalRow.owner_key,canonicalRow.packet,canonicalRow.evidence_digest]);
   }
   return{rows:canonicalRow?[canonicalRow]:[]};
  }
  if(sql.includes('FROM graph_runtime.effects e JOIN'))return{rows:effectRow?[effectRow]:[]};
  return source.deps.identityPool.query(sql,args);
 }};
 const journal={async readBoundRequest(input){
   const row=await source.deps.journal.readBoundRequest(input);
   return Object.fromEntries(['session_id','status','request_hash','request_version','result_json'].map(key=>[key,row[key]]));
  },
  async claim(input){calls.claim++;if(journalRow)return{status:journalRow.status,result:journalRow.result_json,claimId:id(3)};
   const request=createTurnRequest(input);journalRow={session_id:input.sessionId,request_id:input.requestId,
    request_hash:request.hash,request_version:request.version,status:'started',result_json:null};
   return{status:'claimed',claimId:id(3)};},
  async complete(input){await check();calls.complete++;journalRow.status='completed';journalRow.result_json=structuredClone(input.result);},
  async markUncertain(){calls.uncertain++;if(journalRow&&journalRow.status!=='completed')journalRow.status='uncertain';}};
 const conversationRepository={...source.deps.conversations,
  async getBoundSession(sid){return sid===assessmentSession?{id:sid,state:'active',purpose:'persona_inbox',binding}
   :sid===p.source.sessionId?{id:sid,...await source.deps.conversations.getBoundSession(sid)}:null;},
  async acquireBoundSession(){calls.acquire++;return{id:assessmentSession,state:'active'};}};
 const service=createSearchEchoBrowserAssessment({evidenceVersion,identityPool,agentsPool:{query:async()=>({rows:journalRow?[journalRow]:[]})},
  launches:{assertCurrent:check},conversationRepository,journal,bindingRepository:source.deps.bindingRepository,
  coordinator:{async run(sid,options,work){const admitted=await options.admit();if(admitted.skip)return admitted.value;
   return work({runId:assessmentRun,ownerKey:owner,durableGeneration:'1',check,
    async effectWithReceipt(node,fn){calls.effects++;const value=await fn();
     const receipt={version:1,status:'completed',runId:assessmentRun,ownerKey:owner,generation:'1',effectKey:`${options.idempotencyKey}:${node}`};
     effectRow={run_id:assessmentRun,owner_key:owner,generation:'1',effect_key:receipt.effectKey,
      status:'completed',run_status:'completed',live_generation:'1'};return{value,receipt};}});}},
  personaAuthority:{capture:input=>({binding:{...createLaunchScope(input.scope),personaId:input.personaId,
   role:input.role,sessionId:input.sessionId,authorityVersion:input.authorityVersion},assertRemoteAdmission:check})},
  personaBindings:{capture:async()=>({controlled:true})},scenes:{readExisting:async()=>scene},
  modeAuthority:{capture:async()=>({snapshot:p.execution,assertCurrent:check}),assertToken:value=>value},
  publicationModes:{getEvaluationScope:async()=>publication},progress:{getGeneration:async()=>publication.generation,getEvaluationScope:async()=>publication},
  receipts:{async beginEvaluation(input){
   const rubric=JSON.parse(input.recovery.packet).rubric;
   canonicalRow={tenant_id:id(4),principal_id:id(5),evaluation_id:input.evaluationId,shop_user_id:persona.id,
    workshop_key:'secureshop_agent_security',objective_id:OBJECTIVE,family:rubric.family,scenario:rubric.scenario,rubric_version:rubric.version,
    mode:publication.mode,generation:publication.generation,mode_stamp:publication.modeStamp,owner_key:owner,owner_generation:'1',live_owner_generation:'1',
    current_tenant_id:id(4),current_principal_id:id(5),current_membership_version:'1',run_id:assessmentRun,
    execution_json:{tenantId:id(4),principalId:id(5),membershipVersion:'1',scope,
     personaSessionId:session.sessionId,personaAuthorityVersion:session.authorityVersion,role:'customer',runId:assessmentRun},
    packet:input.recovery.packet,evidence_digest:hash(input.recovery.packet),child_id:null};
   return{verdict:null};},
   async recordVerdict({result}){calls.verdict++;const serialized=JSON.stringify(result);
    Object.assign(canonicalRow,{verdict:result.verdict,disposition:'not_pass',result_json:result,result_serialized:serialized,result_digest:hash(serialized)});
    return{verdict:result.verdict,disposition:'not_pass',result};}},
  qualifyModel:source.qualifyModel,
  browserQualification:{readComponent:()=>component,async qualifySearchEcho(input){calls.browser++;
   assert.equal(input.html,`<p>Results for: <b>${JSON.parse(p.traces.find(r=>r.kind==='model_decision'&&r.step===p.source.step).params_json).toolCalls[0].args.search}</b></p>`);
   assert.equal(input.modeCapability.featureId,'customer_chat');
   assert.equal(input.captureDom,evidenceVersion>=8?true:undefined);
   await browserMutation();return structuredClone(source.effect.value);}},
  judge:async input=>{calls.judge++;capturedPacket=prepareJudgeInput(input).packet;await judgeMutation();
   return{verdict:'fail',explanation:'Controlled negative Judge; no credit',criteria:[]};},
 });
 const input={scope,persona,personaSession:{...session,expiresAt:'2099-01-01T00:00:00Z'},...p.source};
 return{source,p,service,input,calls,publication,get journalRow(){return journalRow;},get canonicalRow(){return canonicalRow;},
  get effectRow(){return effectRow;},get packet(){return capturedPacket;},revoke:()=>{active=false;},disable:()=>{enabled=false;},
  setScene:value=>{scene=value;},changeComponent:()=>{component={...component,sourceSha256:'0'.repeat(64)};},
  onBrowser:fn=>{browserMutation=fn;},onJudge:fn=>{judgeMutation=fn;}};
}
function preserveV1Packet(f){
 const v2=JSON.parse(f.packet),v1={...v2,rubric:{...RUBRIC,mode:'vuln'},evidence:[v2.evidence[0]]};
 const prepared=prepareJudgeInput(v1);assert.equal(prepared.evidenceError,undefined);
 Object.assign(f.canonicalRow,{rubric_version:RUBRIC.version,packet:prepared.packet,evidence_digest:prepared.evidenceDigest});
 return prepared;
}
test('search assessment source identity includes exact session, request and selected step',()=>{
 const key=assessmentRequestId(id(1),id(2),1);assert.equal(key,assessmentRequestId(id(1),id(2),1));
 assert.notEqual(key,assessmentRequestId(id(1),id(2),2));assert.notEqual(key,assessmentRequestId(id(3),id(2),1));
 for(const step of [0,5,1.1,'1'])assert.throws(()=>assessmentRequestId(id(1),id(2),step));
});
test('genuine-shaped controlled source and browser reach negative Judge once; saved GET and POST replay have no effect',async()=>{
 const f=fixture(),outcome=await f.service.runAttempt(f.input);
 assert.equal(outcome.completed,false);assert.equal(outcome.judgment.verdict,'fail');assert.equal(f.calls.judge,1);
 assert.equal(f.calls.browser,1);assert.equal(f.calls.verdict,1);assert.equal(f.calls.complete,1);
 const saved=await f.service.readOutcome(f.input);assert.deepEqual(saved,{...outcome,replayed:true});
 assert.deepEqual(await f.service.runAttempt(f.input),saved);
 assert.equal(f.calls.browser,1);assert.equal(f.calls.effects,1);assert.equal(f.calls.judge,1);assert.equal(f.calls.complete,1);
 const guard=await f.service.assertRetainedPacket({...f.input,packet:f.packet});await guard.assertCurrent();
 assert.equal(f.calls.browser,1);assert.equal(f.calls.judge,1);
});
test('new v2 admissions preserve a byte-exact protected v1 saved packet path',async()=>{
 const f=fixture();await f.service.runAttempt(f.input);
 const v2=JSON.parse(f.packet);assert.equal(v2.rubric.version,RUBRIC_V2.version);
 assert.equal(f.canonicalRow.rubric_version,RUBRIC_V2.version);
 const prepared=preserveV1Packet(f);
 const saved=await f.service.readOutcome(f.input);
 assert.equal(saved.replayed,true);assert.equal(saved.judgment.verdict,'fail');
 const guard=await f.service.assertRetainedPacket({...f.input,packet:prepared.packet});await guard.assertCurrent();
 assert.equal(f.calls.browser,1);assert.equal(f.calls.judge,1);
});
test('stored rubric version dispatch rejects v1/v2 substitution and unknown versions before replay',async()=>{
 for(const mutate of [
  f=>{f.canonicalRow.rubric_version=RUBRIC.version;},
  f=>{f.canonicalRow.rubric_version='secureshop-search-echo-browser-v999';},
  f=>{f.canonicalRow.rubric_version='__proto__';},
  f=>{f.canonicalRow.rubric_version='constructor';},
 ]){
  const f=fixture();await f.service.runAttempt(f.input);mutate(f);
  await assert.rejects(f.service.readOutcome(f.input));
  await assert.rejects(f.service.assertRetainedPacket({...f.input,packet:f.packet}));
  assert.equal(f.calls.browser,1);assert.equal(f.calls.judge,1);
 }
 const f=fixture();await f.service.runAttempt(f.input);
 for(const version of ['secureshop-search-echo-browser-v999','__proto__','constructor']){
  const forged=JSON.parse(f.packet);forged.rubric.version=version;
  await assert.rejects(f.service.assertRetainedPacket({...f.input,packet:JSON.stringify(forged)}));
 }
 assert.equal(f.calls.browser,1);assert.equal(f.calls.judge,1);
});
test('fixed, disabled, missing provenance and ambiguous source deny before browser or Judge',async()=>{
 for(const change of [f=>{f.p.execution.mode='fixed';},f=>f.disable(),
  f=>{delete f.p.turn.result_json.taskMetadata.searchEcho;},f=>{f.input.step=4;}]){
  const f=fixture();change(f);assert.deepEqual(await f.service.runAttempt(f.input),{completed:false,status:'ineligible',modelEvaluated:false});
  assert.equal(f.calls.browser,0);assert.equal(f.calls.judge,0);assert.equal(f.calls.claim,0);
 }
 const f=fixture();f.input.scope={...f.input.scope,platformOwnerId:999};f.setScene(null);
 await assert.rejects(f.service.readOutcome(f.input),{code:'CONVERSATION_UNAVAILABLE'});assert.equal(f.calls.browser,0);
});
test('authority, source or component changes during browser and Judge prevent result publication',async()=>{
 for(const stage of ['onBrowser','onJudge']){
  const f=fixture();f[stage](()=>f.revoke());await assert.rejects(f.service.runAttempt(f.input),{code:'SHOP_AUTH_INVALID'});
  assert.equal(f.calls.verdict,0);assert.equal(f.calls.complete,0);
 }
 for(const stage of ['onBrowser','onJudge'])for(const change of [f=>f.changeComponent(),
  f=>{f.p.turn.result_json.hops[0].params.search='swapped';},f=>{f.publication.modeStamp='changed';},
  f=>f.setScene(null)]){
  const f=fixture();f[stage](()=>change(f));await assert.rejects(f.service.runAttempt(f.input));
  assert.equal(f.calls.judge,stage==='onJudge'?1:0);assert.equal(f.calls.verdict,0);assert.equal(f.calls.complete,0);
 }
});
test('saved replay and recovery deny changed original, effect, canonical packet and current renderer without rerunning browser',async()=>{
 for(const mutate of [f=>{f.effectRow.live_generation='2';},f=>{f.effectRow.status='failed';},
  f=>f.changeComponent(),f=>{f.p.turn.request_hash='0'.repeat(64);},f=>f.revoke()]){
  const f=fixture();await f.service.runAttempt(f.input);const guard=await f.service.assertRetainedPacket({...f.input,packet:f.packet});
  mutate(f);await assert.rejects(guard.assertCurrent());assert.equal(f.calls.browser,1);assert.equal(f.calls.judge,1);
 }
 for(const mutate of [r=>{r.execution_json.personaSessionId=id(99);},r=>{r.packet+=' ';},r=>{r.result_digest='0'.repeat(64);}]){
  const f=fixture();await f.service.runAttempt(f.input);mutate(f.canonicalRow);
  await assert.rejects(f.service.readOutcome(f.input));assert.equal(f.calls.browser,1);assert.equal(f.calls.judge,1);
 }
});

test('same-source explicit retry starts only before admission and cannot replay an uncertain browser effect',async()=>{
 const f=fixture();
 assert.deepEqual(await f.service.readOutcome(f.input),{completed:false,status:'unconfirmed',modelEvaluated:false});
 f.onBrowser(()=>{throw Error('browser acknowledgement lost');});
 await assert.rejects(f.service.runAttempt(f.input),/acknowledgement lost/);
 assert.equal(f.journalRow.status,'uncertain');assert.equal(f.calls.browser,1);
 assert.deepEqual(await f.service.readOutcome(f.input),{completed:false,status:'unconfirmed',modelEvaluated:false});
 await assert.rejects(f.service.runAttempt(f.input),{code:'TURN_RECOVERY_REQUIRED'});
 assert.equal(f.calls.browser,1);assert.equal(f.calls.effects,1);assert.equal(f.calls.judge,0);
});
test('canonical parent run, owner, generation and exact packet bind retained browser evidence',async()=>{
 for(const mutate of [r=>{r.run_id=id(91);r.execution_json.runId=r.run_id;},
  r=>{r.owner_generation='2';r.live_owner_generation='2';},
  r=>{r.owner_key=JSON.stringify(['SecureShopBoundConversation',id(92)]);},
  r=>{r.mode_stamp='new';},r=>{r.execution_json.membershipVersion='2';},
  r=>{r.execution_json.personaAuthorityVersion='3';},r=>{r.packet+=' ';}]){
  const f=fixture();await f.service.runAttempt(f.input);mutate(f.canonicalRow);
  await assert.rejects(f.service.readOutcome(f.input));
  await assert.rejects(f.service.assertRetainedPacket({...f.input,packet:f.packet}));
  assert.equal(f.calls.browser,1);assert.equal(f.calls.judge,1);
 }
 // An original canonical packet remains eligible for retry inspection even if
 // public journal acknowledgement or the Judge result was unavailable.
 const f=fixture();await f.service.runAttempt(f.input);f.journalRow.status='uncertain';
 f.canonicalRow.verdict='unavailable';
 const guard=await f.service.assertRetainedPacket({...f.input,packet:f.packet});await guard.assertCurrent();
 assert.equal(f.calls.browser,1);assert.equal(f.calls.judge,1);
});

test('saved Judge retry child keeps the exact persisted v1, v2, v8 or v9 browser packet and joins its fresh invocation without replay',async()=>{
 for(const version of ['v1','v2','v8','v9']){
 const f=fixture({evidenceVersion:version==='v9'?9:version==='v8'?8:2});
 if(version==='v8'||version==='v9')f.source.effect.value.domCapture=require('./secureshopSearchEchoBrowserV8.test').captureFor(f.source);
 await f.service.runAttempt(f.input);if(version==='v1')preserveV1Packet(f);const row=f.canonicalRow;
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
 const result=await f.service.readOutcome(f.input);
 assert.equal(result.judgment.evaluationId,child.evaluation_id);assert.equal(result.judgment.verdict,'fail');
 const guard=await f.service.assertRetainedPacket({...f.input,packet:row.packet});await guard.assertCurrent();
 assert.equal(f.calls.browser,1);assert.equal(f.calls.judge,1);
 row.child_invocation.execution_json.personaSessionId=id(83);
 await assert.rejects(f.service.readOutcome(f.input));
 }
});

// V8/V9 are private composition options, never request-selected versions.
test('v8 and v9 assessments opt into DOM capture and saved replay without browser or Judge rerun',async()=>{
 for(const evidenceVersion of [8,9]){
  const f=fixture({evidenceVersion});
  f.source.effect.value.domCapture=require('./secureshopSearchEchoBrowserV8.test').captureFor(f.source);
  const result=await f.service.runAttempt(f.input);assert.equal(result.judgment.verdict,'fail');
  assert.equal(JSON.parse(f.packet).rubric.version,`secureshop-search-echo-browser-v${evidenceVersion}`);
  const saved=await f.service.readOutcome(f.input);assert.equal(saved.judgment.verdict,'fail');
  const retained=await f.service.assertRetainedPacket({...f.input,packet:f.canonicalRow.packet});await retained.assertCurrent();
  assert.equal(f.calls.browser,1);assert.equal(f.calls.judge,1);
  f.revoke();await assert.rejects(f.service.readOutcome(f.input),{code:'SHOP_AUTH_INVALID'});
 }
});
test('untrusted request version cannot switch default assessment; unsupported composition version denies',async()=>{
 const f=fixture();await f.service.runAttempt({...f.input,evidenceVersion:8});
 assert.equal(JSON.parse(f.packet).rubric.version,RUBRIC_V2.version);
 for(const evidenceVersion of [1,3,7,10,'8',null])assert.throws(()=>fixture({evidenceVersion}),/evidence version/);
});
