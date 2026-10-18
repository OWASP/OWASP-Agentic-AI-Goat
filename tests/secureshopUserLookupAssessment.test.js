'use strict';

// Controlled repositories and Judge only: these tests never qualify a model,
// executor, browser, real database, or objective completion.
const test=require('node:test');
const assert=require('node:assert/strict');
const {createHash}=require('node:crypto');
const {packet}=require('./secureshopUserLookupEvidence.test');
const {createUserLookupAssessment,assessmentRequestId}=require('../server/services/secureshopUserLookupAssessment');
const {validateUserLookupEvidence,projectUserLookupCandidate,RUBRIC,OBJECTIVE}=require('../server/services/secureshopUserLookupEvidence');
const {prepareJudgeInput}=require('../server/agent-runtime/objectiveJudge');
const {createTurnRequest}=require('../server/services/secureshopTurnRequest');
const {createLaunchScope}=require('../server/services/secureshopConversationBinding');
const {PURPOSES}=require('../server/database/postgres/secureshopRoleChatBindingRepository');
const {createTurnRequestsRepository}=require('../server/database/postgres/secureshopTurnRequestsRepository');
const id=n=>`20000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
const noop=async()=>{};
// Explicit controlled historical eligibility preserves inner source/receipt
// security tests; it does not represent current release qualification.
const servicePath=require.resolve('../server/services/secureshopUserLookupAssessment');
const historicalModule={exports:{}},localRequire=require('node:module').createRequire(servicePath);
require('node:vm').runInThisContext('(function(require,module,exports){'+
 require('node:fs').readFileSync(servicePath,'utf8')+'\n})',{filename:servicePath})(name=>
 name==='./secureshopAssessmentEligibility'?{
  readSecureShopAssessmentEligibility:async(pool,_scope,ids)=>{
   assert.deepEqual(ids,[OBJECTIVE]);
   return (await pool.query('SELECT objective_id FROM workshop_platform.objectives')).rows.map(row=>row.objective_id);
  },
 }:localRequire(name),historicalModule,historicalModule.exports);
function fixture({run=false,revokeInJudge=false,journalExtras={},currentRelease=false}={}){
 const p=packet(),scope=createLaunchScope(p.binding),admin={id:p.binding.shopUserId,role:'admin'};
 const source={sessionId:p.turn.session_id,requestId:p.turn.request_id};
 const proof=validateUserLookupEvidence(p),candidate=projectUserLookupCandidate(proof);
 const prepared=prepareJudgeInput({rubric:{...RUBRIC,mode:'vuln'},...candidate});
 const publication={generation:1,mode:'vuln',modeStamp:'b'.repeat(64)};
 const assessmentSession=id(80),key=assessmentRequestId(source.sessionId,source.requestId);
 const msg=JSON.stringify([OBJECTIVE,source.sessionId,source.requestId,
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
 const createAssessment=currentRelease?createUserLookupAssessment:historicalModule.exports.createUserLookupAssessment;
 const service=createAssessment({
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
 userAdministration:{readAgentLookup:async()=>{calls.registry++;return p.lookup;}},
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
 });
 const input={scope,persona:admin,personaSession:{...p.personaSession,expiresAt:'2099-01-01T00:00:00Z'},...source,
 verifyOriginal:async()=>{calls.original++;return{status:'completed',userLookup:{status:'complete'}};}};
 return{p,service,input,calls,prepared,publication,get row(){return row;},get judgment(){return judgment;},
 setRow:v=>{row=v;},setJudgment:v=>{judgment=v;},setProcess:v=>{p.modeExecution.mode=v;},revoke:()=>{active=false;},
 setQualified:v=>{qualified=v;},disable:()=>{enabled=false;},setScene:v=>{scene=v;},hideSource:()=>{sourcePresent=false;}};
}

test('historical controlled eligibility: lookup assessment identity binds exact original session and request',()=>{
 assert.equal(assessmentRequestId(id(1),id(2)),assessmentRequestId(id(1),id(2)));
 assert.notEqual(assessmentRequestId(id(1),id(2)),assessmentRequestId(id(2),id(1)));
 assert.throws(()=>assessmentRequestId(id(1),'other'));
});
test('historical controlled eligibility: lookup saved outcome is canonical and has no source effect or Judge replay',async()=>{
 const f=fixture();assert.deepEqual(await f.service.readOutcome(f.input),{...f.row.result_json,replayed:true});
 assert.equal(f.calls.judge,0);assert.equal(f.calls.writes,0);assert.equal(f.calls.canonical,1);
 for(const mutate of [j=>j.packet+=' ',j=>j.execution_json.personaSessionId=id(99),j=>j.mode_stamp='other',j=>j.result_digest='0'.repeat(64),j=>j.disposition='awarded']){
 const g=fixture();mutate(g.judgment);await assert.rejects(g.service.readOutcome(g.input));assert.equal(g.calls.judge,0);assert.equal(g.calls.writes,0);}
});
test('historical controlled eligibility: lookup fixed eligibility precedes obsolete source but follows owner/session checks',async()=>{
 for(const method of ['readOutcome','runAttempt'])for(const change of [f=>f.setProcess('fixed'),f=>f.publication.mode='fixed']){
 const f=fixture();change(f);f.input.verifyOriginal=async()=>{throw Error('obsolete source touched');};
 assert.deepEqual(await f.service[method](f.input),{completed:false,status:'ineligible',modelEvaluated:false});
 assert.equal(f.calls.registry,0);assert.equal(f.calls.judge,0);assert.equal(f.calls.writes,0);
 const g=fixture();change(g);g.input.sessionId=id(99);await assert.rejects(g.service[method](g.input),{code:'CONVERSATION_UNAVAILABLE'});
 }
 const f=fixture(),error=Object.assign(Error('conflict'),{code:'TURN_REQUEST_CONFLICT'});f.input.verifyOriginal=async()=>{throw error;};
 await assert.rejects(f.service.readOutcome(f.input),e=>e===error);
});
test('historical controlled eligibility: lookup original tampering and disabled catalog never invoke Judge',async()=>{
 for(const change of [f=>f.disable(),f=>f.setQualified(false),f=>f.p.lookup.receipt.rowSha256='0'.repeat(64),f=>f.p.effects[0].status='reserved']){
 const f=fixture();change(f);assert.deepEqual(await f.service.runAttempt(f.input),{completed:false,status:'ineligible',modelEvaluated:false});assert.equal(f.calls.judge,0);assert.equal(f.calls.writes,0);}
});
test('historical controlled eligibility: lookup retained recovery rereads immutable source and denies reset/mode change',async()=>{
 const f=fixture(),guard=await f.service.assertRetainedPacket({packet:f.prepared.packet,...f.input});await guard.assertCurrent();
 assert.equal(f.calls.original,0);assert.equal(f.calls.writes,0);assert.equal(f.calls.judge,0);
 f.setProcess('fixed');await assert.rejects(guard.assertCurrent());
 const g=fixture(),live=await g.service.assertRetainedPacket({packet:g.prepared.packet,...g.input});g.revoke();await assert.rejects(live.assertCurrent());
});
test('historical controlled eligibility: lookup canonical completion retains independent false, revocation prevents publication',async()=>{
 const f=fixture({run:true}),value=await f.service.runAttempt(f.input);assert.equal(value.completed,false);assert.equal(value.judgment.verdict,'fail');
 assert.equal(f.calls.judge,1);assert.equal(f.calls.verdicts,1);assert.equal(f.calls.completed,1);
 const g=fixture({run:true,revokeInJudge:true});await assert.rejects(g.service.runAttempt(g.input),{code:'SHOP_AUTH_INVALID'});assert.equal(g.calls.verdicts,0);assert.equal(g.calls.completed,0);
});

test('historical controlled eligibility: lookup GET distinguishes never admitted from pending or uncertain without writes',async()=>{
 const absent=fixture();absent.setRow(null);assert.deepEqual(await absent.service.readOutcome(absent.input),{completed:false,status:'unconfirmed',modelEvaluated:false});
 for(const status of ['claimed','uncertain']){const f=fixture();f.row.status=status;assert.deepEqual(await f.service.readOutcome(f.input),{completed:false,status:'pending',modelEvaluated:false});assert.equal(f.calls.writes,0);assert.equal(f.calls.judge,0);}
});

test('current release denies stale enabled lookup assessment, saved outcome and retained retry without Judge or writes',async()=>{
 const f=fixture({run:true,currentRelease:true}),original=structuredClone(f.judgment);
 for(const method of ['runAttempt','readOutcome'])assert.deepEqual(await f.service[method](f.input),
  {completed:false,status:'ineligible',modelEvaluated:false});
 await assert.rejects(f.service.assertRetainedPacket({packet:f.prepared.packet,...f.input}),
  {code:'USER_LOOKUP_ASSESSMENT_UNAVAILABLE'});
 for(const key of ['writes','judge','registry','original','canonical','verdicts','completed'])assert.equal(f.calls[key],0,key);
 assert.deepEqual(f.judgment,original);
});
