'use strict';
// Controlled BoundRoleChat source + negative Judge. No model, browser, DB, or credit.
const test=require('node:test');
const assert=require('node:assert/strict');
const {createHash}=require('node:crypto');
const {controlledMailHtmlOriginalSource}=require('./secureshopBoundRoleChat.test');
const {createMailHtmlInjectionAssessment}=require('../server/services/secureshopMailHtmlInjectionAssessment');
const {createMailHtmlInjectionOriginalReader}=require('../server/services/secureshopMailHtmlInjectionOriginalReader');
const {OBJECTIVE,MAIL_HTML_INJECTION_RUBRIC:RUBRIC}=require('../server/services/secureshopMailHtmlInjectionEvidence');
const {createTurnRequest}=require('../server/services/secureshopTurnRequest');
const {createLaunchScope}=require('../server/services/secureshopConversationBinding');
const {prepareSend}=require('../server/database/postgres/secureshopBoundMailRepository');
const {createMailHeaderEvidenceRepository}=require('../server/database/postgres/secureshopMailHeaderEvidenceRepository');
const {prepareJudgeInput}=require('../server/agent-runtime/objectiveJudge');
const id=n=>`c0000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
const hash=value=>createHash('sha256').update(value).digest('hex');

async function fixture(){
 const actual=await controlledMailHtmlOriginalSource(),proposal=actual.proposal;
 const binding={scope:actual.scope,targetId:proposal.mailScene.targetId,persona:actual.persona,
  personaSession:actual.personaSession,mode:'vuln',operationId:proposal.proposalId};
 const saved={binding,payload:prepareSend(proposal.send),requestSha256:'a'.repeat(64),
  receipt:{email_id:actual.operation.emailId,senderId:proposal.sender.id,
   recipientId:proposal.recipient.id,contentSha256:'b'.repeat(64)}};
 const assessmentRequestId=id(1),assessmentRun=id(2),tenant=id(3),principal=id(4);
 let assessmentSession=null,journalRow=null,canonicalRow=null,active=true,enabled=true,targetActive=true;
 let capturedPacket=null,effectReceipt=null,sawDetachedTarget=false;
 const trustedTarget=Object.freeze({targetId:binding.targetId,scene:Object.freeze({sceneId:id(90),sceneGeneration:1,grantId:id(91)})});
 const peerTarget=Object.freeze({targetId:id(92),scene:Object.freeze({sceneId:id(93),sceneGeneration:1,grantId:id(94)})});
 binding.target=trustedTarget;
 const calls={source:0,browser:0,judge:0,claim:0,complete:0,effect:0,graph:0};
 const check=async()=>{if(!active)throw Object.assign(Error('revoked'),{code:'SHOP_AUTH_INVALID'});};
 const foreignEvidenceCalls={capture:0,admission:0,recover:0,browse:0};
 const foreignSavedMailEvidence=createMailHeaderEvidenceRepository({
  personaAuthority:{capture(input){foreignEvidenceCalls.capture++;return{binding:{...createLaunchScope(input.scope),
   personaId:input.personaId,role:input.role,sessionId:input.sessionId,authorityVersion:input.authorityVersion},
   async assertRemoteAdmission(){foreignEvidenceCalls.admission++;}};}},
  mailRepository:{async recover(raw){foreignEvidenceCalls.recover++;assert.equal(raw.target,peerTarget);
    assert.equal(raw.targetId,peerTarget.targetId);assert.equal(raw.operationId,binding.operationId);
    assert.equal(raw.scope.launchId,id(96));assert.equal(raw.scope.platformOwnerId,binding.scope.platformOwnerId+1);
    assert.equal(raw.scope.platformSessionId,binding.scope.platformSessionId+1);
    assert.equal(raw.persona.id,binding.persona.id+1);assert.equal(raw.persona.role,'merchant');
    assert.notEqual(saved.receipt.senderId,raw.persona.id);return{found:true,action:'send',operationId:raw.operationId,
     requestSha256:saved.requestSha256,receipt:structuredClone(saved.receipt)};},
   async browse(){foreignEvidenceCalls.browse++;throw Error('Foreign saved source browse must not run');}}});
 const publication={mode:'vuln',generation:1,modeStamp:'mail-html-controlled'};
 const component={id:'SecureShop.MailMessageBody',sourceSha256:'c'.repeat(64),artifactSha256:'d'.repeat(64)};
 const originalReader=createMailHtmlInjectionOriginalReader(actual.originalDependencies);
 const identityPool={async query(sql,args){
  if(sql.includes('identity.secureshop_authority_owners'))return{rows:[{realm:'platform',shop_tenant_id:null}]};
  if(sql.includes('workshop_platform.objectives'))return{rows:enabled?[{objective_id:OBJECTIVE}]:[]};
  if(sql.includes('FROM graph_runtime.effects')){calls.graph++;assert.deepEqual(args,[effectReceipt.ownerKey,effectReceipt.generation,effectReceipt.effectKey,effectReceipt.runId]);
   return{rows:[{runId:effectReceipt.runId,ownerKey:effectReceipt.ownerKey,generation:String(effectReceipt.generation),
    effectKey:effectReceipt.effectKey,status:'completed',runStatus:'completed',liveGeneration:String(effectReceipt.generation)}]};}
  if(sql.includes('FROM secureshop_auth.execution_authority_state'))return{rows:canonicalRow?[canonicalRow]:[]};
  throw Error('Unexpected SQL: '+sql);
 }};
 const journal={
  async claim(input){calls.claim++;if(journalRow)return journalRow.status==='completed'
   ?{status:'completed',result:journalRow.result_json,claimId:id(5)}:{status:journalRow.status,claimId:id(5)};
   const request=createTurnRequest(input);journalRow={session_id:input.sessionId,request_id:input.requestId,
    request_hash:request.hash,request_version:request.version,status:'started',result_json:null};
   return{status:'claimed',claimId:id(5)};},
  async complete(input){calls.complete++;journalRow.status='completed';journalRow.result_json=structuredClone(input.result);},
  async markUncertain(){if(journalRow&&journalRow.status!=='completed')journalRow.status='uncertain';}
 };
 const assessmentConversations=new Map();
 const conversationRepository={
  async acquireBoundSession({id:sessionId,binding:conversationBinding,purpose}){assessmentSession=sessionId;
   const row={id:sessionId,binding:conversationBinding,purpose,state:'pending'};assessmentConversations.set(sessionId,row);return row;},
  async activateBoundSession(sessionId){assessmentConversations.get(sessionId).state='active';return true;},
  async getBoundSession(sessionId){return assessmentConversations.get(sessionId)||null;}
 };
 const service=createMailHtmlInjectionAssessment({identityPool,agentsPool:{query:async()=>({rows:journalRow?[journalRow]:[]})},
  launches:{assertCurrent:check},conversationRepository,journal,
  coordinator:{async run(sessionId,options,work){const admitted=await options.admit();if(admitted.skip)return admitted.value;
   const ownerKey=JSON.stringify(['SecureShopBoundConversation',sessionId]);return work({runId:assessmentRun,
    ownerKey,durableGeneration:'0',signal:options.signal,check,
    async effectWithReceipt(key,callback){calls.effect++;const value=await callback();effectReceipt={version:1,status:'completed',
     runId:assessmentRun,ownerKey,generation:'0',effectKey:`${options.idempotencyKey}:${key}`};return{value,receipt:effectReceipt};}});}},
  personaAuthority:{capture:input=>({binding:{...createLaunchScope(input.scope),personaId:input.personaId,role:input.role,
   sessionId:input.sessionId,authorityVersion:input.authorityVersion},assertRemoteAdmission:check})},
  personaBindings:{capture:async()=>({controlled:true})},
  receipts:{async beginEvaluation(input){const rubric=JSON.parse(input.recovery.packet).rubric,ownerKey=JSON.stringify(['SecureShopBoundConversation',assessmentSession]);
   canonicalRow={tenant_id:tenant,principal_id:principal,evaluation_id:input.evaluationId,shop_user_id:actual.persona.id,
    workshop_key:'secureshop_agent_security',objective_id:OBJECTIVE,family:rubric.family,scenario:rubric.scenario,
    rubric_version:rubric.version,mode:publication.mode,generation:publication.generation,mode_stamp:publication.modeStamp,
    owner_key:ownerKey,owner_generation:'0',live_owner_generation:'0',current_tenant_id:tenant,current_principal_id:principal,
    current_membership_version:'1',run_id:assessmentRun,execution_json:{tenantId:tenant,principalId:principal,
     membershipVersion:'1',scope:createLaunchScope(binding.scope),personaSessionId:actual.personaSession.sessionId,
     personaAuthorityVersion:actual.personaSession.authorityVersion,role:'merchant',runId:assessmentRun},
    packet:input.recovery.packet,evidence_digest:hash(input.recovery.packet),child_id:null};return{verdict:null};},
   async recordVerdict({result}){const serialized=JSON.stringify(result);Object.assign(canonicalRow,{verdict:result.verdict,
    disposition:'not_pass',result_json:result,result_serialized:serialized,result_digest:hash(serialized)});
    return{verdict:result.verdict,disposition:'not_pass',result};}},
  progress:{getGeneration:async()=>publication.generation,getEvaluationScope:async()=>publication},
  publicationModes:{getEvaluationScope:async()=>publication},
  savedMailEvidence:{async readHeader(raw){if(raw.targetId===peerTarget.targetId)return foreignSavedMailEvidence.readHeader(raw);assert.equal(raw.target,trustedTarget);assert.deepEqual(raw,binding);return structuredClone(saved);}},
  async resolveRetainedBinding(raw){
   const retained=raw?.targetId===trustedTarget.targetId?trustedTarget:raw?.targetId===peerTarget.targetId?peerTarget:null;
   if(!retained||!targetActive&&retained===trustedTarget)throw Object.assign(Error('stale target'),{code:'MAIL_SCENE_STALE'});
   if(raw.target&&raw.target!==retained)sawDetachedTarget=true;
   return {...raw,target:retained};
  },
  originalReader:{async read(input){calls.source++;const result=await originalReader.read(input);
   assert.deepEqual(result,actual.original);return result;}},
  browserQualification:{async qualifyInjection(input){calls.browser++;assert.equal(input.html,saved.payload.body_html);
    assert.equal(input.learnerHtml,actual.body);return{component,learnerElementPreserved:true,learnerElementTag:'iframe',
     syntheticCookieOnly:true,finalCookieIsSyntheticOnly:true,elementCount:1,blockedRequests:[]};},
   async readComponent(){return component;}},
  qualifyModel:identity=>identity.provider==='ollama'&&identity.model==='llama3.1:8b'&&identity.mocked===false,
  judge:async input=>{calls.judge++;capturedPacket=prepareJudgeInput(input).packet;
   return{verdict:'fail',rubricVersion:RUBRIC.version,explanation:'Controlled negative Judge; no credit',criteria:[]};}
 });
 const input={binding,requestId:assessmentRequestId,sourceSessionId:actual.sessionId,
  sourceRequestId:actual.sourceRequestId,messageId:actual.operation.emailId};
 return{actual,binding,service,input,calls,get packet(){return capturedPacket;},get canonicalRow(){return canonicalRow;},
  get journalRow(){return journalRow;},get sawDetachedTarget(){return sawDetachedTarget;},get foreignEvidenceCalls(){return structuredClone(foreignEvidenceCalls);},
  foreignInput(){return{...input,requestId:id(95),binding:{...binding,scope:{...binding.scope,launchId:id(96),platformOwnerId:binding.scope.platformOwnerId+1,platformSessionId:binding.scope.platformSessionId+1},targetId:peerTarget.targetId,target:peerTarget,persona:{id:binding.persona.id+1,role:'merchant'},personaSession:{sessionId:id(97),authorityVersion:binding.personaSession.authorityVersion}}};},
  disable(){enabled=false;},setMode(value){assert(['vuln','fixed'].includes(value));binding.mode=value;
   publication.mode=value;publication.generation++;publication.modeStamp=`mail-html-controlled-${value}`;},
  revoke(){active=false;},retireTarget(){targetActive=false;}};
}

test('actual BoundRoleChat send source flows through canonical V09 assessment POST and saved GET without replay',async()=>{
 const f=await fixture();assert.deepEqual(await f.service.readOutcome(f.input),{completed:false,status:'unconfirmed',modelEvaluated:false});
 const result=await f.service.runAttempt(f.input);assert.equal(result.completed,false);assert.equal(result.judgment.verdict,'fail');
 assert.deepEqual(f.calls,{source:2,browser:1,judge:1,claim:1,complete:1,effect:1,graph:0});
 const saved=await f.service.readOutcome(f.input);assert.deepEqual(saved,{...result,replayed:true});
 const serialized=JSON.parse(f.packet),packetBinding=serialized.evidence.find(row=>row.id==='mail_agent_html_source').content.binding;
 assert.notEqual(packetBinding.target,f.binding.target);
 const guard=await f.service.assertRetainedPacket({packet:f.packet,scope:f.actual.scope,persona:f.actual.persona,
  personaSession:f.actual.personaSession});await guard.assertCurrent();assert.equal(f.sawDetachedTarget,true);
 assert.deepEqual(f.calls,{source:5,browser:1,judge:1,claim:1,complete:1,effect:1,graph:3});
 assert.equal(f.journalRow.status,'completed');assert.equal(f.canonicalRow.disposition,'not_pass');
});

test('V09 fixed and disabled admissions return ineligible before source, browser, Judge, or credit',async()=>{
 const denied={completed:false,status:'ineligible',modelEvaluated:false};
 const fixed=await fixture();fixed.setMode('fixed');assert.deepEqual(await fixed.service.runAttempt(fixed.input),denied);
 assert.deepEqual(await fixed.service.readOutcome(fixed.input),denied);
 assert.deepEqual(fixed.calls,{source:0,browser:0,judge:0,claim:0,complete:0,effect:0,graph:0});
 const disabled=await fixture();disabled.disable();assert.deepEqual(await disabled.service.runAttempt(disabled.input),denied);
 assert.equal(disabled.calls.source,0);assert.equal(disabled.calls.browser,0);assert.equal(disabled.calls.judge,0);
 const foreign=await fixture();const customer={...foreign.input,binding:{...foreign.binding,
  persona:{...foreign.binding.persona,role:'customer'}}};
 await assert.rejects(foreign.service.runAttempt(customer),error=>error?.code==='MAIL_HTML_INJECTION_ASSESSMENT_UNAVAILABLE');
 assert.deepEqual(foreign.calls,{source:0,browser:0,judge:0,claim:0,complete:0,effect:0,graph:0});
});


test('V09 vulnerable foreign merchant source is rejected by the production saved-source reader before browse, graph, browser, or Judge',async()=>{
 const f=await fixture();await assert.rejects(f.service.runAttempt(f.foreignInput()),error=>error?.code==='MAIL_EVIDENCE_UNAVAILABLE');
 assert.deepEqual(f.foreignEvidenceCalls,{capture:1,admission:1,recover:1,browse:0});
 assert.deepEqual(f.calls,{source:0,browser:0,judge:0,claim:0,complete:0,effect:0,graph:0});
});
test('V09 retained source mutation and revoked authority fail without new Judge or credit',async()=>{
 const revoked=await fixture();await revoked.service.runAttempt(revoked.input);const guard=await revoked.service.assertRetainedPacket({
  packet:revoked.packet,scope:revoked.actual.scope,persona:revoked.actual.persona,personaSession:revoked.actual.personaSession});
 revoked.revoke();await assert.rejects(guard.assertCurrent());assert.equal(revoked.calls.judge,1);
});

test('V09 serialized retained packet re-resolves only the current target and rejects sibling or retired authority',async()=>{
 const sibling=await fixture();await sibling.service.runAttempt(sibling.input);
 const forged=JSON.parse(sibling.packet),source=forged.evidence.find(row=>row.id==='mail_agent_html_source').content;
 source.binding.targetId=id(98);source.binding.target.targetId=id(98);
 await assert.rejects(sibling.service.assertRetainedPacket({packet:forged,scope:sibling.actual.scope,
  persona:sibling.actual.persona,personaSession:sibling.actual.personaSession}),error=>error?.code==='MAIL_SCENE_STALE');
 const retired=await fixture();await retired.service.runAttempt(retired.input);
 const guard=await retired.service.assertRetainedPacket({packet:retired.packet,scope:retired.actual.scope,
  persona:retired.actual.persona,personaSession:retired.actual.personaSession});
 retired.retireTarget();await assert.rejects(guard.assertCurrent(),error=>error?.code==='MAIL_SCENE_STALE');
 assert.equal(retired.calls.judge,1);
});
