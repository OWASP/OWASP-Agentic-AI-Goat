'use strict';

const {createHash,randomUUID}=require('node:crypto');
const {isDeepStrictEqual:equal}=require('node:util');
const {createLaunchScope,createConversationBinding}=require('./secureshopConversationBinding');
const {createBoundConversationService}=require('./secureshopBoundConversation');
const {createBoundTurns}=require('./secureshopBoundTurns');
const {createTurnAdmission}=require('./secureshopTurnAdmission');
const {createTurnRequest}=require('./secureshopTurnRequest');
const {createAssessmentPersonaCapture}=require('./secureshopAssessmentPersonaCapture');
const {captureAssessmentPublicationScope}=require('./secureshopAssessmentPublicationScope');
const {readSecureShopAssessmentEligibility}=require('./secureshopAssessmentEligibility');
const {createObjectiveCompletionService}=require('./secureshopObjectiveCompletionService');
const {createSavedAssessmentOutcomeReader}=require('./secureshopSavedAssessmentOutcomeReader');
const {OBJECTIVE,RUBRIC,buildCouponBlindCandidate,createCouponBlindJudgeGuard,
 isCouponBlindJudgeInputValid}=require('./secureshopCouponBlindEvidence');
const {prepareJudgeInput}=require('../agent-runtime/objectiveJudge');
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const WORKSHOP='secureshop_agent_security',PURPOSE='persona_inbox',SOURCE_PURPOSE='secureshop_coupon_probe';
const hash=value=>createHash('sha256').update(value).digest('hex');
const fail=()=>Object.assign(Error('Coupon blind assessment unavailable'),{code:'COUPON_BLIND_ASSESSMENT_UNAVAILABLE'});
const status=value=>Object.freeze({completed:false,status:value,modelEvaluated:false});
function assessmentRequestId(sessionId,requestId){
 if(!UUID.test(sessionId||'')||!UUID.test(requestId||''))throw fail();
 const bytes=createHash('sha256').update(JSON.stringify([OBJECTIVE,sessionId,requestId])).digest();
 bytes[6]=(bytes[6]&15)|80;bytes[8]=(bytes[8]&63)|128;
 const h=bytes.subarray(0,16).toString('hex');return `${h.slice(0,8)}-${h.slice(8,12)}-${h.slice(12,16)}-${h.slice(16,20)}-${h.slice(20)}`;
}
const message=(state,original)=>JSON.stringify([OBJECTIVE,state.source,hash(JSON.stringify(original.source)),
 state.personaSession,state.raw,state.sourceBinding,state.publication.binding]);
function createCouponBlindAssessment({identityPool,agentsPool,launches,conversationRepository,
 coordinator,journal,personaAuthority,personaBindings,
 receipts,progress,publicationModes,judge,current,readSource,qualifyModelTrace}={}){
 for(const fn of [identityPool?.query,agentsPool?.query,launches?.assertCurrent,
  conversationRepository?.getBoundSession,
  conversationRepository?.acquireBoundSession,coordinator?.run,journal?.claim,journal?.complete,journal?.markUncertain,
  personaAuthority?.capture,personaBindings?.capture,current,readSource,qualifyModelTrace,
  publicationModes?.getEvaluationScope,judge])
  if(typeof fn!=='function')throw TypeError('Coupon blind assessment dependencies required');
 const conversations=createBoundConversationService({conversations:conversationRepository,launches});
 const turns=createBoundTurns({conversations,coordinator}),admission=createTurnAdmission({journal});
 const savedOutcomes=new Map([RUBRIC].map(rubric=>[rubric.version,
  createSavedAssessmentOutcomeReader({identityPool,objectiveId:OBJECTIVE,rubric,role:'customer'})]));
 const capture=createAssessmentPersonaCapture(personaBindings),scopes=new WeakMap(),packets=new WeakMap();
 const guardedJudge=createCouponBlindJudgeGuard(judge,qualifyModelTrace);
 const completion=createObjectiveCompletionService({receipts,progress,...capture.options,
  captureInstanceScope:execution=>{const scope=scopes.get(execution);if(!scope)throw fail();return scope;},
  judge:async input=>{const expected=packets.get(input.execution),actual=prepareJudgeInput(input);
   if(!expected||actual.evidenceError||actual.packet!==expected.packet||actual.evidenceDigest!==expected.evidenceDigest)throw fail();
   return guardedJudge(input);
  }});
 const enabled=async binding=>(await readSecureShopAssessmentEligibility(identityPool,binding,[OBJECTIVE])).includes(OBJECTIVE);
 async function authority({scope,persona,personaSession,sessionId,requestId,signal}){
  const binding=createConversationBinding(scope,persona),key=assessmentRequestId(sessionId,requestId);
  if(binding.role!=='customer'||!UUID.test(personaSession?.sessionId||'')
   ||typeof personaSession.authorityVersion!=='string'||!/^[1-9]\d*$/.test(personaSession.authorityVersion))throw fail();
  const customer={id:binding.shopUserId,role:'customer'},session={sessionId:personaSession.sessionId,authorityVersion:personaSession.authorityVersion};
  const fence=personaAuthority.capture({scope:binding,personaId:customer.id,role:'customer',...session});
  const expected={...createLaunchScope(binding),personaId:customer.id,role:'customer',...session};
  if(typeof fence?.assertRemoteAdmission!=='function'||!Object.keys(expected).every(k=>fence.binding?.[k]===expected[k]))throw fail();
  signal?.throwIfAborted();await fence.assertRemoteAdmission();
  await conversations.assertOwned(sessionId,binding,customer,SOURCE_PURPOSE);await fence.assertRemoteAdmission();
  const context=Object.freeze({scope:createLaunchScope(binding),persona:customer,personaSession:session});
  const held=await current(context,{requestId,signal});
  if(typeof held?.check!=='function'||!held.state||!equal(createLaunchScope(held.state.scope),createLaunchScope(binding))
   ||!equal(held.state.persona,customer)||!equal(held.state.personaSession,session))throw fail();
  const raw={scope:held.state.scope,persona:held.state.persona,personaSession:session};
  const sourceBinding=structuredClone(held.state.sourceBinding);
  const publication=await captureAssessmentPublicationScope(publicationModes,binding.platformOwnerId,signal,binding);
  const check=async()=>{
   signal?.throwIfAborted();await launches.assertCurrent(binding);await fence.assertRemoteAdmission();
   await conversations.assertOwned(sessionId,binding,customer,SOURCE_PURPOSE);
   await held.check();await publication.assertCurrent();signal?.throwIfAborted();
  };
  await check();return {binding,customer,personaSession:session,fence,raw,sourceBinding,context,publication,check,signal,key,
   source:{sessionId,requestId}};
 }
 async function original(state){
  await state.check();
  try{
   const value=await readSource(state.context,{...state.source,signal:state.signal});
   if(!equal(value?.source?.binding,state.raw)||!equal(value.source.sourceBinding,state.sourceBinding)
    ||value.source.turn.sessionId!==state.source.sessionId||value.source.turn.requestId!==state.source.requestId)throw fail();
   await state.check();return value;
  }catch(error){
   await state.check();if(error?.code==='COUPON_BLIND_SOURCE_UNAVAILABLE')return null;throw error;
  }
 }
 const eligible=async state=>state.sourceBinding.customerMode.mode==='vuln'&&state.sourceBinding.couponMode.mode==='vuln'&&state.publication.binding.mode==='vuln'&&await enabled(state.binding);
 async function retained(state,packet,canonicalExecution){
  let input;try{input=typeof packet==='string'?JSON.parse(packet):structuredClone(packet);}catch{throw fail();}
  if(!isCouponBlindJudgeInputValid(input,qualifyModelTrace)||!await eligible(state))throw fail();
  const rubric=RUBRIC;if(input.rubric.version!==rubric.version)throw fail();
  const content=input.evidence[0].content,ref=content.source.turn;
  if(!equal({sessionId:ref.sessionId,requestId:ref.requestId},state.source))throw fail();
  const current=await original(state);if(!current)throw fail();
  const receipt=content.assessmentExecution;
  if(!canonicalExecution||!equal(receipt,canonicalExecution))throw fail();
  const owner=JSON.parse(receipt.ownerKey);
  await conversations.assertOwned(owner[1],state.binding,state.customer,PURPOSE);
  const candidate=buildCouponBlindCandidate({...current,assessmentExecution:{runId:receipt.runId,
   ownerKey:receipt.ownerKey,durableGeneration:receipt.generation},qualifyModelTrace});
  if(!candidate)throw fail();
  const prepared=prepareJudgeInput({rubric,...candidate}),saved=prepareJudgeInput(input);
  if(prepared.evidenceError||saved.evidenceError||prepared.packet!==saved.packet||prepared.evidenceDigest!==saved.evidenceDigest)throw fail();
  await state.check();return prepared;
 }
 async function readOutcome(input){
  const state=await authority(input);if(!await eligible(state))return status('ineligible');
  const source=await original(state);if(!source)return status('ineligible');
  const b=state.binding;
  const rows=(await agentsPool.query(`SELECT t.session_id,t.request_id,t.request_hash,t.request_version,t.status,t.result_json
   FROM secureshop_agents.turn_requests t JOIN secureshop_agents.agent_sessions s ON s.id=t.session_id
   WHERE t.request_id=$1 AND s.authority_mode='launch_bound' AND s.binding_state='active'
   AND s.conversation_purpose='persona_inbox' AND s.platform_launch_id=$2 AND s.platform_scenario_id=$3
   AND s.platform_launch_generation=$4 AND s.original_platform_owner_id=$5 AND s.original_platform_session_id=$6
   AND s.user_id=$7 AND s.role='customer' LIMIT 2`,[state.key,b.launchId,b.scenarioId,b.generation,b.platformOwnerId,b.platformSessionId,b.shopUserId])).rows;
  await state.check();if(!rows.length)return status('unconfirmed');if(rows.length!==1)throw fail();
  const row=rows[0];await conversations.assertOwned(row.session_id,b,state.customer,PURPOSE);
  const request=createTurnRequest({sessionId:row.session_id,requestId:state.key,binding:b,message:message(state,source)});
  if(row.request_id!==state.key||row.request_hash!==request.hash||Number(row.request_version)!==request.version)throw fail();
  if(row.status!=='completed')return status('unconfirmed');
  if(equal(row.result_json,status('ineligible')))return status('ineligible');
  // Select the immutable original rubric under the current principal. The
  // selected reader repeats all canonical execution, owner and result joins.
  const versions=(await identityPool.query(`SELECT j.rubric_version
   FROM secureshop_auth.execution_authority_state e
   JOIN secureshop_auth.principals p ON p.principal_id=e.principal_id
   JOIN secureshop_auth.assessment_judgments j ON j.tenant_id=e.tenant_id AND j.principal_id=e.principal_id
   WHERE e.session_id=$1 AND e.owner_id=$2 AND e.is_active=1 AND e.expires_at>clock_timestamp()
    AND p.shop_user_id=$3 AND j.evaluation_id=$4 AND j.objective_id=$5 LIMIT 2`,
   [b.platformSessionId,b.platformOwnerId,b.shopUserId,row.result_json.judgment?.evaluationId,OBJECTIVE])).rows;
  await state.check();
  const savedOutcome=versions.length===1?savedOutcomes.get(versions[0].rubric_version):null;
  if(!savedOutcome)throw fail();
  return savedOutcome.read({binding:b,personaSession:state.personaSession,publication:state.publication.binding,
   assessmentOwnerKey:JSON.stringify(['SecureShopBoundConversation',row.session_id]),turnResult:row.result_json,
   prepareRetainedPacket:(packet,execution)=>retained(state,packet,execution),check:state.check});
 }
 async function runAttempt(input){
  const state=await authority(input);if(!await eligible(state))return status('ineligible');
  const source=await original(state);if(!source)return status('ineligible');
  const actor=capture.prepare(state.binding,state.fence),session=await conversations.create(state.binding,state.customer,PURPOSE);
  let prepared;
  const prepare=async()=>{await state.check();prepared=await admission.prepare({sessionId:session.id,requestId:state.key,
   binding:state.binding,message:message(state,source)});return prepared.status==='completed'?{skip:true,value:prepared.outcome}:{skip:false,value:prepared};};
  try{
   const outcome=await turns.run(session.id,state.binding,state.customer,{signal:state.signal,idempotencyKey:state.key,
    conversationPurpose:PURPOSE,admit:prepare},async boundary=>{
    let resultSourceCheck;
    const check=async()=>{await boundary.check();await state.check();
     if(resultSourceCheck)await resultSourceCheck();await boundary.check();};
    await check();if(!prepared){await prepare();if(prepared.status==='completed')return prepared.outcome;}
    return admission.execute(prepared,{...boundary,check},async()=>{
     const execution={runId:boundary.identity.runId,ownerKey:boundary.identity.ownerKey,
      durableGeneration:boundary.identity.durableGeneration,signal:boundary.signal,check};
     scopes.set(execution,state.binding);capture.bind(execution,actor);
     const attempt=await completion.beginAttempt({userId:state.binding.platformOwnerId,workshopKey:WORKSHOP,objectiveId:OBJECTIVE,execution});
     await check();if(attempt.mode!=='vuln'||!await eligible(state))return status('ineligible');
     const candidate=buildCouponBlindCandidate({...source,assessmentExecution:execution,qualifyModelTrace});
     if(!candidate)return status('ineligible');
     const rubric=RUBRIC,packet=prepareJudgeInput({rubric,...candidate});
     if(packet.evidenceError)throw fail();packets.set(execution,packet);
     resultSourceCheck=async()=>{
      const current=await original(state);
      if(!current||!equal(current,source)||!await eligible(state))throw fail();
     };
     await check();
     const result=await completion.evaluate({userId:state.binding.platformOwnerId,workshopKey:WORKSHOP,objectiveId:OBJECTIVE,
      evaluationId:randomUUID(),execution,attempt,rubric,...candidate});
     await check();return {completed:result.completed===true,judgment:result.judgment};
    },state.fence);
   });
   await state.check();if(outcome.replayed===true)return readOutcome(input);
   if(equal(outcome.result,status('ineligible')))return status('ineligible');
   return Object.freeze({...outcome.result,replayed:false});
  }catch(error){await admission.abandon(prepared);throw error;}
 }
 async function assertRetainedPacket({packet,scope,persona,personaSession,signal}){
  let input;try{input=typeof packet==='string'?JSON.parse(packet):structuredClone(packet);}catch{throw fail();}
  if(!isCouponBlindJudgeInputValid(input,qualifyModelTrace))throw fail();
  const rubric=RUBRIC;if(input.rubric.version!==rubric.version)throw fail();
  const ref=input.evidence[0].content.source.turn;
  const state=await authority({scope,persona,personaSession,sessionId:ref.sessionId,requestId:ref.requestId,signal});
  const check=async()=>{
   await state.check();
   const receipt=input.evidence[0].content.assessmentExecution,prepared=prepareJudgeInput(input),b=state.binding;
   // Resolve the canonical parent; retry invocations retain its original packet.
   // No probe execution or model work is repeated by this reader.
   const rows=(await identityPool.query(`SELECT j.*,e.tenant_id AS current_tenant_id,e.principal_id AS current_principal_id,
    s.membership_version::text AS current_membership_version,g.generation::text AS live_owner_generation
    FROM secureshop_auth.execution_authority_state e
    JOIN secureshop_auth.execution_sessions s ON s.session_id=e.session_id
    JOIN secureshop_auth.principals p ON p.principal_id=e.principal_id
    JOIN secureshop_auth.assessment_judgments j ON j.tenant_id=e.tenant_id AND j.principal_id=e.principal_id
    JOIN graph_runtime.owners g ON g.owner_key=j.owner_key
    WHERE e.session_id=$1 AND e.owner_id=$2 AND e.is_active=1 AND e.expires_at>clock_timestamp()
     AND p.shop_user_id=$3 AND j.objective_id=$4 AND j.run_id=$5 AND j.owner_key=$6
     AND j.packet=$7 AND j.evidence_digest=$8
     AND NOT EXISTS (SELECT 1 FROM secureshop_auth.assessment_retries retry
      WHERE retry.tenant_id=j.tenant_id AND retry.principal_id=j.principal_id AND retry.child_id=j.evaluation_id) LIMIT 2`,
   [b.platformSessionId,b.platformOwnerId,b.shopUserId,OBJECTIVE,receipt.runId,receipt.ownerKey,prepared.packet,prepared.evidenceDigest])).rows;
   await state.check();if(rows.length!==1)throw fail();
   const row=rows[0],execution=row.execution_json,publication=state.publication.binding;
   if(row.workshop_key!==WORKSHOP||row.objective_id!==OBJECTIVE||Number(row.shop_user_id)!==b.shopUserId
    ||row.family!==rubric.family||row.scenario!==rubric.scenario||row.rubric_version!==rubric.version
    ||row.mode!=='vuln'||row.mode!==publication.mode||Number(row.generation)!==publication.generation
    ||row.mode_stamp!==publication.modeStamp||row.run_id!==receipt.runId||row.owner_key!==receipt.ownerKey
    ||String(row.owner_generation)!==receipt.generation||String(row.live_owner_generation)!==receipt.generation
    ||execution?.runId!==row.run_id||execution.tenantId!==row.current_tenant_id||execution.principalId!==row.current_principal_id
    ||execution.membershipVersion!==row.current_membership_version||!equal(execution.scope,createLaunchScope(b))
    ||execution.personaSessionId!==state.personaSession.sessionId||execution.personaAuthorityVersion!==state.personaSession.authorityVersion
    ||execution.role!=='customer'||prepared.evidenceError||row.packet!==prepared.packet||row.evidence_digest!==prepared.evidenceDigest)throw fail();
   await retained(state,input,{runId:row.run_id,ownerKey:row.owner_key,generation:String(row.owner_generation)});
  };await check();return Object.freeze({assertCurrent:check});
 }
 return Object.freeze({objectiveId:OBJECTIVE,completionService:completion,runAttempt,readOutcome,assertRetainedPacket});
}
module.exports={createCouponBlindAssessment,assessmentRequestId};
