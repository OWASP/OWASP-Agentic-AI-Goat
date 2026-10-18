'use strict';

const {createHash,randomUUID}=require('node:crypto');
const {isDeepStrictEqual:equal}=require('node:util');
const {createConversationBinding,createLaunchScope}=require('./secureshopConversationBinding');
const {executionScope}=require('./secureshopSceneBinding');
const {createBoundConversationService}=require('./secureshopBoundConversation');
const {createBoundTurns}=require('./secureshopBoundTurns');
const {createTurnAdmission}=require('./secureshopTurnAdmission');
const {createTurnRequest}=require('./secureshopTurnRequest');
const {captureFeatureMode}=require('./secureshopFeatureModeAuthority');
const {createAssessmentPersonaCapture}=require('./secureshopAssessmentPersonaCapture');
const {captureAssessmentPublicationScope}=require('./secureshopAssessmentPublicationScope');
const {readSecureShopAssessmentEligibility}=require('./secureshopAssessmentEligibility');
const {createObjectiveCompletionService}=require('./secureshopObjectiveCompletionService');
const {prepareJudgeInput}=require('../agent-runtime/objectiveJudge');
const {projectJudgment}=require('../agent-runtime/dpiSemanticCreditPolicy');
const {PURPOSES}=require('../database/postgres/secureshopRoleChatBindingRepository');
const {OBJECTIVE,RUBRIC,validateUserLookupEvidence,projectUserLookupCandidate,
 createUserLookupJudgeGuard,isUserLookupJudgeInputValid}=require('./secureshopUserLookupEvidence');
const WORKSHOP='secureshop_agent_security',PURPOSE='persona_inbox';
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const fail=()=>Object.assign(Error('User lookup assessment unavailable'),{code:'USER_LOOKUP_ASSESSMENT_UNAVAILABLE'});
const status=value=>Object.freeze({completed:false,status:value,modelEvaluated:false});
const exact=(v,keys)=>v&&typeof v==='object'&&!Array.isArray(v)&&equal(Object.keys(v).sort(),[...keys].sort());
function assessmentRequestId(sessionId,requestId){
 if(![sessionId,requestId].every(v=>UUID.test(v||'')))throw fail();
 const bytes=createHash('sha256').update(JSON.stringify(['user-lookup-assessment-v1',sessionId,requestId])).digest();
 bytes[6]=(bytes[6]&15)|80;bytes[8]=(bytes[8]&63)|128;
 const h=bytes.subarray(0,16).toString('hex');return `${h.slice(0,8)}-${h.slice(8,12)}-${h.slice(12,16)}-${h.slice(16,20)}-${h.slice(20)}`;
}
const message=state=>JSON.stringify([OBJECTIVE,state.sessionId,state.requestId,
 state.personaSession,state.mode.snapshot,state.publication.binding]);
function createUserLookupAssessment({identityPool,agentsPool,launches,conversationRepository,
 coordinator,turnJournal,bindingRepository,scenes,userAdministration,personaAuthority,personaBindings,
 receipts,progress,publicationModes,judge,qualifyModel,modeAuthority}={}){
 for(const fn of [identityPool?.query,agentsPool?.query,launches?.assertCurrent,
  conversationRepository?.getBoundSession,conversationRepository?.getTraceEvents,
  conversationRepository?.acquireBoundSession,coordinator?.run,turnJournal?.readBoundRequest,
  bindingRepository?.read,scenes?.readExisting,userAdministration?.readAgentLookup,
  personaAuthority?.capture,personaBindings?.capture,publicationModes?.getEvaluationScope,
  modeAuthority?.capture,modeAuthority?.assertToken,judge,qualifyModel])
  if(typeof fn!=='function')throw TypeError('User lookup assessment dependencies required');
 const conversations=createBoundConversationService({conversations:conversationRepository,launches});
 const turns=createBoundTurns({conversations,coordinator}),admission=createTurnAdmission({journal:turnJournal});
 const scopes=new WeakMap(),packets=new WeakMap(),capture=createAssessmentPersonaCapture(personaBindings);
 const guardedJudge=createUserLookupJudgeGuard(judge);
 const completion=createObjectiveCompletionService({receipts,progress,judge:async input=>{
  const expected=packets.get(input.execution),actual=prepareJudgeInput(input);
  if(!expected||actual.evidenceError||actual.packet!==expected.packet||actual.evidenceDigest!==expected.evidenceDigest)throw fail();
  return guardedJudge(input);
 },...capture.options,captureInstanceScope:execution=>{const scope=scopes.get(execution);if(!scope)throw fail();return scope;}});
 const enabled=async scope=>(await readSecureShopAssessmentEligibility(identityPool,scope,[OBJECTIVE])).includes(OBJECTIVE);
 async function authority({scope,persona,personaSession,sessionId,requestId,signal}){
  const binding=createConversationBinding(scope,persona);
  if(binding.role!=='admin'||![sessionId,requestId,personaSession?.sessionId].every(v=>UUID.test(v||''))
   ||typeof personaSession.authorityVersion!=='string'
   ||!/^[1-9]\d*$/.test(personaSession.authorityVersion))throw fail();
  const session=Object.freeze({sessionId:personaSession.sessionId,authorityVersion:personaSession.authorityVersion}),admin={id:binding.shopUserId,role:'admin'};
  const fence=personaAuthority.capture({scope:binding,personaId:admin.id,role:'admin',...session});
  const expected={...createLaunchScope(binding),personaId:admin.id,role:'admin',...session};
  if(typeof fence?.assertRemoteAdmission!=='function'||!Object.keys(expected).every(k=>fence.binding?.[k]===expected[k]))throw fail();
  // Deny a foreign source before consulting the caller's optional scene or
  // assessment configuration. A peer without a scene is still an ownership
  // denial, not an assessment infrastructure failure.
  await fence.assertRemoteAdmission();
  await conversations.assertOwned(sessionId,binding,admin,PURPOSES.admin);
  await fence.assertRemoteAdmission();
  const mode=await captureFeatureMode(modeAuthority,binding,'admin_assistant');
  
  const target=await scenes.readExisting(binding);
  if(!target?.scene||!equal(createLaunchScope(executionScope(target)),createLaunchScope(binding)))throw fail();
  const publication=await captureAssessmentPublicationScope(publicationModes,binding.platformOwnerId,signal,binding);
  const check=async()=>{
   signal?.throwIfAborted();await launches.assertCurrent(binding);await fence.assertRemoteAdmission();
   await mode.assertCurrent();await publication.assertCurrent();
   const current=await scenes.readExisting(binding);
   if(!current?.scene||current.targetId!==target.targetId||!equal(current.scene,target.scene)
    ||!equal(createLaunchScope(current),createLaunchScope(target)))throw fail();
   signal?.throwIfAborted();
  };
  await check();return {binding,admin,personaSession:session,fence,mode,target,publication,
   sessionId,requestId,signal,check};
 }
 async function original(state,verifyOriginal){
  const {binding,admin,personaSession,sessionId,requestId,mode,check}=state;
  await check();
  if(state.publication.binding.mode!=='vuln'||mode.snapshot.mode!=='vuln')return null;
  if(verifyOriginal!==undefined){
   if(typeof verifyOriginal!=='function')throw fail();
   const saved=await verifyOriginal();await check();
   if(saved?.status!=='completed'||saved.userLookup?.status!=='complete')return null;
  }
  await conversations.assertOwned(sessionId,binding,admin,PURPOSES.admin);
  const boundTurn=await bindingRepository.read({sessionId,requestId,scope:binding,persona:admin});
  const savedTurn=await turnJournal.readBoundRequest({sessionId,requestId,binding,purpose:PURPOSES.admin});
  if(savedTurn?.session_id!==sessionId||boundTurn?.session_id!==sessionId||boundTurn.request_id!==requestId
   ||Object.hasOwn(savedTurn,'request_id')&&savedTurn.request_id!==requestId)return null;
  const turn={...savedTurn,request_id:requestId},meta=turn?.result_json?.taskMetadata?.roleChat,origin=meta?.userLookupOrigin;
  if(turn?.status!=='completed'||meta?.userLookup?.status!=='complete'||origin?.version!==1
   ||!UUID.test(origin.runId||'')||!Array.isArray(origin.traceEventIds)||origin.traceEventIds.length<5
   ||origin.traceEventIds.length>256||!equal(origin.execution,mode.snapshot))return null;
  const traces=await conversationRepository.getTraceEvents(sessionId,binding,origin.traceEventIds,PURPOSES.admin);
  const lookup=await userAdministration.readAgentLookup({scope:binding,persona:admin,personaSession,
   username:meta.userLookup.receipt.username,reference:meta.userLookup.receipt,target:state.target,check});
  const owner=JSON.stringify(['SecureShopBoundConversation',sessionId]);
  const runs=(await identityPool.query(`SELECT r.run_id,r.owner_key,r.generation::text AS generation,r.status
   FROM graph_runtime.runs r JOIN graph_runtime.owners o ON o.owner_key=r.owner_key AND o.generation=r.generation
   WHERE r.run_id=$1 AND r.owner_key=$2`,[origin.runId,owner])).rows;
  const effectKey=`${requestId}:${JSON.stringify([origin.step,origin.callId,'admin.user_lookup'])}`;
  const effects=(await identityPool.query(`SELECT run_id,owner_key,generation::text AS generation,effect_key,status
   FROM graph_runtime.effects WHERE run_id=$1 AND owner_key=$2 AND effect_key=$3`,[origin.runId,owner,effectKey])).rows;
  await conversations.assertOwned(sessionId,binding,admin,PURPOSES.admin);await check();
  if(runs.length!==1)return null;
  try{return validateUserLookupEvidence({binding,personaSession,target:state.target,boundTurn,turn,traces,
   run:runs[0],effects,lookup,modeExecution:mode.snapshot,qualifyModel});}
  catch(error){if(error?.code==='USER_LOOKUP_EVIDENCE_INVALID')return null;throw error;}
 }
 function outcome(value,replayed){
  if(exact(value,['completed','status','modelEvaluated'])&&value.completed===false
   &&value.modelEvaluated===false&&['ineligible','unconfirmed','pending'].includes(value.status))return status(value.status);
  if(!exact(value,['completed','judgment'])||typeof value.completed!=='boolean'
   ||!value.judgment||typeof value.judgment!=='object'||Array.isArray(value.judgment))throw fail();
  return Object.freeze({...structuredClone(value),replayed});
 }
 async function readOutcome(input){
  const state=await authority(input);if(typeof input.verifyOriginal!=='function')throw fail();
  if(!await enabled(state.binding))return status('ineligible');
  const proof=await original(state,input.verifyOriginal);if(!proof)return status('ineligible');
  const {binding}=state,key=assessmentRequestId(state.sessionId,state.requestId);
  const rows=(await agentsPool.query(`SELECT t.session_id,t.request_id,t.status,t.request_hash,t.request_version,t.result_json
   FROM secureshop_agents.turn_requests t JOIN secureshop_agents.agent_sessions s ON s.id=t.session_id
   WHERE t.request_id=$1 AND s.authority_mode='launch_bound' AND s.binding_state='active'
    AND s.conversation_purpose='persona_inbox' AND s.platform_launch_id=$2
    AND s.platform_scenario_id=$3 AND s.platform_launch_generation=$4
    AND s.original_platform_owner_id=$5 AND s.original_platform_session_id=$6
    AND s.user_id=$7 AND s.role=$8 LIMIT 2`,[key,binding.launchId,binding.scenarioId,binding.generation,
   binding.platformOwnerId,binding.platformSessionId,binding.shopUserId,binding.role])).rows;
  await state.check();if(!rows.length)return status('unconfirmed');if(rows.length!==1)throw fail();
  const row=rows[0],expected=createTurnRequest({sessionId:row.session_id,requestId:key,binding,message:message(state)});
  if(row.request_id!==key||row.request_hash!==expected.hash||Number(row.request_version)!==expected.version)throw fail();
  if(row.status!=='completed')return status('pending');
  return canonicalOutcome(state,row,proof);
 }
 function canonicalJudgment(row){
  if(!UUID.test(row?.evaluation_id||'')||typeof row.result_digest!=='string'||!/^[a-f0-9]{64}$/.test(row.result_digest)
   ||!row.result_json||!['pass','fail','inconclusive','unavailable'].includes(row.verdict)
   ||row.result_json.verdict!==row.verdict
   ||!['awarded','already_complete','not_pass','grading_unqualified'].includes(row.disposition)
   ||['awarded','already_complete'].includes(row.disposition)&&row.verdict!=='pass')throw fail();
  const serialized=row.result_serialized??JSON.stringify(row.result_json);
  if(typeof serialized!=='string'||createHash('sha256').update(serialized).digest('hex')!==row.result_digest
   ||!equal(JSON.parse(serialized),row.result_json))throw fail();
  return {completed:['awarded','already_complete'].includes(row.disposition),
   judgment:{...projectJudgment({disposition:row.disposition,result:row.result_json}),evaluationId:row.evaluation_id,canRetry:false}};
 }
 async function canonicalOutcome(state,row,proof){
  const result=row.result_json;
  if(equal(result,status('ineligible')))return status('ineligible');
  if(!exact(result,['completed','judgment'])||typeof result.completed!=='boolean'
   ||!UUID.test(result.judgment?.evaluationId||''))throw fail();
  const {binding,admin,personaSession,publication}=state;
  const judgments=(await identityPool.query(`SELECT j.*,r.child_id,to_jsonb(child) AS child_row,to_jsonb(invocation) AS child_invocation,
   e.tenant_id AS current_tenant_id,e.principal_id AS current_principal_id,
   s.membership_version::text AS current_membership_version,g.generation::text AS live_owner_generation
   FROM secureshop_auth.execution_authority_state e
   JOIN secureshop_auth.execution_sessions s ON s.session_id=e.session_id
   JOIN secureshop_auth.principals p ON p.principal_id=e.principal_id
   JOIN secureshop_auth.assessment_judgments j ON j.tenant_id=e.tenant_id AND j.principal_id=e.principal_id
   LEFT JOIN secureshop_auth.assessment_retries r ON r.tenant_id=j.tenant_id AND r.principal_id=j.principal_id AND r.parent_id=j.evaluation_id
   LEFT JOIN secureshop_auth.assessment_judgments child ON child.tenant_id=r.tenant_id AND child.principal_id=r.principal_id AND child.evaluation_id=r.child_id
   LEFT JOIN secureshop_auth.assessment_retry_invocations invocation ON invocation.tenant_id=j.tenant_id
    AND invocation.principal_id=j.principal_id AND invocation.parent_id=j.evaluation_id
    AND invocation.run_id::text=(child.execution_json->>'runId')
   LEFT JOIN graph_runtime.owners g ON g.owner_key=j.owner_key
   WHERE e.session_id=$1 AND e.owner_id=$2 AND e.is_active=1 AND e.expires_at>clock_timestamp()
    AND p.shop_user_id=$3 AND j.evaluation_id=$4 AND j.objective_id=$5 LIMIT 2`,
  [binding.platformSessionId,binding.platformOwnerId,admin.id,result.judgment.evaluationId,OBJECTIVE])).rows;
  await state.check();if(judgments.length!==1)throw fail();
  const judgment=judgments[0],execution=judgment.execution_json,mode=publication.binding;
  const packet=prepareJudgeInput({rubric:{...RUBRIC,mode:'vuln'},...projectUserLookupCandidate(proof)});
  if(judgment.evaluation_id!==result.judgment.evaluationId||judgment.workshop_key!==WORKSHOP||judgment.objective_id!==OBJECTIVE||Number(judgment.shop_user_id)!==admin.id
   ||judgment.family!==RUBRIC.family||judgment.scenario!==RUBRIC.scenario||judgment.rubric_version!==RUBRIC.version
   ||judgment.mode!=='vuln'||judgment.mode!==mode.mode||Number(judgment.generation)!==mode.generation
   ||judgment.mode_stamp!==mode.modeStamp||judgment.owner_key!==JSON.stringify(['SecureShopBoundConversation',row.session_id])
   ||String(judgment.owner_generation)!==String(judgment.live_owner_generation)
   ||execution?.tenantId!==judgment.current_tenant_id||execution.principalId!==judgment.current_principal_id
   ||execution.membershipVersion!==judgment.current_membership_version||!equal(execution.scope,createLaunchScope(binding))
   ||execution.personaSessionId!==personaSession.sessionId||execution.personaAuthorityVersion!==personaSession.authorityVersion
   ||execution.role!=='admin'||execution.runId!==judgment.run_id||packet.evidenceError
   ||packet.packet!==judgment.packet||packet.evidenceDigest!==judgment.evidence_digest)throw fail();
  const parent=canonicalJudgment(judgment);
  if(result.completed!==parent.completed||!equal({...result.judgment,canRetry:false},parent.judgment))throw fail();
  if(!judgment.child_id)return Object.freeze({...parent,replayed:true});
  const child=judgment.child_row;
  if(!child||child.evaluation_id!==judgment.child_id||child.tenant_id!==judgment.tenant_id
   ||child.principal_id!==judgment.principal_id||child.objective_id!==OBJECTIVE||child.workshop_key!==WORKSHOP
   ||child.run_id!==judgment.run_id||child.family!==judgment.family||child.scenario!==judgment.scenario||child.rubric_version!==judgment.rubric_version
   ||child.evidence_digest!==judgment.evidence_digest||child.packet!==judgment.packet||child.generation!==judgment.generation
   ||child.mode!==judgment.mode||child.mode_stamp!==judgment.mode_stamp||child.owner_key!==judgment.owner_key
   ||String(child.owner_generation)!==String(judgment.owner_generation)
   ||!equal({...child.execution_json,runId:null},{...execution,runId:null}))throw fail();
  // A child retains the original evidence run. Its creation execution belongs
  // to a persisted retry invocation, which need not be the final Judge retry.
  const invocation=judgment.child_invocation;
  if(!invocation||invocation.tenant_id!==judgment.tenant_id||invocation.principal_id!==judgment.principal_id
   ||invocation.parent_id!==judgment.evaluation_id||invocation.run_id!==child.execution_json?.runId
   ||!UUID.test(invocation.run_id||'')||!Number.isInteger(invocation.attempt)||invocation.attempt<1||invocation.attempt>3
   ||!equal(invocation.execution_json,child.execution_json))throw fail();
  await state.check();return Object.freeze({...(child.verdict?canonicalJudgment(child):parent),replayed:true});
 }
 async function runAttempt(input){
  const state=await authority(input),{binding,admin,fence,check,signal}=state;
  if(typeof input.verifyOriginal!=='function')throw fail();
  if(state.mode.snapshot.mode!=='vuln'||state.publication.binding.mode!=='vuln'||!await enabled(binding))return status('ineligible');
  const proof=await original(state,input.verifyOriginal);if(!proof)return status('ineligible');
  const candidate=projectUserLookupCandidate(proof),rubric={...RUBRIC,mode:'vuln'};
  const expectedPacket=prepareJudgeInput({rubric,...candidate});if(expectedPacket.evidenceError)return status('ineligible');
  const actor=capture.prepare(binding,fence),session=await conversations.create(binding,admin,PURPOSE);
  const key=assessmentRequestId(state.sessionId,state.requestId);let prepared;
  const prepare=async()=>{await check();prepared=await admission.prepare({sessionId:session.id,requestId:key,binding,message:message(state)});
   return prepared.status==='completed'?{skip:true,value:prepared.outcome}:{skip:false,value:prepared};};
  try{
   const result=await turns.run(session.id,binding,admin,{signal,idempotencyKey:key,conversationPurpose:PURPOSE,admit:prepare},async boundary=>{
    const protectedBoundary={...boundary,async check(){await boundary.check();await check();await boundary.check();}};
    await protectedBoundary.check();if(!prepared){await prepare();if(prepared.status==='completed')return prepared.outcome;}
    return admission.execute(prepared,protectedBoundary,async()=>{
     const execution=Object.freeze({runId:boundary.identity.runId,ownerKey:boundary.identity.ownerKey,
      durableGeneration:boundary.identity.durableGeneration,signal:boundary.signal,check:protectedBoundary.check});
     scopes.set(execution,binding);capture.bind(execution,actor);
     const attempt=await completion.beginAttempt({userId:binding.platformOwnerId,workshopKey:WORKSHOP,objectiveId:OBJECTIVE,execution});
     await protectedBoundary.check();
     if(attempt.mode!=='vuln'||!await enabled(binding))return status('ineligible');
     const confirmed=await original(state,input.verifyOriginal);await protectedBoundary.check();
     if(!confirmed||!equal(proof,confirmed))return status('ineligible');
     packets.set(execution,expectedPacket);
     const evaluated=await completion.evaluate({userId:binding.platformOwnerId,workshopKey:WORKSHOP,objectiveId:OBJECTIVE,
      evaluationId:randomUUID(),execution,attempt,rubric,...candidate});
     await protectedBoundary.check();return {completed:evaluated.completed===true,judgment:evaluated.judgment};
    },fence);
   });
   await check();if(result.replayed===true)return readOutcome(input);
   return outcome(result.result,false);
  }catch(error){await admission.abandon(prepared);throw error;}
 }
 async function assertRetainedPacket({packet,scope,persona,personaSession,signal}){
  let saved;try{saved=typeof packet==='string'?JSON.parse(packet):structuredClone(packet);}catch{throw fail();}
  if(!isUserLookupJudgeInputValid(saved))throw fail();
  const proof={proof:saved.evidence[0].content,user:saved.evidence[1].content,text:saved.evidence[2].content};
  const state=await authority({scope,persona,personaSession,...proof.proof.source,signal});
  if(!await enabled(state.binding))throw fail();
  const reread=async()=>{
   await state.check();if(!await enabled(state.binding))throw fail();
   const current=await original(state);
   if(!current||!equal(current,proof))throw fail();
   const expected=prepareJudgeInput({rubric:{...RUBRIC,mode:'vuln'},...projectUserLookupCandidate(current)});
   const actual=prepareJudgeInput(saved);
   if(expected.evidenceError||actual.evidenceError||expected.packet!==actual.packet
    ||expected.evidenceDigest!==actual.evidenceDigest)throw fail();
   await state.check();
  };
  await reread();return Object.freeze({assertCurrent:reread});
 }
 return Object.freeze({objectiveId:OBJECTIVE,completionService:completion,isEnabled:enabled,runAttempt,readOutcome,assertRetainedPacket});
}
module.exports={createUserLookupAssessment,assessmentRequestId};
