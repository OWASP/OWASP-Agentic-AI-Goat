'use strict';

const {randomUUID}=require('node:crypto');
const {createConversationBinding}=require('./secureshopConversationBinding');
const {createBoundConversationService}=require('./secureshopBoundConversation');
const {createBoundTurns}=require('./secureshopBoundTurns');
const {createTurnAdmission}=require('./secureshopTurnAdmission');
const {captureFeatureMode}=require('./secureshopFeatureModeAuthority');
const {createAssessmentPersonaCapture}=require('./secureshopAssessmentPersonaCapture');
const {readSecureShopAssessmentEligibility}=require('./secureshopAssessmentEligibility');
const {createObjectiveCompletionService}=require('./secureshopObjectiveCompletionService');
const {OBJECTIVE,RUBRIC,buildPolicyTemplateCandidate,projectPolicyTemplateCandidate,createPolicyTemplateJudgeGuard}=require('./secureshopPolicyTemplateEvidence');

const WORKSHOP='secureshop_agent_security';
const PURPOSE='persona_inbox';
const unavailable=()=>Object.assign(new Error('Policy template assessment unavailable'),{code:'POLICY_TEMPLATE_EVIDENCE_UNAVAILABLE'});

function createPolicyTemplateAssessment({identityPool,launches,conversationRepository,coordinator,journal,personaAuthority,personaBindings,
 receipts,progress,judge,qualifyModel,modeAuthority,policyChat}={}){
 for(const value of [identityPool?.query,launches?.assertCurrent,conversationRepository?.getTraceEvents,journal?.readBoundRequest,
  coordinator?.run,personaAuthority?.capture,personaBindings?.capture,policyChat?.readAssessmentPublication,judge,qualifyModel]){
  if(typeof value!=='function')throw unavailable();
 }
 const conversations=createBoundConversationService({conversations:conversationRepository,launches});
 const turns=createBoundTurns({conversations,coordinator}),admission=createTurnAdmission({journal});
 const scopes=new WeakMap(),capture=createAssessmentPersonaCapture(personaBindings);
 const completion=createObjectiveCompletionService({receipts,progress,judge:createPolicyTemplateJudgeGuard(judge),...capture.options,
  captureInstanceScope:execution=>{const scope=scopes.get(execution);if(!scope)throw unavailable();return scope;}});
 const enabled=async scope=>(await readSecureShopAssessmentEligibility(identityPool,scope,[OBJECTIVE])).includes(OBJECTIVE);
 return Object.freeze({objectiveId:OBJECTIVE,completionService:completion,async runAttempt({scope,persona,personaSession,sessionId,requestId,proposal,turn,allowedTargets,signal}={}){
  const binding=createConversationBinding(scope,persona);
  if(binding.role!=='admin'||!proposal||!turn||typeof sessionId!=='string'||typeof requestId!=='string')throw unavailable();
  const fence=personaAuthority.capture({scope:binding,personaId:binding.shopUserId,role:binding.role,...personaSession});
  const adminMode=await captureFeatureMode(modeAuthority,binding,'admin_assistant');
  const policyMode=await captureFeatureMode(modeAuthority,binding,'policy');
  const check=async()=>{signal?.throwIfAborted();await launches.assertCurrent(binding);await adminMode.assertCurrent();await policyMode.assertCurrent();await fence.assertRemoteAdmission();signal?.throwIfAborted();};
  await check();
  if(adminMode.snapshot.mode!=='vuln'||policyMode.snapshot.mode!=='vuln'||proposal.modeCapability?.effectiveMode!=='vuln'||!await enabled(binding)){
   return Object.freeze({completed:false,status:'ineligible',modelEvaluated:false});
  }
  const actor=capture.prepare(binding,fence),assessmentSession=await conversations.create(binding,persona,PURPOSE);
  const message=JSON.stringify([OBJECTIVE,proposal.proposalId,sessionId,requestId,personaSession.sessionId,personaSession.authorityVersion]);
  let prepared;
  const prepare=async()=>{await check();prepared=await admission.prepare({sessionId:assessmentSession.id,requestId:proposal.proposalId,binding,message});
   return prepared.status==='completed'?{skip:true,value:prepared.outcome}:{skip:false,value:prepared};};
  try{
   const outcome=await turns.run(assessmentSession.id,binding,persona,{signal,idempotencyKey:proposal.proposalId,conversationPurpose:PURPOSE,admit:prepare},async original=>{
    const boundary={...original,async check(){await original.check();await check();}};await boundary.check();
    if(!prepared){await prepare();if(prepared.status==='completed')return prepared.outcome;}
    return admission.execute(prepared,boundary,async()=>{
     const execution=Object.freeze({runId:boundary.identity.runId,ownerKey:boundary.identity.ownerKey,durableGeneration:boundary.identity.durableGeneration,signal:boundary.signal,check:boundary.check});
     scopes.set(execution,binding);capture.bind(execution,actor);
     const attempt=await completion.beginAttempt({userId:binding.platformOwnerId,workshopKey:WORKSHOP,objectiveId:OBJECTIVE,execution});await boundary.check();
     if(attempt.mode!=='vuln'||!await enabled(binding))return {completed:false,status:'ineligible',modelEvaluated:false};
     if(turn?.status!=='completed'||!turn.result_json||typeof turn.result_json!=='object')return {completed:false,status:'ineligible',modelEvaluated:false};
     const traceEventIds=turn.result_json?.taskMetadata?.roleChat?.policyTraceEventIds;
     if(!Array.isArray(traceEventIds)||traceEventIds.length<3||traceEventIds.length>4096)return {completed:false,status:'ineligible',modelEvaluated:false};
     await conversations.assertOwned(sessionId,binding,persona,'secureshop_admin_assistant');
     const [traces,publication]=await Promise.all([
      conversationRepository.getTraceEvents(sessionId,binding,traceEventIds,'secureshop_admin_assistant'),
      policyChat.readAssessmentPublication({context:{scope:binding,persona,personaSession},operationId:proposal.proposalId}),
     ]);await conversations.assertOwned(sessionId,binding,persona,'secureshop_admin_assistant');await boundary.check();
     const candidate=buildPolicyTemplateCandidate({proposal,publication,traces,turn:turn.result_json,sessionId,requestId,binding,personaSession,qualifyModel,allowedTargets,policyExecution:policyMode.snapshot});
     if(!candidate)return {completed:false,status:'ineligible',modelEvaluated:false};
     const packet=projectPolicyTemplateCandidate(candidate);
     const result=await completion.evaluate({userId:binding.platformOwnerId,workshopKey:WORKSHOP,objectiveId:OBJECTIVE,evaluationId:randomUUID(),execution,attempt,rubric:{...RUBRIC,mode:attempt.mode},...packet});
     await boundary.check();return {completed:result.completed===true,judgment:result.judgment};
    },fence);
   });
   await check();return Object.freeze({...outcome.result,replayed:outcome.replayed===true});
  }catch(error){await admission.abandon(prepared);throw error;}
 }});
}
module.exports={createPolicyTemplateAssessment};
