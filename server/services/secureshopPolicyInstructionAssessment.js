'use strict';

const {randomUUID}=require('node:crypto');
const {isDeepStrictEqual:equal}=require('node:util');
const {createConversationBinding}=require('./secureshopConversationBinding');
const {createBoundConversationService}=require('./secureshopBoundConversation');
const {createBoundTurns}=require('./secureshopBoundTurns');
const {createTurnAdmission}=require('./secureshopTurnAdmission');
const {captureFeatureMode}=require('./secureshopFeatureModeAuthority');
const {createAssessmentPersonaCapture}=require('./secureshopAssessmentPersonaCapture');
const {readSecureShopAssessmentEligibility}=require('./secureshopAssessmentEligibility');
const {createObjectiveCompletionService}=require('./secureshopObjectiveCompletionService');
const {OBJECTIVE,RUBRIC,buildPolicyInstructionCandidate,createPolicyInstructionJudgeGuard}=require('./secureshopPolicyInstructionEvidence');

const WORKSHOP='secureshop_agent_security',PURPOSE='persona_inbox';
const unavailable=()=>Object.assign(new Error('Policy instruction assessment unavailable'),
 {code:'POLICY_INSTRUCTION_EVIDENCE_UNAVAILABLE'});
const ineligible=()=>Object.freeze({completed:false,status:'ineligible',modelEvaluated:false});
const sameTarget=(a,b)=>a?.targetId===b?.targetId&&a?.scene?.sceneId===b?.scene?.sceneId
 &&a?.scene?.sceneGeneration===b?.scene?.sceneGeneration&&a?.scene?.grantId===b?.scene?.grantId;

// The protected snapshot reader is deliberately mandatory. A mutable current
// policy head, caller-supplied text, or cached assistant summary is not proof
// of the policy that the original model actually consumed.
function createPolicyInstructionAssessment({identityPool,launches,conversationRepository,coordinator,journal,
 roleBindings,policyRepository,personaAuthority,personaBindings,receipts,progress,judge,qualifyModel,
 modeAuthority,systemReads,readRetainedTarget}={}){
 for(const fn of [identityPool?.query,launches?.assertCurrent,conversationRepository?.getTraceEvents,
  journal?.readBoundRequest,roleBindings?.read,policyRepository?.readAssessmentSnapshot,
  policyRepository?.readAssessmentPublication,coordinator?.run,personaAuthority?.capture,
  personaBindings?.capture,systemReads?.operation,readRetainedTarget,judge,qualifyModel])if(typeof fn!=='function')throw unavailable();
 const conversations=createBoundConversationService({conversations:conversationRepository,launches});
 const turns=createBoundTurns({conversations,coordinator}),admission=createTurnAdmission({journal});
 const scopes=new WeakMap(),capture=createAssessmentPersonaCapture(personaBindings);
 const completion=createObjectiveCompletionService({receipts,progress,judge:createPolicyInstructionJudgeGuard(judge),
  ...capture.options,captureInstanceScope:execution=>{const scope=scopes.get(execution);if(!scope)throw unavailable();return scope;}});
 const enabled=async scope=>(await readSecureShopAssessmentEligibility(identityPool,scope,[OBJECTIVE])).includes(OBJECTIVE);
 return Object.freeze({objectiveId:OBJECTIVE,completionService:completion,
  async runAttempt({scope,persona,personaSession,sessionId,requestId,verifyOriginal,signal}={}){
   const binding=createConversationBinding(scope,persona);
   if(binding.role!=='admin'||typeof verifyOriginal!=='function'||typeof sessionId!=='string'
    ||typeof requestId!=='string'||typeof personaSession?.sessionId!=='string')throw unavailable();
   const fence=personaAuthority.capture({scope:binding,personaId:binding.shopUserId,role:'admin',...personaSession});
   const adminMode=await captureFeatureMode(modeAuthority,binding,'admin_assistant');
   const systemMode=await captureFeatureMode(modeAuthority,binding,'system_config');
   const check=async()=>{signal?.throwIfAborted();await launches.assertCurrent(binding);
    await adminMode.assertCurrent();await systemMode.assertCurrent();await fence.assertRemoteAdmission();signal?.throwIfAborted();};
   await check();
   if(adminMode.snapshot.mode!=='vuln'||systemMode.snapshot.mode!=='vuln'||!await enabled(binding))return ineligible();
   // Original RoleChat GET is protected by the original launch/persona/session.
   // The separately retained scene capability is SELECT-only and is used
   // solely to recompute the immutable original envelope.
   const saved=await verifyOriginal();await check();
   if(saved?.status!=='completed'||saved.systemConfigRead?.state!=='completed')return ineligible();
   const target=await readRetainedTarget(binding);await check();
   if(!target?.scene)return ineligible();
   await conversations.assertOwned(sessionId,binding,persona,'secureshop_admin_assistant');
   const [turn,turnBinding]=await Promise.all([
    journal.readBoundRequest({sessionId,requestId,binding,purpose:'secureshop_admin_assistant'}),
    roleBindings.read({sessionId,requestId,scope:binding,persona})]);
   const meta=turn?.result_json?.taskMetadata?.roleChat,proof=meta?.policyInstruction;
   if(turn?.status!=='completed'||turn.request_version!==1||!turnBinding||!proof
    ||!Array.isArray(proof.traceEventIds)||proof.traceEventIds.length<4||proof.traceEventIds.length>4096
    ||!proof.snapshotRunId
    ||!equal(saved.systemConfigRead,meta.systemConfigRead))return ineligible();
   const policyContext={scope:binding,persona,personaSession};
   const [snapshotRecord,traces,operation]=await Promise.all([
    policyRepository.readAssessmentSnapshot({...policyContext,runId:proof.snapshotRunId}),
    conversationRepository.getTraceEvents(sessionId,binding,proof.traceEventIds,'secureshop_admin_assistant'),
    systemReads.operation({context:policyContext,operationId:saved.systemConfigRead.operationId,signal})]);
   if(!snapshotRecord?.publicationOperationId)return ineligible();
   const publication=await policyRepository.readAssessmentPublication({...policyContext,
    operationId:snapshotRecord.publicationOperationId});
   await conversations.assertOwned(sessionId,binding,persona,'secureshop_admin_assistant');await check();
   const candidate=buildPolicyInstructionCandidate({binding,personaSession,sessionId,requestId,
    turn:turn.result_json,traces,publication,snapshotRecord,operation,target,turnBinding,
    requestHash:turn.request_hash,requestVersion:turn.request_version,qualifyModel,
    adminExecution:adminMode.snapshot,systemExecution:systemMode.snapshot});
   if(!candidate)return ineligible();
   const operationId=operation.operationId,actor=capture.prepare(binding,fence);
   const assessmentSession=await conversations.create(binding,persona,PURPOSE);
   const message=JSON.stringify([OBJECTIVE,operationId,sessionId,requestId,
    personaSession.sessionId,personaSession.authorityVersion,proof.snapshotRunId,proof.snapshotSha256]);
   let prepared;
   const prepare=async()=>{await check();prepared=await admission.prepare({sessionId:assessmentSession.id,
    requestId:operationId,binding,message});return prepared.status==='completed'
     ?{skip:true,value:prepared.outcome}:{skip:false,value:prepared};};
   try{
    const outcome=await turns.run(assessmentSession.id,binding,persona,{signal,idempotencyKey:operationId,
     conversationPurpose:PURPOSE,admit:prepare},async original=>{
      const boundary={...original,async check(){await original.check();await check();}};await boundary.check();
      if(!prepared){await prepare();if(prepared.status==='completed')return prepared.outcome;}
      return admission.execute(prepared,boundary,async()=>{
       const execution=Object.freeze({runId:boundary.identity.runId,ownerKey:boundary.identity.ownerKey,
        durableGeneration:boundary.identity.durableGeneration,signal:boundary.signal,check:boundary.check});
       scopes.set(execution,binding);capture.bind(execution,actor);
       const attempt=await completion.beginAttempt({userId:binding.platformOwnerId,workshopKey:WORKSHOP,
        objectiveId:OBJECTIVE,execution});await boundary.check();
       if(attempt.mode!=='vuln'||!await enabled(binding))return ineligible();
       const verified=await verifyOriginal();await boundary.check();
       const currentTarget=await readRetainedTarget(binding);await boundary.check();
       if(verified?.status!=='completed'||verified.systemConfigRead?.operationId!==operationId
        ||!sameTarget(currentTarget,target))return ineligible();
       const result=await completion.evaluate({userId:binding.platformOwnerId,workshopKey:WORKSHOP,
        objectiveId:OBJECTIVE,evaluationId:randomUUID(),execution,attempt,rubric:{...RUBRIC,mode:attempt.mode},
        facts:candidate.facts,evidence:candidate.evidence});
       await boundary.check();return {completed:result.completed===true,judgment:result.judgment};
      },fence);
    });
    await check();
    return outcome.result?.status==='ineligible'?ineligible():Object.freeze({...outcome.result,replayed:outcome.replayed===true});
   }catch(error){await admission.abandon(prepared);throw error;}
  }});
}

module.exports={createPolicyInstructionAssessment};
