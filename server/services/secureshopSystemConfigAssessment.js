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
const traversal=require('./secureshopSystemConfigEvidence');
const credentials=require('./secureshopSystemCredentialEvidence');
const {createTurnRequest}=require('./secureshopTurnRequest');

const WORKSHOP='secureshop_agent_security',PURPOSE='persona_inbox';
const unavailable=()=>Object.assign(new Error('System config assessment unavailable'),{code:'SYSTEM_CONFIG_EVIDENCE_UNAVAILABLE'});

function createSystemConfigAssessment({identityPool,launches,conversationRepository,coordinator,journal,
 personaAuthority,personaBindings,receipts,progress,judge,qualifyModel,modeAuthority,systemReads,scenes}={}){
 for(const value of [identityPool?.query,launches?.assertCurrent,conversationRepository?.getTraceEvents,
  journal?.readBoundRequest,coordinator?.run,personaAuthority?.capture,personaBindings?.capture,
  systemReads?.operation,judge,qualifyModel])if(typeof value!=='function')throw unavailable();
 const conversations=createBoundConversationService({conversations:conversationRepository,launches});
 const turns=createBoundTurns({conversations,coordinator}),admission=createTurnAdmission({journal});
 const scopes=new WeakMap(),capture=createAssessmentPersonaCapture(personaBindings);
 const contracts=new Map([
  ['/app/.env',{...traversal,build:traversal.buildSystemConfigCandidate,guard:traversal.createSystemConfigJudgeGuard}],
  ['/app/platform_secrets.json',{...credentials,build:credentials.buildSystemCredentialCandidate,guard:credentials.createSystemCredentialJudgeGuard}]
 ]);
 for(const contract of contracts.values())contract.completion=createObjectiveCompletionService({receipts,progress,
  judge:contract.guard(judge),...capture.options,
  captureInstanceScope:execution=>{const scope=scopes.get(execution);if(!scope)throw unavailable();return scope;}});
 const assertCredentialScene=async(binding,sourceEnvelope)=>{
  if(typeof scenes?.readRetained!=='function')throw unavailable();
  const source=JSON.parse(sourceEnvelope),current=await scenes.readRetained(binding);
  if(!current||current.scene?.sceneId!==source.sceneId||current.scene.sceneGeneration!==source.sceneGeneration
   ||current.targetId!==source.targetId)throw unavailable();
 };
 const objectiveIds=[...contracts.values()].map(contract=>contract.OBJECTIVE);
 const enabled=async(scope,id)=>(await readSecureShopAssessmentEligibility(identityPool,scope,[id])).includes(id);
 return Object.freeze({objectiveId:traversal.OBJECTIVE,completionService:contracts.get('/app/.env').completion,
  async assertCredentialRetainedPacket({packet,scope,persona,personaSession}={}){
   const raw=credentials.readSystemCredentialRetainedEvidence(packet),binding=createConversationBinding(scope,persona);
   if(!raw||binding.role!=='admin'||!equal(raw.scope,scope)||raw.personaId!==binding.shopUserId
    ||raw.personaSessionId!==personaSession?.sessionId
    ||raw.personaAuthorityVersion!==personaSession?.authorityVersion)throw unavailable();
   const fence=personaAuthority.capture({scope:binding,personaId:binding.shopUserId,role:'admin',...personaSession});
   const admin=await captureFeatureMode(modeAuthority,binding,'admin_assistant');
   const system=await captureFeatureMode(modeAuthority,binding,'system_config');
   if(system.snapshot.mode!=='vuln'||!equal(admin.snapshot,raw.adminExecution)
    ||!equal(system.snapshot,raw.systemExecution))throw unavailable();
   const check=async()=>{await launches.assertCurrent(binding);await fence.assertRemoteAdmission();
    await admin.assertCurrent();await system.assertCurrent();
    await assertCredentialScene(binding,raw.systemCredentialOrigin.sourceEnvelope);};
   await check();
   const {sessionId,requestId}=raw;
   await conversations.assertOwned(sessionId,binding,persona,'secureshop_admin_assistant');
   const turn=await journal.readBoundRequest({sessionId,requestId,binding,purpose:'secureshop_admin_assistant'});
   if(turn?.status!=='completed'||turn.request_version!==1
    ||turn.request_hash!==createTurnRequest({sessionId,requestId,binding,message:raw.systemCredentialOrigin.sourceEnvelope}).hash)
    throw unavailable();
   const [traces,operation]=await Promise.all([
    conversationRepository.getTraceEvents(sessionId,binding,raw.traceEventIds,'secureshop_admin_assistant'),
    systemReads.operation({context:{scope:binding,persona,personaSession},operationId:raw.operationId})]);
   const rebuilt=credentials.buildSystemCredentialCandidate({turn:turn.result_json,traces,operation,
    sessionId,requestId,binding,personaSession,qualifyModel,adminExecution:admin.snapshot,systemExecution:system.snapshot});
   if(!rebuilt||!equal(rebuilt.facts,packet.facts)||!equal(rebuilt.evidence,packet.evidence))throw unavailable();
   await check();return Object.freeze({assertCurrent:check});
  },
  async runAttempt({scope,persona,personaSession,sessionId,requestId,verifyOriginal,signal}={}){
   const binding=createConversationBinding(scope,persona);
   if(binding.role!=='admin'||typeof verifyOriginal!=='function'||typeof sessionId!=='string'
    ||typeof requestId!=='string'||typeof personaSession?.sessionId!=='string')throw unavailable();
   const fence=personaAuthority.capture({scope:binding,personaId:binding.shopUserId,role:binding.role,...personaSession});
   const adminMode=await captureFeatureMode(modeAuthority,binding,'admin_assistant');
   const systemMode=await captureFeatureMode(modeAuthority,binding,'system_config');
   let credentialEnvelope;
   const check=async()=>{signal?.throwIfAborted();await launches.assertCurrent(binding);
    await adminMode.assertCurrent();await systemMode.assertCurrent();await fence.assertRemoteAdmission();
    if(credentialEnvelope)await assertCredentialScene(binding,credentialEnvelope);signal?.throwIfAborted();};
   await check();
   if(systemMode.snapshot.mode!=='vuln'||!(await readSecureShopAssessmentEligibility(identityPool,binding,objectiveIds)).length)
    return Object.freeze({completed:false,status:'ineligible',modelEvaluated:false});
   const saved=await verifyOriginal();await check();
   if(saved?.status!=='completed'||saved.systemConfigRead?.state!=='completed')
    return Object.freeze({completed:false,status:'ineligible',modelEvaluated:false});
   const operationId=saved.systemConfigRead.operationId;
   // Resolve all original immutable evidence before claiming a grading turn.
   // An unavailable protected read or trace lookup can then be explicitly
   // retried without leaving an uncertain assessment admission behind.
   await conversations.assertOwned(sessionId,binding,persona,'secureshop_admin_assistant');
   const turn=await journal.readBoundRequest({sessionId,requestId,binding,purpose:'secureshop_admin_assistant'});
   const eventIds=turn?.result_json?.taskMetadata?.roleChat?.systemConfigTraceEventIds;
   if(turn?.status!=='completed'||!Array.isArray(eventIds)||eventIds.length<3||eventIds.length>4096)
    return Object.freeze({completed:false,status:'ineligible',modelEvaluated:false});
   const [traces,operation]=await Promise.all([
    conversationRepository.getTraceEvents(sessionId,binding,eventIds,'secureshop_admin_assistant'),
    systemReads.operation({context:{scope:binding,persona,personaSession},operationId,signal})]);
   await conversations.assertOwned(sessionId,binding,persona,'secureshop_admin_assistant');await check();
   // Only the owned operation receipt selects the objective. No caller-supplied
   // objective or mutable catalog label can redirect grading to another lesson.
   const contract=contracts.get(operation?.receipt?.readResult?.targetPath);
   if(!contract||!await enabled(binding,contract.OBJECTIVE))
    return Object.freeze({completed:false,status:'ineligible',modelEvaluated:false});
   const {OBJECTIVE,RUBRIC,completion}=contract;
   if(OBJECTIVE===credentials.OBJECTIVE){
    const proof=turn.result_json.taskMetadata.roleChat.systemCredentialOrigin;
    if(typeof proof?.sourceEnvelope!=='string'||turn.request_version!==1
     ||createTurnRequest({sessionId,requestId,binding,message:proof.sourceEnvelope}).hash!==turn.request_hash)
     return Object.freeze({completed:false,status:'ineligible',modelEvaluated:false});
   }
   if(OBJECTIVE===credentials.OBJECTIVE){
    credentialEnvelope=turn.result_json.taskMetadata.roleChat.systemCredentialOrigin.sourceEnvelope;
    await check();
   }
   const candidate=contract.build({turn:turn.result_json,traces,operation,sessionId,requestId,
    binding,personaSession,qualifyModel,adminExecution:adminMode.snapshot,systemExecution:systemMode.snapshot});
   if(!candidate)return Object.freeze({completed:false,status:'ineligible',modelEvaluated:false});
   const actor=capture.prepare(binding,fence),assessmentSession=await conversations.create(binding,persona,PURPOSE);
   const message=JSON.stringify([OBJECTIVE,operationId,sessionId,requestId,
    personaSession.sessionId,personaSession.authorityVersion]);
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
       if(attempt.mode!=='vuln'||!await enabled(binding,OBJECTIVE))
        return {completed:false,status:'ineligible',modelEvaluated:false};
       const verified=await verifyOriginal();await boundary.check();
       if(verified?.status!=='completed'||verified.systemConfigRead?.operationId!==operationId)
        return {completed:false,status:'ineligible',modelEvaluated:false};
       const result=await completion.evaluate({userId:binding.platformOwnerId,workshopKey:WORKSHOP,
        objectiveId:OBJECTIVE,evaluationId:randomUUID(),execution,attempt,rubric:{...RUBRIC,mode:attempt.mode},
        facts:candidate.facts,evidence:candidate.evidence});
       await boundary.check();return {completed:result.completed===true,judgment:result.judgment};
      },fence);
    });
    await check();
    if(outcome.result?.status==='ineligible')
     return Object.freeze({completed:false,status:'ineligible',modelEvaluated:false});
    return Object.freeze({...outcome.result,replayed:outcome.replayed===true});
   }catch(error){await admission.abandon(prepared);throw error;}
  }});
}
module.exports={createSystemConfigAssessment};
