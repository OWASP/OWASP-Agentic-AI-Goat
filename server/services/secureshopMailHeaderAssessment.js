'use strict';
const {captureAssessmentPublicationScope}=require('./secureshopAssessmentPublicationScope');
const {readSecureShopAssessmentEligibility}=require('./secureshopAssessmentEligibility');
const {randomUUID}=require('node:crypto');
const {isDeepStrictEqual}=require('node:util');
const {normalize}=require('../database/postgres/secureshopBoundMailRepository');
const {createConversationBinding}=require('./secureshopConversationBinding');
const {createBoundConversationService}=require('./secureshopBoundConversation');
const {createBoundTurns}=require('./secureshopBoundTurns');
const {createTurnAdmission}=require('./secureshopTurnAdmission');
const {createAssessmentPersonaCapture}=require('./secureshopAssessmentPersonaCapture');
const {createObjectiveCompletionService}=require('./secureshopObjectiveCompletionService');
const {OBJECTIVE,MAIL_HEADER_RUBRIC:RUBRIC,buildMailHeaderCandidate,candidateForVersion}=require('./secureshopMailHeaderEvidence');
const WORKSHOP='secureshop_agent_security',PURPOSE='persona_inbox';
function createMailHeaderAssessment({identityPool,launches,conversationRepository,coordinator,journal,personaAuthority,personaBindings,receipts,progress,publicationModes,judge,evidenceRepository}={}){
 for(const fn of [identityPool?.query,launches?.assertCurrent,personaAuthority?.capture,personaBindings?.capture,judge,evidenceRepository?.readHeader])if(typeof fn!=='function')throw TypeError('Canonical mail header assessment dependencies required');
 if(publicationModes!==undefined&&typeof publicationModes?.getEvaluationScope!=='function')throw TypeError('Canonical mail header publication mode reader required');
 const conversations=createBoundConversationService({conversations:conversationRepository,launches}),turns=createBoundTurns({conversations,coordinator}),admission=createTurnAdmission({journal});
 const scopes=new WeakMap(),capture=createAssessmentPersonaCapture(personaBindings);
 const completion=createObjectiveCompletionService({receipts,progress,judge,...capture.options,captureInstanceScope:execution=>{const scope=scopes.get(execution);if(!scope)throw Error('Mail header grading scope unavailable');return scope;}});
 const enabled=async scope=>(await readSecureShopAssessmentEligibility(identityPool,scope,[OBJECTIVE])).includes(OBJECTIVE);
 return Object.freeze({objectiveId:OBJECTIVE,completionService:completion,async runAttempt({binding:raw,requestId,signal,evaluationId}){
  const b=normalize(raw),binding=createConversationBinding(b.scope,b.persona),fence=personaAuthority.capture({scope:b.scope,personaId:b.persona.id,role:b.persona.role,...b.personaSession});
  const check=async()=>{signal?.throwIfAborted();await launches.assertCurrent(b.scope);await fence.assertRemoteAdmission();signal?.throwIfAborted();};await check();
  if(!await enabled(b.scope))return {completed:false,status:'disabled',modelEvaluated:false};
  const publicationScope=await captureAssessmentPublicationScope(publicationModes||progress,b.scope.platformOwnerId,signal,b.scope);await check();
  if(publicationScope.binding.mode!==b.mode||b.mode!=='vuln')return {completed:false,status:'ineligible',modelEvaluated:false};
  const actor=capture.prepare(binding,fence),session=await conversations.create(b.scope,b.persona,PURPOSE),message=JSON.stringify([OBJECTIVE,b.operationId,b.targetId,b.personaSession,b.mode,publicationScope.binding,evaluationId||null]);let prepared;
  const prepare=async()=>{await check();prepared=await admission.prepare({sessionId:session.id,requestId,binding,message});return prepared.status==='completed'?{skip:true,value:prepared.outcome}:{skip:false,value:prepared};};
  let outcome;try{outcome=await turns.run(session.id,binding,b.persona,{signal,idempotencyKey:requestId,conversationPurpose:PURPOSE,admit:prepare},async original=>{
   const boundary={...original,async check(){await original.check();await check();}};await boundary.check();if(!prepared){await prepare();if(prepared.status==='completed')return prepared.outcome;}
   return admission.execute(prepared,boundary,async()=>{
    const execution=Object.freeze({runId:boundary.identity.runId,ownerKey:boundary.identity.ownerKey,durableGeneration:boundary.identity.durableGeneration,signal:boundary.signal,check:boundary.check});
    scopes.set(execution,b.scope);capture.bind(execution,actor);
    if(!await enabled(b.scope))return {completed:false,status:'disabled',modelEvaluated:false};
    if(evaluationId){
     if(typeof receipts.getRecovery!=='function')throw Error('Mail recovery unavailable');
     const recovery=await receipts.getRecovery({userId:b.scope.platformOwnerId,evaluationId});await boundary.check();
     let packet;try{packet=JSON.parse(recovery?.packet);}catch{throw Error('Mail recovery packet unavailable');}
     const observed=packet?.evidence?.find(row=>row.id==='mail_header'&&row.source==='server_observation')?.content;
     if(recovery.workshop_key!==WORKSHOP||recovery.objective_id!==OBJECTIVE||packet.rubric?.objectiveId!==OBJECTIVE
      ||recovery.owner_key!==execution.ownerKey||String(recovery.owner_generation)!==String(execution.durableGeneration)
      ||!isDeepStrictEqual(observed?.binding,b))throw Error('Mail recovery binding mismatch');
     const current=candidateForVersion(await evidenceRepository.readHeader(b),{rubricVersion:packet.rubric.version,contentVersion:observed?.version});await boundary.check();
     if(!current||!isDeepStrictEqual(current.evidence,packet.evidence))throw Error('Mail recovery effect mismatch');
     const result=await completion.retry({userId:b.scope.platformOwnerId,evaluationId,execution});await boundary.check();
     return {completed:result.completed===true,judgment:result.judgment};
    }
    const attempt=await completion.beginAttempt({userId:b.scope.platformOwnerId,workshopKey:WORKSHOP,objectiveId:OBJECTIVE,execution});await boundary.check();
    if(attempt.mode!==b.mode||b.mode!=='vuln')return {completed:false,status:'ineligible',modelEvaluated:false};
    const observed=await evidenceRepository.readHeader(b);await boundary.check();
    if(!isDeepStrictEqual(observed.binding,b))throw Error('Mail evidence binding mismatch');
    const packet=buildMailHeaderCandidate(observed);await boundary.check();if(!packet)return {completed:false,status:'ineligible',modelEvaluated:false};
    if(!await enabled(b.scope))return {completed:false,status:'disabled',modelEvaluated:false};
    const result=await completion.evaluate({userId:b.scope.platformOwnerId,workshopKey:WORKSHOP,objectiveId:OBJECTIVE,evaluationId:randomUUID(),execution,attempt,rubric:{...RUBRIC,mode:attempt.mode},...packet});await boundary.check();
    return {completed:result.completed===true,judgment:result.judgment};
   },fence);
  });}catch(error){await admission.abandon(prepared);throw error;}
  await publicationScope.assertCurrent();await check();return {...outcome.result,replayed:outcome.replayed===true};
 }});
}
module.exports={createMailHeaderAssessment};
