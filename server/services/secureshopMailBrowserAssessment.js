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
const {OBJECTIVE,MAIL_BROWSER_RUBRIC:RUBRIC,buildMailBrowserCandidate}=require('./secureshopMailBrowserEvidence');
const WORKSHOP='secureshop_agent_security',PURPOSE='persona_inbox';
function createMailBrowserAssessment({identityPool,launches,conversationRepository,coordinator,journal,personaAuthority,personaBindings,receipts,progress,publicationModes,judge,evidenceRepository,browserQualification}={}){
 for(const fn of [identityPool?.query,launches?.assertCurrent,personaAuthority?.capture,personaBindings?.capture,judge,evidenceRepository?.readBrowser,browserQualification?.qualifyMail])if(typeof fn!=='function')throw TypeError('Canonical mail browser assessment dependencies required');
 if(publicationModes!==undefined&&typeof publicationModes?.getEvaluationScope!=='function')throw TypeError('Canonical mail browser publication mode reader required');
 const conversations=createBoundConversationService({conversations:conversationRepository,launches}),turns=createBoundTurns({conversations,coordinator}),admission=createTurnAdmission({journal});
 const scopes=new WeakMap(),capture=createAssessmentPersonaCapture(personaBindings);
 const completion=createObjectiveCompletionService({receipts,progress,judge,...capture.options,captureInstanceScope:execution=>{const scope=scopes.get(execution);if(!scope)throw Error('Mail browser grading scope unavailable');return scope;}});
 const enabled=async scope=>(await readSecureShopAssessmentEligibility(identityPool,scope,[OBJECTIVE])).includes(OBJECTIVE);
 return Object.freeze({objectiveId:OBJECTIVE,completionService:completion,async runAttempt({binding:raw,requestId,signal,messageId,evaluationId}){
  if((evaluationId!==undefined&&(typeof evaluationId!=='string'||! /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(evaluationId)))||typeof requestId!=='string'||! /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(requestId)||!Number.isSafeInteger(messageId)||messageId<1)throw TypeError('Invalid mail browser request');
  const b=normalize(raw),binding=createConversationBinding(b.scope,b.persona),fence=personaAuthority.capture({scope:b.scope,personaId:b.persona.id,role:b.persona.role,...b.personaSession});
  const check=async()=>{signal?.throwIfAborted();await launches.assertCurrent(b.scope);await fence.assertRemoteAdmission();signal?.throwIfAborted();};await check();
  if(!await enabled(b.scope))return {completed:false,status:'disabled',modelEvaluated:false};
  const publicationScope=await captureAssessmentPublicationScope(publicationModes||progress,b.scope.platformOwnerId,signal,b.scope);await check();
  if(publicationScope.binding.mode!==b.mode||b.mode!=='vuln')return {completed:false,status:'ineligible',modelEvaluated:false};
  const actor=capture.prepare(binding,fence),session=await conversations.create(b.scope,b.persona,PURPOSE),message=JSON.stringify([OBJECTIVE,b.operationId,b.targetId,b.personaSession,b.mode,publicationScope.binding,messageId,evaluationId||null]);let prepared;
  const prepare=async()=>{await check();prepared=await admission.prepare({sessionId:session.id,requestId,binding,message});return prepared.status==='completed'?{skip:true,value:prepared.outcome}:{skip:false,value:prepared};};
  let outcome;try{outcome=await turns.run(session.id,binding,b.persona,{signal,idempotencyKey:requestId,conversationPurpose:PURPOSE,admit:prepare},async original=>{
   const boundary={...original,async check(){await original.check();await check();}};await boundary.check();if(!prepared){await prepare();if(prepared.status==='completed')return prepared.outcome;}
   return admission.execute(prepared,boundary,async()=>{
    const execution=Object.freeze({runId:boundary.identity.runId,ownerKey:boundary.identity.ownerKey,durableGeneration:boundary.identity.durableGeneration,signal:boundary.signal,check:boundary.check});
    scopes.set(execution,b.scope);capture.bind(execution,actor);
    if(boundary.trace)await boundary.trace({node:'mail_browser_assessment',type:'node_start',data:{}});
    if(!await enabled(b.scope))return {completed:false,status:'disabled',modelEvaluated:false};
    if(evaluationId){
     if(typeof receipts.getRecovery!=='function'||typeof browserQualification.readComponent!=='function')throw Error('Mail browser recovery unavailable');
     const recovery=await receipts.getRecovery({userId:b.scope.platformOwnerId,evaluationId});await boundary.check();
     let packet;try{packet=JSON.parse(recovery?.packet);}catch{throw Error('Mail browser recovery packet unavailable');}
     const proof=packet?.evidence?.find(row=>row.id==='mail_browser'&&row.source==='server_observation')?.content;
     if(recovery.workshop_key!==WORKSHOP||recovery.objective_id!==OBJECTIVE||recovery.owner_key!==execution.ownerKey||String(recovery.owner_generation)!==String(execution.durableGeneration)
      ||!isDeepStrictEqual(packet.rubric,require('../agent-runtime/objectiveJudge').rubricSchema.parse({...RUBRIC,mode:b.mode}))||proof?.version!==1||!isDeepStrictEqual(proof.binding,b)||proof.sendReceipt?.email_id!==messageId)throw Error('Mail browser recovery binding mismatch');
     const r=proof.effectReceipt;
     if(r?.runId!==recovery.run_id||r.ownerKey!==execution.ownerKey||String(r.generation)!==String(execution.durableGeneration))throw Error('Mail browser recovery effect mismatch');
     const rows=(await identityPool.query(`SELECT owner_key AS "ownerKey",generation::text AS generation,effect_key AS "effectKey",run_id AS "runId",status FROM graph_runtime.effects
      WHERE owner_key=$1 AND generation=$2 AND effect_key=$3 AND run_id=$4 AND status='completed'`,[r.ownerKey,r.generation,r.effectKey,r.runId])).rows;await boundary.check();
     if(rows.length!==1||!isDeepStrictEqual({...rows[0],generation:String(rows[0].generation)},{ownerKey:r.ownerKey,generation:String(r.generation),effectKey:r.effectKey,runId:r.runId,status:'completed'}))throw Error('Mail browser recovery effect unavailable');
     const current=await evidenceRepository.readBrowser(b,messageId);await boundary.check();
     const component=await browserQualification.readComponent();await boundary.check();
     if(!isDeepStrictEqual(component,proof.component))throw Error('Mail browser recovery component mismatch');
     const rebuilt=buildMailBrowserCandidate(current,{receipt:r,value:{...proof.browser,component}},{runId:r.runId,ownerKey:r.ownerKey,durableGeneration:r.generation,effectKey:r.effectKey});
     if(!rebuilt||!isDeepStrictEqual(rebuilt.facts,packet.facts)||!isDeepStrictEqual(rebuilt.evidence,packet.evidence))throw Error('Mail browser recovery evidence mismatch');
     const result=await completion.retry({userId:b.scope.platformOwnerId,evaluationId,execution});await boundary.check();
     return {completed:result.completed===true,judgment:result.judgment};
    }
    const attempt=await completion.beginAttempt({userId:b.scope.platformOwnerId,workshopKey:WORKSHOP,objectiveId:OBJECTIVE,execution});await boundary.check();
    if(attempt.mode!==b.mode||b.mode!=='vuln')return {completed:false,status:'ineligible',modelEvaluated:false};
    const observed=await evidenceRepository.readBrowser(b,messageId);await boundary.check();
    if(!isDeepStrictEqual(observed.binding,b))throw Error('Mail evidence binding mismatch');
    const effectKey=`${requestId}:mail-browser:${messageId}`;
    const effect=await boundary.effectWithReceipt(`mail-browser:${messageId}`,async()=>{
     await boundary.check();
     const value=await browserQualification.qualifyMail({html:observed.payload.body_html,messageId,signal:boundary.signal});
     await boundary.check();return value;
    });
    await boundary.check();
    const current=await evidenceRepository.readBrowser(b,messageId);await boundary.check();
    if(!isDeepStrictEqual(current,observed))throw Error('Mail browser source changed');
    const packet=buildMailBrowserCandidate(observed,effect,{...execution,effectKey});await boundary.check();if(!packet)return {completed:false,status:'ineligible',modelEvaluated:false};
    if(!await enabled(b.scope))return {completed:false,status:'disabled',modelEvaluated:false};
    const result=await completion.evaluate({userId:b.scope.platformOwnerId,workshopKey:WORKSHOP,objectiveId:OBJECTIVE,evaluationId:randomUUID(),execution,attempt,rubric:{...RUBRIC,mode:attempt.mode},...packet});await boundary.check();
    return {completed:result.completed===true,judgment:result.judgment};
   },fence);
  });}catch(error){await admission.abandon(prepared);throw error;}
  await publicationScope.assertCurrent();await check();return {...outcome.result,replayed:outcome.replayed===true};
 }});
}
module.exports={createMailBrowserAssessment};
