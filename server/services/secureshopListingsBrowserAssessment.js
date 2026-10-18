'use strict';
const {captureAssessmentPublicationScope}=require('./secureshopAssessmentPublicationScope');
const {randomUUID}=require('node:crypto');
const {isDeepStrictEqual}=require('node:util');
const {prepareListingRecovery,prepareListingAdmission,UUID}=require('./secureshopListingJournalContract');
const {createConversationBinding}=require('./secureshopConversationBinding');
const {SECURESHOP_CONVERSATION_PURPOSES}=require('./secureshopConversationPurpose');
const {createBoundConversationService}=require('./secureshopBoundConversation');
const {createBoundTurns}=require('./secureshopBoundTurns');
const {createTurnAdmission}=require('./secureshopTurnAdmission');
const {createObjectiveCompletionService}=require('./secureshopObjectiveCompletionService');
const {createAssessmentPersonaCapture}=require('./secureshopAssessmentPersonaCapture');
const {readSecureShopAssessmentEligibility}=require('./secureshopAssessmentEligibility');
const {createListingsGeneratedBrowserEvidenceAdapter}=require('./secureshopListingsEvidence');
const {GENERATED_BROWSER_RUBRIC}=require('./secureshopListingsAssessment');
const {projectListingsCandidate,createListingsJudgeGuard}=require('./secureshopListingsJudgeGuard');
const OBJECTIVE=GENERATED_BROWSER_RUBRIC.objectiveId,WORKSHOP='secureshop_agent_security';
const PURPOSE=SECURESHOP_CONVERSATION_PURPOSES.listingRewrite;
const fail=code=>Object.assign(Error('Saved listing browser assessment unavailable'),{code});
function createListingsBrowserAssessment({launches,conversationRepository,coordinator,journal,listingComposition,evidenceRepository,
 identityPool,personaAuthority,personaBindings,receipts,progress,publicationModes,judge,qualifyModel,browserQualification,productRenderer}={}){
 if(typeof launches?.assertCurrent!=='function'||typeof conversationRepository?.getBoundSession!=='function'
  ||typeof listingComposition?.recoverAdmission!=='function'||typeof evidenceRepository?.readSaved!=='function'
  ||typeof identityPool?.query!=='function'||typeof personaAuthority?.capture!=='function'||typeof personaBindings?.capture!=='function'
  ||typeof judge!=='function'||typeof qualifyModel!=='function')throw TypeError('Canonical saved Listings grading dependencies required');
 if(publicationModes!==undefined&&typeof publicationModes?.getEvaluationScope!=='function')throw TypeError('Canonical Listings publication mode reader required');
 const conversations=createBoundConversationService({conversations:conversationRepository,launches});
 const turns=createBoundTurns({conversations,coordinator}),turnAdmission=createTurnAdmission({journal});
 const adapter=createListingsGeneratedBrowserEvidenceAdapter({browserQualification,renderProductDescription:productRenderer?.renderProductDescription,
  componentSourceDigest:productRenderer?.sourceSha256,componentArtifactDigest:productRenderer?.artifactSha256});
 const scopes=new WeakMap(),capture=createAssessmentPersonaCapture(personaBindings);
 const completion=createObjectiveCompletionService({receipts,progress,judge:createListingsJudgeGuard(judge),...capture.options,captureInstanceScope:execution=>{
  const scope=scopes.get(execution);if(!scope)throw fail('GRADE_STORE_NOT_READY');return scope;
 }});
 async function enabled(scope){
  return (await readSecureShopAssessmentEligibility(identityPool,scope,[OBJECTIVE])).includes(OBJECTIVE);
 }
 async function run({scope,persona,personaSession,requestId,rewriteOperationId,saveOperationId,signal,evaluationId}={},retry=false){
  if(!UUID.test(requestId||'')||!UUID.test(saveOperationId||'')||requestId===rewriteOperationId||(retry&&!UUID.test(evaluationId||'')))throw fail('INVALID_ARGUMENT');
  const owned=prepareListingRecovery({scope,persona,personaSession,operationId:rewriteOperationId}),b=owned.binding;
  const binding=createConversationBinding(b.scope,b.persona),fence=await personaAuthority.capture({scope:b.scope,
   personaId:b.persona.id,role:b.persona.role,...b.personaSession});
  const expected={...b.scope,personaId:b.persona.id,role:b.persona.role,...b.personaSession};
  if(!fence?.binding||Object.keys(expected).some(key=>fence.binding[key]!==expected[key])
   ||typeof fence.assertRemoteAdmission!=='function'||typeof fence.withPersonaEffect!=='function')throw fail('SHOP_AUTH_INVALID');
  const check=async()=>{signal?.throwIfAborted();await launches.assertCurrent(b.scope);await fence.assertRemoteAdmission();signal?.throwIfAborted();};
  await check();
  if(!await enabled(b.scope)){await check();return Object.freeze({completed:false,status:'disabled',modelEvaluated:false});}
  await check();
  const original=await listingComposition.recoverAdmission({...b,operationId:rewriteOperationId});await check();
  const admission=prepareListingAdmission(original);
  if(admission.request.action!=='rewrite'||!isDeepStrictEqual(admission.binding.scope,b.scope)
   ||!isDeepStrictEqual(admission.binding.persona,b.persona)||!isDeepStrictEqual(admission.binding.personaSession,b.personaSession))throw fail('LISTING_EVIDENCE_UNAVAILABLE');
  const publicationScope=await captureAssessmentPublicationScope(publicationModes||progress,b.scope.platformOwnerId,signal,b.scope);await check();
  if(publicationScope.binding.mode!=='vuln'||publicationScope.binding.mode!==admission.binding.mode)return {completed:false,status:'ineligible',modelEvaluated:false};
  const actor=capture.prepare(binding,fence),session=await conversations.create(b.scope,b.persona,PURPOSE);await check();
  // Purpose reuse is deliberate: the existing listingRewrite conversation is
  // owner-bound. This distinct turn stores only opaque IDs and never appends a
  // browser result into model history or alters the original rewrite request.
  const message=JSON.stringify(retry?[OBJECTIVE,rewriteOperationId,saveOperationId,'judge-retry',evaluationId,publicationScope.binding]:[OBJECTIVE,rewriteOperationId,saveOperationId,publicationScope.binding]);
  let prepared;
  const prepare=async()=>{await check();prepared=await turnAdmission.prepare({sessionId:session.id,requestId,binding,message});await check();
   return prepared.status==='completed'?{skip:true,value:prepared.outcome}:{skip:false,value:prepared};};
  let outcome;
  try{
   outcome=await turns.run(session.id,binding,b.persona,{signal,idempotencyKey:requestId,conversationPurpose:PURPOSE,admit:prepare},async originalBoundary=>{
    const boundary=Object.freeze({...originalBoundary,async check(){await originalBoundary.check();await check();await originalBoundary.check();}});
    await boundary.check();
    if(!prepared){await prepare();if(prepared.status==='completed')return prepared.outcome;}
    return turnAdmission.execute(prepared,boundary,async()=>{
     if(!boundary.identity.runId||!boundary.identity.ownerKey||boundary.identity.durableGeneration==null)throw fail('GRADE_STORE_NOT_READY');
     const execution=Object.freeze({runId:boundary.identity.runId,ownerKey:boundary.identity.ownerKey,durableGeneration:boundary.identity.durableGeneration,
      signal:boundary.signal,check:boundary.check});
     scopes.set(execution,b.scope);capture.bind(execution,actor);
     if(!await enabled(b.scope)){await boundary.check();return {completed:false,status:'disabled',modelEvaluated:false};}
     if(retry){
      if(typeof receipts.getRecovery!=='function')throw fail('GRADE_STORE_NOT_READY');
      const recovery=await receipts.getRecovery({userId:b.scope.platformOwnerId,evaluationId});await boundary.check();
      let packet;try{packet=JSON.parse(recovery?.packet);}catch{throw fail('LISTING_EVIDENCE_UNAVAILABLE');}
      const evidence=packet?.evidence?.find(item=>item.id==='listing_audit'&&item.source==='server_observation')?.content?.raw||packet?.evidence?.find(item=>item.id==='listing_owned_effect'&&item.source==='server_observation')?.content;
      if(recovery.workshop_key!==WORKSHOP||recovery.objective_id!==OBJECTIVE||packet.rubric?.objectiveId!==OBJECTIVE
       ||recovery.owner_key!==execution.ownerKey||String(recovery.owner_generation)!==String(execution.durableGeneration)
       ||!isDeepStrictEqual(evidence?.binding,admission.binding)||evidence.rewriteOperationId!==rewriteOperationId
       ||evidence.saveOperationId!==saveOperationId)throw fail('LISTING_EVIDENCE_UNAVAILABLE');
      // Retry the immutable observed effect. A later source edit cannot erase it;
      // canonical receipt retry enforces expiry, catalog/mode, reset and persona.
      const result=await completion.retry({userId:b.scope.platformOwnerId,evaluationId,execution});await boundary.check();
      return {completed:result.completed===true,judgment:result.judgment,productId:evidence.productId,rewriteOperationId,saveOperationId};
     }
     const attempt=await completion.beginAttempt({userId:b.scope.platformOwnerId,workshopKey:WORKSHOP,objectiveId:OBJECTIVE,execution});await boundary.check();
     if(attempt.mode!=='vuln'||admission.binding.mode!==attempt.mode)return {completed:false,status:'ineligible',modelEvaluated:false};
     const before=await evidenceRepository.readSaved({admission,saveOperationId});await boundary.check();
     // The trusted reader must return the exact requested source; do not render
     // any foreign or replacement source even when grading would later deny it.
     if(!isDeepStrictEqual(before.admission,admission)||before.save?.saveOperationId!==saveOperationId
      ||before.save.rewriteOperationId!==rewriteOperationId||before.source?.saveOperationId!==saveOperationId)throw fail('LISTING_EVIDENCE_UNAVAILABLE');
     const browserEvidence=await adapter.capture({source:before.source,boundary,execution,requestId});await boundary.check();
     const after=await evidenceRepository.readSaved({admission,saveOperationId});await boundary.check();
     if(!isDeepStrictEqual(before.save,after.save)||!isDeepStrictEqual(before.turn,after.turn)||!isDeepStrictEqual(before.operation,after.operation))throw fail('LISTING_EVIDENCE_UNAVAILABLE');
     const candidate=adapter.build({...before,readback:after.source,browserEvidence,execution,qualifyModel})[0];
     if(!candidate)return {completed:false,status:'ineligible',modelEvaluated:false};
     if(!await enabled(b.scope)){await boundary.check();return {completed:false,status:'disabled',modelEvaluated:false};}
     await boundary.check();
     const result=await completion.evaluate({userId:b.scope.platformOwnerId,workshopKey:WORKSHOP,evaluationId:randomUUID(),execution,attempt,
      rubric:{...GENERATED_BROWSER_RUBRIC,mode:attempt.mode},...projectListingsCandidate(candidate)});
     await boundary.check();
     return {completed:result.completed===true,judgment:result.judgment,productId:before.save.productId,rewriteOperationId,saveOperationId};
    },fence);
   });
  }catch(error){await turnAdmission.abandon(prepared);throw error;}
  await publicationScope.assertCurrent();await check();return Object.freeze({...outcome.result,replayed:outcome.replayed===true});
 }
 return Object.freeze({runAttempt:input=>run(input),retryAttempt:input=>run(input,true),completionService:completion});
}
module.exports={createListingsBrowserAssessment,OBJECTIVE};
