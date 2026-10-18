'use strict';
const {isDeepStrictEqual:equal}=require('node:util');
const {UUID,exact}=require('./secureshopCouponContract');
const {createLaunchScope,createConversationBinding}=require('./secureshopConversationBinding');
const {createBoundConversationService}=require('./secureshopBoundConversation');
const {createBoundTurns}=require('./secureshopBoundTurns');
const {createTurnAdmission}=require('./secureshopTurnAdmission');
const {inventoryGradingProjection}=require('./secureshopInventoryGradingProjection');
const {OBJECTIVE}=require('./secureshopInventoryEvidence');
const {fail}=require('./secureshopInventoryContract');
const PURPOSE=require('./secureshopConversationPurpose').SECURESHOP_CONVERSATION_PURPOSES.inventory;
function assertInventoryRetryEvidence({recovery,original,scope,persona,personaSession,originalRequestId,evaluationId,execution}){
 let packet;try{packet=JSON.parse(recovery?.packet);}catch{throw fail('INVENTORY_EVIDENCE_UNAVAILABLE');}
 const originalGrade=original?.outcome?.taskMetadata?.inventory?.grading;
 const raw=packet?.evidence?.find(item=>item.id==='inventory_stock'&&item.source==='server_observation')?.content?.raw,b=raw?.entry?.receipt?.binding;
 if(recovery.workshop_key!=='secureshop_agent_security'||recovery.objective_id!==OBJECTIVE||packet.rubric?.objectiveId!==OBJECTIVE||recovery.owner_key!==execution.ownerKey||String(recovery.owner_generation)!==String(execution.durableGeneration)
  ||original.status!=='completed'||originalGrade?.judgment?.evaluationId!==evaluationId||originalGrade.judgment.verdict!=='unavailable'||originalGrade.judgment.canRetry!==true
  ||raw?.context?.requestId!==originalRequestId||b?.execution?.requestId!==originalRequestId||raw?.execution?.runId!==b?.execution?.runId
  ||!equal(raw?.context?.binding,createConversationBinding(scope,persona))||!equal(b?.scope,scope)||!equal(b?.persona,persona)||!equal(b?.personaSession,personaSession)
  ||!original.outcome.taskMetadata.inventory.receipts.some(entry=>equal(entry,raw.entry)))throw fail('INVENTORY_EVIDENCE_UNAVAILABLE');
 return packet;
}
function createInventoryJudgeRetry({launches,personaAuthority,conversationRepository,coordinator,journal,recoveryRepository,receipts,assessment}={}){
 const conversations=createBoundConversationService({conversations:conversationRepository,launches}),turns=createBoundTurns({conversations,coordinator}),admission=createTurnAdmission({journal});
 return async function retry(input,{signal}={}){
  exact(input,['scope','persona','personaSession','requestId','originalRequestId','evaluationId']);
  const {persona,personaSession,requestId,originalRequestId,evaluationId}=input,scope=createLaunchScope(input.scope);
  if(persona?.role!=='merchant'||![requestId,originalRequestId,evaluationId].every(id=>UUID.test(id||''))||requestId===originalRequestId)throw fail('INVENTORY_INVALID');
  const fence=await personaAuthority.capture({scope,personaId:persona.id,role:persona.role,...personaSession}),expected={...scope,personaId:persona.id,role:persona.role,...personaSession};
  if(Object.keys(expected).some(key=>fence.binding?.[key]!==expected[key]))throw fail('SHOP_AUTH_INVALID');
  const check=async()=>{signal?.throwIfAborted();await launches.assertCurrent(scope);await fence.assertRemoteAdmission();signal?.throwIfAborted();};
  await check();const disabled={ok:true,status:'completed',requestId,originalRequestId,grading:{status:'disabled',completed:false}};
  if(!await assessment.isEnabled(scope)){await check();return disabled;}
  const original=await recoveryRepository.read({scope,persona,personaSession,requestId:originalRequestId});await check();
  const binding=createConversationBinding(scope,persona),session=await conversations.create(scope,persona,PURPOSE);await check();
  // Distinct UUID + tagged request digest: retry cannot be confused with a stock turn.
  const message=JSON.stringify({kind:'inventory-judge-retry-v1',originalRequestId,evaluationId});let prepared;
  const prepare=async()=>{await check();prepared=await admission.prepare({sessionId:session.id,requestId,binding,message});await check();return prepared.status==='completed'?{skip:true,value:prepared.outcome}:{skip:false,value:prepared};};
  let outcome;
  try{outcome=await turns.run(session.id,binding,persona,{signal,idempotencyKey:requestId,conversationPurpose:PURPOSE,admit:prepare},async boundary=>{
   const execution={runId:boundary.identity.runId,ownerKey:boundary.identity.ownerKey,durableGeneration:boundary.identity.durableGeneration,signal:boundary.signal,async check(){await boundary.check();await check();await boundary.check();}};
   await execution.check();if(!prepared){await prepare();if(prepared.status==='completed')return prepared.outcome;}
   return admission.execute(prepared,execution,async()=>{
    if(!await assessment.isEnabled(scope))return disabled;
    const recovery=await receipts.getRecovery({userId:scope.platformOwnerId,evaluationId});await execution.check();
    assertInventoryRetryEvidence({recovery,original,scope,persona,personaSession,originalRequestId,evaluationId,execution});
    const result=await assessment.completionService.retry({userId:scope.platformOwnerId,evaluationId,execution});await execution.check();
    return{ok:true,status:'completed',requestId,originalRequestId,grading:inventoryGradingProjection(result)};
   },fence);
  });}catch(error){await admission.abandon(prepared);throw error;}
  await check();if(!await assessment.isEnabled(scope)){await check();return disabled;}await check();
  return{...outcome.result,replayed:outcome.replayed===true};
 };
}
module.exports={createInventoryJudgeRetry,assertInventoryRetryEvidence};
