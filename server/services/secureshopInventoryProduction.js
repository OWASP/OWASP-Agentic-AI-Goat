'use strict';
const {createHash}=require('node:crypto');
const {createLaunchScope}=require('./secureshopConversationBinding');
const {executionScope}=require('./secureshopSceneBinding');
const {isDeepStrictEqual:equal}=require('node:util');
const {fail}=require('./secureshopInventoryContract');
// Scoped actor/Judge28425, transport14392, catalog75379 and enabled retry/readback54341 accepted.
// Instructor catalog visibility remains independent and default disabled.
const PRODUCTION_QUALIFIED=true;
function project(outcome,requestId,grading){const metadata=outcome?.taskMetadata?.inventory;if(outcome?.stopReason!=='end_turn'||metadata?.requestId!==requestId||!Array.isArray(metadata.receipts))throw fail('INVENTORY_RESULT_UNAVAILABLE');return{ok:true,status:'completed',requestId,answer:outcome.text,operations:metadata.receipts.map(entry=>({action:entry.receipt.binding.action,result:entry.receipt.result})),replayed:outcome.replayed===true,...(outcome.modeCapability?{modeCapability:outcome.modeCapability}:{}),...(grading?{grading}:{})};}
async function projectVisibleInventoryOutcome(outcome,requestId,scope,isEnabled){return project(outcome,requestId,await isEnabled(scope)?require('./secureshopInventoryGradingProjection').inventoryGradingProjection(outcome?.taskMetadata?.inventory?.grading):{status:'disabled',completed:false});}
async function createInventoryProduction({enabled=false,identityPool,agentsPool,reviewPool,resetComposition,catalog,personaAuthority,provider,promptPolicyRepository,toolPolicyRepository,assessmentDependencies,authenticatePersona,mode='vuln',modeAuthority,resolveExistingTarget}={}){
 if(typeof enabled!=='boolean')throw fail('INVENTORY_UNAVAILABLE');if(!enabled)return Object.freeze({ready:false});
 if(typeof promptPolicyRepository?.admitRunSnapshot!=='function'||typeof toolPolicyRepository?.admitTool!=='function'||typeof authenticatePersona!=='function'||typeof resetComposition?.launches?.assertCurrent!=='function'||typeof resolveExistingTarget!=='function')throw fail('INVENTORY_UNAVAILABLE');
 await require('./secureshopInventorySchema').assertInventorySchema(reviewPool);
 const purpose=(await agentsPool.query("SELECT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='secureshop_agents.agent_sessions'::regclass AND conname='agent_sessions_conversation_purpose_shape' AND position('secureshop_inventory' in pg_get_constraintdef(oid))>0) AS ready")).rows[0];if(purpose?.ready!==true)throw fail('INVENTORY_UNAVAILABLE');
 const launches=resetComposition.launches,checkCurrent=scope=>launches.assertCurrent(scope),repository=require('../database/postgres/secureshopOwnedInventoryRepository').createOwnedInventoryRepository({pool:reviewPool,checkCurrent});
 const inventory=require('./secureshopBoundInventory').createBoundInventory({repository,checkCurrent,mode,modeAuthority}),qualifyModel=require('./secureshopModelQualification').createSecureShopModelQualifier(provider);
 const assessment=require('./secureshopInventoryAssessment').createInventoryAssessment({...assessmentDependencies,identityPool,qualifyModel});
 const graph=require('./secureshopBoundInventoryGraph').createBoundInventoryGraph({launches,personaAuthority,conversationRepository:resetComposition.conversations,journal:resetComposition.journal,coordinator:resetComposition.runCoordinator,provider,inventory,catalog,promptPolicyRepository,toolPolicyRepository,assessmentFactory:assessment.assessmentFactory,mode,modeAuthority});
 const recoveries=new Map(['vuln','fixed'].map(selected=>[selected,require('../database/postgres/secureshopInventoryRecoveryRepository').createInventoryRecoveryRepository({personaAuthority,checkCurrent,mode:selected})]));
 const capture=input=>require('./secureshopFeatureModeAuthority').captureFeatureMode(modeAuthority,input.scope,'inventory',mode);
 const recovery={async read(input){const token=await capture(input);await token.assertCurrent();const result=await recoveries.get(token.snapshot.mode).read(input);await token.assertCurrent();return result;}};
 const retry=require('./secureshopInventoryJudgeRetry').createInventoryJudgeRetry({launches,personaAuthority,conversationRepository:resetComposition.conversations,coordinator:resetComposition.runCoordinator,journal:resetComposition.journal,recoveryRepository:recovery,receipts:assessmentDependencies.receipts,assessment});
 let closed=false;const active=new Map();
 const current=async input=>{if(closed)throw fail('INVENTORY_UNAVAILABLE');const scope=createLaunchScope(input.scope);if(input.persona?.role!=='merchant')throw fail('SHOP_AUTH_INVALID');const fence=await personaAuthority.capture({scope,personaId:input.persona.id,role:'merchant',...input.personaSession});await checkCurrent(scope);await fence.assertRemoteAdmission();return scope;};
 const historyRepository=require('../database/postgres/secureshopInventoryHistoryRepository').createInventoryHistoryRepository({agentsPool,reviewPool,checkCurrent});
 const historical=async(input,method)=>{
  const scope=await current(input);
  const fence=await personaAuthority.capture({scope,personaId:input.persona.id,role:'merchant',...input.personaSession});
  const expected={...scope,personaId:input.persona.id,role:'merchant',...input.personaSession};
  if(Object.keys(expected).some(key=>fence.binding?.[key]!==expected[key]))throw fail('SHOP_AUTH_INVALID');
  await fence.assertRemoteAdmission();
  const target=await resolveExistingTarget(scope);
  if(!target?.scene||!equal(executionScope(target),scope))throw fail('INVENTORY_HISTORY_NOT_FOUND');
  await checkCurrent(scope);await fence.assertRemoteAdmission();
  const result=await historyRepository[method]({...input,scope,target});
  await checkCurrent(scope);await fence.assertRemoteAdmission();
  return result;
 };
 const application=Object.freeze({async readiness(input){if(closed)return{ready:false};const scope=await current(input),token=await capture(input);return{ready:true,modeCapability:require('./secureshopFeatureModeAuthority').projectFeatureMode(token),scopeKey:createHash('sha256').update(JSON.stringify({scope,persona:input.persona,personaSession:input.personaSession,mode:token.snapshot})).digest('hex')};},
 async run(input,{signal}={}){await current(input);const controller=new AbortController(),combined=signal?AbortSignal.any([signal,controller.signal]):controller.signal;const task=graph.run(input,{signal:combined});active.set(controller,task);try{const result=await task;await current(input);const grading=await require('./secureshopInventoryGradingReadback').readInventoryGrading({outcome:result,input,receipts:assessmentDependencies.receipts,isEnabled:assessment.isEnabled,check:()=>current(input),identityPool});const projected=project(result,input.requestId,grading);await current(input);return projected;}finally{active.delete(controller);}},
 async retry(input,{signal}={}){await current(input);const controller=new AbortController(),combined=signal?AbortSignal.any([signal,controller.signal]):controller.signal,task=retry(input,{signal:combined});active.set(controller,task);try{const result=await task;await current(input);return result;}finally{active.delete(controller);}},
 async recover(input){await current(input);const saved=await recovery.read(input);await current(input);if(saved.status!=='completed')return saved;const grading=await require('./secureshopInventoryGradingReadback').readInventoryGrading({outcome:saved.outcome,input,receipts:assessmentDependencies.receipts,isEnabled:assessment.isEnabled,check:()=>current(input),identityPool});const projected=project(saved.outcome,input.requestId,grading);await current(input);return{...projected,replayed:true};},
 async listHistory(input){return historical(input,'list');},
 async readHistory(input){return historical(input,'read');},
 });
 const router=require('../routes/secureshop/boundInventory').createBoundInventoryRouter({application,authenticatePersona});
 return Object.freeze({ready:true,application,router,assessment,async close(){closed=true;for(const controller of active.keys())controller.abort();await Promise.allSettled([...active.values()]);}});
}
module.exports={createInventoryProduction,PRODUCTION_QUALIFIED,projectInventoryOutcome:project,projectVisibleInventoryOutcome};
