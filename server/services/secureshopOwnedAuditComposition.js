'use strict';
function createOwnedAuditComposition({identityPool,launches,personaAuth,auditReader,cleanupAuthority,turns,journal,conversations,conversationRepository,client,provider,receipts,progress,judge,agentEnabled=false,personaAuthority,personaBindings,gradingCore,gradingBootstrap,agentsPool,resetComposition,toolPolicyAdmission,toolPolicyRepository,promptPolicyRepository,modeAuthority,assessmentReleaseAdmission}){
 if(gradingBootstrap!==undefined){
  const prepared=require('./secureshopGradingBootstrap').resolveSecureShopGradingBootstrap(gradingBootstrap,{identityPool,agentsPool,resetComposition,assessmentReleaseAdmission});
  for(const [name,value] of Object.entries({gradingCore,personaAuthority,personaBindings}))if(Object.hasOwn(arguments[0]||{},name)&&value!==prepared[name])throw TypeError('Matching prepared audit grading dependencies required');
  if(launches!==prepared.resetComposition.launches)throw TypeError('Matching audit launch authority required');
  ({gradingCore,personaAuthority,personaBindings}=prepared);
 }
 if(gradingCore!==undefined){const dependencies=require('./objectiveGradingCore').resolveObjectiveGradingDependencies(gradingCore,{identityPool,...(Object.hasOwn(arguments[0]||{},'personaBindings')?{personaBindings}:{})});if((receipts!==undefined&&receipts!==dependencies.receipts)||(progress!==undefined&&progress!==dependencies.progress))throw TypeError('Matching grading core stores required');({receipts,progress,personaBindings}=dependencies);}
 if(gradingBootstrap===undefined&&(personaBindings!==undefined||personaAuthority!==undefined))throw Object.assign(Error('Owned audit persona effect readiness unavailable'),{code:'PERSONA_EFFECT_NOT_READY'});
 if(toolPolicyRepository!==undefined){
  if(toolPolicyAdmission!==undefined)throw TypeError('Specify one owned audit policy source');
  if(typeof personaAuthority?.capture!=='function')throw TypeError('Owned audit policy authority required');
  toolPolicyAdmission=require('./secureshopBoundToolPolicyAdmission').createBoundToolPolicyAdmission({repository:toolPolicyRepository,
   workflow:'audit-query',declaredTools:[require('./secureshopOwnedAuditDecisionGraph').OWNED_AUDIT_TOOL]});
 }
 const promptPolicyOptions=require('./secureshopPromptPolicyRunnerOptions').promptPolicyRunnerOptions(promptPolicyRepository,personaAuthority);
 const targetAdmissions=require('../database/postgres/secureshopAuditTargetAdmissionRepository').createAuditTargetAdmissionRepository({pool:identityPool});
 const executionBinding=require('./secureshopAuditQueryExecutionBinding').createAuditQueryExecutionBinding({repository:conversationRepository,conversations});
 const graphRepository=require('../database/postgres/secureshopAuditQueryRepository').createAuditQueryRepository({pool:identityPool,checkExecutionBinding:executionBinding});
 const manualRepository=require('../database/postgres/secureshopAuditManualRepository').createAuditManualRepository({pool:identityPool,personaAuth});
 const graphAdapter=require('./secureshopOwnedAuditQueryAdapter').createOwnedAuditQueryAdapter({repository:graphRepository,client});
 const manualAdapter=require('./secureshopOwnedAuditManualAdapter').createOwnedAuditManualAdapter({repository:manualRepository,client});
 const snapshots=require('./secureshopOwnedAuditSearchSnapshot').createOwnedAuditSearchSnapshotBuilder({reader:auditReader,assertCurrent:scope=>launches.assertCurrent(scope)});
 const assessmentDeps={receipts,progress,judge,...(personaBindings===undefined?{}:{personaBindings})};
 const agent=agentEnabled?{decisionGraph:require('./secureshopOwnedAuditDecisionGraph').createOwnedAuditDecisionGraph({provider}),
  beginAssessment:require('./secureshopOwnedAuditAssessment').createOwnedAuditAssessment(assessmentDeps),
  beginTimingAssessment:require('./secureshopOwnedAuditTimingAssessment').createOwnedAuditTimingAssessment(assessmentDeps)}:{};
 const application=require('./secureshopOwnedAuditSearchApplication').createOwnedAuditSearchApplication({modeAuthority,launches,personaAuth,snapshots,client,manualAdapter,graphAdapter,turns,journal,conversations,targetAdmissions,...promptPolicyOptions,...(toolPolicyAdmission===undefined?{}:{toolPolicyAdmission}),...(personaAuthority===undefined?{}:{personaAuthority}),...agent});
 const lifecycle=require('./secureshopOwnedAuditLifecycle').createOwnedAuditLifecycle({cleanupAuthority,client});
 return Object.freeze({application,lifecycle,async checkReadiness(){if(personaBindings!==undefined&&await personaBindings.assertReady()===false)throw Error('Persona grading readiness rejected');await targetAdmissions.checkReadiness();await graphRepository.checkReadiness();await manualRepository.checkReadiness();const ready=await client.readiness();if(ready?.ready!==true||ready.capability!=='owned-audit-postgres.v1')throw Error('Owned audit service unavailable');return{ready:true};}});
}
module.exports={createOwnedAuditComposition};
