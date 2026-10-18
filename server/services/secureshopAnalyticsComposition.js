'use strict';
async function createAnalyticsComposition({runtime,agentsPool,launches,personaAuthority,conversationRepository,journal,coordinator,provider,promptPolicyRepository,assessmentFactory,disclosureAssessmentFactory,nlSqlAssessmentFactory,identityPool,qualifyModel,modeAuthority,authenticatePersona,lifecycle}={}){
 if(typeof runtime?.assertReady!=='function'||!runtime.service||typeof agentsPool?.query!=='function'||typeof authenticatePersona!=='function'||typeof assessmentFactory!=='function'||!promptPolicyRepository||!require('./secureshopAnalyticsLifecycle').isAnalyticsLifecycleFor(lifecycle,runtime.service))throw TypeError('Complete owned Analytics composition required');
 await runtime.assertReady();await require('../database/postgres/secureshopAnalyticsRequestReadiness').assertAnalyticsRequestReadiness(agentsPool,{requiredVersion:modeAuthority?2:1});
 const requests=require('../database/postgres/secureshopAnalyticsRequestRepository').createAnalyticsRequestRepository({personaAuthority});
 const ownedQuery=require('./secureshopOwnedAnalyticsAdapter').createOwnedAnalyticsAdapter({launches,personaAuthority,targetService:runtime.service,schema:runtime.service.schema});
 const foundation=require('./secureshopBoundAnalytics').createSecureShopBoundAnalytics({launches,conversationRepository,journal,coordinator,provider,personaAuthority,ownedQuery,promptPolicyRepository,assessmentFactory,disclosureAssessmentFactory,nlSqlAssessmentFactory,modeAuthority,requestRepository:requests});
 const application=require('./secureshopAnalyticsApplication').createAnalyticsApplication({foundation,requests,ownedQuery,launches,personaAuthority});
 const authenticate=(req,res,next)=>authenticatePersona(req,res,error=>{if(error)return next(error);if(!Number.isSafeInteger(req.ssUser?.id)||!['merchant','admin'].includes(req.ssUser?.role))return res.status(403).json({error:'Shop persona unavailable'});req.boundPersona=Object.freeze({id:req.ssUser.id,role:req.ssUser.role});return next();});
 const router=require('../routes/secureshop/boundAnalytics').createBoundAnalyticsRouter({application,authenticate});
 const nlSqlAssessment=nlSqlAssessmentFactory?require('./secureshopAnalyticsNlSqlRetained').createAnalyticsNlSqlRetained({foundation,requests,conversations:conversationRepository,identityPool,modeAuthority,qualifyModel}):null;
 return Object.freeze({ready:true,application,router,foundation,requests,nlSqlAssessment});
}
module.exports={createAnalyticsComposition};
